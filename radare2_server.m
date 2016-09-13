#import "radare2_server.h"

int sockfd;

struct client {
    struct client* next;
    int fd;
    
    char* readbuf;
    unsigned int readbuf_sz;
    unsigned int readbuf_read;
    unsigned int readbuf_off;
    
    struct rap_controller* controller;
    
    void* user_value;
    
};

struct client* client_list = NULL;


struct rap_controller {
    struct rap_controller* next;
    char* name;
    rap_server_open open;
    rap_server_read read;
    rap_server_seek seek;
    rap_server_write write;
    rap_server_cmd cmd;
    rap_server_close close;
};

struct rap_controller* controllers;

void register_controller(const char* name, rap_server_open open, rap_server_read read, rap_server_write write, rap_server_seek seek, rap_server_close close, rap_server_cmd cmd)
{
    struct rap_controller* cnt = calloc(1, sizeof(struct rap_controller));
    cnt->name = strdup(name);
    cnt->open = open;
    cnt->read = read;
    cnt->write = write;
    cnt->seek = seek;
    cnt->close = close;
    cnt->cmd = cmd;
    cnt->next = controllers;
    controllers = cnt;
}


enum {
    RAP_RMT_OPEN = 0x01,
    RAP_RMT_READ,
    RAP_RMT_WRITE,
    RAP_RMT_SEEK,
    RAP_RMT_CLOSE,
    RAP_RMT_CMD,
    RAP_RMT_REPLY = 0x80,
    RAP_RMT_MAX = 4096
};

int asyncread(struct client* client, void* out, size_t reqbytes) {
    if (client->readbuf_read - client->readbuf_off >= reqbytes) {
        memcpy(out, client->readbuf + client->readbuf_off, reqbytes);
        client->readbuf_off += reqbytes;
        return reqbytes;
    }
    return -1;
}
void* asyncread_nocopy(struct client* client, size_t reqbytes) {
    if (client->readbuf_read - client->readbuf_off >= reqbytes) {
        client->readbuf_off += reqbytes;
        return client->readbuf + client->readbuf_off - reqbytes;
    }
    return 0;
}
#define ASYNC_FAIL goto end;
#define ASYNC_READ(client, out, reqbytes) if (asyncread(client,out,reqbytes) == -1) ASYNC_FAIL;

int kq;

void disconnect_fd(int fd) {
    printf("disconnect\n");
    struct kevent kev;
    
    EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    assert (kevent(kq, &kev, 1, NULL, 0, NULL) != -1);
    
    struct client* client_iter = client_list;
    struct client* client_iter_prev = NULL;
    while (client_iter) {
        
        if (fd == client_iter->fd) {
            if (client_iter_prev) {
                client_iter_prev->next = client_iter->next;
            }
            if (client_iter == client_list) {
                client_list = client_iter->next;
            }
            if (client_iter->readbuf) {
                free(client_iter->readbuf);
            }
            free(client_iter);
            break;
        }
        
        
        client_iter_prev = client_iter;
        client_iter = client_iter->next;
    }
    
    close(fd);
    
}
#define ASYNC_READ_TYPE(type, name) type name; ASYNC_READ(client, &name, sizeof(type));
void handle_client_buffer(struct client* client) {
    uint8_t packet = 0;
    
    ASYNC_READ(client, &packet, 1);
    
    switch (packet) {
        case RAP_RMT_OPEN:
        {
            ASYNC_READ_TYPE(uint8_t, rw);
            ASYNC_READ_TYPE(uint8_t, strl);
            char *pathnam = alloca(strl+1);
            ASYNC_READ(client, pathnam, strl);
            pathnam[strl]=0;
            //printf("trying to open %s\n", pathnam);
            
            char* arg = strchr(pathnam, '/');
            if (arg) {
                *arg = 0;
                arg++;
            }

            struct rap_controller* cont_iter = controllers;
            while (cont_iter) {
                if (strcmp(pathnam, cont_iter->name) == 0) {
                    client->controller = cont_iter;
                    break;
                }
                cont_iter = cont_iter->next;
            }
            if (!client->controller) {
                printf("couldn't find controller for %s\n", pathnam);
                disconnect_fd(client->fd);
                return;
            }
            printf("connected to controller %s\n", pathnam);
            if (!arg) {
                arg="";
            }
            if (client->controller->open) {
                if (client->controller->open(&client->user_value, arg, rw, 0) == -1) {
                    disconnect_fd(client->fd);
                    return;
                }
            }
            uint8_t reply[] = {RAP_RMT_OPEN | RAP_RMT_REPLY, 1, 0, 0, 0};
            write(client->fd, reply, 5);
            break;
        }
            
        case RAP_RMT_READ:
        {
            assert(client->controller);
            uint32_t read_sz = 0;
            ASYNC_READ(client, &read_sz, 4);
            read_sz = OSSwapBigToHostInt32(read_sz);
            //printf("read chunk %x\n", read_sz);
            if (read_sz > RAP_RMT_MAX) {
                read_sz = RAP_RMT_MAX;
            }
            uint8_t* buf = alloca(read_sz);
            bzero(buf, read_sz);
            if (client->controller->read) {
                client->controller->read(&client->user_value, buf, read_sz);
            }
            uint8_t *repl = alloca(5 + read_sz);
            repl[0] = packet | RAP_RMT_REPLY;
            *(uint32_t*)(&repl[1]) = OSSwapHostToBigInt32(read_sz);
            memcpy(&repl[5], buf, read_sz);
            write(client->fd, repl, read_sz+5);
            break;
            
        }
        case RAP_RMT_WRITE:
        {
            assert(client->controller);
            uint32_t read_sz = 0;
            ASYNC_READ(client, &read_sz, 4);
            read_sz = OSSwapBigToHostInt32(read_sz);
            //printf("write chunk %x\n", read_sz);
            if (read_sz > RAP_RMT_MAX) {
                read_sz = RAP_RMT_MAX;
            }
            uint8_t* dwrite = asyncread_nocopy(client, read_sz);
            if (!dwrite) {
                ASYNC_FAIL;
            }
            
            if (client->controller->read) {
                client->controller->write(&client->user_value, dwrite, read_sz);
            }
            
            packet |= RAP_RMT_REPLY;
            
            read_sz = OSSwapHostToBigInt32(read_sz);
            
            uint8_t reply[] = {RAP_RMT_SEEK | RAP_RMT_REPLY, 0, 0, 0, 0};
            *(uint32_t*)(&reply[1]) = read_sz;
            write(client->fd, reply, 5);
            
            break;
        }
        case RAP_RMT_SEEK:
        {
            assert(client->controller);
            ASYNC_READ_TYPE(uint8_t, whence);
            ASYNC_READ_TYPE(uint64_t, offset);
            offset = OSSwapBigToHostInt64(offset);
            //printf("seek to %llx %s\n", offset, whence == SEEK_CUR ? "SEEK_CUR" : whence == SEEK_SET ? "SEEK_SET" : whence == SEEK_END ? "SEEK_END" : "unknown");
            if (client->controller->seek) {
                offset = client->controller->seek(&client->user_value, offset, whence);
            }
            offset = OSSwapHostToBigInt64(offset);
            uint8_t reply[] = {RAP_RMT_SEEK | RAP_RMT_REPLY, 0, 0, 0, 0, 0, 0, 0, 0};
            *(uint64_t*)(&reply[1]) = offset;
            write(client->fd, reply, 9);
            break;
        }
        case RAP_RMT_CMD:
        {
            assert(client->controller);
            ASYNC_READ_TYPE(uint32_t, cmdsize);
            cmdsize = OSSwapBigToHostInt32(cmdsize);
            char* cmd = asyncread_nocopy(client, cmdsize);
            if (!cmd) {
                ASYNC_FAIL;
            }
            char* ptr = 0;
            if (client->controller->cmd) {
                ptr = client->controller->cmd(&client->user_value, cmd);
            }
            if (ptr) {
                uint32_t read_sz = (uint32_t)strlen(ptr)+1;
                uint8_t *repl = alloca(5 + read_sz);
                repl[0] = RAP_RMT_CMD | RAP_RMT_REPLY;
                *(uint32_t*)(&repl[1]) = OSSwapHostToBigInt32(read_sz);
                memcpy(&repl[5], ptr, read_sz);
                write(client->fd, repl, read_sz+5);
                
                
                free(ptr);
            } else {
                uint8_t reply[] = {RAP_RMT_CMD | RAP_RMT_REPLY, 0, 0, 0, 0};
                write(client->fd, reply, 5);
            }
            break;
        }
        case RAP_RMT_CLOSE:
        {
            assert(client->controller);
            
            ASYNC_READ_TYPE(uint32_t, param);
            param = OSSwapBigToHostInt32(param);
            if (client->controller->close) {
                client->controller->close(&client->user_value, param);
            }
            param = OSSwapHostToBigInt32(param);
            
            uint8_t reply[] = {RAP_RMT_CLOSE | RAP_RMT_REPLY, 0, 0, 0, 0};
            write(client->fd, reply, 5);
        }
            break;
            
        default:
            disconnect_fd(client->fd);
            return;
            break;
    }
    
    // entirely parsed packet.
    
    if (client->readbuf_read > client->readbuf_off) {
        memcpy(client->readbuf, client->readbuf+client->readbuf_off, client->readbuf_read-client->readbuf_off);
        client->readbuf_read -= client->readbuf_off;
        client->readbuf_off = 0;
        return handle_client_buffer(client);
    } else {
        client->readbuf_read=0;
        client->readbuf_off = 0;
    }
    
end:
    client->readbuf_off = 0;
    return;
    
    
}

void handle_client_read(struct client* client) {
    if (!client->readbuf) {
        client->readbuf = malloc(4096);
        client->readbuf_sz = 4096;
    }
    
    
    char rdbuf[4096];
    ssize_t readsz = read(client->fd, rdbuf, 4096);
    assert(readsz != -1);
    if (client->readbuf_read + readsz > client->readbuf_sz) {
        client->readbuf_sz *= 2;
        client->readbuf = realloc(client->readbuf, client->readbuf_sz);
    }
    memcpy(client->readbuf + client->readbuf_read, rdbuf, readsz);
    client->readbuf_read += readsz;
    
    assert(client->readbuf != 0);
    assert(client->readbuf_read > 0);
    
    return handle_client_buffer(client);
}


void
watch_loop() {
    struct kevent evSet;
    struct kevent evList[32];
    int nev, i;
    struct sockaddr_storage addr;
    socklen_t socklen = sizeof(addr);
    int fd;
    
    while(1) {
        nev = kevent(kq, NULL, 0, evList, 32, NULL);
        if(nev < 1) continue;
        for (i=0; i<nev; i++) {
            if (evList[i].flags & EV_EOF) {
                disconnect_fd((int)evList[i].ident);
                continue;
            }
            else if (evList[i].ident == sockfd) {
                printf("connect\n");
                
                fd = accept((int)evList[i].ident, (struct sockaddr *)&addr, &socklen);
                assert(fd != -1);
                
                EV_SET(&evSet, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
                assert (kevent(kq, &evSet, 1, NULL, 0, NULL) != -1);
                
                struct client* new_client = calloc(sizeof(struct client),1);
                new_client->next = client_list;
                client_list = new_client;
                
                new_client->fd = fd;
            }
            else if (evList[i].flags & EVFILT_READ) {
                struct client* client_iter = client_list;
                while (client_iter) {
                    
                    if (evList[i].ident == client_iter->fd) {
                        handle_client_read(client_iter);
                        break;
                    }
                    
                    client_iter = client_iter->next;
                }
            }
        }
    }
}

void start_radare_server() {
    kq = kqueue();
    struct kevent kev;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd != -1);
    
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    
    struct sockaddr_in srv;
    bzero(&srv, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(31336);
    
    assert( bind(sockfd,(struct sockaddr *)&srv , sizeof(srv)) != -1 );
    
    listen(sockfd, 5);
    
    EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    
    assert(kevent(kq, &kev, 1, NULL, 0, NULL) != -1);
    pthread_t pt;
    pthread_create(&pt, 0, (void*) watch_loop, 0);
}
