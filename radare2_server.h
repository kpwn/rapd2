//
//  radare2_server.h
//  yalux_clean
//
//  Created by qwertyoruiop on 12/09/16.
//  Copyright © 2016 qwertyoruiop. All rights reserved.
//

#ifndef radare2_server_h
#define radare2_server_h

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <sys/event.h>
#include <pthread.h>
#include <libkern/OSByteOrder.h>

typedef int (*rap_server_open)(void **user, const char *file, int flg, int mode);
typedef uint64_t (*rap_server_seek)(void **user, uint64_t offset, int whence);
typedef int (*rap_server_read)(void **user, uint8_t *buf, int len);
typedef int (*rap_server_write)(void **user, uint8_t *buf, int len);
typedef char *(*rap_server_cmd)(void **user, const char *command);
typedef int (*rap_server_close)(void **user, int fd);

void register_controller(const char* name, rap_server_open open, rap_server_read read, rap_server_write write, rap_server_seek seek, rap_server_close close, rap_server_cmd cmd);
void start_radare_server();

#endif /* radare2_server_h */
