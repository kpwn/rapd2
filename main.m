#import "radare2_server.h"
#import <mach-o/loader.h>
#import <mach/mach_vm.h>
#import <mach/mach.h>
struct r2serv_mach_userdata {
    pid_t pid;
    mach_port_t port;
    mach_vm_address_t seekpos;
};


int r2serv_mach_read(struct r2serv_mach_userdata**user, uint8_t *buf, int len)
{
    struct r2serv_mach_userdata* data = *user;
    assert(data);
    
    
    mach_msg_type_number_t readl = len;
    mach_vm_address_t to_read = data->seekpos;
    mach_port_t taskport = data->port;
    //data->seekpos += len;
    
    kern_return_t kr      = KERN_SUCCESS;
    vm_address_t  address = 0;
    vm_size_t     size    = 0;
    
    vm_address_t validate_begin = to_read;
    vm_address_t validate_end = to_read + len;
    
    while (1) {
        mach_msg_type_number_t count;
        struct vm_region_submap_info_64 info;
        uint32_t nesting_depth;
        
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(data->port, &address, &size, &nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }
        
        if (info.is_submap) {
            nesting_depth++;
        } else {
            if (validate_begin >= address && validate_begin < address+size) {
                if (validate_end > address+size) {
                    validate_begin += size;
                } else {
                    validate_begin = validate_end;
                }
            }
        }
        address += size;
        
    }
    
    if (validate_end != validate_begin) {
        return 0;
    }

    mach_vm_read_overwrite(taskport, to_read, readl, buf, &readl);
    //mach_vm_read_overwrite(data->port, data->seekpos, len, buf, &readl);
    
    
    return readl;
}
char* r2serv_mach_cmd(struct r2serv_mach_userdata**user, const char* command) {
    while (*command == ' ') {
        command++;
    }
    struct r2serv_mach_userdata* data = *user;
    assert(data);
    
    printf("command is %s\n", command);
    if (*command == 'd') {
        command++;
        if (*command == 'm') {
            command++;
            
            char* buf = malloc(4096);
            *buf = 0;
            uint64_t bufsize = 4096;
            uint64_t bufcur = 0;
            kern_return_t kr      = KERN_SUCCESS;
            vm_address_t  address = 0;
            vm_size_t     size    = 0;
            
            while (1) {
                mach_msg_type_number_t count;
                struct vm_region_submap_info_64 info;
                uint32_t nesting_depth;
                
                count = VM_REGION_SUBMAP_INFO_COUNT_64;
                kr = vm_region_recurse_64(data->port, &address, &size, &nesting_depth,
                                          (vm_region_info_64_t)&info, &count);
                if (kr == KERN_INVALID_ADDRESS) {
                    break;
                } else if (kr) {
                    mach_error("vm_region:", kr);
                    break; /* last region done */
                }
                
                if (info.is_submap) {
                    nesting_depth++;
                } else {
                    
#define AppendFormat(...) {\
                    char memprot[512];\
                    snprintf(memprot, 512, __VA_ARGS__);\
                    if (bufcur + strlen(memprot) < bufsize) {\
                        strcat(buf, memprot);\
                    } else {\
                        bufsize *= 2;\
                        buf = realloc(buf, bufsize);\
                        strcat(buf, memprot);\
                    }\
                    bufcur += strlen(memprot);}
                    
                    AppendFormat("region: %p -> %p (%lx bytes) - prot: %s%s%s\n", (void*)address, (void*)(address+size), size, info.protection&VM_PROT_READ ? "r" : "-",info.protection&VM_PROT_WRITE ? "w" : "-",info.protection&VM_PROT_EXECUTE ? "x" : "-");
                    
                    if (data->pid != 0) {
                        union {
                            struct mach_header mh;
                            struct mach_header_64 mh64;
                        } hdr;
                        mach_vm_size_t osz = sizeof(hdr);
                        mach_vm_read_overwrite(data->port, address, osz, (mach_vm_address_t)&hdr, &osz);
                        
                        vm_address_t load_commands = 0;
                        vm_size_t loadcmd_size = 0;
                        uint64_t loadcmd_n = 0;
                        if (hdr.mh.magic == MH_MAGIC) {
                            AppendFormat("\tregion is a Mach-O header\n");
                            load_commands = address + sizeof(struct mach_header);
                            loadcmd_size = hdr.mh.sizeofcmds;
                            loadcmd_n = hdr.mh.ncmds;
                        } else if (hdr.mh64.magic == MH_MAGIC_64) {
                            AppendFormat("\tregion is a Mach-O 64 header\n");
                            load_commands = address + sizeof(struct mach_header_64);
                            loadcmd_size = hdr.mh64.sizeofcmds;
                            loadcmd_n = hdr.mh64.ncmds;
                        }
                        if (load_commands && loadcmd_size) {
                            char* loadcmds = malloc(loadcmd_size);
                            mach_vm_size_t outsize = loadcmd_size;
                            assert(mach_vm_read_overwrite(data->port, load_commands, loadcmd_size, (mach_vm_address_t) loadcmds, &outsize) == KERN_SUCCESS);
                            struct load_command* lc = (void*)loadcmds;
                            for (int i = 0; i < loadcmd_n; i++) {
                                if (lc->cmd == LC_SEGMENT) {
                                    struct segment_command* seg = (struct segment_command*)lc;
                                    AppendFormat("\tsegment: 0x%08x -> 0x%08x (%s)\n", seg->vmaddr, seg->vmaddr+seg->vmsize, seg->segname);
                                } else if (lc->cmd == LC_SEGMENT_64) {
                                    struct segment_command_64* seg = (struct segment_command_64*)lc;
                                    AppendFormat("\tsegment64: 0x%016llx -> 0x%016llx (%s)\n", seg->vmaddr, seg->vmaddr+seg->vmsize, seg->segname);
                                    
                                }
                                lc = (struct load_command*)(((char*)lc) + lc->cmdsize);
                                if (((vm_address_t)lc) > (vm_address_t)(loadcmds + loadcmd_size)) {
                                    break;
                                }
                            }
                        }
                    }
                    
                    
                }
                address += size;

            }
            
            return buf;

        }
    }
    
    
    return NULL;
}

int r2serv_mach_write(struct r2serv_mach_userdata**user, uint8_t *buf, int len)
{
    struct r2serv_mach_userdata* data = *user;
    assert(data);
    
    mach_vm_write(data->port, data->seekpos, (vm_offset_t)buf, len);
    
    return len;
}

uint64_t r2serv_mach_seek(struct r2serv_mach_userdata**user, uint64_t offset, int whence) {
    struct r2serv_mach_userdata* data = *user;
    assert(data);
    
    switch (whence) {
        case 0:
            data->seekpos = offset;
            break;
            
        case 1:
            data->seekpos += offset;
            break;
            
        case 2:
            return -1;
            break;
            
        default:
            break;
    }
    
    return data->seekpos;
}

int r2serv_mach_open(struct r2serv_mach_userdata**user, char *file, int flg, int mode)
{
    printf("arg is %s\n", file);
    
    char* arg = strchr(file, '/');
    if (arg) {
        *arg = 0;
    }
    
    pid_t pid = (pid_t)strtol(file, 0, 0);
    
    if (pid == 0) {
        pid = getpid();
    }
    printf("about to task_for_pid(%d)\n", pid);
    
    mach_port_t taskport = 0;
    if (task_for_pid(mach_task_self(), pid, &taskport) == KERN_SUCCESS) {
        struct r2serv_mach_userdata* data = calloc(1, sizeof(struct r2serv_mach_userdata));
        data->pid = pid;
        data->port = taskport;
        data->seekpos = 0;
        *user = data;
        return 0;
    }
    
    printf("task_for_pid(%d) failed\n", pid);
    return -1;
}

extern kern_return_t
bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

int r2serv_mach_open_kern(struct r2serv_mach_userdata**user, char *file, int flg, int mode)
{
    printf("about to task_for_pid(0)\n");
    
    mach_port_t taskport = 0;
    if (bootstrap_look_up(bootstrap_port, "com.apple.kernel_task", &taskport) == KERN_SUCCESS) {
        printf("looked up taskport\n");
        goto success;
    } else
    if (task_for_pid(mach_task_self(), 0, &taskport) == KERN_SUCCESS) {
        goto success;
    }
    else
    if (host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskport)  == KERN_SUCCESS) {
        goto success;
    }
    
    printf("task_for_pid(0) failed\n");
    return -1;

success:;
    
    struct r2serv_mach_userdata* data = calloc(1, sizeof(struct r2serv_mach_userdata));
    data->pid = 0;
    data->port = taskport;
    data->seekpos = 0;
    *user = data;
    return 0;

}

int main(int argc , char *argv[])
{
    register_controller("pid", (rap_server_open)r2serv_mach_open, (rap_server_read)r2serv_mach_read, (rap_server_write)r2serv_mach_write, (rap_server_seek)r2serv_mach_seek, 0, (rap_server_cmd)r2serv_mach_cmd);
    register_controller("kernel", (rap_server_open)r2serv_mach_open_kern, (rap_server_read)r2serv_mach_read, (rap_server_write)r2serv_mach_write, (rap_server_seek)r2serv_mach_seek, 0, (rap_server_cmd)r2serv_mach_cmd);

    start_radare_server();
    
    while (1) {
        sleep(1000);
    }
    
    return 0;
}
