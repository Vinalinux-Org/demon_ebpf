#ifndef __COMMON_H
#define __COMMON_H

#define COMM_LEN 16
#define FILENAME_LEN 128
#define SYSCALL_OPEN  0
#define SYSCALL_READ  1
#define SYSCALL_WRITE 2

struct file_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 cgroup_id;
    int type;
    char   comm[COMM_LEN];
    int    fd;
    int    count;
    char   filename[FILENAME_LEN];
};

#endif
