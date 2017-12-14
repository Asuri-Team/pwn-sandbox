#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "protect.h"

char protect_buf[PROTECT_BUFSIZE];

void print_regs(struct user_regs_struct regs);

struct user_regs_struct saved_regs;
void save_reg(pid_t pid){
    ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs); 
}

void dump_read(pid_t pid, long syscall, long len) {
    char tmp[128];
    int fd, i;
    long t, words, bytes;
    struct user_regs_struct regs = saved_regs;
    //ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if(regs.rdi == 0 || regs.rdi == 1){
        sprintf(tmp, "/tmp/pwnlog-std");
    } else {
        sprintf(tmp, "/tmp/pwnlog-%lld", regs.rdi);    
    }
    words = regs.rdx/8;
    bytes = regs.rdx%8;
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);
    for(i=0; i<len && i < words; ++i) {
        t = ptrace(PTRACE_PEEKTEXT, pid, regs.rsi + i * 8, 0);
        write(fd, &t, 8);
    }
    if(bytes > 0){
        t = ptrace(PTRACE_PEEKTEXT, pid, regs.rsi + words * 8, 0);
        write(fd, &t, bytes);
    }
    close(fd);
}

void dump_write(pid_t pid, long syscall) {
    int i, fd;
    char tmp[128];
    long t, words, bytes;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if(regs.rdi == 0 || regs.rdi == 1){
        sprintf(tmp, "/tmp/pwnlog-std");
    } else {
        sprintf(tmp, "/tmp/pwnlog-%lld", regs.rdi);    
    }
    words = regs.rdx/8;
    bytes = regs.rdx%8;
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);
    for(i=0; i < words; ++i) {
        t = ptrace(PTRACE_PEEKTEXT, pid, regs.rsi + i * 8, 0);
        write(fd, &t, 8);
    }
    if(bytes > 0){
        t = ptrace(PTRACE_PEEKTEXT, pid, regs.rsi + words * 8, 0);
        write(fd, &t, bytes);
    }
    close(fd);
}

void dump_execve(pid_t pid, long syscall) {
    struct user_regs_struct regs;
    int i, j, fd;
    long t;
    char *a, tmp[128];
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    sprintf(tmp, "/tmp/pwnlog-syscalls");
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);   
    for(i=0; ; i+=8) {
        t = ptrace(PTRACE_PEEKTEXT, pid, regs.rdi + i, 0);
        a = (char *)&t;
        for(j=0; j<8; ++j){
            if(a[j] == 0){
                write(fd, &t, j);
            }
        }
        write(fd, &t, 8);
    }
    close(fd);
    kill(pid, SIGKILL);
    exit(-1);
}

void pwn_preprotect(pid_t pid, long syscall) {
    printf("pre syscall: %ld\n", syscall);
    switch(syscall){
        case SYS_read:
            save_reg(pid);
            break;
        case SYS_write:
            dump_write(pid, syscall);
            break;
        case SYS_execve:
            dump_execve(pid, syscall);
            break;
    } 
}

void pwn_postprotect(pid_t pid, long syscall, long retval) {
    printf("post syscall: %ld, retval: %ld\n", syscall, retval);
    if(syscall == SYS_read){
        dump_read(pid, syscall, retval);
    }
}




void print_regs(struct user_regs_struct regs){
        printf("rdi: 0x%llx, rsi: 0x%llx, rdx: 0x%llx, rcx: 0x%llx, r8:0x%llx, r9:0x%llx\n", regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9);
}
