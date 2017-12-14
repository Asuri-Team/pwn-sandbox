#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "protect.h"
void print_regs(struct user_regs_struct regs);

void dump_read(pid_t pid, long syscall) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("read: ");
    print_regs(regs);
}

void dump_write(pid_t pid, long syscall) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("write: ");
    print_regs(regs);
}

void print_regs(struct user_regs_struct regs){
        printf("rdi: 0x%llx, rsi: 0x%llx, rdx: 0x%llx, rcx: 0x%llx, r8:0x%llx, r9:0x%llx\n", regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9);
}

void pwn_protect(pid_t pid, long syscall) {
    printf("syscall: %ld\n", syscall);
    if(syscall == SYS_read){
        dump_read(pid, syscall);
    } 
    else if(syscall == SYS_write){
        dump_write(pid, syscall);
    }
}

