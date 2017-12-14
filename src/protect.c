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

void pwn_protect(pid_t pid, long syscall) {
    if(syscall == SYS_read){
        dump_read(pid, syscall);
    }
}

void dump_read(pid_t pid, long syscall) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("rsi: %p, rdi: %p, rcx:%p, rdx:%p, r8:%p, r9:%p\n", regs.rsi, regs.rdi,regs.rcx,regs.rdx, regs.r8,regs.r9);
}

