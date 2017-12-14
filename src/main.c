#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "utils.h"
#include "protect.h"

int do_child(char* cmd, char **argv, char **envp);
int do_trace(pid_t child);
void protect(long syscall);
pid_t child;

int main(int argc, char **argv, char **envp) {
    char buf[1024];
    sprintf(buf, "%s-orig", argv[0]);
    child = fork();
    if(child == -1){
        exit_error("fork()", errno);
    } else if (child == 0) {
        return do_child(buf, argv, envp);
    } else {
        return do_trace(child);
    }
}

int do_child(char* cmd, char **argv, char **envp) {

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execve(cmd, argv, 0);
}

int wait_for_syscall(pid_t child);

int do_trace(pid_t child) {
    long status, sys_no, retval;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {
        //entrance of syscall
        if (wait_for_syscall(child) != 0) break;
        sys_no = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        pwn_protect(child, sys_no);

        //out of syscall
        if (wait_for_syscall(child) != 0) break;
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        fprintf(stderr, "%d\n", retval);
    }
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}
