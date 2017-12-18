#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "protect.h"

int do_child(char* cmd, char **argv, char **envp);
int do_trace(pid_t child);
void protect(long syscall);
pid_t child;


int get_filename(char *dst, char *src) {
    int len, i, j;
    len = strlen(src);
    for(i=len - 1; i>=0; --i) {
        if(src[i] == '/') {
            break;
        }
    }
    strcpy(dst, src + i + 1);
}

int main(int argc, char **argv, char **envp) {
    char buf[256];
    char fname[128];
    char path[512];
    sprintf(buf, "%s-orig", argv[0]);
    get_filename(fname, argv[0]);
    sprintf(path, "/tmp/.%s", fname);
    mkdir(path, 0777);
    time_t ts = time(NULL);
    sprintf(path, "/tmp/.%s/%ld", fname, ts);
    set_logfile_name(path);
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
    return execve(cmd, argv, 0);
}

int wait_for_syscall(pid_t child);

int do_trace(pid_t child) {
    int status;
    long sys_no, retval;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
    get_arch(child);
    while(1) {
        //entrance of syscall
        if (wait_for_syscall(child) != 0) break;
        sys_no = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        pwn_preprotect(child, sys_no);

        //out of syscall
        if (wait_for_syscall(child) != 0) break;
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        pwn_postprotect(child, sys_no, retval);
    }
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);
    if (WIFEXITED(status))
        return 1;
    return 0;
}
