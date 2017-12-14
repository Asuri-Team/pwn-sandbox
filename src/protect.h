#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define PROTECT_BUFSIZE 2048
char cap_file[1024];

void pwn_preprotect(pid_t pid, long syscall);
void pwn_postprotect(pid_t pid, long syscall, long retval);