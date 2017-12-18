#ifndef PROTECT_H
#define PROTECT_H
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>

#include "defs.h"

#define PROTECT_BUFSIZE 2048
char cap_file[512];

void get_arch(pid_t pid);
void pwn_preprotect(pid_t pid, long syscall);
void pwn_postprotect(pid_t pid, long syscall, long retval);
void set_logfile_name(char *filename);

static union {
	struct user_regs_struct      x86_64_r;
	struct i386_user_regs_struct i386_r;
} x86_regs_union;
#define x86_64_regs x86_regs_union.x86_64_r
#define i386_regs   x86_regs_union.i386_r

extern uint32_t *const i386_esp_ptr;
extern uint64_t *const x86_64_rsp_ptr;

static struct iovec x86_io = {
	.iov_base = &x86_regs_union
};

#define ARCH_REGS_FOR_GETREGSET x86_regs_union
#define ARCH_IOVEC_FOR_GETREGSET x86_io
#define ARCH_PC_REG (x86_io.iov_len == sizeof(i386_regs) ? i386_regs.eip : x86_64_regs.rip)

#endif