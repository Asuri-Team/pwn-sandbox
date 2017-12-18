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
#include <elf.h>

#include "kernel_types.h"
#include "defs.h"
#include "x86_syscallent.h"
#include "x86_64_syscallent.h"
#include "protect.h"
#include "utils.h"


struct user_regs_struct saved_regs;

kernel_ulong_t u_arg[MAX_ARGS];

uint32_t *const i386_esp_ptr = &i386_regs.esp;
uint64_t *const x86_64_rsp_ptr = (uint64_t *) &x86_64_regs.rsp;
char protect_buf[PROTECT_BUFSIZE];
const static struct_sysent *syscallent;

static long
ptrace_getregset(pid_t pid);

static int
get_syscall_args();

void get_arch(pid_t pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (regs.cs == 0x33) {
        syscallent = x86_64_sysent;
        printf("x86_64 program\n");
    } else if (regs.cs == 0x23) {
        syscallent = x86_sysent;
        printf("x86 program\n");
    }
}

void print_args();

void save_reg(pid_t pid){
    ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs); 
}

void set_logfile_name(char *filename){
    strcpy(cap_file, filename);
    fprintf(stderr, "\033[31mcap file: %s\033[0m\n", cap_file);
}

/*
 * len = read(fd, buf, max);
 */
void x64_dump_read(pid_t pid, long syscall, long len) {
    char tmp[128];
    int fd, i;
    long t, words, bytes;
    if(u_arg[0] == 0 || u_arg[0] == 1){
        sprintf(tmp, "%s-std", cap_file);
    } else {
        sprintf(tmp, "%s-%ld", cap_file, u_arg[0]);    
    }
    words = len/8;
    bytes = len%8;
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);
    if (fd == -1)
        exit_error("open()", errno);
    for(i=0; i<len && i < words; ++i) {
        t = ptrace(PTRACE_PEEKTEXT, pid, u_arg[1] + i * 8, 0);
        write(fd, &t, 8);
    }
    if(bytes > 0){
        t = ptrace(PTRACE_PEEKTEXT, pid, u_arg[1] + words * 8, 0);
        write(fd, &t, bytes);
    }
    close(fd);
}

/*
 * len = read(fd, buf, len);
 */
void x64_dump_write(pid_t pid, long syscall) {
    int i, fd;
    char tmp[128];
    long t, words, bytes;
    if(u_arg[0] == 0 || u_arg[0] == 1){
        sprintf(tmp, "%s-std", cap_file);
    } else {
        sprintf(tmp, "%s-%ld", cap_file, u_arg[0]);    
    }
    words = u_arg[2]/8;
    bytes = u_arg[2]%8;
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);
    if (fd == -1)
        exit_error("open()", errno);
    for(i=0; i < words; ++i) {
        t = ptrace(PTRACE_PEEKTEXT, pid, u_arg[1] + i * 8, 0);
        write(fd, &t, 8);
    }
    if(bytes > 0){
        t = ptrace(PTRACE_PEEKTEXT, pid, u_arg[1] + words * 8, 0);
        write(fd, &t, bytes);
    }
    close(fd);
}

/*
 * stat = execve(path, arg, env);
 */
void x64_dump_execve(pid_t pid, long syscall) {
    int i, j, fd;
    long t;
    char *a, tmp[128];
    sprintf(tmp, "%s-syscall", cap_file);    
    fd = open(tmp, O_WRONLY|O_CREAT|O_APPEND, 0666);   
    for(i=0; ; i+=8) {
        t = ptrace(PTRACE_PEEKTEXT, pid, u_arg[0] + i, 0);
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

void preprotect_x86_64(pid_t pid, long syscall){
    switch(syscallent[syscall].sen){
        case SEN_write:
            x64_dump_write(pid, syscall);
            break;
        case SEN_execve:
            x64_dump_execve(pid, syscall);
            break;
    } 
}

void preprotect_x86(pid_t pid, long syscall){

}

void pwn_preprotect(pid_t pid, long syscall) {
    ptrace_getregset(pid);
    get_syscall_args(pid);
    fprintf(stderr, "\033[31mpre syscall: %s \033[0m\n", syscallent[syscall].sys_name);
    print_args();
    if(syscallent == x86_64_sysent){
        preprotect_x86_64(pid, syscall);
    } else if(syscallent == x86_sysent) {
        preprotect_x86(pid, syscall);
    }
}



void pwn_postprotect(pid_t pid, long syscall, long retval) {
    fprintf(stderr, "\033[31mpost syscall: %s, retval: %ld\033[0m\n", syscallent[syscall].sys_name, retval);
    switch(syscallent[syscall].sen){
        case SEN_read:
            x64_dump_read(pid, syscall, retval);
            break;
    } 
}

void print_args(){
    int i;
    fprintf(stderr, "\033[31msyscall args: ");
    for (i=0; i<6; ++i){
        fprintf(stderr, "0x%lx ", u_arg[i]);
    }
    fprintf(stderr, "\033[0m\n");
}

static long
ptrace_getregset(pid_t pid)
{
# ifdef ARCH_IOVEC_FOR_GETREGSET
	/* variable iovec */
	ARCH_IOVEC_FOR_GETREGSET.iov_len = sizeof(ARCH_REGS_FOR_GETREGSET);
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS,
		      &ARCH_IOVEC_FOR_GETREGSET);
# else
	/* constant iovec */
	static struct iovec io = {
		.iov_base = &ARCH_REGS_FOR_GETREGSET,
		.iov_len = sizeof(ARCH_REGS_FOR_GETREGSET)
	};
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);

# endif
}

/*
 * PTRACE_GETREGSET was added to the kernel in v2.6.25,
 * a PTRACE_GETREGS based fallback is provided for old kernels.
 */
static int
getregs_old(pid_t pid)
{
	/* Use old method, with unreliable heuristical detection of 32-bitness. */
	long r = ptrace(PTRACE_GETREGS, pid, NULL, &x86_64_regs);
	if (r)
		return r;

	if (x86_64_regs.cs == 0x23) {
		/*
		 * The order is important: i386_regs and x86_64_regs
		 * are overlaid in memory!
		 */
		i386_regs.ebx = x86_64_regs.rbx;
		i386_regs.ecx = x86_64_regs.rcx;
		i386_regs.edx = x86_64_regs.rdx;
		i386_regs.esi = x86_64_regs.rsi;
		i386_regs.edi = x86_64_regs.rdi;
		i386_regs.ebp = x86_64_regs.rbp;
		i386_regs.eax = x86_64_regs.rax;
		/* i386_regs.xds = x86_64_regs.ds; unused by strace */
		/* i386_regs.xes = x86_64_regs.es; ditto... */
		/* i386_regs.xfs = x86_64_regs.fs; */
		/* i386_regs.xgs = x86_64_regs.gs; */
		i386_regs.orig_eax = x86_64_regs.orig_rax;
		i386_regs.eip = x86_64_regs.rip;
		/* i386_regs.xcs = x86_64_regs.cs; */
		/* i386_regs.eflags = x86_64_regs.eflags; */
		i386_regs.esp = x86_64_regs.rsp;
		/* i386_regs.xss = x86_64_regs.ss; */
	}
	return 0;
}

/* Return -1 on error or 1 on success (never 0!). */
static int
get_syscall_args()
{
	if (syscallent == x86_64_sysent) {
        u_arg[0] = x86_64_regs.rdi;
        u_arg[1] = x86_64_regs.rsi;
        u_arg[2] = x86_64_regs.rdx;
        u_arg[3] = x86_64_regs.r10;
        u_arg[4] = x86_64_regs.r8;
        u_arg[5] = x86_64_regs.r9;
	} else {
		/*
		 * i386 ABI: zero-extend from 32 bits.
		 * Use truncate_klong_to_current_wordsize(tcp->u_arg[N])
		 * in syscall handlers
		 * if you need to use *sign-extended* parameter.
		 */
		u_arg[0] = (uint32_t) i386_regs.ebx;
		u_arg[1] = (uint32_t) i386_regs.ecx;
		u_arg[2] = (uint32_t) i386_regs.edx;
		u_arg[3] = (uint32_t) i386_regs.esi;
		u_arg[4] = (uint32_t) i386_regs.edi;
		u_arg[5] = (uint32_t) i386_regs.ebp;
	}
	return 1;
}