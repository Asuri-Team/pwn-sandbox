#ifndef DEFS_H
#define DEFS_H
#include <stdint.h>


struct i386_user_regs_struct {
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
};

#  define MAX_ARGS	6

# define TD	TRACE_DESC
# define TF	TRACE_FILE
# define TI	TRACE_IPC
# define TN	TRACE_NETWORK
# define TP	TRACE_PROCESS
# define TS	TRACE_SIGNAL
# define TM	TRACE_MEMORY
# define TST	TRACE_STAT
# define TLST	TRACE_LSTAT
# define TFST	TRACE_FSTAT
# define TSTA	TRACE_STAT_LIKE
# define TSF	TRACE_STATFS
# define TFSF	TRACE_FSTATFS
# define TSFA	TRACE_STATFS_LIKE
# define NF	SYSCALL_NEVER_FAILS
# define MA	MAX_ARGS
# define SI	STACKTRACE_INVALIDATE_CACHE
# define SE	STACKTRACE_CAPTURE_ON_ENTER
# define CST	COMPAT_SYSCALL_TYPES
#define SEN(syscall_name) SEN_ ## syscall_name, 0

#endif