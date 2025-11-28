/**
 * Project Overwatch - Linux Userspace EDR
 * Phase 2: Syscall Decoding (The Decoder)
 * 
 * This module handles reading and interpreting syscall information:
 * - Reading CPU registers using PTRACE_GETREGS
 * - Mapping syscall numbers to names (syscall table)
 * - Decoding syscall arguments based on x86_64 ABI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

#include "watchtower.h"

/* ============================================================================
 * SYSCALL NAME TABLE
 * ============================================================================
 * Maps syscall numbers to human-readable names.
 * Reference: /usr/include/asm/unistd_64.h or ausyscall --dump
 */

typedef struct {
    long number;
    const char *name;
    const char *description;
} syscall_entry_t;

static const syscall_entry_t syscall_table[] = {
    { 0,   "read",       "Read from file descriptor" },
    { 1,   "write",      "Write to file descriptor" },
    { 2,   "open",       "Open file" },
    { 3,   "close",      "Close file descriptor" },
    { 4,   "stat",       "Get file status" },
    { 5,   "fstat",      "Get file status by fd" },
    { 6,   "lstat",      "Get symbolic link status" },
    { 7,   "poll",       "Wait for events on file descriptors" },
    { 8,   "lseek",      "Reposition file offset" },
    { 9,   "mmap",       "Map files into memory" },
    { 10,  "mprotect",   "Set protection on memory region" },
    { 11,  "munmap",     "Unmap files from memory" },
    { 12,  "brk",        "Change data segment size" },
    { 13,  "rt_sigaction", "Signal action" },
    { 14,  "rt_sigprocmask", "Signal mask" },
    { 15,  "rt_sigreturn", "Return from signal handler" },
    { 16,  "ioctl",      "Device control" },
    { 17,  "pread64",    "Read from file at offset" },
    { 18,  "pwrite64",   "Write to file at offset" },
    { 19,  "readv",      "Read into multiple buffers" },
    { 20,  "writev",     "Write from multiple buffers" },
    { 21,  "access",     "Check file permissions" },
    { 22,  "pipe",       "Create pipe" },
    { 23,  "select",     "Synchronous I/O multiplexing" },
    { 24,  "sched_yield", "Yield CPU" },
    { 25,  "mremap",     "Remap memory" },
    { 26,  "msync",      "Synchronize memory" },
    { 27,  "mincore",    "Check memory residency" },
    { 28,  "madvise",    "Memory advice" },
    { 29,  "shmget",     "Get shared memory segment" },
    { 30,  "shmat",      "Attach shared memory" },
    { 31,  "shmctl",     "Shared memory control" },
    { 32,  "dup",        "Duplicate file descriptor" },
    { 33,  "dup2",       "Duplicate file descriptor" },
    { 34,  "pause",      "Wait for signal" },
    { 35,  "nanosleep",  "High-resolution sleep" },
    { 36,  "getitimer",  "Get interval timer" },
    { 37,  "alarm",      "Set alarm clock" },
    { 38,  "setitimer",  "Set interval timer" },
    { 39,  "getpid",     "Get process ID" },
    { 40,  "sendfile",   "Transfer data between file descriptors" },
    { 41,  "socket",     "Create socket" },
    { 42,  "connect",    "Connect to remote socket" },
    { 43,  "accept",     "Accept connection" },
    { 44,  "sendto",     "Send message on socket" },
    { 45,  "recvfrom",   "Receive message from socket" },
    { 46,  "sendmsg",    "Send message on socket" },
    { 47,  "recvmsg",    "Receive message from socket" },
    { 48,  "shutdown",   "Shut down socket" },
    { 49,  "bind",       "Bind socket to address" },
    { 50,  "listen",     "Listen on socket" },
    { 51,  "getsockname", "Get socket name" },
    { 52,  "getpeername", "Get peer name" },
    { 53,  "socketpair", "Create pair of sockets" },
    { 54,  "setsockopt", "Set socket options" },
    { 55,  "getsockopt", "Get socket options" },
    { 56,  "clone",      "Create child process" },
    { 57,  "fork",       "Create child process" },
    { 58,  "vfork",      "Create child process (virtual fork)" },
    { 59,  "execve",     "Execute program" },
    { 60,  "exit",       "Terminate process" },
    { 61,  "wait4",      "Wait for process" },
    { 62,  "kill",       "Send signal" },
    { 63,  "uname",      "Get system information" },
    { 64,  "semget",     "Get semaphore set" },
    { 65,  "semop",      "Semaphore operations" },
    { 66,  "semctl",     "Semaphore control" },
    { 67,  "shmdt",      "Detach shared memory" },
    { 68,  "msgget",     "Get message queue" },
    { 69,  "msgsnd",     "Send message" },
    { 70,  "msgrcv",     "Receive message" },
    { 71,  "msgctl",     "Message queue control" },
    { 72,  "fcntl",      "File control" },
    { 73,  "flock",      "File lock" },
    { 74,  "fsync",      "Synchronize file" },
    { 75,  "fdatasync",  "Synchronize file data" },
    { 76,  "truncate",   "Truncate file" },
    { 77,  "ftruncate",  "Truncate file by fd" },
    { 78,  "getdents",   "Get directory entries" },
    { 79,  "getcwd",     "Get current directory" },
    { 80,  "chdir",      "Change directory" },
    { 81,  "fchdir",     "Change directory by fd" },
    { 82,  "rename",     "Rename file" },
    { 83,  "mkdir",      "Create directory" },
    { 84,  "rmdir",      "Remove directory" },
    { 85,  "creat",      "Create file" },
    { 86,  "link",       "Create hard link" },
    { 87,  "unlink",     "Remove file" },
    { 88,  "symlink",    "Create symbolic link" },
    { 89,  "readlink",   "Read symbolic link" },
    { 90,  "chmod",      "Change file mode" },
    { 91,  "fchmod",     "Change file mode by fd" },
    { 92,  "chown",      "Change file owner" },
    { 93,  "fchown",     "Change file owner by fd" },
    { 94,  "lchown",     "Change symbolic link owner" },
    { 95,  "umask",      "Set file creation mask" },
    { 96,  "gettimeofday", "Get time" },
    { 97,  "getrlimit",  "Get resource limits" },
    { 98,  "getrusage",  "Get resource usage" },
    { 99,  "sysinfo",    "Get system information" },
    { 100, "times",      "Get process times" },
    { 101, "ptrace",     "Process trace" },
    { 102, "getuid",     "Get user ID" },
    { 103, "syslog",     "System log" },
    { 104, "getgid",     "Get group ID" },
    { 105, "setuid",     "Set user ID" },
    { 106, "setgid",     "Set group ID" },
    { 107, "geteuid",    "Get effective user ID" },
    { 108, "getegid",    "Get effective group ID" },
    { 109, "setpgid",    "Set process group ID" },
    { 110, "getppid",    "Get parent process ID" },
    { 111, "getpgrp",    "Get process group" },
    { 112, "setsid",     "Create session" },
    { 113, "setreuid",   "Set real/effective UID" },
    { 114, "setregid",   "Set real/effective GID" },
    { 115, "getgroups",  "Get supplementary groups" },
    { 116, "setgroups",  "Set supplementary groups" },
    { 117, "setresuid",  "Set real/effective/saved UID" },
    { 118, "getresuid",  "Get real/effective/saved UID" },
    { 119, "setresgid",  "Set real/effective/saved GID" },
    { 120, "getresgid",  "Get real/effective/saved GID" },
    { 121, "getpgid",    "Get process group ID" },
    { 122, "setfsuid",   "Set filesystem UID" },
    { 123, "setfsgid",   "Set filesystem GID" },
    { 124, "getsid",     "Get session ID" },
    { 125, "capget",     "Get capabilities" },
    { 126, "capset",     "Set capabilities" },
    { 157, "prctl",      "Process control" },
    { 158, "arch_prctl", "Architecture-specific control" },
    { 217, "getdents64", "Get directory entries (64-bit)" },
    { 231, "exit_group", "Exit all threads" },
    { 257, "openat",     "Open file relative to directory" },
    { 258, "mkdirat",    "Create directory relative to directory" },
    { 259, "mknodat",    "Create device node relative to directory" },
    { 260, "fchownat",   "Change owner relative to directory" },
    { 262, "newfstatat", "Get file status relative to directory" },
    { 263, "unlinkat",   "Remove file relative to directory" },
    { 264, "renameat",   "Rename file relative to directory" },
    { 265, "linkat",     "Create hard link relative to directory" },
    { 266, "symlinkat",  "Create symbolic link relative to directory" },
    { 267, "readlinkat", "Read symbolic link relative to directory" },
    { 268, "fchmodat",   "Change mode relative to directory" },
    { 269, "faccessat",  "Check permissions relative to directory" },
    { 270, "pselect6",   "Synchronous I/O multiplexing" },
    { 271, "ppoll",      "Wait for events on file descriptors" },
    { 288, "accept4",    "Accept connection with flags" },
    { 302, "prlimit64",  "Get/set resource limits" },
    { 318, "getrandom",  "Get random bytes" },
    { 322, "execveat",   "Execute program relative to directory" },
    { 332, "statx",      "Get extended file status" },
    { 435, "clone3",     "Create child process (v3)" },
    { -1,  NULL,         NULL }  /* Sentinel */
};

/**
 * Look up syscall name by number
 * 
 * @param syscall_num The syscall number (from RAX)
 * @return Syscall name, or "unknown" if not found
 */
const char *syscall_name(long syscall_num) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (syscall_table[i].number == syscall_num) {
            return syscall_table[i].name;
        }
    }
    return "unknown";
}

/**
 * Get syscall description
 */
const char *syscall_description(long syscall_num) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (syscall_table[i].number == syscall_num) {
            return syscall_table[i].description;
        }
    }
    return "Unknown syscall";
}

/**
 * Phase 2: Read syscall information from traced process
 * 
 * Uses PTRACE_GETREGS to read the complete register state.
 * On x86_64, the System V AMD64 ABI defines:
 *   RAX = syscall number (or return value after syscall)
 *   RDI = arg1
 *   RSI = arg2  
 *   RDX = arg3
 *   R10 = arg4
 *   R8  = arg5
 *   R9  = arg6
 *   RIP = instruction pointer
 * 
 * @param pid   PID of the traced process
 * @param info  Output structure to fill with syscall info
 * @return 0 on success, -1 on error
 */
int get_syscall_info(pid_t pid, syscall_info_t *info) {
    struct user_regs_struct regs;
    
    /* Read all registers at once */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        log_message(LOG_LEVEL_ERROR, "PTRACE_GETREGS failed: %s", strerror(errno));
        return -1;
    }
    
    /* Extract syscall information according to x86_64 ABI */
    info->syscall_num = regs.orig_rax;  /* orig_rax holds the syscall number */
    info->arg1 = regs.rdi;              /* First argument */
    info->arg2 = regs.rsi;              /* Second argument */
    info->arg3 = regs.rdx;              /* Third argument */
    info->arg4 = regs.r10;              /* Fourth argument */
    info->arg5 = regs.r8;               /* Fifth argument */
    info->arg6 = regs.r9;               /* Sixth argument */
    info->rip = regs.rip;               /* Instruction pointer */
    info->return_value = regs.rax;      /* Return value (only valid on exit) */
    
    return 0;
}

/**
 * Check if a syscall is file-related
 */
static int is_file_syscall(long syscall_num) {
    switch (syscall_num) {
        case SYS_OPEN:
        case SYS_OPENAT:
        case SYS_CREAT:
        case SYS_READ:
        case SYS_WRITE:
        case SYS_CLOSE:
        case SYS_STAT:
        case SYS_FSTAT:
        case SYS_LSTAT:
        case SYS_ACCESS:
        case SYS_RENAME:
        case SYS_MKDIR:
        case SYS_RMDIR:
        case SYS_UNLINK:
        case SYS_CHMOD:
        case SYS_CHOWN:
        case SYS_LINK:
        case SYS_UNLINKAT:
        case SYS_RENAMEAT:
        case SYS_MKDIRAT:
            return 1;
        default:
            return 0;
    }
}

/**
 * Check if a syscall is network-related
 */
static int is_network_syscall(long syscall_num) {
    switch (syscall_num) {
        case SYS_SOCKET:
        case SYS_CONNECT:
        case SYS_ACCEPT:
        case SYS_SENDTO:
        case SYS_RECVFROM:
        case SYS_BIND:
        case SYS_LISTEN:
            return 1;
        default:
            return 0;
    }
}

/**
 * Check if a syscall is process-related
 */
static int is_process_syscall(long syscall_num) {
    switch (syscall_num) {
        case SYS_FORK:
        case SYS_VFORK:
        case SYS_CLONE:
        case SYS_EXECVE:
        case SYS_EXECVEAT:
        case SYS_KILL:
        case SYS_EXIT:
            return 1;
        default:
            return 0;
    }
}

/**
 * Get syscall category string
 */
static const char *syscall_category(long syscall_num) {
    if (is_file_syscall(syscall_num)) return "FILE";
    if (is_network_syscall(syscall_num)) return "NETWORK";
    if (is_process_syscall(syscall_num)) return "PROCESS";
    return "SYSTEM";
}

/**
 * Print detailed syscall information (Phase 2 output)
 * 
 * @param info Syscall information structure
 */
void print_syscall_info(const syscall_info_t *info) {
    if (!info->is_entry) {
        /* Don't print on exit, we handle that separately */
        return;
    }
    
    const char *name = syscall_name(info->syscall_num);
    const char *category = syscall_category(info->syscall_num);
    
    /* Color-coded output based on category */
    const char *color;
    if (is_process_syscall(info->syscall_num)) {
        color = "\033[1;31m";  /* Bold Red for process syscalls */
    } else if (is_network_syscall(info->syscall_num)) {
        color = "\033[1;35m";  /* Bold Magenta for network */
    } else if (is_file_syscall(info->syscall_num)) {
        color = "\033[1;33m";  /* Bold Yellow for file */
    } else {
        color = "\033[1;36m";  /* Bold Cyan for others */
    }
    const char *reset = "\033[0m";
    
    log_message(LOG_LEVEL_INFO, 
        "%s[%s]%s %s (syscall %ld)", 
        color, category, reset, name, info->syscall_num);
    
    /* Print arguments based on syscall type */
    switch (info->syscall_num) {
        case SYS_OPEN:
        case SYS_CREAT:
        case SYS_ACCESS:
        case SYS_STAT:
        case SYS_LSTAT:
        case SYS_UNLINK:
        case SYS_RMDIR:
        case SYS_MKDIR:
        case SYS_CHMOD:
        case SYS_CHOWN:
            /* arg1 is filename pointer */
            log_message(LOG_LEVEL_DEBUG, "  -> filename_ptr: 0x%llx, flags: %llu, mode: %llu",
                        info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_OPENAT:
        case SYS_UNLINKAT:
        case SYS_MKDIRAT:
            /* arg1 is dirfd, arg2 is filename pointer */
            log_message(LOG_LEVEL_DEBUG, "  -> dirfd: %lld, filename_ptr: 0x%llx, flags: %llu",
                        (long long)info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_READ:
        case SYS_WRITE:
            log_message(LOG_LEVEL_DEBUG, "  -> fd: %llu, buf: 0x%llx, count: %llu",
                        info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_EXECVE:
            log_message(LOG_LEVEL_DEBUG, "  -> filename_ptr: 0x%llx, argv: 0x%llx, envp: 0x%llx",
                        info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_CONNECT:
            log_message(LOG_LEVEL_DEBUG, "  -> sockfd: %llu, addr: 0x%llx, addrlen: %llu",
                        info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_SOCKET:
            log_message(LOG_LEVEL_DEBUG, "  -> domain: %llu, type: %llu, protocol: %llu",
                        info->arg1, info->arg2, info->arg3);
            break;
            
        case SYS_KILL:
            log_message(LOG_LEVEL_DEBUG, "  -> pid: %lld, sig: %llu",
                        (long long)info->arg1, info->arg2);
            break;
            
        default:
            log_message(LOG_LEVEL_DEBUG, "  -> args: 0x%llx, 0x%llx, 0x%llx",
                        info->arg1, info->arg2, info->arg3);
            break;
    }
}
