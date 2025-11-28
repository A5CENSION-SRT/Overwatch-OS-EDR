/**
 * Project Watchtower - Linux Userspace EDR
 * Main Header File
 * 
 * This header defines the core structures and function prototypes
 * for the ptrace-based system call tracer and enforcer.
 */

#ifndef WATCHTOWER_H
#define WATCHTOWER_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================ */

#define WATCHTOWER_VERSION "1.0.0"
#define MAX_PATH_LENGTH 4096
#define MAX_STRING_LENGTH 1024
#define MAX_RULES 100
#define WORD_SIZE 8  /* 64-bit system: 8 bytes per word */

/* Log levels */
#define LOG_LEVEL_DEBUG   0
#define LOG_LEVEL_INFO    1
#define LOG_LEVEL_WARN    2
#define LOG_LEVEL_ERROR   3
#define LOG_LEVEL_ALERT   4

/* ============================================================================
 * x86_64 SYSCALL NUMBERS (from asm/unistd_64.h)
 * Reference: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
 * ============================================================================ */

#define SYS_READ            0
#define SYS_WRITE           1
#define SYS_OPEN            2
#define SYS_CLOSE           3
#define SYS_STAT            4
#define SYS_FSTAT           5
#define SYS_LSTAT           6
#define SYS_POLL            7
#define SYS_LSEEK           8
#define SYS_MMAP            9
#define SYS_MPROTECT        10
#define SYS_MUNMAP          11
#define SYS_BRK             12
#define SYS_IOCTL           16
#define SYS_ACCESS          21
#define SYS_PIPE            22
#define SYS_DUP             32
#define SYS_DUP2            33
#define SYS_SOCKET          41
#define SYS_CONNECT         42
#define SYS_ACCEPT          43
#define SYS_SENDTO          44
#define SYS_RECVFROM        45
#define SYS_BIND            49
#define SYS_LISTEN          50
#define SYS_CLONE           56
#define SYS_FORK            57
#define SYS_VFORK           58
#define SYS_EXECVE          59
#define SYS_EXIT            60
#define SYS_KILL            62
#define SYS_RENAME          82
#define SYS_MKDIR           83
#define SYS_RMDIR           84
#define SYS_CREAT           85
#define SYS_LINK            86
#define SYS_UNLINK          87
#define SYS_CHMOD           90
#define SYS_CHOWN           92
#define SYS_GETUID          102
#define SYS_GETGID          104
#define SYS_GETEUID         107
#define SYS_GETEGID         108
#define SYS_SETUID          105
#define SYS_SETGID          106
#define SYS_PTRACE          101
#define SYS_OPENAT          257
#define SYS_MKDIRAT         258
#define SYS_UNLINKAT        263
#define SYS_RENAMEAT        264
#define SYS_EXECVEAT        322

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * Represents a decoded system call with all relevant information
 */
typedef struct {
    long syscall_num;           /* RAX: The syscall number */
    unsigned long long arg1;    /* RDI: First argument */
    unsigned long long arg2;    /* RSI: Second argument */
    unsigned long long arg3;    /* RDX: Third argument */
    unsigned long long arg4;    /* R10: Fourth argument */
    unsigned long long arg5;    /* R8:  Fifth argument */
    unsigned long long arg6;    /* R9:  Sixth argument */
    unsigned long long rip;     /* RIP: Instruction pointer */
    long return_value;          /* RAX after syscall completion */
    bool is_entry;              /* True if entry stop, false if exit stop */
} syscall_info_t;

/**
 * Threat levels for detection rules
 */
typedef enum {
    THREAT_NONE = 0,
    THREAT_LOW,
    THREAT_MEDIUM,
    THREAT_HIGH,
    THREAT_CRITICAL
} threat_level_t;

/**
 * Actions the enforcer can take
 */
typedef enum {
    ACTION_ALLOW = 0,
    ACTION_LOG,
    ACTION_ALERT,
    ACTION_BLOCK,
    ACTION_KILL
} enforcement_action_t;

/**
 * Detection rule structure
 */
typedef struct {
    const char *name;           /* Rule name/identifier */
    const char *description;    /* Human-readable description */
    long syscall_num;           /* Syscall to match (-1 for any) */
    const char *path_pattern;   /* Path pattern to match (NULL for any) */
    threat_level_t threat;      /* Threat level */
    enforcement_action_t action;/* Action to take */
    bool enabled;               /* Is rule active? */
} detection_rule_t;

/**
 * Statistics tracking
 */
typedef struct {
    unsigned long total_syscalls;
    unsigned long blocked_syscalls;
    unsigned long alerts_generated;
    unsigned long processes_killed;
    unsigned long files_accessed;
    unsigned long network_connections;
    unsigned long executions;
} stats_t;

/**
 * Main tracer context
 */
typedef struct {
    pid_t child_pid;            /* PID of traced process */
    bool is_running;            /* Is the tracee still running? */
    bool in_syscall;            /* Are we at entry or exit? (Double-stop tracking) */
    int log_level;              /* Current logging level */
    bool enforce_mode;          /* Kill malicious processes? */
    stats_t stats;              /* Statistics */
    detection_rule_t rules[MAX_RULES];
    int rule_count;
} tracer_context_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/* Phase 1: Process Instrumentation */
pid_t spawn_traced_process(const char *program, char *const argv[]);
int attach_to_process(pid_t pid);
int detach_from_process(pid_t pid);

/* Phase 2: Syscall Decoding */
int get_syscall_info(pid_t pid, syscall_info_t *info);
const char *syscall_name(long syscall_num);
void print_syscall_info(const syscall_info_t *info);

/* Phase 3: Memory Inspection */
int read_string_from_child(pid_t pid, unsigned long addr, char *buffer, size_t max_len);
int read_bytes_from_child(pid_t pid, unsigned long addr, void *buffer, size_t len);

/* Phase 4: Heuristic Enforcement */
void init_default_rules(tracer_context_t *ctx);
enforcement_action_t evaluate_syscall(tracer_context_t *ctx, const syscall_info_t *info);
int kill_traced_process(pid_t pid, const char *reason);

/* Utility Functions */
void init_tracer_context(tracer_context_t *ctx);
void log_message(int level, const char *format, ...);
void print_banner(void);
void print_stats(const stats_t *stats);
const char *threat_level_str(threat_level_t level);
const char *action_str(enforcement_action_t action);

/* Main Tracing Loop */
int run_tracer_loop(tracer_context_t *ctx);

#endif /* WATCHTOWER_H */
