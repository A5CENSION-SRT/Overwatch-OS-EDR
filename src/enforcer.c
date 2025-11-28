/**
 * Project Watchtower - Linux Userspace EDR
 * Phase 4: Heuristic Enforcement (The Enforcer)
 * 
 * This module implements the detection engine:
 * - Rule-based detection system
 * - Pattern matching for suspicious behavior
 * - Enforcement actions (log, alert, block, kill)
 * 
 * Detection Philosophy:
 * We look for behaviors that are suspicious regardless of the program name:
 * - Access to sensitive files (/etc/passwd, /etc/shadow, SSH keys)
 * - Execution of shells from unusual locations
 * - Network connections to suspicious ports
 * - Attempts to disable security mechanisms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <fnmatch.h>
#include <errno.h>

#include "watchtower.h"

/* Forward declaration */
void inspect_syscall_args(pid_t pid, const syscall_info_t *info, 
                          char *arg_str, size_t max_len);

/* ============================================================================
 * DETECTION RULES DATABASE
 * ============================================================================
 * Each rule specifies:
 * - What syscall to match (or -1 for any)
 * - What path pattern to look for (glob syntax)
 * - Threat level and action to take
 */

/* Known malicious network ports */
static const int suspicious_ports[] = {
    4444,   /* Metasploit default */
    5555,   /* Common reverse shell */
    6666,   /* Various malware */
    31337,  /* Elite/Back Orifice */
    12345,  /* NetBus */
    1234,   /* Common test backdoor */
    8080,   /* Alternative HTTP (sometimes suspicious) */
    0       /* Sentinel */
};

/**
 * Initialize the default detection rules
 * 
 * These rules represent common malware behaviors:
 * 1. Reading sensitive system files
 * 2. Executing from temporary directories
 * 3. Connecting to suspicious ports
 * 4. Spawning shells
 * 5. Modifying security configurations
 */
void init_default_rules(tracer_context_t *ctx) {
    int idx = 0;
    
    log_message(LOG_LEVEL_INFO, "Loading default detection rules...");
    
    /* Rule 1: Block reading shadow file */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "shadow_access",
        .description = "Attempt to read /etc/shadow (password hashes)",
        .syscall_num = SYS_OPEN,
        .path_pattern = "/etc/shadow*",
        .threat = THREAT_CRITICAL,
        .action = ACTION_KILL,
        .enabled = 1
    };
    
    /* Rule 2: Alert on SSH key access */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "ssh_key_access",
        .description = "Attempt to access SSH private keys",
        .syscall_num = -1,  /* Any file syscall */
        .path_pattern = "*/.ssh/id_*",
        .threat = THREAT_HIGH,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    /* Rule 3: Block execution from /tmp */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "tmp_execution",
        .description = "Attempt to execute from /tmp directory",
        .syscall_num = SYS_EXECVE,
        .path_pattern = "/tmp/*",
        .threat = THREAT_HIGH,
        .action = ACTION_KILL,
        .enabled = 1
    };
    
    /* Rule 4: Block execution from /dev/shm */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "devshm_execution",
        .description = "Attempt to execute from /dev/shm (memory-only)",
        .syscall_num = SYS_EXECVE,
        .path_pattern = "/dev/shm/*",
        .threat = THREAT_CRITICAL,
        .action = ACTION_KILL,
        .enabled = 1
    };
    
    /* Rule 5: Alert on netcat execution */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "netcat_execution",
        .description = "Netcat (nc) execution - potential reverse shell",
        .syscall_num = SYS_EXECVE,
        .path_pattern = "*/nc",
        .threat = THREAT_MEDIUM,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    /* Rule 6: Alert on ncat execution */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "ncat_execution",
        .description = "Ncat execution - potential reverse shell",
        .syscall_num = SYS_EXECVE,
        .path_pattern = "*/ncat",
        .threat = THREAT_MEDIUM,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    /* Rule 7: Alert on sudoers access */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "sudoers_access",
        .description = "Attempt to access sudoers configuration",
        .syscall_num = -1,
        .path_pattern = "/etc/sudoers*",
        .threat = THREAT_HIGH,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    /* Rule 8: Alert on passwd file access */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "passwd_access",
        .description = "Reading password file",
        .syscall_num = SYS_OPEN,
        .path_pattern = "/etc/passwd",
        .threat = THREAT_LOW,
        .action = ACTION_LOG,
        .enabled = 1
    };
    
    /* Rule 9: Block deleting system logs */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "log_deletion",
        .description = "Attempt to delete system logs",
        .syscall_num = SYS_UNLINK,
        .path_pattern = "/var/log/*",
        .threat = THREAT_HIGH,
        .action = ACTION_KILL,
        .enabled = 1
    };
    
    /* Rule 10: Alert on kernel module directory access */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "kernel_module_access",
        .description = "Access to kernel modules directory",
        .syscall_num = -1,
        .path_pattern = "/lib/modules/*",
        .threat = THREAT_MEDIUM,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    /* Rule 11: Block proc mem access */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "proc_mem_access",
        .description = "Direct process memory access attempt",
        .syscall_num = SYS_OPEN,
        .path_pattern = "/proc/*/mem",
        .threat = THREAT_CRITICAL,
        .action = ACTION_KILL,
        .enabled = 1
    };
    
    /* Rule 12: Alert on cron modification */
    ctx->rules[idx++] = (detection_rule_t){
        .name = "cron_modification",
        .description = "Modification of cron jobs (persistence)",
        .syscall_num = -1,
        .path_pattern = "/etc/cron*",
        .threat = THREAT_MEDIUM,
        .action = ACTION_ALERT,
        .enabled = 1
    };
    
    ctx->rule_count = idx;
    log_message(LOG_LEVEL_INFO, "Loaded %d detection rules", idx);
}

/**
 * Check if a path matches a glob pattern
 */
static int path_matches(const char *path, const char *pattern) {
    if (path == NULL || pattern == NULL) {
        return 0;
    }
    return fnmatch(pattern, path, FNM_PATHNAME) == 0;
}

/**
 * Check if a port is in the suspicious list
 */
static int is_suspicious_port(int port) {
    for (int i = 0; suspicious_ports[i] != 0; i++) {
        if (suspicious_ports[i] == port) {
            return 1;
        }
    }
    return 0;
}

/**
 * Evaluate a syscall against all rules
 * 
 * This is the core detection logic. For each syscall:
 * 1. Extract the relevant argument (filename, address, etc.)
 * 2. Check against each enabled rule
 * 3. Return the highest-priority action that matches
 * 
 * @param ctx  Tracer context with rules
 * @param info Syscall information
 * @return Action to take
 */
enforcement_action_t evaluate_syscall(tracer_context_t *ctx, const syscall_info_t *info) {
    char arg_str[MAX_PATH_LENGTH];
    char path_buf[MAX_PATH_LENGTH];
    enforcement_action_t max_action = ACTION_ALLOW;
    const char *triggered_rule = NULL;
    threat_level_t max_threat = THREAT_NONE;
    
    /* Get decoded arguments for this syscall */
    inspect_syscall_args(ctx->child_pid, info, arg_str, sizeof(arg_str));
    
    /* Extract path from syscall if applicable */
    path_buf[0] = '\0';
    
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
            read_string_from_child(ctx->child_pid, info->arg1, path_buf, sizeof(path_buf));
            break;
            
        case SYS_OPENAT:
        case SYS_UNLINKAT:
        case SYS_MKDIRAT:
            read_string_from_child(ctx->child_pid, info->arg2, path_buf, sizeof(path_buf));
            break;
            
        case SYS_EXECVE:
        case SYS_EXECVEAT:
            read_string_from_child(ctx->child_pid, info->arg1, path_buf, sizeof(path_buf));
            ctx->stats.executions++;
            break;
            
        case SYS_CONNECT:
            /* Check for suspicious network connections */
            {
                char addr[64];
                int port;
                extern int read_sockaddr_from_child(pid_t, unsigned long, char*, size_t, int*);
                
                if (read_sockaddr_from_child(ctx->child_pid, info->arg2, addr, sizeof(addr), &port) == 0) {
                    ctx->stats.network_connections++;
                    
                    if (is_suspicious_port(port)) {
                        log_message(LOG_LEVEL_ALERT, 
                            "ALERT: Connection to suspicious port %d (%s)", port, addr);
                        
                        if (ctx->enforce_mode) {
                            return ACTION_KILL;
                        }
                        return ACTION_ALERT;
                    }
                }
            }
            return ACTION_ALLOW;
            
        default:
            return ACTION_ALLOW;
    }
    
    /* Track file access */
    if (path_buf[0] != '\0') {
        ctx->stats.files_accessed++;
    }
    
    /* Check against all rules */
    for (int i = 0; i < ctx->rule_count; i++) {
        detection_rule_t *rule = &ctx->rules[i];
        
        if (!rule->enabled) continue;
        
        /* Check if syscall matches (or rule applies to all) */
        if (rule->syscall_num != -1 && rule->syscall_num != info->syscall_num) {
            continue;
        }
        
        /* Check if path matches pattern */
        if (rule->path_pattern != NULL && path_buf[0] != '\0') {
            if (path_matches(path_buf, rule->path_pattern)) {
                /* Rule matched! */
                log_message(LOG_LEVEL_WARN, 
                    "Rule '%s' triggered: %s", rule->name, rule->description);
                log_message(LOG_LEVEL_WARN, 
                    "  Path: %s", path_buf);
                log_message(LOG_LEVEL_WARN, 
                    "  Threat: %s, Action: %s",
                    threat_level_str(rule->threat), action_str(rule->action));
                
                /* Track highest severity match */
                if (rule->action > max_action) {
                    max_action = rule->action;
                    max_threat = rule->threat;
                    triggered_rule = rule->name;
                }
            }
        }
    }
    
    /* Log if we're taking action */
    if (max_action >= ACTION_ALERT) {
        log_message(LOG_LEVEL_ALERT, 
            "=== THREAT DETECTED ===");
        log_message(LOG_LEVEL_ALERT, 
            "Rule: %s", triggered_rule);
        log_message(LOG_LEVEL_ALERT, 
            "Path: %s", path_buf);
        log_message(LOG_LEVEL_ALERT, 
            "Threat Level: %s", threat_level_str(max_threat));
        log_message(LOG_LEVEL_ALERT, 
            "Action: %s", action_str(max_action));
        
        /* In enforcement mode, escalate alerts to kills for high threats */
        if (ctx->enforce_mode && max_threat >= THREAT_HIGH && max_action < ACTION_KILL) {
            log_message(LOG_LEVEL_ALERT, 
                "Enforcement mode: Escalating to KILL");
            max_action = ACTION_KILL;
        }
    }
    
    return max_action;
}

/**
 * Kill the traced process
 * 
 * When we detect malicious activity, we terminate the process immediately.
 * This prevents the syscall from completing.
 * 
 * @param pid    PID to kill
 * @param reason Human-readable reason for the kill
 * @return 0 on success, -1 on error
 */
int kill_traced_process(pid_t pid, const char *reason) {
    log_message(LOG_LEVEL_ALERT, "*** KILLING PROCESS %d ***", pid);
    log_message(LOG_LEVEL_ALERT, "Reason: %s", reason);
    
    /* First, try PTRACE_KILL for a clean termination */
    if (ptrace(PTRACE_KILL, pid, NULL, NULL) == -1) {
        /* PTRACE_KILL failed, use SIGKILL directly */
        log_message(LOG_LEVEL_WARN, "PTRACE_KILL failed, sending SIGKILL");
        
        if (kill(pid, SIGKILL) == -1) {
            log_message(LOG_LEVEL_ERROR, "Failed to kill process: %s", strerror(errno));
            return -1;
        }
    }
    
    log_message(LOG_LEVEL_INFO, "Process %d terminated", pid);
    return 0;
}

/**
 * Convert threat level to string
 */
const char *threat_level_str(threat_level_t level) {
    switch (level) {
        case THREAT_NONE:     return "NONE";
        case THREAT_LOW:      return "LOW";
        case THREAT_MEDIUM:   return "MEDIUM";
        case THREAT_HIGH:     return "HIGH";
        case THREAT_CRITICAL: return "CRITICAL";
        default:              return "UNKNOWN";
    }
}

/**
 * Convert action to string
 */
const char *action_str(enforcement_action_t action) {
    switch (action) {
        case ACTION_ALLOW: return "ALLOW";
        case ACTION_LOG:   return "LOG";
        case ACTION_ALERT: return "ALERT";
        case ACTION_BLOCK: return "BLOCK";
        case ACTION_KILL:  return "KILL";
        default:           return "UNKNOWN";
    }
}

/**
 * Add a custom rule at runtime
 */
int add_detection_rule(tracer_context_t *ctx, 
                       const char *name,
                       const char *description,
                       long syscall_num,
                       const char *path_pattern,
                       threat_level_t threat,
                       enforcement_action_t action) {
    if (ctx->rule_count >= MAX_RULES) {
        log_message(LOG_LEVEL_ERROR, "Maximum number of rules reached");
        return -1;
    }
    
    ctx->rules[ctx->rule_count++] = (detection_rule_t){
        .name = name,
        .description = description,
        .syscall_num = syscall_num,
        .path_pattern = path_pattern,
        .threat = threat,
        .action = action,
        .enabled = 1
    };
    
    log_message(LOG_LEVEL_INFO, "Added rule: %s", name);
    return 0;
}

/**
 * Enable or disable a rule by name
 */
int set_rule_enabled(tracer_context_t *ctx, const char *name, int enabled) {
    for (int i = 0; i < ctx->rule_count; i++) {
        if (strcmp(ctx->rules[i].name, name) == 0) {
            ctx->rules[i].enabled = enabled;
            log_message(LOG_LEVEL_INFO, "Rule '%s' %s", 
                        name, enabled ? "enabled" : "disabled");
            return 0;
        }
    }
    
    log_message(LOG_LEVEL_WARN, "Rule '%s' not found", name);
    return -1;
}
