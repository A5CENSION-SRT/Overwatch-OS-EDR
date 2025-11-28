/**
 * Project Watchtower - Linux Userspace EDR
 * Phase 1: Process Instrumentation (The Spy)
 * 
 * This module handles the core ptrace operations:
 * - Spawning a traced child process (fork + PTRACE_TRACEME + execl)
 * - Attaching to existing processes
 * - The main interception loop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <signal.h>

#include "watchtower.h"

/* Global flag for graceful shutdown */
static volatile sig_atomic_t g_shutdown_requested = 0;

/**
 * Signal handler for graceful termination
 */
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_shutdown_requested = 1;
    }
}

/**
 * Phase 1: Spawn a new process and trace it from birth
 * 
 * This is the "Spy" component. We:
 * 1. fork() to create a child process
 * 2. In the child: call PTRACE_TRACEME, then exec the target program
 * 3. In the parent: wait for the child to stop, then begin tracing
 * 
 * @param program Path to the program to execute
 * @param argv    Arguments to pass (argv[0] should be program name)
 * @return PID of the child process, or -1 on error
 */
pid_t spawn_traced_process(const char *program, char *const argv[]) {
    pid_t child_pid;
    
    log_message(LOG_LEVEL_INFO, "Spawning traced process: %s", program);
    
    child_pid = fork();
    
    if (child_pid == -1) {
        log_message(LOG_LEVEL_ERROR, "fork() failed: %s", strerror(errno));
        return -1;
    }
    
    if (child_pid == 0) {
        /* ================================================================
         * CHILD PROCESS (The Tracee)
         * ================================================================
         * This code runs in the child after fork().
         * We must call PTRACE_TRACEME BEFORE exec.
         * This tells the kernel: "My parent wants to trace me."
         * 
         * After this, any exec() will cause the child to STOP,
         * sending SIGTRAP to the parent.
         */
        
        /* Request to be traced by parent */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            fprintf(stderr, "[CHILD] PTRACE_TRACEME failed: %s\n", strerror(errno));
            _exit(1);
        }
        
        /* Stop ourselves to synchronize with parent */
        /* The parent will be waiting in waitpid() */
        raise(SIGSTOP);
        
        /* Replace our memory image with the target program */
        /* After this, we are no longer running this code */
        execvp(program, argv);
        
        /* If we get here, exec failed */
        fprintf(stderr, "[CHILD] execvp(%s) failed: %s\n", program, strerror(errno));
        _exit(1);
    }
    
    /* ====================================================================
     * PARENT PROCESS (The Tracer)
     * ====================================================================
     * The child is now either:
     * 1. Stopped at SIGSTOP (from raise())
     * 2. Or has exec'd and stopped at the exec boundary
     */
    
    int status;
    
    /* Wait for child to stop */
    if (waitpid(child_pid, &status, 0) == -1) {
        log_message(LOG_LEVEL_ERROR, "waitpid() failed: %s", strerror(errno));
        return -1;
    }
    
    if (!WIFSTOPPED(status)) {
        log_message(LOG_LEVEL_ERROR, "Child did not stop as expected");
        return -1;
    }
    
    log_message(LOG_LEVEL_DEBUG, "Child stopped with signal: %d", WSTOPSIG(status));
    
    /* Set ptrace options for better syscall tracing */
    /* PTRACE_O_TRACESYSGOOD: Set bit 7 in signal number for syscall stops
     * This helps distinguish syscall stops from other stops */
    if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, 
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC) == -1) {
        log_message(LOG_LEVEL_WARN, "PTRACE_SETOPTIONS failed: %s", strerror(errno));
        /* Not fatal, continue without enhanced options */
    }
    
    log_message(LOG_LEVEL_INFO, "Successfully spawned and attached to process %d", child_pid);
    
    return child_pid;
}

/**
 * Attach to an already-running process
 * 
 * This is useful for tracing existing processes.
 * Note: Requires appropriate permissions (same user or CAP_SYS_PTRACE)
 * 
 * @param pid PID of process to attach to
 * @return 0 on success, -1 on error
 */
int attach_to_process(pid_t pid) {
    log_message(LOG_LEVEL_INFO, "Attaching to process %d", pid);
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        log_message(LOG_LEVEL_ERROR, "PTRACE_ATTACH failed: %s", strerror(errno));
        return -1;
    }
    
    /* Wait for the process to stop */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        log_message(LOG_LEVEL_ERROR, "waitpid() after attach failed: %s", strerror(errno));
        return -1;
    }
    
    if (!WIFSTOPPED(status)) {
        log_message(LOG_LEVEL_ERROR, "Process did not stop after attach");
        return -1;
    }
    
    /* Set tracing options */
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
        log_message(LOG_LEVEL_WARN, "PTRACE_SETOPTIONS failed: %s", strerror(errno));
    }
    
    log_message(LOG_LEVEL_INFO, "Successfully attached to process %d", pid);
    return 0;
}

/**
 * Detach from a traced process, allowing it to continue normally
 * 
 * @param pid PID of process to detach from
 * @return 0 on success, -1 on error
 */
int detach_from_process(pid_t pid) {
    log_message(LOG_LEVEL_INFO, "Detaching from process %d", pid);
    
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        log_message(LOG_LEVEL_ERROR, "PTRACE_DETACH failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * The Main Interception Loop
 * 
 * This is the "Core Engine" described in the methodology.
 * We implement the TRAP -> PAUSE -> SIGNAL -> INSPECT -> DECIDE cycle.
 * 
 * Key concept: DOUBLE-STOP PHENOMENON
 * - Each syscall causes TWO stops: Entry and Exit
 * - We track this with ctx->in_syscall flag
 * - Entry: Arguments are in registers, syscall hasn't executed
 * - Exit: Return value is in RAX, syscall has completed
 * 
 * @param ctx Tracer context (contains child_pid, rules, stats)
 * @return Exit status of child, or -1 on error
 */
int run_tracer_loop(tracer_context_t *ctx) {
    int status;
    syscall_info_t sysinfo;
    enforcement_action_t action;
    
    /* Setup signal handlers for graceful shutdown */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    ctx->is_running = 1;
    ctx->in_syscall = 0;  /* Start outside a syscall */
    
    log_message(LOG_LEVEL_INFO, "Starting tracer loop for PID %d", ctx->child_pid);
    log_message(LOG_LEVEL_INFO, "Enforcement mode: %s", 
                ctx->enforce_mode ? "ACTIVE (will kill threats)" : "PASSIVE (log only)");
    
    /* Resume the child, stopping at the next syscall */
    if (ptrace(PTRACE_SYSCALL, ctx->child_pid, NULL, NULL) == -1) {
        log_message(LOG_LEVEL_ERROR, "Initial PTRACE_SYSCALL failed: %s", strerror(errno));
        return -1;
    }
    
    /* ====================================================================
     * THE INTERCEPTION LOOP
     * ====================================================================
     * This is where the magic happens. We loop forever, catching every
     * syscall the child makes.
     */
    while (ctx->is_running && !g_shutdown_requested) {
        
        /* STEP 1: WAIT (Sleep until child does something) */
        pid_t result = waitpid(ctx->child_pid, &status, 0);
        
        if (result == -1) {
            if (errno == EINTR) {
                /* Interrupted by signal, check shutdown flag */
                continue;
            }
            log_message(LOG_LEVEL_ERROR, "waitpid() error: %s", strerror(errno));
            break;
        }
        
        /* STEP 2: CHECK CHILD STATUS */
        
        /* Did the child exit? */
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            log_message(LOG_LEVEL_INFO, "Child exited with code %d", exit_code);
            ctx->is_running = 0;
            return exit_code;
        }
        
        /* Was the child killed by a signal? */
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            log_message(LOG_LEVEL_WARN, "Child killed by signal %d (%s)", 
                        sig, strsignal(sig));
            ctx->is_running = 0;
            return -1;
        }
        
        /* Did the child stop? */
        if (WIFSTOPPED(status)) {
            int stop_sig = WSTOPSIG(status);
            
            /* Check if this is a syscall stop
             * With PTRACE_O_TRACESYSGOOD, syscall stops have (SIGTRAP | 0x80)
             * Without it, they just have SIGTRAP */
            if (stop_sig == (SIGTRAP | 0x80) || stop_sig == SIGTRAP) {
                
                /* STEP 3: INSPECT (Read the frozen child's registers) */
                if (get_syscall_info(ctx->child_pid, &sysinfo) == 0) {
                    
                    /* HANDLE THE DOUBLE-STOP PHENOMENON */
                    ctx->in_syscall = !ctx->in_syscall;
                    sysinfo.is_entry = ctx->in_syscall;
                    
                    if (sysinfo.is_entry) {
                        /* ================================================
                         * SYSCALL ENTRY - This is where we make decisions
                         * ================================================
                         * The child WANTS to do something.
                         * We inspect BEFORE the kernel does the work.
                         */
                        ctx->stats.total_syscalls++;
                        
                        /* Print syscall info (Phase 2: Decoding) */
                        print_syscall_info(&sysinfo);
                        
                        /* STEP 4: DECIDE (Apply heuristic rules) */
                        action = evaluate_syscall(ctx, &sysinfo);
                        
                        if (action == ACTION_KILL) {
                            /* MALICIOUS! Kill the process immediately */
                            log_message(LOG_LEVEL_ALERT, 
                                "THREAT DETECTED! Killing process %d", ctx->child_pid);
                            kill_traced_process(ctx->child_pid, "Malicious syscall detected");
                            ctx->stats.processes_killed++;
                            ctx->is_running = 0;
                            return -1;
                        } else if (action == ACTION_BLOCK) {
                            /* Block this specific syscall by returning error */
                            log_message(LOG_LEVEL_WARN, "Blocking syscall %ld", 
                                        sysinfo.syscall_num);
                            ctx->stats.blocked_syscalls++;
                            /* TODO: Implement syscall blocking by modifying RAX to -1 */
                        } else if (action == ACTION_ALERT) {
                            ctx->stats.alerts_generated++;
                        }
                        
                    } else {
                        /* ================================================
                         * SYSCALL EXIT - Syscall has completed
                         * ================================================
                         * We can check the return value to see if it succeeded.
                         * RAX now contains the return value.
                         */
                        if (sysinfo.return_value < 0) {
                            log_message(LOG_LEVEL_DEBUG, 
                                "  -> Syscall returned error: %ld (%s)", 
                                sysinfo.return_value, 
                                strerror(-sysinfo.return_value));
                        } else {
                            log_message(LOG_LEVEL_DEBUG, 
                                "  -> Syscall returned: %ld", sysinfo.return_value);
                        }
                    }
                }
                
                /* STEP 5: CONTINUE (Let the child proceed to next syscall) */
                if (ptrace(PTRACE_SYSCALL, ctx->child_pid, NULL, NULL) == -1) {
                    if (errno == ESRCH) {
                        /* Process no longer exists */
                        log_message(LOG_LEVEL_INFO, "Child process no longer exists");
                        ctx->is_running = 0;
                        break;
                    }
                    log_message(LOG_LEVEL_ERROR, "PTRACE_SYSCALL failed: %s", strerror(errno));
                    break;
                }
                
            } else {
                /* Child stopped for some other signal, deliver it */
                log_message(LOG_LEVEL_DEBUG, "Child received signal %d (%s)", 
                            stop_sig, strsignal(stop_sig));
                
                /* Continue and deliver the signal to the child */
                if (ptrace(PTRACE_SYSCALL, ctx->child_pid, NULL, (void*)(long)stop_sig) == -1) {
                    log_message(LOG_LEVEL_ERROR, "PTRACE_SYSCALL with signal failed: %s", 
                                strerror(errno));
                    break;
                }
            }
        }
    }
    
    /* Cleanup if we're shutting down */
    if (g_shutdown_requested && ctx->is_running) {
        log_message(LOG_LEVEL_INFO, "Shutdown requested, detaching from child");
        detach_from_process(ctx->child_pid);
    }
    
    return 0;
}
