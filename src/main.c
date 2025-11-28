/**
 * Project Watchtower - Linux Userspace EDR
 * Main Entry Point
 * 
 * This is the main program that ties all phases together:
 * - Phase 1: Process Instrumentation (tracer.c)
 * - Phase 2: Syscall Decoding (decoder.c)
 * - Phase 3: Memory Inspection (memory.c)
 * - Phase 4: Heuristic Enforcement (enforcer.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "watchtower.h"

/* External function declarations */
extern void set_log_level(int level);
extern void print_usage(const char *program_name);
extern int parse_arguments(int argc, char *argv[], tracer_context_t *ctx);

int main(int argc, char *argv[]) {
    tracer_context_t ctx;
    int program_idx;
    int exit_code;
    
    /* Initialize the tracer context */
    init_tracer_context(&ctx);
    
    /* Parse command line arguments */
    program_idx = parse_arguments(argc, argv, &ctx);
    
    /* Check if a program was specified */
    if (program_idx < 0 || program_idx >= argc) {
        print_banner();
        fprintf(stderr, "Error: No program specified to trace.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Print the banner */
    print_banner();
    
    log_message(LOG_LEVEL_INFO, "Project Watchtower EDR starting...");
    log_message(LOG_LEVEL_INFO, "Target program: %s", argv[program_idx]);
    
    /* Initialize detection rules */
    init_default_rules(&ctx);
    
    /* Phase 1: Spawn the traced process */
    log_message(LOG_LEVEL_INFO, "=== PHASE 1: Process Instrumentation ===");
    
    ctx.child_pid = spawn_traced_process(argv[program_idx], &argv[program_idx]);
    
    if (ctx.child_pid == -1) {
        log_message(LOG_LEVEL_ERROR, "Failed to spawn traced process");
        return 1;
    }
    
    log_message(LOG_LEVEL_INFO, "Child process created with PID %d", ctx.child_pid);
    
    /* Phase 2-4: Run the main tracing loop */
    log_message(LOG_LEVEL_INFO, "=== ENTERING INTERCEPTION LOOP ===");
    log_message(LOG_LEVEL_INFO, "Press Ctrl+C to stop monitoring\n");
    
    exit_code = run_tracer_loop(&ctx);
    
    /* Print final statistics */
    print_stats(&ctx.stats);
    
    if (ctx.stats.processes_killed > 0) {
        log_message(LOG_LEVEL_ALERT, 
            "*** %lu MALICIOUS PROCESS(ES) TERMINATED ***", 
            ctx.stats.processes_killed);
    } else if (ctx.stats.alerts_generated > 0) {
        log_message(LOG_LEVEL_WARN, 
            "Session completed with %lu alert(s)", 
            ctx.stats.alerts_generated);
    } else {
        log_message(LOG_LEVEL_INFO, "Session completed. No threats detected.");
    }
    
    return exit_code;
}
