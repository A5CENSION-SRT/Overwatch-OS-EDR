/**
 * Project Overwatch - Linux Userspace EDR
 * Utility Functions
 * 
 * This module provides common utilities:
 * - Logging with colors and levels
 * - Context initialization
 * - Statistics reporting
 * - Banner display
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include "watchtower.h"

/* Global log level - can be set externally */
static int g_log_level = LOG_LEVEL_INFO;

/* ANSI color codes */
#define COLOR_RESET       "\033[0m"
#define COLOR_RED         "\033[31m"
#define COLOR_GREEN       "\033[32m"
#define COLOR_YELLOW      "\033[33m"
#define COLOR_BLUE        "\033[34m"
#define COLOR_MAGENTA     "\033[35m"
#define COLOR_CYAN        "\033[36m"
#define COLOR_WHITE       "\033[37m"
#define COLOR_BOLD        "\033[1m"
#define COLOR_BOLD_RED    "\033[1;31m"
#define COLOR_BOLD_GREEN  "\033[1;32m"
#define COLOR_BOLD_YELLOW "\033[1;33m"
#define COLOR_BOLD_BLUE   "\033[1;34m"
#define COLOR_BOLD_MAGENTA "\033[1;35m"
#define COLOR_BOLD_CYAN   "\033[1;36m"
#define COLOR_BOLD_WHITE  "\033[1;37m"
#define COLOR_BG_BLUE     "\033[44m"
#define COLOR_ORANGE      "\033[38;5;208m"
#define COLOR_BOLD_ORANGE "\033[1;38;5;208m"

/**
 * Print the Project Overwatch banner
 */
void print_banner(void) {
    printf("\n");
    printf("\033[1;34m");  /* Bold Blue border */
    printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║\033[0m                                                                      \033[1;34m║\n");
    printf("║\033[1;38;5;208m    ██████╗ ██╗   ██╗███████╗██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗  \033[1;34m║\n");
    printf("║\033[1;38;5;208m   ██╔═══██╗██║   ██║██╔════╝██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║  \033[1;34m║\n");
    printf("║\033[1;33m   ██║   ██║██║   ██║█████╗  ██████╔╝██║ █╗ ██║███████║   ██║   ██║     ███████║  \033[1;34m║\n");
    printf("║\033[1;33m   ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██║███╗██║██╔══██║   ██║   ██║     ██╔══██║  \033[1;34m║\n");
    printf("║\033[1;31m   ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║  \033[1;34m║\n");
    printf("║\033[1;31m    ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝  \033[1;34m║\n");
    printf("║\033[0m                                                                      \033[1;34m║\n");
    printf("║\033[1;37m                   ⚡ PROJECT OVERWATCH ⚡  v%s                     \033[1;34m║\n", OVERWATCH_VERSION);
    printf("║\033[0;36m                Linux Userspace EDR • Syscall Tracer                   \033[1;34m║\n");
    printf("║\033[0m                                                                      \033[1;34m║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("\n");
}

/**
 * Log a message with timestamp, level, and optional colors
 * 
 * @param level   Log level (DEBUG, INFO, WARN, ERROR, ALERT)
 * @param format  printf-style format string
 * @param ...     Format arguments
 */
void log_message(int level, const char *format, ...) {
    if (level < g_log_level) {
        return;
    }
    
    /* Get current timestamp */
    time_t now;
    struct tm *tm_info;
    char time_buf[32];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
    
    /* Select color and prefix based on level */
    const char *color;
    const char *prefix;
    
    switch (level) {
        case LOG_LEVEL_DEBUG:
            color = COLOR_CYAN;
            prefix = "DEBUG";
            break;
        case LOG_LEVEL_INFO:
            color = COLOR_GREEN;
            prefix = "INFO ";
            break;
        case LOG_LEVEL_WARN:
            color = COLOR_YELLOW;
            prefix = "WARN ";
            break;
        case LOG_LEVEL_ERROR:
            color = COLOR_RED;
            prefix = "ERROR";
            break;
        case LOG_LEVEL_ALERT:
            color = COLOR_BOLD_RED;
            prefix = "ALERT";
            break;
        default:
            color = COLOR_WHITE;
            prefix = "?????";
            break;
    }
    
    /* Check if stdout is a terminal (for color support) */
    int use_color = isatty(STDOUT_FILENO);
    
    if (use_color) {
        printf("%s[%s] [%s]%s ", color, time_buf, prefix, COLOR_RESET);
    } else {
        printf("[%s] [%s] ", time_buf, prefix);
    }
    
    /* Print the actual message */
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}

/**
 * Set the global log level
 */
void set_log_level(int level) {
    g_log_level = level;
    log_message(LOG_LEVEL_DEBUG, "Log level set to %d", level);
}

/**
 * Initialize the tracer context with default values
 */
void init_tracer_context(tracer_context_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->child_pid = -1;
    ctx->is_running = 0;
    ctx->in_syscall = 0;
    ctx->log_level = LOG_LEVEL_INFO;
    ctx->enforce_mode = 0;  /* Default: passive monitoring */
    ctx->rule_count = 0;
    
    /* Clear statistics */
    ctx->stats.total_syscalls = 0;
    ctx->stats.blocked_syscalls = 0;
    ctx->stats.alerts_generated = 0;
    ctx->stats.processes_killed = 0;
    ctx->stats.files_accessed = 0;
    ctx->stats.network_connections = 0;
    ctx->stats.executions = 0;
}

/**
 * Print statistics summary
 */
void print_stats(const stats_t *stats) {
    printf("\n");
    printf(COLOR_CYAN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BOLD "                    SESSION STATISTICS\n" COLOR_RESET);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("  Total Syscalls Traced:     %lu\n", stats->total_syscalls);
    printf("  Files Accessed:            %lu\n", stats->files_accessed);
    printf("  Network Connections:       %lu\n", stats->network_connections);
    printf("  Process Executions:        %lu\n", stats->executions);
    printf(COLOR_CYAN "───────────────────────────────────────────────────────────\n" COLOR_RESET);
    printf("  Alerts Generated:          ");
    if (stats->alerts_generated > 0) {
        printf(COLOR_YELLOW "%lu" COLOR_RESET "\n", stats->alerts_generated);
    } else {
        printf(COLOR_GREEN "%lu" COLOR_RESET "\n", stats->alerts_generated);
    }
    printf("  Syscalls Blocked:          ");
    if (stats->blocked_syscalls > 0) {
        printf(COLOR_YELLOW "%lu" COLOR_RESET "\n", stats->blocked_syscalls);
    } else {
        printf(COLOR_GREEN "%lu" COLOR_RESET "\n", stats->blocked_syscalls);
    }
    printf("  Processes Killed:          ");
    if (stats->processes_killed > 0) {
        printf(COLOR_RED "%lu" COLOR_RESET "\n", stats->processes_killed);
    } else {
        printf(COLOR_GREEN "%lu" COLOR_RESET "\n", stats->processes_killed);
    }
    printf(COLOR_CYAN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
}

/**
 * Print usage information
 */
void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] -- PROGRAM [ARGS...]\n", program_name);
    printf("\n");
    printf("Options:\n");
    printf("  -e, --enforce     Enable enforcement mode (kill malicious processes)\n");
    printf("  -p, --passive     Passive monitoring only (default)\n");
    printf("  -d, --debug       Enable debug output\n");
    printf("  -q, --quiet       Only show alerts and errors\n");
    printf("  -h, --help        Show this help message\n");
    printf("  -v, --version     Show version information\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -- ls -la                    # Monitor 'ls' command\n", program_name);
    printf("  %s -e -- ./suspicious_script    # Enforce and monitor script\n", program_name);
    printf("  %s -d -- cat /etc/passwd        # Debug mode\n", program_name);
    printf("\n");
    printf("Detection Rules:\n");
    printf("  The EDR monitors for suspicious behaviors including:\n");
    printf("  - Access to sensitive files (/etc/shadow, SSH keys, etc.)\n");
    printf("  - Execution from temporary directories (/tmp, /dev/shm)\n");
    printf("  - Connections to known malicious ports\n");
    printf("  - System log deletion attempts\n");
    printf("\n");
}

/**
 * Parse command line arguments
 * Returns the index of the first non-option argument (the program to trace)
 */
int parse_arguments(int argc, char *argv[], tracer_context_t *ctx) {
    int i;
    
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            /* Everything after -- is the program to trace */
            return i + 1;
        }
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--enforce") == 0) {
            ctx->enforce_mode = 1;
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--passive") == 0) {
            ctx->enforce_mode = 0;
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            set_log_level(LOG_LEVEL_DEBUG);
        }
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            set_log_level(LOG_LEVEL_WARN);
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("Project Overwatch v%s\n", OVERWATCH_VERSION);
            exit(0);
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
        else {
            /* First non-option argument is the program to trace */
            return i;
        }
    }
    
    return -1;  /* No program specified */
}
