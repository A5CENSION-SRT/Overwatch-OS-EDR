/**
 * Project Watchtower - Linux Userspace EDR
 * Phase 3: Deep Memory Inspection (The Data Thief)
 * 
 * This module handles reading data from the traced process's memory:
 * - Using PTRACE_PEEKDATA to read words (8 bytes) at a time
 * - Reconstructing strings from the child's address space
 * - Handling the "wormhole" - crossing the memory barrier between processes
 * 
 * KEY CONCEPT: Virtual Memory Isolation
 * Each process has its own virtual address space. Address 0x4000 in the
 * child is NOT the same as 0x4000 in the parent. ptrace is our only
 * way to reach across this barrier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "watchtower.h"

/**
 * Read a single word (8 bytes on x86_64) from the child's memory
 * 
 * @param pid  PID of the traced process
 * @param addr Address in the child's memory space
 * @param word Output buffer for the word
 * @return 0 on success, -1 on error
 */
static int peek_word(pid_t pid, unsigned long addr, unsigned long *word) {
    errno = 0;
    
    /* PTRACE_PEEKDATA returns the data directly, sets errno on error */
    *word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    
    if (*word == (unsigned long)-1 && errno != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Phase 3: Read a string from the child's memory (The Wormhole)
 * 
 * This is the heart of deep inspection. When we see a syscall like:
 *   open(0x7ffd12345678, O_RDONLY)
 * 
 * The first argument is a POINTER to a string in the child's memory.
 * We cannot dereference it directly (segfault or garbage).
 * 
 * We use PTRACE_PEEKDATA to:
 * 1. Read 8 bytes from the child at address 0x7ffd12345678
 * 2. Check for null terminator
 * 3. If not found, increment by 8 and read again
 * 4. Stitch together the bytes to form the complete string
 * 
 * @param pid     PID of the traced process
 * @param addr    Address of string in child's memory
 * @param buffer  Output buffer (must be at least max_len bytes)
 * @param max_len Maximum bytes to read
 * @return Length of string read, or -1 on error
 */
int read_string_from_child(pid_t pid, unsigned long addr, char *buffer, size_t max_len) {
    size_t bytes_read = 0;
    unsigned long word;
    char *word_bytes;
    
    if (addr == 0) {
        /* NULL pointer */
        buffer[0] = '\0';
        return 0;
    }
    
    if (max_len < WORD_SIZE + 1) {
        log_message(LOG_LEVEL_ERROR, "Buffer too small for string read");
        return -1;
    }
    
    /* Reserve space for null terminator */
    max_len--;
    
    log_message(LOG_LEVEL_DEBUG, "Reading string from child address 0x%lx", addr);
    
    while (bytes_read < max_len) {
        /* Read one word (8 bytes) from the child */
        if (peek_word(pid, addr, &word) == -1) {
            log_message(LOG_LEVEL_DEBUG, "peek_word failed at 0x%lx: %s", 
                        addr, strerror(errno));
            break;
        }
        
        /* Process each byte in the word */
        word_bytes = (char*)&word;
        
        for (int i = 0; i < WORD_SIZE && bytes_read < max_len; i++) {
            buffer[bytes_read] = word_bytes[i];
            
            /* Check for null terminator */
            if (word_bytes[i] == '\0') {
                log_message(LOG_LEVEL_DEBUG, "Found null terminator at offset %zu", 
                            bytes_read);
                return bytes_read;
            }
            
            bytes_read++;
        }
        
        /* Move to next word */
        addr += WORD_SIZE;
    }
    
    /* String was truncated, add null terminator */
    buffer[bytes_read] = '\0';
    
    return bytes_read;
}

/**
 * Read arbitrary bytes from the child's memory
 * 
 * Similar to read_string_from_child but doesn't stop at null.
 * Useful for reading binary data structures.
 * 
 * @param pid    PID of the traced process
 * @param addr   Address in child's memory
 * @param buffer Output buffer
 * @param len    Number of bytes to read
 * @return Number of bytes successfully read
 */
int read_bytes_from_child(pid_t pid, unsigned long addr, void *buffer, size_t len) {
    size_t bytes_read = 0;
    unsigned long word;
    char *buf = (char*)buffer;
    
    if (addr == 0 || len == 0) {
        return 0;
    }
    
    while (bytes_read < len) {
        /* Calculate how many bytes we need from this word */
        size_t to_copy = len - bytes_read;
        if (to_copy > WORD_SIZE) {
            to_copy = WORD_SIZE;
        }
        
        /* Handle unaligned start address */
        size_t offset = (addr + bytes_read) % WORD_SIZE;
        unsigned long aligned_addr = (addr + bytes_read) - offset;
        
        if (peek_word(pid, aligned_addr, &word) == -1) {
            log_message(LOG_LEVEL_DEBUG, "peek_word failed at 0x%lx: %s",
                        aligned_addr, strerror(errno));
            break;
        }
        
        /* Copy the bytes we need */
        char *word_bytes = (char*)&word;
        size_t copy_len = WORD_SIZE - offset;
        if (copy_len > to_copy) {
            copy_len = to_copy;
        }
        
        memcpy(buf + bytes_read, word_bytes + offset, copy_len);
        bytes_read += copy_len;
    }
    
    return bytes_read;
}

/**
 * Read and decode a sockaddr structure from child's memory
 * Useful for inspecting network connections
 * 
 * @param pid      PID of the traced process
 * @param addr     Address of sockaddr in child's memory
 * @param out_addr Output buffer for the decoded address string
 * @param out_port Output pointer for the port number
 * @return 0 on success, -1 on error
 */
int read_sockaddr_from_child(pid_t pid, unsigned long addr, 
                             char *out_addr, size_t addr_len, 
                             int *out_port) {
    /* sockaddr_in structure (IPv4) */
    struct {
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char zero[8];
    } sa;
    
    if ((size_t)read_bytes_from_child(pid, addr, &sa, sizeof(sa)) < sizeof(sa)) {
        return -1;
    }
    
    if (sa.family == 2) {  /* AF_INET */
        /* Convert network byte order to host byte order */
        unsigned short port = ((sa.port & 0xFF) << 8) | ((sa.port >> 8) & 0xFF);
        unsigned int ip = sa.addr;
        
        snprintf(out_addr, addr_len, "%u.%u.%u.%u",
                 ip & 0xFF,
                 (ip >> 8) & 0xFF,
                 (ip >> 16) & 0xFF,
                 (ip >> 24) & 0xFF);
        
        *out_port = port;
        return 0;
    } else if (sa.family == 10) {  /* AF_INET6 */
        snprintf(out_addr, addr_len, "[IPv6]");
        *out_port = ((sa.port & 0xFF) << 8) | ((sa.port >> 8) & 0xFF);
        return 0;
    }
    
    snprintf(out_addr, addr_len, "unknown-family-%d", sa.family);
    *out_port = 0;
    return -1;
}

/**
 * Read an array of string pointers (argv-style) from child's memory
 * 
 * This is used for inspecting execve() arguments:
 *   execve(filename, argv[], envp[])
 * 
 * argv is an array of char* pointers, terminated by NULL.
 * We need to:
 * 1. Read each pointer from the array
 * 2. For each pointer, read the string it points to
 * 
 * @param pid       PID of the traced process
 * @param argv_addr Address of the argv array
 * @param args      Output array of strings
 * @param max_args  Maximum number of arguments to read
 * @return Number of arguments read
 */
int read_argv_from_child(pid_t pid, unsigned long argv_addr, 
                         char args[][MAX_STRING_LENGTH], int max_args) {
    unsigned long ptr;
    int argc = 0;
    
    if (argv_addr == 0) {
        return 0;
    }
    
    while (argc < max_args) {
        /* Read the next pointer from argv[] */
        if (peek_word(pid, argv_addr + (argc * WORD_SIZE), &ptr) == -1) {
            break;
        }
        
        /* NULL pointer marks end of array */
        if (ptr == 0) {
            break;
        }
        
        /* Read the string this pointer points to */
        if (read_string_from_child(pid, ptr, args[argc], MAX_STRING_LENGTH) < 0) {
            strcpy(args[argc], "<error>");
        }
        
        argc++;
    }
    
    return argc;
}

/**
 * Inspect syscall and extract relevant string arguments
 * 
 * This is the main interface for Phase 3. Given a syscall,
 * it determines which arguments are string pointers and reads them.
 * 
 * @param pid     PID of the traced process
 * @param info    Syscall information
 * @param arg_str Output buffer for the decoded argument string
 * @param max_len Maximum length of output
 */
void inspect_syscall_args(pid_t pid, const syscall_info_t *info, 
                          char *arg_str, size_t max_len) {
    char path_buf[MAX_PATH_LENGTH];
    char addr_buf[64];
    int port;
    
    arg_str[0] = '\0';
    
    switch (info->syscall_num) {
        /* File operations - arg1 is filename */
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
            if (read_string_from_child(pid, info->arg1, path_buf, sizeof(path_buf)) >= 0) {
                snprintf(arg_str, max_len, "path=\"%s\"", path_buf);
            }
            break;
        
        /* openat, unlinkat, etc - arg2 is filename */
        case SYS_OPENAT:
        case SYS_UNLINKAT:
        case SYS_MKDIRAT:
            if (read_string_from_child(pid, info->arg2, path_buf, sizeof(path_buf)) >= 0) {
                snprintf(arg_str, max_len, "dirfd=%lld, path=\"%s\"",
                         (long long)info->arg1, path_buf);
            }
            break;
        
        /* execve - arg1 is filename, arg2 is argv */
        case SYS_EXECVE:
        case SYS_EXECVEAT:
            if (read_string_from_child(pid, info->arg1, path_buf, sizeof(path_buf)) >= 0) {
                char argv_str[512] = "";
                char args[8][MAX_STRING_LENGTH];
                int argc = read_argv_from_child(pid, info->arg2, args, 8);
                size_t argv_pos = 0;
                
                /* Build argv string safely */
                for (int i = 0; i < argc && i < 4 && argv_pos < sizeof(argv_str) - 70; i++) {
                    if (i > 0) {
                        argv_pos += snprintf(argv_str + argv_pos, sizeof(argv_str) - argv_pos, ", ");
                    }
                    argv_pos += snprintf(argv_str + argv_pos, sizeof(argv_str) - argv_pos, "\"%.60s\"", args[i]);
                }
                if (argc > 4) {
                    snprintf(argv_str + argv_pos, sizeof(argv_str) - argv_pos, ", ...");
                }
                
                snprintf(arg_str, max_len, "exec=\"%s\" argv=[%s]", path_buf, argv_str);
            }
            break;
        
        /* rename - arg1 and arg2 are filenames */
        case SYS_RENAME:
        case SYS_LINK:
            {
                char old_path[MAX_PATH_LENGTH];
                char new_path[MAX_PATH_LENGTH];
                
                read_string_from_child(pid, info->arg1, old_path, sizeof(old_path));
                read_string_from_child(pid, info->arg2, new_path, sizeof(new_path));
                
                snprintf(arg_str, max_len, "from=\"%s\" to=\"%s\"", old_path, new_path);
            }
            break;
        
        /* connect - arg2 is sockaddr */
        case SYS_CONNECT:
        case SYS_BIND:
            if (read_sockaddr_from_child(pid, info->arg2, addr_buf, sizeof(addr_buf), &port) == 0) {
                snprintf(arg_str, max_len, "addr=%s:%d", addr_buf, port);
            }
            break;
        
        /* read/write - show fd and size */
        case SYS_READ:
        case SYS_WRITE:
            snprintf(arg_str, max_len, "fd=%llu, size=%llu", info->arg1, info->arg3);
            break;
        
        default:
            /* No special handling needed */
            break;
    }
}
