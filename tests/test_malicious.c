/**
 * Test program: Simulated Malicious Behavior
 * 
 * WARNING: This is a SAFE test program that simulates behaviors
 * that real malware might exhibit. It does NOT actually perform
 * any harmful actions - it only attempts syscalls that trigger
 * the EDR's detection rules.
 * 
 * Run with enforcement mode to see the EDR kill this process:
 *   ./bin/watchtower -e -- ./bin/test_malicious
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(void) {
    printf("=== Simulated Malicious Behavior Test ===\n");
    printf("This program will attempt suspicious syscalls.\n");
    printf("In enforcement mode, the EDR should kill this process.\n\n");
    
    /* Give user a moment to see the message */
    sleep(1);
    
    /* Malicious Behavior 1: Try to read /etc/shadow */
    printf("[!] Attempting to read /etc/shadow...\n");
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd >= 0) {
        printf("    WARNING: /etc/shadow was accessible!\n");
        close(fd);
    } else {
        printf("    Access denied (errno=%d: %s) - Good!\n", errno, strerror(errno));
    }
    
    /* Malicious Behavior 2: Try to read SSH private key */
    printf("\n[!] Attempting to read SSH private key...\n");
    char ssh_key_path[256];
    snprintf(ssh_key_path, sizeof(ssh_key_path), "%s/.ssh/id_rsa", getenv("HOME"));
    fd = open(ssh_key_path, O_RDONLY);
    if (fd >= 0) {
        printf("    WARNING: SSH key was readable!\n");
        close(fd);
    } else {
        printf("    Access denied or file not found - Good!\n");
    }
    
    /* Malicious Behavior 3: Try to access /proc/self/mem */
    printf("\n[!] Attempting to access /proc/self/mem...\n");
    fd = open("/proc/self/mem", O_RDONLY);
    if (fd >= 0) {
        printf("    /proc/self/mem opened\n");
        close(fd);
    } else {
        printf("    Access denied - Good!\n");
    }
    
    /* Malicious Behavior 4: Simulate persistence (just check crontab) */
    printf("\n[!] Checking crontab access...\n");
    if (access("/etc/crontab", R_OK) == 0) {
        printf("    /etc/crontab is readable (monitoring should trigger)\n");
    }
    
    printf("\n=== Test Complete ===\n");
    printf("If you see this message, the EDR did not kill the process.\n");
    printf("Run with -e (enforce) mode to see the EDR in action.\n");
    
    return 0;
}
