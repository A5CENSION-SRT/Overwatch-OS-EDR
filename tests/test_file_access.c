/**
 * Test program: File Access Patterns
 * 
 * This test demonstrates various file access syscalls that
 * the EDR should monitor and log.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(void) {
    printf("=== File Access Test ===\n\n");
    
    /* Test 1: Read a normal file */
    printf("[1] Reading /etc/hostname...\n");
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("    Hostname: %s", buf);
        }
        close(fd);
    } else {
        printf("    (Could not open)\n");
    }
    
    /* Test 2: Check file permissions */
    printf("\n[2] Checking access to /etc/passwd...\n");
    if (access("/etc/passwd", R_OK) == 0) {
        printf("    /etc/passwd is readable\n");
    }
    
    /* Test 3: Get file stats */
    printf("\n[3] Getting stats for /bin/ls...\n");
    struct stat st;
    if (stat("/bin/ls", &st) == 0) {
        printf("    Size: %ld bytes\n", (long)st.st_size);
        printf("    Mode: %o\n", st.st_mode & 0777);
    }
    
    /* Test 4: Read /etc/passwd (should be monitored) */
    printf("\n[4] Reading /etc/passwd (first 3 lines)...\n");
    FILE *fp = fopen("/etc/passwd", "r");
    if (fp) {
        char line[256];
        for (int i = 0; i < 3 && fgets(line, sizeof(line), fp); i++) {
            printf("    %s", line);
        }
        fclose(fp);
    }
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
