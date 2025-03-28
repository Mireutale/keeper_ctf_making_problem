// Compile: gcc -o shell_basic shell_basic.c -lseccomp
// apt install seccomp libseccomp-dev

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void open_file_descriptor() {
    int fd = open("/home/kali/wargame/0x01_making/KillerName", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    dup2(fd, 255);
    close(fd);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);

    open_file_descriptor();
}

void banned_execve() {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        exit(0);
    }
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

    seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
    char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void (*sc)();
    
    init();
    
    banned_execve();

    printf("shellcode: ");
    read(0, shellcode, 0x1000);

    sc = (void *)shellcode;
    sc();
}