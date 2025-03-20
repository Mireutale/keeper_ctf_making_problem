#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
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


// ki112r 생성
void create_ki112r() {
    // /home/process_kill 파일에 프로세스명 저장
    FILE *fp = fopen("/home/process_kill", "w");
    if (fp) {
        fprintf(fp, "plz!! kill the ki112r\n");
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
    char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void (*sc)();
    
    init();
    banned_execve();
    
    create_ki112r();

    printf("Read the process_kill(/home/process_kill): ");
    read(0, shellcode, 0x1000);

    sc = (void *)shellcode;
    sc();

    char input[16];
    printf("Do you know the name of the killer?: ");
    scanf("%15s", input);

    if (strcmp(input, "ki112r") == 0) {
            printf("safe the victim!!\n");
            printf("KEEPER{Can_y0u_b2c0me_a_ke2p2r?}\n");
    } else {
        printf("Wrong process! The ki112r is still alive...\n");
    }

    return 0;
}
