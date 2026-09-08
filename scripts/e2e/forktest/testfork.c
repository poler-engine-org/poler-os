#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    printf("TESTFORK: start (pid view)\n");
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("TESTFORK: child post-fork pre-exec\n");
        fflush(stdout);
        char *argv[] = {"hello-exec", 0};
        char *envp[] = {"HOME=/root", "TESTVAR=42", 0};
        execve("/hello-exec", argv, envp);
        printf("TESTFORK: EXECVE FAILED errno=%d\n", errno);
        return 99;
    }
    printf("TESTFORK: parent forked pid=%d\n", pid);
    fflush(stdout);
    int st = 0;
    errno = 0;
    pid_t r = wait4(pid, &st, 0, 0);
    printf("TESTFORK: wait4 ret=%d errno=%d status=0x%x WEXITSTATUS=%d\n",
           r, errno, st, (st >> 8) & 0xFF);
    fflush(stdout);
    printf(r == pid && ((st >> 8) & 0xFF) == 42 ? "TESTFORK: *** PASS ***\n" : "TESTFORK: *** FAIL ***\n");
    fflush(stdout);
    return 0;
}
