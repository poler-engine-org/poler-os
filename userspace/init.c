// ============================================================================
// POLER-OS CachyOS / Arch Linux Userspace — PID 1 System Init
// ============================================================================

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_fork 57

static inline long syscall1(long n, long a1) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static void print(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    syscall3(SYS_write, 1, (long)s, len);
}

void _start(void) {
    print("\n\033[1;36m:: Starting POLER-OS CachyOS Userspace Substrate (PID 1)...\033[0m\n");
    print("\033[1;32m:: Mounted rootfs (CPIO RO), /tmp (tmpfs), /dev (devfs)\033[0m\n");
    print("\033[1;33m:: Spawning interactive userspace shell (/bin/sh)...\033[0m\n\n");

    const char *argv[] = {"/bin/sh", (void*)0};
    const char *envp[] = {
        "HOME=/root",
        "TERM=xterm-256color",
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
        "USER=root",
        "SHELL=/bin/sh",
        "XDG_CACHE_HOME=/tmp",
        (void*)0
    };

    syscall3(SYS_execve, (long)"/bin/sh", (long)argv, (long)envp);
    syscall3(SYS_execve, (long)"bin/sh", (long)argv, (long)envp);

    print("init: failed to execute /bin/sh\n");
    syscall1(SYS_exit, 1);
}
