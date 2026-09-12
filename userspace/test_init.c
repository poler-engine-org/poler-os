// Linux x86_64 freestanding syscalls
static inline long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(1), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int code) {
    asm volatile ("syscall" : : "a"(60), "D"(code) : "rcx", "r11", "memory");
    while (1) {}
}

void _start(void) {
    const char msg[] = "Hello from Linux Ring 3 Userspace!\n";
    sys_write(1, msg, sizeof(msg) - 1);
    sys_exit(0);
}
