void _start(void) {
    static const char msg[] = "HELLO-EXEC: i am the post-execve image!\n";
    long n = (long)sizeof(msg) - 1;
    __asm__ volatile ("syscall" : : "a"(1L), "D"(1L), "S"(msg), "d"(n) : "rcx", "r11", "memory");
    __asm__ volatile ("syscall" : : "a"(60L), "D"(42L) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
