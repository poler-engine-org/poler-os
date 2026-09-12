// ============================================================================
// POLER-OS CachyOS / Arch Linux Userspace Shell (/bin/sh)
// ============================================================================

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_lseek 8
#define SYS_mkdir 83
#define SYS_unlink 87
#define SYS_getdents64 217
#define SYS_exit 60
#define SYS_execve 59
#define SYS_fork 57
#define SYS_wait4 61
#define SYS_getpid 39
#define SYS_uname 63

struct input_event {
    long sec;
    long usec;
    unsigned short type;
    unsigned short code;
    int value;
};

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

__attribute__((used)) unsigned long strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

__attribute__((used)) void *memset(void *s, int c, unsigned long n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

__attribute__((used)) void *memcpy(void *dest, const void *src, unsigned long n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

static int strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(const unsigned char*)a - *(const unsigned char*)b;
}

static int strncmp(const char *a, const char *b, unsigned long n) {
    while (n && *a && (*a == *b)) { a++; b++; n--; }
    if (n == 0) return 0;
    return *(const unsigned char*)a - *(const unsigned char*)b;
}

static void print(const char *s) {
    syscall3(SYS_write, 1, (long)s, strlen(s));
}

static const char key_table[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' '
};

static const char key_table_shift[128] = {
    0, 27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0, '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,
    '*', 0, ' '
};

static char get_key(void) {
    char ch = 0;
    while (1) {
        long n = syscall3(SYS_read, 0, (long)&ch, 1);
        if (n > 0 && ch != 0) return ch;
        for (volatile int i = 0; i < 20000; i++) asm volatile ("pause");
    }
}

static void print_banner(void) {
    print("\033[1;36m"
          "  ____   ___  _     _____ ____        ___  ____  \n"
          " |  _ \\ / _ \\| |   | ____|  _ \\      / _ \\/ ___| \n"
          " | |_) | | | | |   |  _| | |_) |____| | | \\___ \\ \n"
          " |  __/| |_| | |___| |___|  _ <_____| |_| |___) |\n"
          " |_|    \\___/|_____|_____|_| \\_\\     \\___/|____/ \n\n"
          "\033[1;37m"
          " Linux-ABI CachyOS / Arch Substrate on POLER Microkernel\n"
          " Architecture: x86_64 | Session: Ring 3 POSIX Userspace (/bin/sh)\n"
          " DRM/KMS: /dev/dri/card0 | Input: /dev/input/event0,1 | VFS: CPIO RO + tmpfs\n"
          "\033[0m\n"
          " Type \033[1;33m'help'\033[0m or \033[1;33m'fetch'\033[0m to explore commands and hardware status.\n\n");
}

static void cmd_help(void) {
    print("\033[1;32mAvailable Shell Commands:\033[0m\n"
          "  help               - Show this help reference\n"
          "  fetch              - Display system status, hardware & kernel architecture\n"
          "  uname -a           - Print kernel name, version and architecture\n"
          "  ls [path]          - List directory entries\n"
          "  cat <file>         - Display file contents\n"
          "  echo [text...]     - Print text to stdout\n"
          "  clear              - Clear terminal screen\n"
          "  pwd                - Print current working directory\n"
          "  mkdir <dir>        - Create a directory in writable tmpfs\n"
          "  touch <file>       - Create or update an empty file\n"
          "  write <file> <str> - Write string to a file in tmpfs\n"
          "  rm <file>          - Remove file from tmpfs\n"
          "  ps                 - List active tasks and processes\n"
          "  drminfo            - Display DRM/KMS card0 status\n"
          "  gnome / mutter     - Launch CachyOS GNOME Desktop Session on DRM/KMS\n"
          "  startx / plasma    - Launch CachyOS KDE Plasma 6 Desktop on DRM/KMS\n"
          "  exit               - Terminate shell session\n");
}

static void cmd_fetch(void) {
    print("\033[1;36m"
          "        /\\         OS: CachyOS / Arch Linux Substrate on POLER-OS\n"
          "       /  \\        Kernel: POLER-Microkernel 0.20.0-rc (x86_64)\n"
          "      /\\   \\       Architecture: x86_64 (Ring 0 Microkernel + Ring 3 POSIX)\n"
          "     /      \\      Init System: /sbin/init (PID 1)\n"
          "    /   ,,   \\     Display Server: DRM/KMS Dumb + VirtIO-GPU (/dev/dri/card0)\n"
          "   /   |  |  -\\    Desktop Environment: KDE Plasma 6 / Gamescope Compositor\n"
          "  /_-''    ''-_\\   Substrate: Dual-ABI (Linux ELF glibc + Windows PE64)\n"
          "                   VFS: CPIO Read-Only Root + In-Memory tmpfs Overlay\n"
          "                   Memory: 1024 MB Physical RAM, PMM Next-Fit Bitmap\n"
          "\033[0m\n");
}

static void cmd_cat(const char *path) {
    if (!*path) {
        print("cat: missing file operand\n");
        return;
    }
    long fd = syscall3(SYS_open, (long)path, 0, 0);
    if (fd < 0) {
        print("cat: ");
        print(path);
        print(": No such file or directory\n");
        return;
    }
    char buf[512];
    while (1) {
        long n = syscall3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        syscall3(SYS_write, 1, (long)buf, n);
    }
    syscall1(SYS_close, fd);
}

struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

static void cmd_ls(const char *path) {
    const char *p = (*path) ? path : ".";
    long fd = syscall3(SYS_open, (long)p, 0, 0);
    if (fd < 0) {
        print("ls: cannot access '");
        print(p);
        print("': No such directory\n");
        return;
    }
    char buf[1024];
    long nread = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
    if (nread > 0) {
        long pos = 0;
        while (pos < nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
            if (d->d_type == 4) { // Directory
                print("\033[1;34m");
                print(d->d_name);
                print("/\033[0m  ");
            } else {
                print(d->d_name);
                print("  ");
            }
            pos += d->d_reclen;
        }
        print("\n");
    }
    syscall1(SYS_close, fd);
}

void main_entry(void) {
    print_banner();

    long kbd_fd = syscall3(SYS_open, (long)"/dev/input/event0", 0, 0);
    if (kbd_fd < 0) kbd_fd = 0; // fallback to stdin

    char line[256];
    while (1) {
        print("\033[1;32m[root@poler-cachyos \033[1;34m~\033[1;32m]#\033[0m ");
        
        unsigned long idx = 0;
        while (idx < sizeof(line) - 1) {
            char ch = get_key();
            if (ch == '\r' || ch == '\n') {
                line[idx] = '\0';
                print("\n");
                break;
            } else if (ch == '\b' || ch == 127) { // Backspace
                if (idx > 0) {
                    idx--;
                    print("\b \b");
                }
            } else if (ch >= 32 && ch <= 126) {
                line[idx++] = ch;
                char echo_buf[2] = {ch, 0};
                print(echo_buf);
            }
        }
        
        char *cmd = line;
        while (*cmd == ' ') cmd++;
        if (!*cmd) continue;

        if (strcmp(cmd, "help") == 0) {
            cmd_help();
        } else if (strcmp(cmd, "fetch") == 0 || strcmp(cmd, "neofetch") == 0) {
            cmd_fetch();
        } else if (strncmp(cmd, "uname", 5) == 0) {
            print("Linux poler-cachyos 6.12.0-poler #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n");
        } else if (strcmp(cmd, "clear") == 0) {
            print("\033[2J\033[H");
        } else if (strcmp(cmd, "pwd") == 0) {
            print("/root\n");
        } else if (strncmp(cmd, "echo ", 5) == 0) {
            print(cmd + 5);
            print("\n");
        } else if (strcmp(cmd, "echo") == 0) {
            print("\n");
        } else if (strncmp(cmd, "cat ", 4) == 0) {
            char *arg = cmd + 4;
            while (*arg == ' ') arg++;
            cmd_cat(arg);
        } else if (strncmp(cmd, "ls", 2) == 0) {
            char *arg = cmd + 2;
            while (*arg == ' ') arg++;
            cmd_ls(arg);
        } else if (strcmp(cmd, "ps") == 0) {
            print("  PID TTY          TIME CMD\n"
                  "    1 ?        00:00:00 init\n"
                  "    2 tty1     00:00:00 sh\n");
        } else if (strcmp(cmd, "drminfo") == 0) {
            print("[DRM/KMS] Card: /dev/dri/card0 (virtio-gpu / dumb-kms)\n"
                  "[DRM/KMS] Active Connector: Virtual-1 (Connected)\n"
                  "[DRM/KMS] Current Mode: 1024x768 @ 60Hz 32bpp XRGB8888\n");
        } else if (strcmp(cmd, "gnome") == 0 || strcmp(cmd, "mutter") == 0 || strcmp(cmd, "gdm") == 0) {
            print("\033[1;36m[WAYLAND] Starting CachyOS GNOME Desktop Session on DRM/KMS...\033[0m\n");
            const char *argv[2];
            argv[0] = "/bin/compositor";
            argv[1] = 0;
            const char *envp[4];
            envp[0] = "TERM=xterm";
            envp[1] = "XDG_SESSION_TYPE=wayland";
            envp[2] = "XDG_CURRENT_DESKTOP=GNOME";
            envp[3] = 0;
            syscall3(SYS_execve, (long)"/bin/compositor", (long)argv, (long)envp);
            print("sh: failed to launch /bin/compositor\n");
        } else if (strcmp(cmd, "startx") == 0 || strcmp(cmd, "plasma") == 0 || strcmp(cmd, "kde") == 0 || strcmp(cmd, "gamescope") == 0 || strcmp(cmd, "wayland") == 0) {
            print("\033[1;36m[WAYLAND] Starting CachyOS KDE Plasma 6 Desktop Session on DRM/KMS...\033[0m\n");
            const char *argv[2];
            argv[0] = "/bin/compositor";
            argv[1] = 0;
            const char *envp[4];
            envp[0] = "TERM=xterm";
            envp[1] = "XDG_SESSION_TYPE=wayland";
            envp[2] = "XDG_CURRENT_DESKTOP=KDE";
            envp[3] = 0;
            syscall3(SYS_execve, (long)"/bin/compositor", (long)argv, (long)envp);
            print("sh: failed to launch /bin/compositor\n");
        } else if (strcmp(cmd, "exit") == 0) {
            print("Shell exit. Restarting session...\n\n");
            print_banner();
        } else {
            char full_path1[64] = "/bin/";
            char full_path2[64] = "/usr/bin/";
            int p_idx1 = 5;
            int p_idx2 = 9;
            const char *c_ptr = cmd;
            while (*c_ptr && *c_ptr != ' ' && p_idx1 < 60 && p_idx2 < 60) {
                full_path1[p_idx1++] = *c_ptr;
                full_path2[p_idx2++] = *c_ptr++;
            }
            full_path1[p_idx1] = '\0';
            full_path2[p_idx2] = '\0';
            const char *argv[3] = {full_path1, 0, 0};
            if (*c_ptr == ' ') {
                while (*c_ptr == ' ') c_ptr++;
                if (*c_ptr) argv[1] = c_ptr;
            }
            const char *envp[3] = {"PATH=/bin:/usr/bin:/usr/lib", "TERM=linux", 0};
            if (cmd[0] == '/') {
                argv[0] = cmd;
                syscall3(SYS_execve, (long)cmd, (long)argv, (long)envp);
            } else {
                syscall3(SYS_execve, (long)full_path1, (long)argv, (long)envp);
                argv[0] = full_path2;
                syscall3(SYS_execve, (long)full_path2, (long)argv, (long)envp);
            }
            print("sh: command not found: ");
            print(cmd);
            print(" (type 'help' for available commands)\n");
        }
    }

    syscall1(SYS_exit, 0);
}

void _start(void) {
    asm volatile (
        "andq $-16, %%rsp\n"
        "call main_entry\n"
        "movq $60, %%rax\n"
        "xorq %%rdi, %%rdi\n"
        "syscall\n"
        : : : "memory"
    );
}
