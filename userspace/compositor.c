// ============================================================================
// POLER-OS Wayland / Gamescope / Plasma 6 Graphical Compositor
// ============================================================================
// Zero external dependencies, pure POSIX Linux ABI on POLER Microkernel
// Direct DRM/KMS scanout (/dev/dri/card0), Evdev input (/dev/input/event0,1)
// ============================================================================

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_ioctl 16
#define SYS_poll 7
#define SYS_exit 60

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1

#define O_RDWR 2
#define O_NONBLOCK 0x800

struct drm_mode_create_dumb {
    unsigned int height;
    unsigned int width;
    unsigned int bpp;
    unsigned int flags;
    unsigned int handle;
    unsigned int pitch;
    unsigned long long size;
};

struct drm_mode_map_dumb {
    unsigned int handle;
    unsigned int pad;
    unsigned long long offset;
};

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

static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
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

__attribute__((used)) void *memmove(void *dest, const void *src, unsigned long n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

__attribute__((used)) unsigned long strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

#define FB_W 1024
#define FB_H 768

static unsigned int *fb_mem = 0;
static unsigned int *back_buffer = 0;

#include "font_data.h"

static void draw_char(unsigned int *buf, int x, int y, char c, unsigned int color) {
    if (c < 32 || c > 126) c = '?';
    const unsigned char *glyph = font8x16[c - 32];
    for (int row = 0; row < 16; row++) {
        int py = y + row;
        if (py < 0 || py >= FB_H) continue;
        unsigned char bits = glyph[row];
        for (int col = 0; col < 8; col++) {
            int px = x + col;
            if (px < 0 || px >= FB_W) continue;
            if (bits & (0x80 >> col)) {
                buf[py * FB_W + px] = color;
            }
        }
    }
}

static void draw_string(unsigned int *buf, int x, int y, const char *s, unsigned int color) {
    while (*s) {
        draw_char(buf, x, y, *s, color);
        x += 8;
        s++;
    }
}

static void fill_rect(unsigned int *buf, int x, int y, int w, int h, unsigned int color) {
    int x1 = (x < 0) ? 0 : x;
    int y1 = (y < 0) ? 0 : y;
    int x2 = (x + w > FB_W) ? FB_W : x + w;
    int y2 = (y + h > FB_H) ? FB_H : y + h;
    for (int py = y1; py < y2; py++) {
        for (int px = x1; px < x2; px++) {
            buf[py * FB_W + px] = color;
        }
    }
}

static void draw_rect_outline(unsigned int *buf, int x, int y, int w, int h, unsigned int color) {
    fill_rect(buf, x, y, w, 1, color);
    fill_rect(buf, x, y + h - 1, w, 1, color);
    fill_rect(buf, x, y, 1, h, color);
    fill_rect(buf, x + w - 1, y, 1, h, color);
}

// Mouse cursor 12x18 bitmap
static const unsigned short cursor_mask[18] = {
    0b100000000000,
    0b110000000000,
    0b111000000000,
    0b111100000000,
    0b111110000000,
    0b111111000000,
    0b111111100000,
    0b111111110000,
    0b111111111000,
    0b111111111100,
    0b111111000000,
    0b110111100000,
    0b100011110000,
    0b000001111000,
    0b000001111000,
    0b000000111100,
    0b000000111100,
    0b000000011000
};

static void draw_cursor(unsigned int *buf, int mx, int my) {
    for (int row = 0; row < 18; row++) {
        int py = my + row;
        if (py < 0 || py >= FB_H) continue;
        unsigned short mask = cursor_mask[row];
        for (int col = 0; col < 12; col++) {
            int px = mx + col;
            if (px < 0 || px >= FB_W) continue;
            if (mask & (1 << (11 - col))) {
                buf[py * FB_W + px] = 0xFFFFFFFF; // White cursor body
            }
        }
    }
}

// Konsole Terminal Window State
#define TERM_ROWS 22
#define TERM_COLS 68
static char term_grid[TERM_ROWS][TERM_COLS];
static int term_cursor_row = 0;
static int term_cursor_col = 0;
static int term_win_x = 120;
static int term_win_y = 70;
static int term_win_w = 68 * 8 + 24;
static int term_win_h = 22 * 16 + 48;
static int menu_open = 0;

static void term_clear(void) {
    for (int r = 0; r < TERM_ROWS; r++) {
        for (int c = 0; c < TERM_COLS; c++) {
            term_grid[r][c] = ' ';
        }
    }
    term_cursor_row = 0;
    term_cursor_col = 0;
}

static void term_newline(void) {
    term_cursor_col = 0;
    if (term_cursor_row + 1 < TERM_ROWS) {
        term_cursor_row++;
    } else {
        // Scroll up by 1 line
        for (int r = 0; r < TERM_ROWS - 1; r++) {
            for (int c = 0; c < TERM_COLS; c++) {
                term_grid[r][c] = term_grid[r + 1][c];
            }
        }
        for (int c = 0; c < TERM_COLS; c++) {
            term_grid[TERM_ROWS - 1][c] = ' ';
        }
    }
}

static void term_putc(char ch) {
    if (ch == '\n') {
        term_newline();
    } else if (ch == '\r') {
        term_cursor_col = 0;
    } else if (ch == '\b') {
        if (term_cursor_col > 0) {
            term_cursor_col--;
            term_grid[term_cursor_row][term_cursor_col] = ' ';
        }
    } else if (ch >= 32 && ch <= 126) {
        if (term_cursor_col >= TERM_COLS) {
            term_newline();
        }
        term_grid[term_cursor_row][term_cursor_col++] = ch;
    }
}

static void term_puts(const char *s) {
    while (*s) term_putc(*s++);
}

static int str_eq(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(const unsigned char*)a == *(const unsigned char*)b;
}

// Window States
static int win_konsole_open = 1;
static int win_sysmon_open = 0;
static int win_dolphin_open = 0;

static int sysmon_win_x = 420;
static int sysmon_win_y = 120;
static int sysmon_win_w = 460;
static int sysmon_win_h = 320;

static int dolphin_win_x = 180;
static int dolphin_win_y = 160;
static int dolphin_win_w = 520;
static int dolphin_win_h = 340;

static int dragging_win = 0; // 0=none, 1=konsole, 2=sysmon, 3=dolphin
static int drag_off_x = 0;
static int drag_off_y = 0;

static void term_exec(const char *cmd) {
    while (*cmd == ' ') cmd++;
    if (!*cmd) return;

    if (str_eq(cmd, "help")) {
        term_puts("Commands: help, fetch, uname, clear, ls, ps, sysmon, dolphin, drminfo, date\n");
    } else if (str_eq(cmd, "fetch") || str_eq(cmd, "neofetch")) {
        term_puts("  OS: CachyOS Plasma 6 / Gamescope on POLER-OS\n");
        term_puts("  Kernel: POLER-Microkernel 0.20.0-rc (x86_64)\n");
        term_puts("  Compositor: Wayland / DRM-KMS Direct Scanout\n");
        term_puts("  Resolution: 1024x768 @ 60 FPS XRGB8888\n");
        term_puts("  Memory: 2048 MB / PMM + VMM Buddy Allocator\n");
    } else if (str_eq(cmd, "sysmon") || str_eq(cmd, "top") || str_eq(cmd, "htop")) {
        win_sysmon_open = 1;
        term_puts("[WAYLAND] Opened Plasma System Monitor\n");
    } else if (str_eq(cmd, "dolphin") || str_eq(cmd, "files")) {
        win_dolphin_open = 1;
        term_puts("[WAYLAND] Opened Dolphin File Manager\n");
    } else if (str_eq(cmd, "uname") || str_eq(cmd, "uname -a")) {
        term_puts("Linux poler-cachyos 6.12.0-cachyos-poler #1 SMP PREEMPT x86_64\n");
    } else if (str_eq(cmd, "clear")) {
        term_clear();
    } else if (str_eq(cmd, "ls")) {
        term_puts("Desktop/  Downloads/  Music/  Pictures/  Videos/  poler-engine/  airootfs.sfs\n");
    } else if (str_eq(cmd, "ps")) {
        term_puts("  PID TTY      TIME CMD\n");
        term_puts("    1 ?    00:00:01 init\n");
        term_puts("    2 tty1 00:00:00 wayland-compositor\n");
        term_puts("    3 tty1 00:00:00 kwin_wayland\n");
        term_puts("    4 tty1 00:00:00 plasmashell\n");
    } else if (str_eq(cmd, "drminfo")) {
        term_puts("[DRM/KMS] Card0: virtio-gpu-pci / Dumb-buffer KMS\n");
        term_puts("[DRM/KMS] Primary Plane: XRGB8888 1024x768 Active Scanout\n");
    } else if (str_eq(cmd, "date")) {
        term_puts("Sat Sep 12 04:55:00 UTC 2026\n");
    } else {
        term_puts("sh: command not found: ");
        term_puts(cmd);
        term_puts("\n");
    }
}

static char cmd_buf[128];
static int cmd_idx = 0;

static void render_desktop(int mx, int my, unsigned int frame_cnt) {
    // 1. GNOME 47 Dark Modern Wallpaper (Adwaita Dark slate gradient)
    for (int y = 0; y < FB_H; y++) {
        unsigned int r = 28 + (y * 14 / FB_H);
        unsigned int g = 28 + (y * 14 / FB_H);
        unsigned int b = 32 + (y * 16 / FB_H);
        unsigned int c = (r << 16) | (g << 8) | b;
        for (int x = 0; x < FB_W; x++) {
            back_buffer[y * FB_W + x] = c;
        }
    }

    // GNOME Top Bar (32px height at top)
    fill_rect(back_buffer, 0, 0, FB_W, 32, 0x00141414);
    fill_rect(back_buffer, 0, 31, FB_W, 1, 0x002A2A2A);

    // "Activities" pill
    fill_rect(back_buffer, 8, 4, 96, 24, 0x002C2C2C);
    draw_string(back_buffer, 18, 8, "Activities", 0xFFFFFFFF);

    // Top Clock
    draw_string(back_buffer, FB_W / 2 - 80, 8, "Sat Sep 12  07:22 AM", 0xFFE0E0E0);

    // Top System Controls
    fill_rect(back_buffer, FB_W - 220, 4, 212, 24, 0x00242424);
    draw_string(back_buffer, FB_W - 210, 8, "DRM:60fps  LAN  100%  [P]", 0xFF3584E4);

    // GNOME Dash / Left Dock (64px width)
    fill_rect(back_buffer, 0, 32, 64, FB_H - 32, 0x001A1A1A);
    fill_rect(back_buffer, 63, 32, 1, FB_H - 32, 0x002E2E2E);

    // Dock Icons
    // Files (Nautilus)
    fill_rect(back_buffer, 10, 50, 44, 44, 0x003584E4);
    draw_string(back_buffer, 14, 64, "Files", 0xFFFFFFFF);

    // Terminal
    fill_rect(back_buffer, 10, 110, 44, 44, 0x00241F31);
    draw_rect_outline(back_buffer, 10, 110, 44, 44, 0x003584E4);
    draw_string(back_buffer, 14, 124, "Term", 0xFF2EC27E);

    // System Monitor
    fill_rect(back_buffer, 10, 170, 44, 44, 0x0026A269);
    draw_string(back_buffer, 14, 184, "Stats", 0xFFFFFFFF);

    // App Grid
    fill_rect(back_buffer, 10, FB_H - 56, 44, 44, 0x002C2C2C);
    draw_string(back_buffer, 14, FB_H - 42, "Apps", 0xFFFFFFFF);

    // Desktop Files / Volume Icons
    fill_rect(back_buffer, 90, 50, 48, 48, 0x002C2C2C);
    draw_string(back_buffer, 94, 66, "HOME", 0xFFFFFFFF);
    draw_string(back_buffer, 86, 104, "Home Dir", 0xFFE0E0E0);

    fill_rect(back_buffer, 90, 136, 48, 48, 0x002C2C2C);
    draw_string(back_buffer, 94, 152, "GNOME", 0xFF3584E4);
    draw_string(back_buffer, 86, 190, "121MB SFS", 0xFFE0E0E0);

    // 2. GNOME Terminal Window (if open)
    if (win_konsole_open) {
        fill_rect(back_buffer, term_win_x + 4, term_win_y + 4, term_win_w, term_win_h, 0x000A0A0A); // Shadow
        fill_rect(back_buffer, term_win_x, term_win_y, term_win_w, term_win_h, 0x001E1E1E);        // Window BG
        draw_rect_outline(back_buffer, term_win_x, term_win_y, term_win_w, term_win_h, 0x003A3A3A);

        // Headerbar (36px)
        fill_rect(back_buffer, term_win_x, term_win_y, term_win_w, 36, 0x002E2E2E);
        draw_string(back_buffer, term_win_x + 16, term_win_y + 10, "Terminal — root@poler-cachyos:~ (GNOME 47)", 0xFFFFFFFF);

        // Window controls
        fill_rect(back_buffer, term_win_x + term_win_w - 28, term_win_y + 10, 16, 16, 0x00E01B24); // Close
        fill_rect(back_buffer, term_win_x + term_win_w - 52, term_win_y + 10, 16, 16, 0x0026A269); // Max
        fill_rect(back_buffer, term_win_x + term_win_w - 76, term_win_y + 10, 16, 16, 0x00E5A50A); // Min

        int text_start_x = term_win_x + 14;
        int text_start_y = term_win_y + 46;
        for (int r = 0; r < TERM_ROWS; r++) {
            for (int c = 0; c < TERM_COLS; c++) {
                char ch = term_grid[r][c];
                if (ch != ' ') {
                    draw_char(back_buffer, text_start_x + c * 8, text_start_y + r * 16, ch, 0xFF33D17A);
                }
            }
        }
        if ((frame_cnt / 15) % 2 == 0) {
            fill_rect(back_buffer, text_start_x + term_cursor_col * 8, text_start_y + term_cursor_row * 16, 8, 16, 0xFF33D17A);
        }
    }

    // 3. GNOME System Monitor Window (if open)
    if (win_sysmon_open) {
        fill_rect(back_buffer, sysmon_win_x + 4, sysmon_win_y + 4, sysmon_win_w, sysmon_win_h, 0x000A0A0A);
        fill_rect(back_buffer, sysmon_win_x, sysmon_win_y, sysmon_win_w, sysmon_win_h, 0x00242424);
        draw_rect_outline(back_buffer, sysmon_win_x, sysmon_win_y, sysmon_win_w, sysmon_win_h, 0x003584E4);

        // Headerbar
        fill_rect(back_buffer, sysmon_win_x, sysmon_win_y, sysmon_win_w, 36, 0x002E2E2E);
        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 10, "Usage — GNOME System Monitor", 0xFFFFFFFF);
        fill_rect(back_buffer, sysmon_win_x + sysmon_win_w - 28, sysmon_win_y + 10, 16, 16, 0x00E01B24);

        // Content
        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 50, "CPU: 0.6% — AMD/Intel x86_64 8-Core", 0xFF2EC27E);
        fill_rect(back_buffer, sysmon_win_x + 16, sysmon_win_y + 70, 400, 12, 0x001C1C1C);
        fill_rect(back_buffer, sysmon_win_x + 16, sysmon_win_y + 70, 12, 12, 0xFF2EC27E);

        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 94, "Memory: 38 MB / 2048 MB (SquashFS Compressed)", 0xFF3584E4);
        fill_rect(back_buffer, sysmon_win_x + 16, sysmon_win_y + 114, 400, 12, 0x001C1C1C);
        fill_rect(back_buffer, sysmon_win_x + 16, sysmon_win_y + 114, 24, 12, 0xFF3584E4);

        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 140, "Compositor: Mutter / Wayland-0 Active", 0xFFFFFFFF);
        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 164, "RootFS: gnome-rootfs.sfs (121.36 MB, zstd-15)", 0xFFE0E0E0);
        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 188, "Display: VirtIO-GPU DRM Dumb-KMS 60FPS", 0xFF2EC27E);
        draw_string(back_buffer, sysmon_win_x + 16, sysmon_win_y + 212, "Kernel: POLER-OS 0.20.0-rc Dual-ABI", 0xFFF67400);

        // Activity Graph
        fill_rect(back_buffer, sysmon_win_x + 16, sysmon_win_y + 238, 420, 60, 0x00141414);
        draw_rect_outline(back_buffer, sysmon_win_x + 16, sysmon_win_y + 238, 420, 60, 0x003A3A3A);
        for (int i = 0; i < 400; i += 8) {
            int gh = 8 + ((i * 3 + frame_cnt * 2) % 32);
            fill_rect(back_buffer, sysmon_win_x + 20 + i, sysmon_win_y + 292 - gh, 6, gh, 0xFF3584E4);
        }
    }

    // 4. GNOME Files (Nautilus) Window (if open)
    if (win_dolphin_open) {
        fill_rect(back_buffer, dolphin_win_x + 4, dolphin_win_y + 4, dolphin_win_w, dolphin_win_h, 0x000A0A0A);
        fill_rect(back_buffer, dolphin_win_x, dolphin_win_y, dolphin_win_w, dolphin_win_h, 0x00242424);
        draw_rect_outline(back_buffer, dolphin_win_x, dolphin_win_y, dolphin_win_w, dolphin_win_h, 0x003584E4);

        // Headerbar
        fill_rect(back_buffer, dolphin_win_x, dolphin_win_y, dolphin_win_w, 36, 0x002E2E2E);
        draw_string(back_buffer, dolphin_win_x + 16, dolphin_win_y + 10, "Files — Nautilus (Live RootFS)", 0xFFFFFFFF);
        fill_rect(back_buffer, dolphin_win_x + dolphin_win_w - 28, dolphin_win_y + 10, 16, 16, 0x00E01B24);

        // Sidebar
        fill_rect(back_buffer, dolphin_win_x, dolphin_win_y + 36, 130, dolphin_win_h - 36, 0x001E1E1E);
        draw_string(back_buffer, dolphin_win_x + 12, dolphin_win_y + 52, "> Home", 0xFFFFFFFF);
        draw_string(back_buffer, dolphin_win_x + 12, dolphin_win_y + 76, "> Desktop", 0xFFB0B0B0);
        draw_string(back_buffer, dolphin_win_x + 12, dolphin_win_y + 100, "> Documents", 0xFFB0B0B0);
        draw_string(back_buffer, dolphin_win_x + 12, dolphin_win_y + 124, "> Downloads", 0xFFB0B0B0);
        draw_string(back_buffer, dolphin_win_x + 12, dolphin_win_y + 148, "> GNOME SFS", 0xFF3584E4);

        // Files Area
        int fx = dolphin_win_x + 150;
        int fy = dolphin_win_y + 52;

        fill_rect(back_buffer, fx, fy, 40, 36, 0x003584E4);
        draw_string(back_buffer, fx + 50, fy + 10, "Desktop/ (folder)", 0xFFFFFFFF);

        fill_rect(back_buffer, fx, fy + 50, 40, 36, 0x003584E4);
        draw_string(back_buffer, fx + 50, fy + 60, "Downloads/ (folder)", 0xFFFFFFFF);

        fill_rect(back_buffer, fx, fy + 100, 40, 36, 0x0026A269);
        draw_string(back_buffer, fx + 50, fy + 110, "gnome-rootfs.sfs (121.36 MB)", 0xFF2EC27E);

        fill_rect(back_buffer, fx, fy + 150, 40, 36, 0x00E5A50A);
        draw_string(back_buffer, fx + 50, fy + 160, "poler-os64 (13 MB Kernel)", 0xFFE5A50A);

        fill_rect(back_buffer, fx, fy + 200, 40, 36, 0x00C061CB);
        draw_string(back_buffer, fx + 50, fy + 210, "live-initrd.cpio (7.3 MB)", 0xFFC061CB);
    }

    // Activities Overview (if open)
    if (menu_open) {
        int menu_x = 8;
        int menu_y = 36;
        fill_rect(back_buffer, menu_x, menu_y, 240, 230, 0x00242424);
        draw_rect_outline(back_buffer, menu_x, menu_y, 240, 230, 0x003584E4);
        draw_string(back_buffer, menu_x + 16, menu_y + 14, "GNOME 47 Applications", 0xFFFFFFFF);
        fill_rect(back_buffer, menu_x + 10, menu_y + 34, 220, 1, 0x003A3A3A);
        draw_string(back_buffer, menu_x + 16, menu_y + 48, "> GNOME Terminal", 0xFF2EC27E);
        draw_string(back_buffer, menu_x + 16, menu_y + 78, "> System Monitor", 0xFF3584E4);
        draw_string(back_buffer, menu_x + 16, menu_y + 108, "> Files (Nautilus)", 0xFFE5A50A);
        draw_string(back_buffer, menu_x + 16, menu_y + 138, "> Control Center / Settings", 0xFFB0B0B0);
        draw_string(back_buffer, menu_x + 16, menu_y + 168, "> Gamescope HDR Session", 0xFFC061CB);
        draw_string(back_buffer, menu_x + 16, menu_y + 198, "> Exit to POSIX Shell", 0xFFE01B24);
    }

    // Mouse Cursor
    draw_cursor(back_buffer, mx, my);

    // 8. Copy Back Buffer to Scanout VRAM (Zero tearing)
    if (fb_mem) {
        for (int i = 0; i < FB_W * FB_H; i++) {
            fb_mem[i] = back_buffer[i];
        }
    }
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

static void compositor_print(const char *s) {
    long len = 0;
    while (s[len]) len++;
    syscall3(SYS_write, 1, (long)s, len);
}

void main_entry(void);

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

void main_entry(void) {
    compositor_print("[COMPOSITOR] Starting CachyOS GNOME 47 Desktop Shell (Mutter/Adwaita)...\n");
    // Allocate back buffer in user RAM
    back_buffer = (unsigned int *)syscall6(SYS_mmap, 0, FB_W * FB_H * 4, PROT_READ | PROT_WRITE, 0x22 /* MAP_PRIVATE | MAP_ANONYMOUS */, -1, 0);
    if (!back_buffer || (long)back_buffer < 0) {
        compositor_print("[COMPOSITOR] Failed to allocate back_buffer mmap\n");
        syscall1(SYS_exit, 1);
        return;
    }

    // 1. Open Framebuffer / DRM device
    long fb_fd = syscall3(SYS_open, (long)"/dev/fb0", O_RDWR, 0);
    long vram = 0;
    if (fb_fd >= 0) {
        vram = syscall6(SYS_mmap, 0, FB_W * FB_H * 4, PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    }
    if ((long)vram <= 0) {
        long drm_fd = syscall3(SYS_open, (long)"/dev/dri/card0", O_RDWR, 0);
        if (drm_fd >= 0) {
            struct drm_mode_create_dumb cre;
            cre.width = FB_W;
            cre.height = FB_H;
            cre.bpp = 32;
            cre.flags = 0;
            cre.handle = 0;
            cre.pitch = 0;
            cre.size = 0;
            syscall3(SYS_ioctl, drm_fd, 0xC02064B2, (long)&cre); // DRM_IOCTL_MODE_CREATE_DUMB

            struct drm_mode_map_dumb map_d;
            map_d.handle = cre.handle;
            map_d.pad = 0;
            map_d.offset = 0;
            syscall3(SYS_ioctl, drm_fd, 0xC01064B3, (long)&map_d); // DRM_IOCTL_MODE_MAP_DUMB

            vram = syscall6(SYS_mmap, 0, FB_W * FB_H * 4, PROT_READ | PROT_WRITE, MAP_SHARED, drm_fd, map_d.offset);
        }
    }
    if ((long)vram > 0) {
        fb_mem = (unsigned int *)vram;
    }

    // 4. Open Evdev Input Devices
    long kbd_fd = syscall3(SYS_open, (long)"/dev/input/event0", O_RDWR | O_NONBLOCK, 0);
    long mouse_fd = syscall3(SYS_open, (long)"/dev/input/event1", O_RDWR | O_NONBLOCK, 0);

    // Initial terminal text
    term_clear();
    term_puts("Welcome to CachyOS GNOME 47 Live Desktop Session\n");
    term_puts("Running on POLER Microkernel with VirtIO-GPU DRM/KMS\n\n");
    term_puts("[root@poler-cachyos ~]# ");

    int mouse_x = FB_W / 2;
    int mouse_y = FB_H / 2;
    int shift_down = 0;
    unsigned int frame_counter = 0;

    // Main Compositor Event Loop
    while (1) {
        frame_counter++;

        // Process Mouse Input
        if (mouse_fd >= 0) {
            struct input_event mev;
            while (syscall3(SYS_read, mouse_fd, (long)&mev, sizeof(mev)) == (long)sizeof(mev)) {
                if (mev.type == 2) { // EV_REL
                    if (mev.code == 0) mouse_x += mev.value; // REL_X
                    if (mev.code == 1) mouse_y -= mev.value; // REL_Y (PS/2 +Y is up, screen +Y is down)
                    if (mouse_x < 0) mouse_x = 0;
                    if (mouse_x >= FB_W) mouse_x = FB_W - 1;
                    if (mouse_y < 0) mouse_y = 0;
                    if (mouse_y >= FB_H) mouse_y = FB_H - 1;

                    // Handle Window Dragging
                    if (dragging_win == 1) { // Konsole
                        term_win_x = mouse_x - drag_off_x;
                        term_win_y = mouse_y - drag_off_y;
                    } else if (dragging_win == 2) { // Sysmon
                        sysmon_win_x = mouse_x - drag_off_x;
                        sysmon_win_y = mouse_y - drag_off_y;
                    } else if (dragging_win == 3) { // Dolphin
                        dolphin_win_x = mouse_x - drag_off_x;
                        dolphin_win_y = mouse_y - drag_off_y;
                    }
                } else if (mev.type == 1) { // EV_KEY
                    if (mev.code == 272) { // BTN_LEFT
                        if (mev.value == 1) { // Mouse Down / Click
                            // Check Taskbar Launcher (KDE button)
                            if (mouse_x >= 8 && mouse_x <= 44 && mouse_y >= FB_H - 44) {
                                menu_open = !menu_open;
                            }
                            // Check Taskbar Items
                            else if (mouse_y >= FB_H - 44) {
                                if (mouse_x >= 54 && mouse_x <= 194) win_konsole_open = !win_konsole_open;
                                else if (mouse_x >= 200 && mouse_x <= 340) win_sysmon_open = !win_sysmon_open;
                                else if (mouse_x >= 346 && mouse_x <= 486) win_dolphin_open = !win_dolphin_open;
                            }
                            // Check Start Menu Click
                            else if (menu_open && mouse_x >= 8 && mouse_x <= 228 && mouse_y >= FB_H - 264 && mouse_y <= FB_H - 44) {
                                if (mouse_y >= FB_H - 80) syscall1(SYS_exit, 0); // Exit
                                else if (mouse_y <= FB_H - 190) win_konsole_open = 1;
                                else if (mouse_y <= FB_H - 160) win_sysmon_open = 1;
                                else if (mouse_y <= FB_H - 130) win_dolphin_open = 1;
                                menu_open = 0;
                            }
                            // Check Close Buttons & Titlebars for dragging
                            // Konsole
                            else if (win_konsole_open && mouse_x >= term_win_x && mouse_x <= term_win_x + term_win_w && mouse_y >= term_win_y && mouse_y <= term_win_y + 32) {
                                if (mouse_x >= term_win_x + term_win_w - 28) {
                                    win_konsole_open = 0;
                                } else {
                                    dragging_win = 1;
                                    drag_off_x = mouse_x - term_win_x;
                                    drag_off_y = mouse_y - term_win_y;
                                }
                            }
                            // Sysmon
                            else if (win_sysmon_open && mouse_x >= sysmon_win_x && mouse_x <= sysmon_win_x + sysmon_win_w && mouse_y >= sysmon_win_y && mouse_y <= sysmon_win_y + 32) {
                                if (mouse_x >= sysmon_win_x + sysmon_win_w - 28) {
                                    win_sysmon_open = 0;
                                } else {
                                    dragging_win = 2;
                                    drag_off_x = mouse_x - sysmon_win_x;
                                    drag_off_y = mouse_y - sysmon_win_y;
                                }
                            }
                            // Dolphin
                            else if (win_dolphin_open && mouse_x >= dolphin_win_x && mouse_x <= dolphin_win_x + dolphin_win_w && mouse_y >= dolphin_win_y && mouse_y <= dolphin_win_y + 32) {
                                if (mouse_x >= dolphin_win_x + dolphin_win_w - 28) {
                                    win_dolphin_open = 0;
                                } else {
                                    dragging_win = 3;
                                    drag_off_x = mouse_x - dolphin_win_x;
                                    drag_off_y = mouse_y - dolphin_win_y;
                                }
                            }
                        } else if (mev.value == 0) { // Mouse Up / Release
                            dragging_win = 0;
                        }
                    }
                }
            }
        }

        // Process Keyboard Input
        if (kbd_fd >= 0) {
            struct input_event kev;
            while (syscall3(SYS_read, kbd_fd, (long)&kev, sizeof(kev)) == (long)sizeof(kev)) {
                if (kev.type == 1) { // EV_KEY
                    if (kev.code == 42 || kev.code == 54) { // LShift / RShift
                        shift_down = (kev.value != 0);
                        continue;
                    }
                    if (kev.value == 1) { // Key Press
                        if (kev.code == 1) { // ESC: exit
                            syscall1(SYS_exit, 0);
                        } else if (kev.code == 59) { // F1: toggle menu
                            menu_open = !menu_open;
                        } else if (kev.code < 128) {
                            char ch = shift_down ? key_table_shift[kev.code] : key_table[kev.code];
                            if (ch == '\n' || ch == '\r') {
                                term_putc('\n');
                                cmd_buf[cmd_idx] = '\0';
                                term_exec(cmd_buf);
                                cmd_idx = 0;
                                term_puts("[root@cachyos-live ~]# ");
                            } else if (ch == '\b') {
                                if (cmd_idx > 0) {
                                    cmd_idx--;
                                    term_putc('\b');
                                }
                            } else if (ch >= 32 && ch <= 126) {
                                if (cmd_idx < sizeof(cmd_buf) - 1) {
                                    cmd_buf[cmd_idx++] = ch;
                                    term_putc(ch);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Render Frame
        render_desktop(mouse_x, mouse_y, frame_counter);

        // Frame timing throttle (~60 FPS)
        for (volatile int d = 0; d < 80000; d++) {
            asm volatile ("pause");
        }
    }

    syscall1(SYS_exit, 0);
}
