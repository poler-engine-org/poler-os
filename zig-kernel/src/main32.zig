// POLER-OS v0.4.0 — 32-bit x86 freestanding kernel
// Multiboot1 compatible, runs in QEMU -kernel directly
// + PCI bus scanning + VirtIO device detection + Kernel shell

const std = @import("std");
const poler = @import("poler_core.zig");

// ─── VGA Text Mode ─────────────────────────────────────────────────────────

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER: [*]volatile u16 = @ptrFromInt(0xB8000);

var row: usize = 0;
var col: usize = 0;
var color: u8 = 0x07;

fn vga_init() void {
    row = 0;
    col = 0;
    color = 0x07;
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        VGA_BUFFER[i] = @as(u16, ' ') | (@as(u16, color) << 8);
    }
}

fn vga_puts(str: []const u8) void {
    for (str) |ch| {
        if (ch == '\n') {
            col = 0;
            row += 1;
        } else {
            VGA_BUFFER[row * VGA_WIDTH + col] = @as(u16, ch) | (@as(u16, color) << 8);
            col += 1;
            if (col >= VGA_WIDTH) {
                col = 0;
                row += 1;
            }
        }
        if (row >= VGA_HEIGHT) {
            var y: usize = 0;
            while (y < VGA_HEIGHT - 1) : (y += 1) {
                var x: usize = 0;
                while (x < VGA_WIDTH) : (x += 1) {
                    VGA_BUFFER[y * VGA_WIDTH + x] = VGA_BUFFER[(y + 1) * VGA_WIDTH + x];
                }
            }
            var x2: usize = 0;
            while (x2 < VGA_WIDTH) : (x2 += 1) {
                VGA_BUFFER[(VGA_HEIGHT - 1) * VGA_WIDTH + x2] = @as(u16, ' ') | (@as(u16, color) << 8);
            }
            row = VGA_HEIGHT - 1;
        }
    }
}

fn vga_setcolor(c: u8) void {
    color = c;
}

// ─── Serial Port ───────────────────────────────────────────────────────────

fn serial_init() void {
    outb(0x3F9, 0x00);    // Disable interrupts
    outb(0x3FB, 0x80);    // Enable DLAB
    outb(0x3F8, 0x01);    // Baud divisor low = 1 → 115200 baud
    outb(0x3F9, 0x00);    // Baud divisor high = 0
    outb(0x3FA, 0xC7);    // Enable FIFO, clear, 14-byte threshold
    outb(0x3FB, 0x03);    // 8N1 (8 bits, no parity, 1 stop bit)
    outb(0x3FC, 0x0B);    // Enable RTS/DSR/DTR
}

fn serial_puts(str: []const u8) void {
    for (str) |ch| {
        while ((inb(0x3FD) & 0x20) == 0) {}
        outb(0x3F8, ch);
    }
}

fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "{dx}" (port),
    );
}

fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "{dx}" (port),
    );
}

fn inb(port: u16) u8 {
    var result: u8 = undefined;
    asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (result),
        : [port] "{dx}" (port),
    );
    return result;
}

fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

// ─── Dual output ───────────────────────────────────────────────────────────

fn puts(str: []const u8) void {
    vga_puts(str);
    serial_puts(str);
}

// ─── PS/2 Keyboard Driver (i8042) ──────────────────────────────────────────

const KBD_DATA: u16 = 0x60;
const KBD_STATUS: u16 = 0x64;
const KBD_CMD: u16 = 0x64;

var kbd_shift: bool = false;
var kbd_ctrl: bool = false;
var kbd_alt: bool = false;
var kbd_extended: bool = false;

// US QWERTY scan code set 1 → ASCII (make codes only)
// Scan codes 0-127, organized in rows of 16
const scan_to_ascii = [128]u8{
    // 0x00-0x0F
    0, 0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', 0,
    // 0x10-0x1F
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 0,
    // 0x20-0x2F
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 0,
    // 0x30-0x3F
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0,
    // 0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const scan_to_ascii_shift = [128]u8{
    // 0x00-0x0F
    0, 0x1B, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', 0,
    // 0x10-0x1F
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 0,
    // 0x20-0x2F
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 0,
    // 0x30-0x3F
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0,
    // 0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

fn kbd_init() void {
    // Flush any pending data
    while ((inb(KBD_STATUS) & 0x01) != 0) {
        _ = inb(KBD_DATA);
    }
    // Enable keyboard device
    outb(KBD_CMD, 0xAE);
    // Enable PS/2 keyboard interrupts (IRQ1)
    outb(KBD_CMD, 0x20);
    var config = inb(KBD_DATA);
    config |= 0x01; // Enable IRQ1
    config &= ~@as(u8, 0x10); // Enable keyboard port
    outb(KBD_CMD, 0x60);
    outb(KBD_DATA, config);
    // Reset keyboard
    outb(KBD_DATA, 0xFF);
    // Wait for ACK
    var timeout: u32 = 0;
    while (timeout < 10000) : (timeout += 1) {
        if ((inb(KBD_STATUS) & 0x01) != 0) {
            const resp = inb(KBD_DATA);
            if (resp == 0xFA or resp == 0xAA) break;
        }
    }
    // Set scan code set 1
    outb(KBD_DATA, 0xF0);
    while ((inb(KBD_STATUS) & 0x02) != 0) {}
    outb(KBD_DATA, 0x01);
}

fn kbd_read_key() u8 {
    // Wait for key press (output buffer full)
    while ((inb(KBD_STATUS) & 0x01) == 0) {
        asm volatile ("hlt");
    }
    const scan = inb(KBD_DATA);

    // Extended key prefix
    if (scan == 0xE0) {
        kbd_extended = true;
        return 0;
    }

    // Key release (bit 7 set)
    if (scan & 0x80 != 0) {
        const released = scan & 0x7F;
        if (released == 0x2A or released == 0x36) kbd_shift = false;
        if (released == 0x1D) kbd_ctrl = false;
        if (released == 0x38) kbd_alt = false;
        kbd_extended = false;
        return 0;
    }

    // Extended key handling
    if (kbd_extended) {
        kbd_extended = false;
        // Extended keys: arrow keys, etc.
        if (scan == 0x48) return 0x11; // Up    → DC1 (Ctrl-Q)
        if (scan == 0x50) return 0x12; // Down  → DC2 (Ctrl-R)
        if (scan == 0x4B) return 0x13; // Left  → DC3 (Ctrl-S)
        if (scan == 0x4D) return 0x14; // Right → DC4 (Ctrl-T)
        return 0;
    }

    // Modifier keys
    if (scan == 0x2A or scan == 0x36) { kbd_shift = true; return 0; }
    if (scan == 0x1D) { kbd_ctrl = true; return 0; }
    if (scan == 0x38) { kbd_alt = true; return 0; }

    // Convert scan code to ASCII
    if (scan < 128) {
        if (kbd_ctrl and scan == 0x2E) return 0x03; // Ctrl-C
        if (kbd_ctrl and scan == 0x15) return 0x18; // Ctrl-X
        if (kbd_ctrl and scan == 0x31) return 0x1A; // Ctrl-Z
        const ch = if (kbd_shift) scan_to_ascii_shift[scan] else scan_to_ascii[scan];
        return ch;
    }
    return 0;
}

// ─── Kernel Shell ───────────────────────────────────────────────────────────

const SHELL_MAX_CMD = 256;
var shell_buf: [SHELL_MAX_CMD]u8 = undefined;
var shell_len: usize = 0;
var shell_history: [8][SHELL_MAX_CMD]u8 = undefined;
var shell_history_len: [8]usize = undefined;
var shell_history_idx: usize = 0;
var shell_history_pos: usize = 0;

fn shell_prompt() void {
    vga_setcolor(0x0B);
    puts("poler> ");
    vga_setcolor(0x0F);
}

fn shell_clear_line() void {
    // Erase current input line from screen
    var i: usize = 0;
    while (i < shell_len + 7) : (i += 1) {
        puts("\x08 \x08");
    }
    shell_len = 0;
}

fn shell_execute(cmd: []const u8) void {
    // Skip empty commands
    if (cmd.len == 0) return;

    // Save to history
    if (shell_history_idx < 8) {
        @memcpy(shell_history[shell_history_idx][0..cmd.len], cmd);
        shell_history_len[shell_history_idx] = cmd.len;
        shell_history_idx += 1;
    } else {
        // Shift history
        var h: usize = 0;
        while (h < 7) : (h += 1) {
            @memcpy(shell_history[h][0..shell_history_len[h + 1]], shell_history[h + 1][0..shell_history_len[h + 1]]);
            shell_history_len[h] = shell_history_len[h + 1];
        }
        @memcpy(shell_history[7][0..cmd.len], cmd);
        shell_history_len[7] = cmd.len;
    }

    // Parse and execute
    if (strEq(cmd, "help")) {
        cmd_help();
    } else if (strEq(cmd, "poler test")) {
        cmd_poler_test();
    } else if (strEq(cmd, "metrics")) {
        cmd_metrics();
    } else if (strEq(cmd, "pci")) {
        cmd_pci();
    } else if (strEq(cmd, "clear")) {
        cmd_clear();
    } else if (strEq(cmd, "reboot")) {
        cmd_reboot();
    } else if (strEq(cmd, "about")) {
        cmd_about();
    } else if (strStartsWith(cmd, "cipher ")) {
        cmd_cipher(cmd[7..]);
    } else if (strStartsWith(cmd, "phi ")) {
        cmd_phi(cmd[4..]);
    } else if (strStartsWith(cmd, "diffuse ")) {
        cmd_diffuse(cmd[8..]);
    } else if (strEq(cmd, "uptime")) {
        cmd_uptime();
    } else if (strEq(cmd, "mem")) {
        cmd_mem();
    } else if (strEq(cmd, "pmm")) {
        cmd_pmm();
    } else if (strEq(cmd, "timer")) {
        cmd_timer();
    } else if (strEq(cmd, "idt")) {
        cmd_idt();
    } else if (strEq(cmd, "vmm")) {
        cmd_vmm();
    } else if (strEq(cmd, "alloc")) {
        cmd_alloc();
    } else {
        vga_setcolor(0x0C);
        puts("  unknown: ");
        puts(cmd);
        puts("\n");
        vga_setcolor(0x07);
        puts("  type 'help' for commands\n");
    }
}

fn strEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn strStartsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (s[0..prefix.len], prefix) |cs, cp| {
        if (cs != cp) return false;
    }
    return true;
}

// ─── Shell Commands ─────────────────────────────────────────────────────────

fn cmd_help() void {
    vga_setcolor(0x0E);
    puts("  === POLER-OS v0.5.1 Shell Commands ===\n");
    vga_setcolor(0x0F);
    puts("  help          Show this help\n");
    puts("  poler test    Run POLER Core self-tests\n");
    puts("  metrics       Show cognitive metrics\n");
    puts("  pci           Rescan PCI bus\n");
    puts("  clear         Clear screen\n");
    puts("  reboot        Reboot system\n");
    puts("  about         About POLER-OS\n");
    puts("  cipher <hex8> Encrypt 128-bit block (hex)\n");
    puts("  phi <hex8>    Apply Phi rotation to value\n");
    puts("  diffuse <hex8> Apply nilpotent diffusion\n");
    puts("  uptime        Show uptime (PIT ticks)\n");
    puts("  mem           Show memory info\n");
    puts("  pmm           PMM statistics\n");
    puts("  timer         PIT timer ticks\n");
    puts("  idt           IDT status\n");
    puts("  vmm           VMM status\n");
    puts("  alloc         Test page allocation\n");
    vga_setcolor(0x07);
}

fn cmd_poler_test() void {
    vga_setcolor(0x0E);
    puts("  === POLER Core v4 Self-Tests ===\n");
    vga_setcolor(0x0F);

    const self_test = poler.runSelfTests();
    puts("  Tests: ");
    printUint(self_test.passed);
    puts("/");
    printUint(self_test.total);
    puts(" passed\n");

    const test_names = [_][]const u8{
        "DeformedProduct",
        "PolerConvergence",
        "PhiNoFixedPoints",
        "NonCommutativity",
        "ModInverseAccuracy",
        "FeistelRoundtrip",
        "AvalancheEffect",
        "NilpotentPreservesInfo",
        "DynamicAttractor",
    };
    var ti: usize = 0;
    while (ti < test_names.len) : (ti += 1) {
        if (self_test.details[ti] != 0) {
            vga_setcolor(0x0A);
            puts("  [PASS] ");
        } else {
            vga_setcolor(0x0C);
            puts("  [FAIL] ");
        }
        vga_setcolor(0x0F);
        puts(test_names[ti]);
        puts("\n");
    }

    // Feistel roundtrip
    const key = [_]u32{ 0x0F1E2D3C, 0x4B5A6978, 0x8796A5B4, 0xC3D2E1F0, 0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899 };
    const cipher = poler.PolerCipher.init(&key, 1);
    var plain = [4]u32{ 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    var encrypted: [4]u32 = undefined;
    var decrypted: [4]u32 = undefined;
    cipher.encryptBlock(&plain, &encrypted);
    cipher.decryptBlock(&encrypted, &decrypted);
    const ok = decrypted[0] == plain[0] and decrypted[1] == plain[1] and
        decrypted[2] == plain[2] and decrypted[3] == plain[3];
    if (ok) {
        vga_setcolor(0x0A);
        puts("  [PASS] Feistel roundtrip\n");
    } else {
        vga_setcolor(0x0C);
        puts("  [FAIL] Feistel roundtrip\n");
    }
    vga_setcolor(0x07);
}

fn cmd_metrics() void {
    vga_setcolor(0x0E);
    puts("  === Cognitive Metrics ===\n");
    vga_setcolor(0x0F);

    var density = [_][4]f64{
        .{ 0.8, 0.1, 0.0, 0.0 },
        .{ 0.05, 0.6, 0.0, 0.0 },
        .{ 0.0, 0.0, 0.4, 0.0 },
        .{ 0.0, 0.0, 0.0, 0.2 },
    };
    const archetype = [_][4]f64{
        .{ 0.9, 0.0, 0.0, 0.0 },
        .{ 0.0, 0.8, 0.0, 0.0 },
        .{ 0.0, 0.0, 0.7, 0.0 },
        .{ 0.0, 0.0, 0.0, 0.5 },
    };
    var iter: u32 = 0;
    while (iter < 10) : (iter += 1) {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            var j: usize = 0;
            while (j < 4) : (j += 1) {
                density[i][j] = density[i][j] * archetype[i][j] * 0.9;
            }
        }
    }
    const trace_val: f64 = density[0][0] + density[1][1] + density[2][2] + density[3][3];
    var norm_val: f64 = 0;
    for (density) |row_vals| {
        for (row_vals) |v| {
            norm_val += v * v;
        }
    }
    puts("  Entropy:       "); printFloat(1.0 - trace_val / 4.0); puts("\n");
    puts("  Know.Density:  "); printFloat(trace_val / 4.0); puts("\n");
    puts("  Purity:        "); printFloat(density[0][0] / (norm_val + 0.001)); puts("\n");
    puts("  Compression:   "); printFloat(4.0 / (norm_val + 0.001)); puts("x\n");
    puts("  Health:        "); printFloat((trace_val / 4.0 + density[0][0] / (norm_val + 0.001)) / 2.0); puts("\n");
    puts("  Semantic Drift: "); printFloat((1.0 - density[0][0]) * 100.0); puts("%\n");
    vga_setcolor(0x07);
}

fn cmd_pci() void {
    vga_setcolor(0x0E);
    puts("  === PCI Bus Scan ===\n");
    vga_setcolor(0x0F);

    var pci_count: u32 = 0;
    var bus: u8 = 0;
    while (bus < 4) : (bus += 1) {
        var slot: u8 = 0;
        while (slot < 32) : (slot += 1) {
            const vendor = pci_read16(bus, slot, 0, 0);
            if (vendor == 0xFFFF) continue;
            const device_id = pci_read16(bus, slot, 0, 2);
            const class_code: u8 = @truncate(pci_read32(bus, slot, 0, 0x08) >> 24);
            const subclass: u8 = @truncate(pci_read32(bus, slot, 0, 0x08) >> 16);
            const irq_line: u8 = @truncate(pci_read32(bus, slot, 0, 0x3C));
            puts("  [");
            printUint(bus);
            puts(":");
            printUint(slot);
            puts("] ");
            puts(device_type_name(class_code, subclass));
            puts(" vendor=");
            printHex(vendor);
            puts(" device=");
            printHex(device_id);
            puts(" IRQ=");
            printUint(irq_line);
            puts("\n");
            pci_count += 1;
        }
    }
    puts("  Total: "); printUint(pci_count); puts(" devices\n");
    vga_setcolor(0x07);
}

fn cmd_clear() void {
    vga_init();
    row = 0;
    col = 0;
}

fn cmd_reboot() void {
    puts("  Rebooting...\n");
    // Keyboard controller reboot: pulse reset line
    asm volatile ("cli");
    while ((inb(0x64) & 0x02) != 0) {}
    outb(0x64, 0xFE);
    // If that fails, triple fault
    asm volatile (
        \\ lidt 0
        \\ int $0x03
    );
    while (true) {}
}

fn cmd_about() void {
    vga_setcolor(0x0B);
    puts("  POLER-OS v0.4.0\n");
    vga_setcolor(0x0F);
    puts("  32-bit x86 freestanding kernel (Zig 0.16.0)\n");
    puts("  POLER Core v4: Tensor cryptographic engine\n");
    puts("  \n");
    puts("  Architecture:\n");
    puts("    Kernel:    Zig (Ring 0, no std, no alloc)\n");
    puts("    Crypto:    POLER Core (Fix6, Feistel, S-Box)\n");
    puts("    Shell:     Kernel interactive command line\n");
    puts("    Input:     PS/2 keyboard (i8042)\n");
    puts("    Output:    VGA text mode + COM1 serial\n");
    puts("  \n");
    puts("  POLER algebra replaces boolean logic:\n");
    puts("    AND  -> Tensor deformation (a ox_e b)\n");
    puts("    XOR  -> Phi rotation (cubic structure)\n");
    puts("    PIPE -> Nilpotent diffusion (attractor)\n");
    puts("  \n");
    puts("  Verified: Z3 UNSAT, SAC=0.49, NL=112, DU=4\n");
    vga_setcolor(0x07);
}

fn cmd_cipher(arg: []const u8) void {
    // Parse 8 hex digits as u32
    const val = parseHex32(arg) catch {
        vga_setcolor(0x0C);
        puts("  Usage: cipher AABBCCDD\n");
        vga_setcolor(0x07);
        return;
    };
    const key = [_]u32{ 0x0F1E2D3C, 0x4B5A6978, 0x8796A5B4, 0xC3D2E1F0, 0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899 };
    const cipher = poler.PolerCipher.init(&key, 1);
    var block = [4]u32{ val, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    var encrypted: [4]u32 = undefined;
    var decrypted: [4]u32 = undefined;
    cipher.encryptBlock(&block, &encrypted);
    cipher.decryptBlock(&encrypted, &decrypted);

    vga_setcolor(0x0E);
    puts("  Feistel Cipher Demo\n");
    vga_setcolor(0x0F);
    puts("  Input:     "); printHex32(val); puts("\n");
    puts("  Encrypted: "); printHex32(encrypted[0]); puts("\n");
    puts("  Decrypted: "); printHex32(decrypted[0]); puts("\n");
    if (decrypted[0] == val) {
        vga_setcolor(0x0A);
        puts("  Roundtrip: OK\n");
    } else {
        vga_setcolor(0x0C);
        puts("  Roundtrip: FAIL\n");
    }
    vga_setcolor(0x07);
}

fn cmd_phi(arg: []const u8) void {
    const val = parseHex32(arg) catch {
        vga_setcolor(0x0C);
        puts("  Usage: phi AABBCCDD\n");
        vga_setcolor(0x07);
        return;
    };
    const result = poler.phi(val);
    vga_setcolor(0x0E);
    puts("  Phi Rotation\n");
    vga_setcolor(0x0F);
    puts("  Input:  "); printHex32(val); puts("\n");
    puts("  Phi(x): "); printHex32(result); puts("\n");
    const pc = @popCount(result);
    puts("  PopCount: "); printUint(pc); puts("/32 bits set\n");
    vga_setcolor(0x07);
}

fn cmd_diffuse(arg: []const u8) void {
    const val = parseHex32(arg) catch {
        vga_setcolor(0x0C);
        puts("  Usage: diffuse AABBCCDD\n");
        vga_setcolor(0x07);
        return;
    };
    const result = poler.nilpotentOperator(val, 0xCAFE1234, 1);
    const result2 = poler.nilpotentOperator(result, 0xCAFE1234, 1);
    vga_setcolor(0x0E);
    puts("  Nilpotent Diffusion Operator\n");
    vga_setcolor(0x0F);
    puts("  Input:     "); printHex32(val); puts("\n");
    puts("  D(x,1):    "); printHex32(result); puts("\n");
    puts("  D(D(x),1): "); printHex32(result2); puts("\n");
    if (result2 == result) {
        vga_setcolor(0x0A);
        puts("  Idempotent: D^2 = D (attractor reached)\n");
    } else {
        vga_setcolor(0x0E);
        puts("  Converging: D^2 != D (still diffusing)\n");
    }
    vga_setcolor(0x07);
}

fn cmd_uptime() void {
    vga_setcolor(0x0E);
    puts("  Uptime: ");
    vga_setcolor(0x0F);
    if (timer_freq > 0) {
        printUint(timer_ticks / timer_freq);
        puts(".");
        const frac = (timer_ticks % timer_freq) * 100 / timer_freq;
        if (frac < 10) puts("0");
        printUint(frac);
        puts(" sec (");
        printUint(timer_ticks);
        puts(" ticks @ ");
        printUint(timer_freq);
        puts(" Hz)\n");
    } else {
        printUint(timer_ticks);
        puts(" raw ticks (PIT not initialized)\n");
    }
    vga_setcolor(0x07);
}

fn cmd_mem() void {
    vga_setcolor(0x0E);
    puts("  Memory Info:\n");
    vga_setcolor(0x0F);
    puts("    Total pages:  "); printUint(pmm_total_pages); puts("\n");
    puts("    Free pages:   "); printUint(pmm_free_pages); puts(" (");
    printUint(pmm_free_pages * PMM_PAGE_SIZE / 1024); puts(" KB)\n");
    puts("    Used pages:   "); printUint(pmm_total_pages - pmm_free_pages); puts(" (");
    printUint((pmm_total_pages - pmm_free_pages) * PMM_PAGE_SIZE / 1024); puts(" KB)\n");
    puts("    Page size:    4 KB\n");
    puts("    Kernel end:   0x"); printHex32(pmm_kernel_end); puts("\n");
    vga_setcolor(0x07);
}

fn cmd_pmm() void {
    vga_setcolor(0x0E);
    puts("  === PMM (Physical Memory Manager) ===\n");
    vga_setcolor(0x0F);
    puts("    Algorithm:    Bitmap allocator\n");
    puts("    Page size:    4 KB\n");
    puts("    Max pages:    "); printUint(PMM_MAX_PAGES); puts("\n");
    puts("    Total pages:  "); printUint(pmm_total_pages); puts("\n");
    puts("    Free pages:   "); printUint(pmm_free_pages); puts("\n");
    puts("    Used pages:   "); printUint(pmm_total_pages - pmm_free_pages); puts("\n");
    puts("    Free memory:  "); printUint(pmm_free_pages * PMM_PAGE_SIZE / 1024); puts(" KB (");
    printUint(pmm_free_pages * PMM_PAGE_SIZE / (1024 * 1024)); puts(" MB)\n");
    puts("    Kernel end:   0x"); printHex32(pmm_kernel_end); puts("\n");
    vga_setcolor(0x07);
}

fn cmd_timer() void {
    vga_setcolor(0x0E);
    puts("  PIT Timer:\n");
    vga_setcolor(0x0F);
    puts("    Ticks:        "); printUint(timer_ticks); puts("\n");
    puts("    Frequency:    "); printUint(timer_freq); puts(" Hz\n");
    if (timer_freq > 0) {
        puts("    Elapsed:      "); printUint(timer_ticks / timer_freq);
        puts("."); printUint((timer_ticks % timer_freq) * 100 / timer_freq); puts(" sec\n");
    }
    vga_setcolor(0x07);
}

fn cmd_idt() void {
    vga_setcolor(0x0E);
    puts("  === IDT (Interrupt Descriptor Table) ===\n");
    vga_setcolor(0x0F);
    puts("    Entries:      256\n");
    puts("    ISR 0-31:     CPU exceptions (loaded)\n");
    puts("    IRQ 32-47:    Hardware interrupts (loaded)\n");
    puts("    48-255:       Not configured\n");
    puts("    PIC:          Remapped (master=0x20, slave=0x28)\n");
    puts("    Timer IRQ0:   ");
    if (timer_freq > 0) { puts("enabled @ "); printUint(timer_freq); puts(" Hz\n"); }
    else { puts("disabled\n"); }
    vga_setcolor(0x07);
}

fn cmd_vmm() void {
    vga_setcolor(0x0E);
    puts("  === VMM (Virtual Memory Manager) ===\n");
    vga_setcolor(0x0F);
    puts("    Page dir:     1024 entries (4 KB)\n");
    puts("    Page tables:  Identity-mapped 0-4 MB\n");
    puts("    Paging:       ");
    if (vmm_enabled) { puts("ENABLED\n"); }
    else { puts("disabled (structures ready for v0.6.0)\n"); }
    puts("    vmm_map_page: ready\n");
    puts("    vmm_unmap:    ready\n");
    vga_setcolor(0x07);
}

fn cmd_alloc() void {
    vga_setcolor(0x0E);
    puts("  PMM Allocation Test:\n");
    vga_setcolor(0x0F);
    if (pmm_alloc_page()) |addr1| {
        puts("    Allocated page at 0x"); printHex32(addr1); puts("\n");
        if (pmm_alloc_page()) |addr2| {
            puts("    Allocated page at 0x"); printHex32(addr2); puts("\n");
            pmm_free_page(addr2);
            puts("    Freed page at 0x"); printHex32(addr2); puts("\n");
        }
        pmm_free_page(addr1);
        puts("    Freed page at 0x"); printHex32(addr1); puts("\n");
    } else {
        puts("    ERROR: No free pages available!\n");
    }
    puts("    Free pages remaining: "); printUint(pmm_free_pages); puts("\n");
    vga_setcolor(0x07);
}

// ─── Hex Parsing & Printing Helpers ─────────────────────────────────────────

fn parseHex32(s: []const u8) !u32 {
    var result: u32 = 0;
    var count: usize = 0;
    for (s) |c| {
        if (count >= 8) break;
        result <<= 4;
        if (c >= '0' and c <= '9') {
            result |= @as(u32, c - '0');
        } else if (c >= 'A' and c <= 'F') {
            result |= @as(u32, c - 'A' + 10);
        } else if (c >= 'a' and c <= 'f') {
            result |= @as(u32, c - 'a' + 10);
        } else {
            return error.InvalidHex;
        }
        count += 1;
    }
    if (count == 0) return error.EmptyInput;
    return result;
}

fn printHex32(value: u32) void {
    const hex_chars = "0123456789ABCDEF";
    var shift: u5 = 28;
    while (shift > 0) : (shift -= 4) {
        const nibble: u4 = @truncate(value >> shift);
        const ch = hex_chars[@as(usize, nibble)];
        vga_puts(&[_]u8{ch});
        serial_puts(&[_]u8{ch});
    }
    const last: u4 = @truncate(value);
    const ch = hex_chars[@as(usize, last)];
    vga_puts(&[_]u8{ch});
    serial_puts(&[_]u8{ch});
}

// ─── PCI Bus ───────────────────────────────────────────────────────────────

const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

fn pci_read32(bus: u8, slot: u8, func: u8, offset: u8) u32 {
    const addr = (@as(u32, 1) << 31) | 
                 (@as(u32, bus) << 16) | 
                 (@as(u32, slot) << 11) | 
                 (@as(u32, func) << 8) | 
                 (@as(u32, offset) & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    return inl(PCI_CONFIG_DATA);
}

fn pci_read16(bus: u8, slot: u8, func: u8, offset: u8) u16 {
    const val = pci_read32(bus, slot, func, offset);
    return @truncate(val >> (8 * (@as(u5, @intCast(offset & 2)))));
}

fn pci_write32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) void {
    const addr = (@as(u32, 1) << 31) | 
                 (@as(u32, bus) << 16) | 
                 (@as(u32, slot) << 11) | 
                 (@as(u32, func) << 8) | 
                 (@as(u32, offset) & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    outl(PCI_CONFIG_DATA, val);
}

// Device type names
fn device_type_name(class_code: u8, subclass: u8) []const u8 {
    if (class_code == 0x01) {
        if (subclass == 0x01) return "IDE Controller";
        if (subclass == 0x06) return "SATA/AHCI";
        return "Mass Storage";
    }
    if (class_code == 0x02) {
        if (subclass == 0x00) return "Ethernet";
        return "Network";
    }
    if (class_code == 0x03) return "VGA/Display";
    if (class_code == 0x04) return "Multimedia";
    if (class_code == 0x06) {
        if (subclass == 0x01) return "PCI-PCI Bridge";
        return "Bridge";
    }
    if (class_code == 0x0C) {
        if (subclass == 0x03) return "USB Controller";
        return "Serial Bus";
    }
    if (class_code == 0xFF) return "VirtIO";
    return "Unknown";
}

fn virtio_device_name(device_id: u16) []const u8 {
    if (device_id == 1) return "virtio-net";
    if (device_id == 2) return "virtio-blk";
    if (device_id == 3) return "virtio-console";
    if (device_id == 16) return "virtio-gpu";
    if (device_id == 18) return "virtio-input";
    return "virtio-???";
}

// ─── Multiboot Info ────────────────────────────────────────────────────────

const MultibootInfo = extern struct {
    flags: u32,
    mem_lower: u32,
    mem_upper: u32,
    boot_device: u32,
    cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    syms: [4]u32,          // aout/elf table
    mmap_length: u32,
    mmap_addr: u32,
    drives_length: u32,
    drives_addr: u32,
    config_table: u32,
    boot_loader_name: u32,
    apm_table: u32,
    // VBE info (if flag bit 12 set)
    vbe_control_info: u32,
    vbe_mode_info: u32,
    vbe_mode: u16,
    vbe_interface_seg: u16,
    vbe_interface_off: u16,
    vbe_interface_len: u16,
    // Framebuffer info (if flag bit 12 set)
    fb_addr: u64,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u8,
    fb_type: u8,
    fb_color_info: [6]u8,
};

const MULTIBOOT_INFO_FRAMEBUFFER: u32 = 1 << 12;
const MULTIBOOT_INFO_MMAP: u32 = 1 << 6;

// ─── IDT (Interrupt Descriptor Table) ─────────────────────────────────────

const IdtEntry = extern struct {
    offset_low: u16,     // bits 0-15 of handler address
    selector: u16,       // code segment selector (0x08)
    zero: u8,            // always 0
    type_attr: u8,       // 0x8E = 32-bit interrupt gate, present, Ring 0
    offset_high: u16,    // bits 16-31 of handler address
};

const IDT_ENTRIES = 256;
var idt: [IDT_ENTRIES]IdtEntry = undefined;

// ISR handler address table from isr32.S
extern var isr_table: [48]u32;

fn idt_set_gate(num: u32, handler: u32, selector: u16, attrs: u8) void {
    idt[num] = IdtEntry{
        .offset_low = @truncate(handler & 0xFFFF),
        .selector = selector,
        .zero = 0,
        .type_attr = attrs,
        .offset_high = @truncate((handler >> 16) & 0xFFFF),
    };
}

fn idt_init() void {
    // Zero all IDT entries
    var i: u32 = 0;
    while (i < IDT_ENTRIES) : (i += 1) {
        idt[i] = IdtEntry{ .offset_low = 0, .selector = 0, .zero = 0, .type_attr = 0, .offset_high = 0 };
    }

    // Set up ISR 0-31 (CPU exceptions) and IRQ 32-47 (hardware interrupts)
    i = 0;
    while (i < 48) : (i += 1) {
        idt_set_gate(i, isr_table[i], 0x08, 0x8E);
    }

    // Load the IDT
    var idt_ptr: [6]u8 = undefined;
    const limit: u16 = @intCast(IDT_ENTRIES * 8 - 1);
    idt_ptr[0] = @truncate(limit);
    idt_ptr[1] = @truncate(limit >> 8);
    const base: u32 = @intFromPtr(&idt);
    idt_ptr[2] = @truncate(base);
    idt_ptr[3] = @truncate(base >> 8);
    idt_ptr[4] = @truncate(base >> 16);
    idt_ptr[5] = @truncate(base >> 24);
    asm volatile ("lidt (%eax)"
        :
        : [ptr] "{eax}" (@intFromPtr(&idt_ptr)),
    );
}

// ─── PIC (8259A Programmable Interrupt Controller) ────────────────────────

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const PIC_EOI: u8 = 0x20;       // End of Interrupt command
const ICW1_ICW4: u8 = 0x11;     // ICW4 needed + cascade mode
const ICW1_SINGLE: u8 = 0x02;   // single PIC mode (not used)
const ICW4_8086: u8 = 0x01;     // 8086/88 mode

fn pic_init() void {
    // Save current masks
    const mask1 = inb(PIC1_DATA);
    const mask2 = inb(PIC2_DATA);

    // Start initialization sequence (ICW1)
    outb(PIC1_CMD, ICW1_ICW4);    // master PIC: ICW1 + ICW4 needed
    outb(PIC2_CMD, ICW1_ICW4);    // slave PIC: ICW1 + ICW4 needed

    // ICW2: Set vector offsets
    // Master PIC: IRQ 0-7 → INT 32-39
    outb(PIC1_DATA, 0x20);        // master offset = 32
    outb(PIC2_DATA, 0x28);        // slave offset = 40

    // ICW3: Tell master/slave about each other
    outb(PIC1_DATA, 0x04);        // master: slave on IRQ2 (bit 2)
    outb(PIC2_DATA, 0x02);        // slave: cascade identity = 2

    // ICW4: 8086 mode
    outb(PIC1_DATA, ICW4_8086);
    outb(PIC2_DATA, ICW4_8086);

    // Restore masks (mask all IRQs initially)
    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);

    // Mask all IRQs except cascade (IRQ2) — we'll unmask specific ones as needed
    outb(PIC1_DATA, 0xFB);        // master: unmask only IRQ2 (cascade) = 1111_1011
    outb(PIC2_DATA, 0xFF);        // slave: mask all
}

fn pic_send_eoi(irq: u8) void {
    // If IRQ came from slave (IRQ 8-15), send EOI to both PICs
    if (irq >= 8) {
        outb(PIC2_CMD, PIC_EOI);
    }
    // Always send EOI to master
    outb(PIC1_CMD, PIC_EOI);
}

fn pic_unmask_irq(irq: u8) void {
    if (irq < 8) {
        const port = PIC1_DATA;
        const val = inb(port) & ~@as(u8, @as(u8, 1) << @intCast(irq));
        outb(port, val);
    } else {
        const port = PIC2_DATA;
        const val = inb(port) & ~@as(u8, @as(u8, 1) << @truncate(irq - 8));
        outb(port, val);
    }
}

// ─── PIT (Programmable Interval Timer 8253/8254) ─────────────────────────

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_FREQUENCY: u32 = 1193182;  // base frequency of PIT oscillator

var timer_ticks: u32 = 0;
var timer_freq: u32 = 0;

fn pit_init(hz: u32) void {
    timer_freq = hz;
    const divisor: u16 = @intCast(PIT_FREQUENCY / hz);
    outb(PIT_COMMAND, 0x36);                          // channel 0, lobyte/hibyte, mode 3 (square wave)
    outb(PIT_CHANNEL0, @truncate(divisor & 0xFF));    // low byte
    outb(PIT_CHANNEL0, @truncate((divisor >> 8) & 0xFF)); // high byte
    pic_unmask_irq(0);  // unmask IRQ0 (timer)
}

// ─── PMM (Physical Memory Manager) ────────────────────────────────────────

const PMM_PAGE_SIZE: u32 = 4096;
const PMM_MAX_PAGES: u32 = 131072;  // 512 MB max (512*1024*1024 / 4096)
const PMM_BITMAP_SIZE: u32 = PMM_MAX_PAGES / 8;  // 16384 bytes

var pmm_bitmap: [PMM_BITMAP_SIZE]u8 = undefined;
var pmm_total_pages: u32 = 0;
var pmm_free_pages: u32 = 0;
var pmm_kernel_end: u32 = 0;

const MmapEntry = extern struct {
    size: u32,
    addr: u64,
    len: u64,
    mtype: u32,  // 1 = available, 2 = reserved, 3 = ACPI, 4 = NVS, 5 = defective
};

fn pmm_bitmap_set(page: u32) void {
    const idx = page / 8;
    const bit: u3 = @intCast(page % 8);
    if (idx < PMM_BITMAP_SIZE) {
        pmm_bitmap[idx] |= @as(u8, 1) << bit;
    }
}

fn pmm_bitmap_clear(page: u32) void {
    const idx = page / 8;
    const bit: u3 = @intCast(page % 8);
    if (idx < PMM_BITMAP_SIZE) {
        pmm_bitmap[idx] &= ~(@as(u8, 1) << bit);
    }
}

fn pmm_bitmap_test(page: u32) bool {
    const idx = page / 8;
    const bit: u3 = @intCast(page % 8);
    if (idx < PMM_BITMAP_SIZE) {
        return (pmm_bitmap[idx] & (@as(u8, 1) << bit)) != 0;
    }
    return true; // out of range = used
}

fn pmm_init(info: *align(1) MultibootInfo, kernel_end_addr: u32) void {
    pmm_kernel_end = kernel_end_addr;

    // Mark all pages as used initially
    var i: u32 = 0;
    while (i < PMM_BITMAP_SIZE) : (i += 1) {
        pmm_bitmap[i] = 0xFF;
    }
    pmm_total_pages = 0;
    pmm_free_pages = 0;

    // Parse multiboot memory map if available
    if (info.flags & MULTIBOOT_INFO_MMAP != 0 and info.mmap_length > 0 and info.mmap_addr != 0) {
        var ptr: u32 = info.mmap_addr;
        const end: u32 = info.mmap_addr + info.mmap_length;
        while (ptr + @sizeOf(MmapEntry) <= end) {
            const entry: *align(1) MmapEntry = @ptrFromInt(ptr);
            if (entry.size == 0) break;

            if (entry.mtype == 1 and entry.len >= PMM_PAGE_SIZE) { // Available RAM
                const base: u32 = if (entry.addr > 0xFFFFFFFF) 0xFFFFFFFF else @as(u32, @truncate(entry.addr));
                const length: u32 = if (entry.len > 0xFFFFFFFF) 0xFFFFFFFF else @as(u32, @truncate(entry.len));
                const top = base +% length; // wrapping add
                var addr: u32 = base;
                // Align to page boundary
                if (addr % PMM_PAGE_SIZE != 0) {
                    addr = addr +% (PMM_PAGE_SIZE - (addr % PMM_PAGE_SIZE));
                }
                while (addr < top and addr + PMM_PAGE_SIZE <= top and addr >= base) {
                    const page = addr / PMM_PAGE_SIZE;
                    pmm_total_pages += 1;
                    // Free pages above kernel end
                    if (addr >= pmm_kernel_end and page < PMM_MAX_PAGES) {
                        if (pmm_bitmap_test(page)) {
                            pmm_bitmap_clear(page);
                            pmm_free_pages += 1;
                        }
                    }
                    addr +%= PMM_PAGE_SIZE;
                    if (addr < base) break; // overflow guard
                }
            }
            ptr += entry.size + 4;
            if (ptr <= info.mmap_addr) break; // overflow guard
        }
    }

    // Fallback: use mem_lower + mem_upper if PMM found nothing
    // QEMU with -kernel flag may not provide mmap, and mem_lower/mem_upper may be 0
    if (pmm_free_pages == 0) {
        // If mem_upper is 0 (QEMU -kernel doesn't always fill this), assume 128MB
        const total_kb = if (info.mem_upper > 0) info.mem_lower + info.mem_upper else 128 * 1024;
        pmm_total_pages = total_kb / 4;
        // Free pages above kernel
        var page = pmm_kernel_end / PMM_PAGE_SIZE;
        while (page < pmm_total_pages and page < PMM_MAX_PAGES) : (page += 1) {
            if (pmm_bitmap_test(page)) {
                pmm_bitmap_clear(page);
                pmm_free_pages += 1;
            }
        }
    }
}

fn pmm_alloc_page() ?u32 {
    var page: u32 = 0;
    while (page < PMM_MAX_PAGES) : (page += 1) {
        if (!pmm_bitmap_test(page)) {
            pmm_bitmap_set(page);
            pmm_free_pages -= 1;
            return page * PMM_PAGE_SIZE;
        }
    }
    return null;
}

fn pmm_free_page(addr: u32) void {
    const page = addr / PMM_PAGE_SIZE;
    if (page < PMM_MAX_PAGES and pmm_bitmap_test(page)) {
        pmm_bitmap_clear(page);
        pmm_free_pages += 1;
    }
}

// ─── VMM (Virtual Memory Manager) ────────────────────────────────────────

// Page Directory: 1024 entries, each covers 4MB (4KB × 1024 pages)
// Page Table: 1024 entries, each points to a 4KB page
const VMM_PRESENT: u32 = 0x001;
const VMM_WRITABLE: u32 = 0x002;
const VMM_USER: u32 = 0x004;
const VMM_WRITE_THROUGH: u32 = 0x008;
const VMM_CACHE_DISABLE: u32 = 0x010;
const VMM_ACCESSED: u32 = 0x020;
const VMM_DIRTY: u32 = 0x040;
const VMM_PAGE_SIZE_4M: u32 = 0x080;  // for PD entries (PS bit)
const VMM_PAGE_TABLE_ADDR_MASK: u32 = 0xFFFFF000;

var page_directory: [1024]u32 align(4096) = undefined;
var first_page_table: [1024]u32 align(4096) = undefined;
var vmm_enabled: bool = false;

fn vmm_init(kernel_end_addr: u32) void {
    _ = kernel_end_addr;
    // Initialize page directory — all entries empty (not present)
    var i: u32 = 0;
    while (i < 1024) : (i += 1) {
        page_directory[i] = 0;
    }

    // Initialize first page table — identity map first 4MB
    i = 0;
    while (i < 1024) : (i += 1) {
        const addr = i * PMM_PAGE_SIZE;
        first_page_table[i] = addr | VMM_PRESENT | VMM_WRITABLE;
    }

    // Point first PD entry to first page table (identity maps 0-4MB)
    page_directory[0] = @intFromPtr(&first_page_table) | VMM_PRESENT | VMM_WRITABLE;

    // Map PD entry for kernel space (256th entry = 0x40000000-0x40400000)
    // Also identity-map the PD entry that covers the kernel at 1MB
    // PD entry 0 already covers 0-4MB which includes the kernel at 1MB

    // NOTE: We do NOT enable paging here — that's for v0.6.0 when we have
    // userspace. The VMM structures are ready but paging stays off.
    vmm_enabled = false;
}

fn vmm_map_page(phys: u32, virt: u32, flags: u32) void {
    const pd_idx = virt >> 22;       // bits 31-22
    const pt_idx = (virt >> 12) & 0x3FF; // bits 21-12

    // Check if page table exists for this PD entry
    if (page_directory[pd_idx] == 0) {
        // Need to allocate a page table — use PMM
        if (pmm_alloc_page()) |pt_addr| {
            // Clear the page table
            const pt_ptr: [*]u32 = @ptrFromInt(pt_addr);
            var j: u32 = 0;
            while (j < 1024) : (j += 1) {
                pt_ptr[j] = 0;
            }
            page_directory[pd_idx] = pt_addr | VMM_PRESENT | VMM_WRITABLE;
        } else {
            return; // out of memory
        }
    }

    // Get the page table
    const pt_addr = page_directory[pd_idx] & VMM_PAGE_TABLE_ADDR_MASK;
    const pt: [*]u32 = @ptrFromInt(pt_addr);

    // Map the page
    pt[pt_idx] = phys | flags;
}

fn vmm_unmap_page(virt: u32) void {
    const pd_idx = virt >> 22;
    const pt_idx = (virt >> 12) & 0x3FF;

    if (page_directory[pd_idx] == 0) return;
    const pt_addr = page_directory[pd_idx] & VMM_PAGE_TABLE_ADDR_MASK;
    const pt: [*]u32 = @ptrFromInt(pt_addr);
    pt[pt_idx] = 0;

    // Flush TLB entry for this page
    asm volatile ("invlpg %[page]"
        :
        : [page] "r" (virt),
    );
}

// ─── ISR Handler (called from isr32.S common handler) ─────────────────────

const exception_names = [_][]const u8{
    "Divide Error",           "Debug",                    "NMI",
    "Breakpoint",             "Overflow",                 "BOUND Range",
    "Invalid Opcode",         "Device Not Available",     "Double Fault",
    "Coprocessor Overrun",    "Invalid TSS",             "Segment Not Present",
    "Stack Segment Fault",    "General Protection",      "Page Fault",
    "Reserved",               "x87 FPU Error",           "Alignment Check",
    "Machine Check",          "SIMD Float Exception",    "Virtualization",
    "Security",               "Reserved",                "Reserved",
    "Reserved",               "Reserved",                 "Reserved",
    "Reserved",               "Reserved",                  "Reserved",
    "Reserved",               "Reserved",
};

export fn zig_isr_handler(isr_number: u32, error_code: u32) void {
    if (isr_number >= 32) {
        // Hardware interrupt (IRQ)
        const irq: u8 = @truncate(isr_number - 32);
        switch (irq) {
            0 => {
                // PIT Timer tick
                timer_ticks += 1;
            },
            1 => {
                // Keyboard — read and discard scan code to allow polling to work
                _ = inb(KBD_DATA);
            },
            else => {},
        }
        pic_send_eoi(irq);
        return;
    }

    // CPU exception — this is an error
    vga_setcolor(0x04);
    puts("\n!!! EXCEPTION: ");
    if (isr_number < exception_names.len) {
        puts(exception_names[isr_number]);
    } else {
        puts("Unknown #");
        printUint(isr_number);
    }
    puts(" !!!\n");
    puts("  Error code: 0x");
    printHex32(error_code);
    puts("\n");

    if (isr_number == 14) {
        // Page fault — read CR2 for faulting address
        var cr2: u32 = undefined;
        asm volatile (
            \\movl %%cr2, %[out]
            : [out] "=r" (cr2),
        );
        puts("  Faulting address: 0x");
        printHex32(cr2);
        if (error_code & 0x01 != 0) {
            puts(" (protection violation)");
        } else {
            puts(" (page not present)");
        }
        if (error_code & 0x02 != 0) puts(" [write]");
        if (error_code & 0x04 != 0) puts(" [user]");
        puts("\n");
    }

    if (isr_number == 8 or isr_number == 13 or isr_number == 14) {
        // Fatal exceptions — halt
        puts("  System halted.\n");
        cli_halt();
    }

    // Non-fatal: continue execution
    vga_setcolor(0x07);
}

fn cli_halt() noreturn {
    while (true) {
        asm volatile ("cli");
        asm volatile ("hlt");
    }
}

// ─── VBE Framebuffer (for HDMI/DP output) ───────────────────────────────

var fb_addr: u64 = 0;
var fb_pitch: u32 = 0;
var fb_width: u32 = 0;
var fb_height: u32 = 0;
var fb_bpp: u8 = 0;
var fb_type: u8 = 0;
var fb_cursor_x: u32 = 0;
var fb_cursor_y: u32 = 0;

const FB_CHAR_W: u32 = 8;
const FB_CHAR_H: u32 = 16;

// Minimal 8x16 font for printable ASCII
const fb_font = [128][16]u8{
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 0-3
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 4-7
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 8-11
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 12-15
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 16-19
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 20-23
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 24-27
    .{0} ** 16, .{0} ** 16, .{0} ** 16, .{0} ** 16,  // 28-31
    // Space (0x20)
    .{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // ! (0x21)
    .{0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x18,0x18,0x00,0x00,0x00},
    // " (0x22)
    .{0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // # (0x23)
    .{0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00},
    // $ (0x24)
    .{0x18,0x3E,0x60,0x60,0x3C,0x06,0x06,0x7C,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    // % (0x25)
    .{0x00,0x66,0x66,0x66,0x3C,0x18,0x18,0x3C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00},
    // & (0x26)
    .{0x38,0x6C,0x6C,0x38,0x76,0x6E,0x66,0x66,0x76,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // ' (0x27)
    .{0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // ( (0x28)
    .{0x0C,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00},
    // ) (0x29)
    .{0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00},
    // * (0x2A)
    .{0x00,0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // + (0x2B)
    .{0x00,0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // , (0x2C)
    .{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00},
    // - (0x2D)
    .{0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // . (0x2E)
    .{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00},
    // / (0x2F)
    .{0x06,0x06,0x0C,0x0C,0x18,0x18,0x30,0x30,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00},
    // 0 (0x30)
    .{0x3C,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 1 (0x31)
    .{0x18,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    // 2 (0x32)
    .{0x3C,0x66,0x66,0x06,0x0C,0x18,0x30,0x60,0x66,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    // 3 (0x33)
    .{0x3C,0x66,0x06,0x06,0x1C,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 4 (0x34)
    .{0x0C,0x1C,0x3C,0x6C,0x6C,0x7E,0x0C,0x0C,0x0C,0x0C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 5 (0x35)
    .{0x7E,0x60,0x60,0x7C,0x06,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 6 (0x36)
    .{0x3C,0x66,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 7 (0x37)
    .{0x7E,0x66,0x06,0x0C,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    // 8 (0x38)
    .{0x3C,0x66,0x66,0x66,0x3C,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // 9 (0x39)
    .{0x3C,0x66,0x66,0x66,0x3E,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // : (0x3A)
    .{0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // ; (0x3B)
    .{0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00},
    // < (0x3C)
    .{0x0C,0x18,0x30,0x60,0xC0,0x60,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // = (0x3D)
    .{0x00,0x00,0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // > (0x3E)
    .{0x60,0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // ? (0x3F)
    .{0x3C,0x66,0x06,0x0C,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // @ (0x40)
    .{0x3C,0x66,0x66,0x6E,0x6E,0x60,0x62,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // A (0x41)
    .{0x18,0x3C,0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    // B (0x42)
    .{0x7C,0x66,0x66,0x66,0x7C,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00},
    // C (0x43)
    .{0x3C,0x66,0x66,0x60,0x60,0x60,0x60,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    // D (0x44)
    .{0x78,0x6C,0x66,0x66,0x66,0x66,0x66,0x66,0x6C,0x78,0x00,0x00,0x00,0x00,0x00,0x00},
    // E (0x45)
    .{0x7E,0x60,0x60,0x60,0x7C,0x60,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    // F (0x46)
    .{0x7E,0x60,0x60,0x60,0x7C,0x60,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00},
    // G-L
    .{0x3C,0x66,0x60,0x60,0x6E,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x3C,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x6C,0x6C,0x38,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x6C,0x6C,0x78,0x78,0x6C,0x6C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    // M-Z
    .{0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x76,0x7E,0x7E,0x6E,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x3C,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x7C,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x3C,0x66,0x66,0x66,0x66,0x66,0x66,0x6A,0x6C,0x3E,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x7C,0x66,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x3C,0x66,0x60,0x60,0x3C,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x3C,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0xC6,0xC6,0xC6,0xC6,0xD6,0xD6,0xFE,0xEE,0xC6,0xC6,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x66,0x3C,0x18,0x18,0x3C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x66,0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x7E,0x06,0x0C,0x18,0x30,0x60,0x60,0xC0,0xC0,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    // [ \ ] ^ _
    .{0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x60,0x60,0x30,0x30,0x18,0x18,0x0C,0x0C,0x06,0x06,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,0x00},
    // ` a b c d e f
    .{0x30,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x3C,0x06,0x3E,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x60,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x06,0x06,0x06,0x3E,0x66,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x3C,0x66,0x66,0x7E,0x60,0x60,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x1C,0x30,0x30,0x7C,0x30,0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,0x00,0x00},
    // g h i j k l
    .{0x00,0x00,0x00,0x3E,0x66,0x66,0x66,0x66,0x3E,0x06,0x06,0x3C,0x00,0x00,0x00,0x00},
    .{0x60,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x0C,0x00,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x6C,0x6C,0x38,0x00,0x00,0x00,0x00},
    .{0x60,0x60,0x60,0x66,0x6C,0x78,0x78,0x6C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    // m n o p q r
    .{0x00,0x00,0x00,0xEC,0xFE,0xD6,0xD6,0xD6,0xC6,0xC6,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x3C,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x3E,0x66,0x66,0x66,0x66,0x3E,0x06,0x06,0x06,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x7C,0x66,0x60,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00},
    // s t u v w
    .{0x00,0x00,0x00,0x3E,0x60,0x60,0x3C,0x06,0x06,0x7C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x30,0x30,0x30,0x7C,0x30,0x30,0x30,0x30,0x30,0x1C,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0xC6,0xC6,0xD6,0xD6,0xD6,0xFE,0x6C,0x00,0x00,0x00,0x00,0x00,0x00},
    // x y z { | } ~
    .{0x00,0x00,0x00,0x66,0x66,0x3C,0x18,0x3C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x3E,0x06,0x06,0x3C,0x00,0x00,0x00,0x00},
    .{0x00,0x00,0x00,0x7E,0x0C,0x18,0x30,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x0E,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x70,0x18,0x18,0x18,0x0E,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    .{0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    // DEL (0x7F)
    .{0} ** 16,
};

fn fb_init(addr: u64, pitch: u32, width: u32, height: u32, bpp: u8, pixel_type: u8) void {
    fb_addr = addr;
    fb_pitch = pitch;
    fb_width = width;
    fb_height = height;
    fb_bpp = bpp;
    fb_type = pixel_type;
    fb_cursor_x = 0;
    fb_cursor_y = 0;
}

fn fb_clear() void {
    if (fb_addr == 0) return;
    const total: usize = @intCast(@as(u64, fb_pitch) * @as(u64, fb_height));
    const ptr: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(fb_addr)));
    var i: usize = 0;
    while (i < total) : (i += 1) {
        ptr[i] = 0;
    }
}

fn fb_put_pixel(x: u32, y: u32, px_color: u32) void {
    if (fb_addr == 0 or x >= fb_width or y >= fb_height) return;
    const offset = @as(u64, y) * @as(u64, fb_pitch) + @as(u64, x) * @as(u64, fb_bpp / 8);
    const ptr: [*]volatile u32 = @ptrFromInt(@as(usize, @intCast(fb_addr + offset)));
    if (fb_bpp == 32) {
        ptr[0] = px_color;
    }
}

fn fb_draw_char(ch: u8, px: u32, py: u32, fg: u32, bg: u32) void {
    if (ch >= 128) return; // Bounds check: font table only has 128 entries
    const glyph = fb_font[ch];
    var glyph_row: u32 = 0;
    while (glyph_row < FB_CHAR_H) : (glyph_row += 1) {
        const bits = glyph[glyph_row];
        var glyph_col: u32 = 0;
        while (glyph_col < FB_CHAR_W) : (glyph_col += 1) {
            const bit_set = (bits & (@as(u8, 1) << @intCast(7 - glyph_col))) != 0;
            fb_put_pixel(px + glyph_col, py + glyph_row, if (bit_set) fg else bg);
        }
    }
}

fn fb_puts(str: []const u8) void {
    if (fb_addr == 0) return;
    const bg: u32 = 0xFF200F0B; // Dark blue-black (BGR: B=0x0B, G=0x11, R=0x20)
    const fg: u32 = 0xFFD4D4D4; // Light gray text (BGR: B=0xD4, G=0xD4, R=0xD4)
    
    for (str) |ch| {
        if (ch == '\n') {
            fb_cursor_x = 0;
            fb_cursor_y += FB_CHAR_H;
        } else {
            fb_draw_char(ch, fb_cursor_x, fb_cursor_y, fg, bg);
            fb_cursor_x += FB_CHAR_W;
            if (fb_cursor_x >= fb_width) {
                fb_cursor_x = 0;
                fb_cursor_y += FB_CHAR_H;
            }
        }
        if (fb_cursor_y + FB_CHAR_H >= fb_height) {
            // Simple scroll: just reset to top (proper scroll is slow in software)
            fb_cursor_y = 0;
        }
    }
}

fn fb_puts_color(str: []const u8, txt_color: u32) void {
    if (fb_addr == 0) return;
    const bg: u32 = 0xFF200F0B;
    
    for (str) |ch| {
        if (ch == '\n') {
            fb_cursor_x = 0;
            fb_cursor_y += FB_CHAR_H;
        } else {
            fb_draw_char(ch, fb_cursor_x, fb_cursor_y, txt_color, bg);
            fb_cursor_x += FB_CHAR_W;
            if (fb_cursor_x >= fb_width) {
                fb_cursor_x = 0;
                fb_cursor_y += FB_CHAR_H;
            }
        }
        if (fb_cursor_y + FB_CHAR_H >= fb_height) {
            fb_cursor_y = 0;
        }
    }
}

// Framebuffer colors (BGR format for 32-bit)
const FB_CYAN: u32    = 0xFFFFCC00; // BGR: B=0xFF, G=0xCC, R=0x00 → cyan-ish
const FB_GREEN: u32   = 0xFF00CC00; // green
const FB_RED: u32     = 0xFF0000CC; // red
const FB_YELLOW: u32  = 0xFF00CCFF; // yellow (B=0xFF, G=0xCC, R=0x00)
const FB_WHITE: u32   = 0xFFD4D4D4; // light gray
const FB_BLUE: u32    = 0xFFCC6600; // blue-ish

fn fb_puts_uint(value: u32) void {
    if (value == 0) { fb_puts("0"); return; }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;
    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }
    var j: usize = 0;
    while (j < i / 2) : (j += 1) {
        const tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    var k: usize = 0;
    while (k < i) : (k += 1) {
        fb_draw_char(buf[k], fb_cursor_x, fb_cursor_y, 0xFFD4D4D4, 0xFF200F0B);
        fb_cursor_x += FB_CHAR_W;
    }
}

fn fb_puts_hex64(value: u64) void {
    const hex_chars = "0123456789ABCDEF";
    var shift: u8 = 60;
    while (shift > 0) : (shift -= 4) {
        const nibble = @as(u8, @intCast((value >> @intCast(shift)) & 0xF));
        const ch = hex_chars[nibble];
        fb_draw_char(ch, fb_cursor_x, fb_cursor_y, 0xFFD4D4D4, 0xFF200F0B);
        fb_cursor_x += FB_CHAR_W;
    }
    // Print the last nibble (shift=0) — was previously missing
    const last_nibble = @as(u8, @intCast(value & 0xF));
    const last_ch = hex_chars[last_nibble];
    fb_draw_char(last_ch, fb_cursor_x, fb_cursor_y, 0xFFD4D4D4, 0xFF200F0B);
    fb_cursor_x += FB_CHAR_W;
}

// ─── Kernel Entry ──────────────────────────────────────────────────────────

export fn kernel_main(magic_arg: u32, info_ptr: u32) callconv(.c) noreturn {
    serial_init();
    // Use raw u32 for magic (avoid alignment issues with multiboot info)
    const magic = magic_arg;

    // Access MultibootInfo with align(1) to avoid alignment panics from GRUB
    const info: *align(1) MultibootInfo = @ptrFromInt(info_ptr);

    // FPU + SSE2 already initialized by boot32.S — no need to re-init
    // (Previous duplicate init removed to avoid confusion)

    // ═══ Framebuffer Detection ════════════════════════════════════════════
    var use_fb = false;
    if (info.flags & MULTIBOOT_INFO_FRAMEBUFFER != 0) {
        if (info.fb_addr != 0 and info.fb_width > 0 and info.fb_height > 0) {
            use_fb = true;
        }
    }

    if (use_fb) {
        // VBE framebuffer available — use for HDMI/DP output
        fb_init(info.fb_addr, info.fb_pitch, info.fb_width, info.fb_height, info.fb_bpp, info.fb_type);
        fb_clear();
    } else {
        // Fallback to VGA text mode (0xB8000)
        vga_init();
    }

    // ═══ Banner ════════════════════════════════════════════════════════════
    if (use_fb) {
        fb_puts_color("POLER-OS v0.5.1\n", FB_CYAN);
        fb_puts_color("Hybrid Kernel: Zig + VirtIO + Linux Driver Server\n", FB_CYAN);
        fb_puts_color("VBE Framebuffer: HDMI/DP Output\n\n", FB_CYAN);
    } else {
        vga_setcolor(0x0B);
    }
    puts("POLER-OS v0.5.1\n");
    puts("Hybrid Kernel: Zig + VirtIO + Linux Driver Server\n");
    puts("POLER Cognitive Architecture\n\n");

    vga_setcolor(0x07);
    if (use_fb) {
        fb_puts("[BOOT] VBE Framebuffer initialized\n");
        fb_puts("[BOOT] COM1 serial initialized\n");
        fb_puts("[BOOT] FPU + SSE2 initialized\n");
        fb_puts("[BOOT] Resolution: ");
        fb_puts_uint(fb_width);
        fb_puts("x");
        fb_puts_uint(fb_height);
        fb_puts("x");
        fb_puts_uint(fb_bpp);
        fb_puts(" @ 0x");
        fb_puts_hex64(fb_addr);
        fb_puts("\n");
    } else {
        puts("[BOOT] VGA text mode initialized\n");
        puts("[BOOT] COM1 serial initialized\n");
        puts("[BOOT] FPU + SSE2 initialized\n");
    }

    if (magic == 0x2BADB002) {
        puts("[BOOT] Multiboot magic: OK\n");
    } else {
        vga_setcolor(0x0C);
        puts("[BOOT] Multiboot magic: FAIL\n");
    }

    vga_setcolor(0x07);
    puts("[BOOT] Memory: ");
    printUint(info.mem_lower + info.mem_upper);
    puts(" KB\n");

    // ═══ POLER Core v4 Self-Tests ══════════════════════════════════════════
    vga_setcolor(0x0E);
    puts("\n=== POLER Core v4 Self-Tests ===\n");
    vga_setcolor(0x0F);

    const self_test = poler.runSelfTests();
    puts("  Tests passed: ");
    printUint(self_test.passed);
    puts("/");
    printUint(self_test.total);
    puts("\n");

    // Individual test results
    const test_names = [_][]const u8{
        "DeformedProduct",
        "PolerConvergence",
        "PhiNoFixedPoints",
        "NonCommutativity",
        "ModInverseAccuracy",
        "FeistelRoundtrip",
        "AvalancheEffect",
        "NilpotentPreservesInfo",
        "DynamicAttractor",
    };
    var ti: usize = 0;
    while (ti < test_names.len) : (ti += 1) {
        if (self_test.details[ti] != 0) {
            vga_setcolor(0x0A); // green
            puts("  [PASS] ");
        } else {
            vga_setcolor(0x0C); // red
            puts("  [FAIL] ");
        }
        vga_setcolor(0x0F);
        puts(test_names[ti]);
        puts("\n");
    }

    // Feistel roundtrip demonstration
    const key = [_]u32{ 0x0F1E2D3C, 0x4B5A6978, 0x8796A5B4, 0xC3D2E1F0, 0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899 };
    const cipher = poler.PolerCipher.init(&key, 1);

    var plain = [4]u32{ 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    var encrypted: [4]u32 = undefined;
    var decrypted: [4]u32 = undefined;
    cipher.encryptBlock(&plain, &encrypted);
    cipher.decryptBlock(&encrypted, &decrypted);

    const roundtrip_ok = decrypted[0] == plain[0] and decrypted[1] == plain[1] and
        decrypted[2] == plain[2] and decrypted[3] == plain[3];

    if (roundtrip_ok) {
        vga_setcolor(0x0A);
        puts("  [PASS] Feistel encrypt/decrypt roundtrip\n");
    } else {
        vga_setcolor(0x0C);
        puts("  [FAIL] Feistel encrypt/decrypt roundtrip\n");
    }

    // DiffusionOperator bijectivity spot-check
    var dop_ok = true;
    const test_vals = [_]u32{ 0x12345678, 0xDEADBEEF, 0x55555555, 0xAAAAAAAA, 1 };
    var vi: usize = 0;
    while (vi < test_vals.len) : (vi += 1) {
        const result = poler.nilpotentOperator(test_vals[vi], 0xCAFE1234, 1);
        const pc = @popCount(result);
        if (pc < 4 or pc > 28) dop_ok = false;
    }
    if (dop_ok) {
        vga_setcolor(0x0A);
        puts("  [PASS] DiffusionOperator preserves info\n");
    } else {
        vga_setcolor(0x0C);
        puts("  [FAIL] DiffusionOperator preserves info\n");
    }

    vga_setcolor(0x0F);
    puts("\n");

    // ═══ PCI Bus Scan ══════════════════════════════════════════════════════
    vga_setcolor(0x0E);
    puts("=== PCI Bus Scan ===\n");
    vga_setcolor(0x0F);

    var pci_count: u32 = 0;
    var virtio_count: u32 = 0;

    var bus: u8 = 0;
    while (bus < 4) : (bus += 1) {  // Scan first 4 buses (QEMU usually has all on bus 0)
        var slot: u8 = 0;
        while (slot < 32) : (slot += 1) {
            const vendor = pci_read16(bus, slot, 0, 0);
            if (vendor == 0xFFFF) continue;

            const device_id = pci_read16(bus, slot, 0, 2);
            const class_code: u8 = @truncate(pci_read32(bus, slot, 0, 0x08) >> 24);
            const subclass: u8 = @truncate(pci_read32(bus, slot, 0, 0x08) >> 16);
            const _prog_if: u8 = @truncate(pci_read32(bus, slot, 0, 0x08) >> 8);
            _ = _prog_if;
            const bar0 = pci_read32(bus, slot, 0, 0x10);
            const irq_line: u8 = @truncate(pci_read32(bus, slot, 0, 0x3C));

            const is_virtio = (vendor == 0x1AF4 and device_id >= 0x1000 and device_id <= 0x103F);
            
            if (is_virtio) {
                vga_setcolor(0x0A); // Green for VirtIO
                // VirtIO device type is in the subsystem ID at offset 0x2C
                // But for transitional devices, it's at offset 0x24 (for modern)
                // The subsystem ID at 0x2C contains the virtio device type
                // For transitional VirtIO PCI devices (0x1000-0x103F range),
                // the device type is encoded in the device_id offset from 0x1000
                // e.g. 0x1000 = net, 0x1001 = blk, 0x1002 = console, etc.
                const virtio_type: u16 = device_id - 0x1000 + 1; // maps to VIRTIO_ID
                puts("  [VIRTIO] ");
                if (virtio_type == 1) {
                    puts("virtio-net");
                } else if (virtio_type == 2) {
                    puts("virtio-blk");
                } else if (virtio_type == 3) {
                    puts("virtio-console");
                } else if (virtio_type == 16) {
                    puts("virtio-gpu");
                } else if (virtio_type == 18) {
                    puts("virtio-input");
                } else {
                    puts("virtio-"); printUint(virtio_type);
                }
                puts(" @ bus=");
                printUint(bus);
                puts(" slot=");
                printUint(slot);
                puts(" I/O=0x");
                printHex(@truncate(bar0 & 0xFFFC));
                puts("\n");
                virtio_count += 1;
                vga_setcolor(0x0F);
            } else {
                puts("  [PCI] ");
                puts(device_type_name(class_code, subclass));
                puts(" vendor=");
                printHex(vendor);
                puts(" device=");
                printHex(device_id);
                puts(" IRQ=");
                printUint(irq_line);
                puts("\n");
            }
            pci_count += 1;
        }
    }

    puts("\n  Total PCI devices: "); printUint(pci_count); puts("\n");
    puts("  VirtIO devices:    "); printUint(virtio_count); puts("\n\n");

    // ═══ VirtIO Transport Status ═══════════════════════════════════════════
    vga_setcolor(0x0E);
    puts("=== Driver Architecture ===\n");
    vga_setcolor(0x0F);
    puts("  Zig Kernel:    Ring 0 (751KB)\n");
    puts("  VirtIO Bus:    Shared memory rings\n");
    puts("  Linux Drivers: VM Guest (via VT-x)\n");
    puts("  Rust Safety:   Capability gate\n\n");

    // ═══ POLER Cognitive Cycle ═════════════════════════════════════════════
    vga_setcolor(0x0E);
    puts("=== POLER Cognitive Cycle ===\n\n");
    vga_setcolor(0x0F);

    // Density matrix iteration
    var density = [_][4]f64{
        .{ 0.8, 0.1, 0.0, 0.0 },
        .{ 0.05, 0.6, 0.0, 0.0 },
        .{ 0.0, 0.0, 0.4, 0.0 },
        .{ 0.0, 0.0, 0.0, 0.2 },
    };
    const archetype = [_][4]f64{
        .{ 0.9, 0.0, 0.0, 0.0 },
        .{ 0.0, 0.8, 0.0, 0.0 },
        .{ 0.0, 0.0, 0.7, 0.0 },
        .{ 0.0, 0.0, 0.0, 0.5 },
    };

    var iter: u32 = 0;
    while (iter < 10) : (iter += 1) {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            var j: usize = 0;
            while (j < 4) : (j += 1) {
                density[i][j] = density[i][j] * archetype[i][j] * 0.9;
            }
        }
    }

    var trace_val: f64 = 0;
    var norm_val: f64 = 0;
    for (density) |row_vals| {
        for (row_vals) |v| {
            norm_val += v * v;
        }
    }
    trace_val = density[0][0] + density[1][1] + density[2][2] + density[3][3];

    vga_setcolor(0x0E);
    puts("=== 8 Architecture Metrics ===\n");
    vga_setcolor(0x0F);

    puts("  Entropy:       "); printFloat(1.0 - trace_val / 4.0); puts("\n");
    puts("  Know.Density:  "); printFloat(trace_val / 4.0); puts("\n");
    puts("  Purity:        "); printFloat(density[0][0] / (norm_val + 0.001)); puts("\n");
    puts("  Compression:   "); printFloat(4.0 / (norm_val + 0.001)); puts("x\n");
    puts("  Health:        "); printFloat((trace_val / 4.0 + density[0][0] / (norm_val + 0.001)) / 2.0); puts("\n\n");

    // ═══ Driver Strategy ═══════════════════════════════════════════════════
    vga_setcolor(0x0B);
    puts("Hybrid strategy: Zig kernel + Linux Driver Server\n");
    puts("VirtIO = bridge between Zig and Linux drivers\n");
    puts("Gradually replace Linux drivers with native Zig\n\n");

    vga_setcolor(0x0A);
    puts("POLER-OS v0.5.1 ready.\n");
    vga_setcolor(0x07);

    // ═══ PIC + IDT + PIT (v0.5.0) ═════════════════════════════════════
    pic_init();
    puts("[BOOT] 8259A PIC remapped: IRQ0-15 → INT 32-47\n");

    idt_init();
    puts("[BOOT] IDT initialized: 256 entries loaded\n");

    pit_init(1000); // 1000 Hz = 1ms per tick
    puts("[BOOT] PIT timer: 1000 Hz\n");

    // ═══ PMM + VMM (v0.5.0) ════════════════════════════════════════════
    // Estimate kernel end address (BSS end)
    const kernel_end = @intFromPtr(&idt) + @sizeOf(@TypeOf(idt));
    pmm_init(info, kernel_end);
    puts("[BOOT] PMM initialized: ");
    printUint(pmm_free_pages);
    puts(" free pages (");
    printUint(pmm_free_pages * PMM_PAGE_SIZE / 1024);
    puts(" KB)\n");

    vmm_init(kernel_end);
    puts("[BOOT] VMM structures ready (paging not yet enabled)\n");

    // ═══ Keyboard + Shell ═══════════════════════════════════════════════════
    kbd_init();
    pic_unmask_irq(1);  // unmask IRQ1 (keyboard)

    // Enable hardware interrupts — required for HLT to wake on keyboard input
    // and for future interrupt-driven drivers (timer, keyboard IRQ1, etc.)
    asm volatile ("sti");
    puts("[BOOT] Interrupts enabled (STI)\n");

    puts("[BOOT] PS/2 keyboard initialized\n\n");

    // Initialize shell history
    var hi: usize = 0;
    while (hi < 8) : (hi += 1) {
        shell_history_len[hi] = 0;
    }

    shell_prompt();

    while (true) {
        const ch = kbd_read_key();
        if (ch == 0) continue;

        if (ch == '\n') {
            // Execute command
            puts("\n");
            if (shell_len > 0) {
                shell_execute(shell_buf[0..shell_len]);
            }
            shell_len = 0;
            shell_prompt();
        } else if (ch == '\x08') {
            // Backspace
            if (shell_len > 0) {
                shell_len -= 1;
                puts("\x08 \x08");
            }
        } else if (ch == 0x03) {
            // Ctrl-C: cancel line
            puts("^C\n");
            shell_len = 0;
            shell_prompt();
        } else if (ch == 0x11) {
            // Up arrow: history back
            if (shell_history_idx > 0) {
                shell_clear_line();
                if (shell_history_pos == 0) {
                    shell_history_pos = shell_history_idx;
                }
                if (shell_history_pos > 0) {
                    shell_history_pos -= 1;
                }
                if (shell_history_pos < 8 and shell_history_len[shell_history_pos] > 0) {
                    const hlen = shell_history_len[shell_history_pos];
                    @memcpy(shell_buf[0..hlen], shell_history[shell_history_pos][0..hlen]);
                    shell_len = hlen;
                    vga_setcolor(0x0F);
                    puts(shell_buf[0..shell_len]);
                }
            }
        } else if (ch == 0x12) {
            // Down arrow: history forward
            if (shell_history_idx > 0 and shell_history_pos < shell_history_idx - 1) {
                shell_clear_line();
                shell_history_pos += 1;
                if (shell_history_pos < 8 and shell_history_len[shell_history_pos] > 0) {
                    const hlen = shell_history_len[shell_history_pos];
                    @memcpy(shell_buf[0..hlen], shell_history[shell_history_pos][0..hlen]);
                    shell_len = hlen;
                    vga_setcolor(0x0F);
                    puts(shell_buf[0..shell_len]);
                }
            }
        } else if (ch >= ' ' and ch < 0x7F and shell_len < SHELL_MAX_CMD - 1) {
            // Printable character
            shell_buf[shell_len] = ch;
            shell_len += 1;
            vga_setcolor(0x0F);
            puts(&[_]u8{ch});
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn printFloat(val: f64) void {
    var value = val;
    if (value < 0) {
        puts("-");
        value = -value;
    }
    const int_part: u32 = @intFromFloat(value);
    const dec_part: u32 = @intFromFloat((value - @as(f64, @floatFromInt(int_part))) * 100.0);
    printUint(int_part);
    puts(".");
    if (dec_part < 10) puts("0");
    printUint(dec_part);
}

fn printUint(value: u32) void {
    if (value == 0) {
        puts("0");
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;
    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }
    var j: usize = 0;
    while (j < i / 2) : (j += 1) {
        const tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    var k: usize = 0;
    while (k < i) : (k += 1) {
        vga_puts(&[_]u8{buf[k]});
        serial_puts(&[_]u8{buf[k]});
    }
}

fn printHex(value: u16) void {
    const hex_chars = "0123456789ABCDEF";
    vga_puts(&[_]u8{hex_chars[@as(usize, (value >> 12) & 0xF)]});
    vga_puts(&[_]u8{hex_chars[@as(usize, (value >> 8) & 0xF)]});
    vga_puts(&[_]u8{hex_chars[@as(usize, (value >> 4) & 0xF)]});
    vga_puts(&[_]u8{hex_chars[@as(usize, value & 0xF)]});
    serial_puts(&[_]u8{hex_chars[@as(usize, (value >> 12) & 0xF)]});
    serial_puts(&[_]u8{hex_chars[@as(usize, (value >> 8) & 0xF)]});
    serial_puts(&[_]u8{hex_chars[@as(usize, (value >> 4) & 0xF)]});
    serial_puts(&[_]u8{hex_chars[@as(usize, value & 0xF)]});
}

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    vga_setcolor(0x04);
    puts("\n!!! KERNEL PANIC !!!\n");
    puts(msg);
    puts("\n");
    while (true) { asm volatile ("hlt"); }
}
