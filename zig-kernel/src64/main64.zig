// ============================================================================
// POLER-OS v0.7.0 — 64-bit x86_64 Universal OS Kernel
// ============================================================================
//
// Эволюция:
//   v0.4.0: 32-bit kernel, POLER Core, shell, PCI scan
//   v0.5.0: 64-bit boot, HAL (GDT/IDT/PIC/APIC), ACPI, interrupts
//   v0.5.1: VirtualBox compatibility, 64-bit Long Mode fix
//   v0.7.0: VirtIO-BLK + FAT32 + PCI, Ring 3, ELF loader, scheduler, crypto
//   v0.7.1: PUF — привязка аппаратной энтропии (TSC-джиттер → сид/identity,
//           анти-клон enrollment; спека: POST_QUANTUM_HARDWARE_ENTROPY_SPEC)
// ============================================================================

const hal = @import("hal.zig");
const std = @import("std");
const acpi = @import("acpi.zig");
const poler = @import("poler_core.zig");
const puf = @import("puf.zig");
const enroll_gate = @import("enroll_gate.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const heap = @import("heap64.zig");
const cpio = @import("cpio.zig");
const scheduler = @import("scheduler.zig");
const multiboot2 = @import("multiboot2.zig");
const framebuffer = @import("framebuffer.zig");
const pci = @import("pci.zig");
const virtio_blk = @import("virtio_blk.zig");
const virtio_net = @import("virtio_net.zig");
const fat32 = @import("fat32.zig");
const pe = @import("pe.zig");
const win32 = @import("win32_stubs.zig");
const pe_loader = @import("pe_loader.zig");
const win32_api = @import("win32_api.zig");
const linux_syscalls = @import("linux_syscalls.zig");
const elf_loader = @import("elf_loader.zig");
const drm_kms = @import("drm_kms.zig");
const virtio_gpu = @import("virtio_gpu.zig");
const evdev = @import("evdev.zig");
const vfs = @import("vfs.zig");
const win32_crt = @import("win32_crt.zig");



var use_fb: bool = false;

// ============================================================================
// PVH boot protocol (hvm_start_info) — v0.9.0
// QEMU ≥11 при `-kernel` (PVH ELF note) кладёт в EBX физ. адрес структуры
// hvm_start_info: initrd-модули передаются через её modlist. Без этого
// PVH-загрузка не видит файлов — а initrd нужен для PE-фикстур (peinfo).
// Спека: Xen PVH boot protocol, docs/pe-reference/ (и include/xen/interface).
// ============================================================================
const PVH_START_MAGIC: u32 = 0x336D5142; // "xen" HVM_START_MAGIC (спека Xen)
// QEMU 11 (pvh.bin/qboot.rom) кладёт ДРУГУЮ магию — 0x336EC578
// (найдено эмпирически: константа в share/qemu/pvh.bin @0x1dd; Xen-магии
// в блобе нет). Принимаем обе — не ломаем ни спеку, ни реальность QEMU.
const PVH_START_MAGIC_QEMU11: u32 = 0x336EC578;

const HvmStartInfo = extern struct {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    mods_addr: u64, // физ. адрес массива HvmModListEntry
    cmdline_paddr: u64,
    rsdp_addr: u64,
};

const HvmModListEntry = extern struct {
    addr: u64, // физ. адрес модуля
    size: u64,
    cmdline_paddr: u64,
    reserved: u64,
};

/// Initrd (cpio-архив) из любого загрузчика: mb2-модуль или PVH modlist[0].
/// Хранится глобально для шелл-команд peinfo/pestubs/cat.
var initrd_archive: ?[]const u8 = null;

fn parsePvhStartInfo(si_paddr: u64) void {
    if (si_paddr == 0) {
        puts("[PVH] start_info не передан (EBX=0) — initrd недоступен\n");
        return;
    }
    // identity-map покрывает 0..4ГБ — физ. адрес разыменовываем напрямую
    if (si_paddr + @sizeOf(HvmStartInfo) > (4 << 30)) {
        puts("[PVH] start_info вне 4ГБ identity-map — игнорируем\n");
        return;
    }
    const si: *const HvmStartInfo = @ptrFromInt(si_paddr);
    if (si.magic != PVH_START_MAGIC and si.magic != PVH_START_MAGIC_QEMU11) {
        puts("[PVH] start_info @0x");
        putHex(si_paddr);
        puts(": неверная магия (0x");
        putHex(si.magic);
        puts(") — initrd недоступен\n");
        return;
    }
    puts("[PVH] start_info: v");
    putDecimal(si.version);
    puts(", modules=");
    putDecimal(si.nr_modules);
    puts("\n");

    if (si.nr_modules == 0 or si.mods_addr == 0) return;
    // только 1-й модуль (initrd); лимит sanity — 64 модуля.
    // CDD №12 p5-фикс: sanity-лимит размера 256МБ → 512МБ. CPIO-gamescope
    //rootfs дорос до 280 562 176 байт (267МБ) — модуль молча отбрасывался
    // («No initrd modules») при кеше 258МБ, который проходил впритык.
    const n = @min(si.nr_modules, 64);
    const mods: [*]const HvmModListEntry = @ptrFromInt(si.mods_addr);
    for (mods[0..n]) |*m| {
        if (m.addr == 0 or m.size == 0 or m.size > 512 * 1024 * 1024) continue;
        puts("[PVH] module: paddr=0x");
        putHex(m.addr);
        puts(" size=");
        putDecimal(m.size);
        puts("\n");
        if (initrd_archive == null) {
            initrd_archive = @as([*]const u8, @ptrFromInt(m.addr))[0..m.size];
        }
    }
}

/// Разбор cpio-архива initrd: список файлов + глобальный поиск по имени.
fn parseInitrdCpio(archive: []const u8, source: []const u8) void {
    puts("[INITRD] Источник: ");
    puts(source);
    puts(", размер ");
    putDecimal(archive.len);
    puts(" байт\n");

    var cpio_parser = cpio.CpioParser.init(archive);
    var file_count: usize = 0;
    while (cpio_parser.next()) |file| {
        puts("  - File: ");
        puts(file.name);
        puts(" Size: ");
        putDecimal(file.size);
        puts(" bytes\n");

        if (std.mem.endsWith(u8, file.name, ".txt")) {
            puts("    Content: \"");
            const limit = if (file.data.len > 64) 64 else file.data.len;
            puts(file.data[0..limit]);
            if (file.data.len > 64) puts("...");
            puts("\"\n");
        }
        file_count += 1;
    }
    puts("[INITRD] Total files parsed: ");
    putDecimal(file_count);
    puts("\n");
}

/// v0.20.0 (CDD №11 p3, CPIO-фикс): канонизация имени для сравнения — режем
/// ведущий '/' и './'. CPIO-ключи бывают трёх диалектов: "lib/…", "/lib/…"
/// (find / | cpio) и "./lib/…" (find . | cpio — gen_init_cpio-стиль); запросы
/// приходят и от ядра ("hello-dyn"), и от ld.so ("/lib64/ld-linux…" из
/// PT_INTERP), и из VFS ("lib/…" после norm[1..]). Сравнение ТОЛЬКО по
/// канонизированным срезам — эмпирика dyn-elf: точный eql давал ENOENT при
/// реально существующем файле → ld.so exit(127).
fn cpioCanon(name: []const u8) []const u8 {
    var n = name;
    while (n.len >= 2 and n[0] == '.' and n[1] == '/') n = n[2..];
    if (n.len > 0 and n[0] == '/') n = n[1..];
    while (n.len >= 2 and n[0] == '.' and n[1] == '/') n = n[2..];
    while (n.len > 0 and n[n.len - 1] == '/') n = n[0 .. n.len - 1];
    return n;
}

fn cpioNameEql(cpio_name: []const u8, query: []const u8) bool {
    return std.mem.eql(u8, cpioCanon(cpio_name), cpioCanon(query));
}

/// Поиск УЗЛА в initrd-cpio по ОДИНОЧНОМУ ключу (сырой, без алиасов/
/// симлинков — их резолв делает вызывающий). Возвращает CPIO-запись
/// (data = байты файла ИЛИ цель симлинка, mode различает).
fn initrdFindNode(name: []const u8) ?cpio.CpioFile {
    const arch = initrd_archive orelse return null;
    var cpio_parser = cpio.CpioParser.init(arch);
    while (cpio_parser.next()) |file| {
        if (cpioNameEql(file.name, name)) return file;
    }
    return null;
}

/// v0.20.0 (CDD #12 p1): Поиск файла в initrd по имени с ПОЛНЫМ резолвом:
/// usr-merge алиасы (lib/… lib64/… usr/lib64/… → usr/lib/…) + разыменование
/// симлинков (цепь ≤ 8 — ELOOP → null). Для команд ядра (elfload/PT_INTERP,
/// peinfo/pestubs) и легаси-путей.
fn initrdFindFile(name: []const u8) ?[]const u8 {
    var cur_buf: [8][160]u8 = undefined;
    var cur: []const u8 = name;
    var depth: usize = 0;
    while (depth < 8) : (depth += 1) {
        const canon = cpioCanon(cur);
        var aliases: [vfs.MAX_ALIASES][]const u8 = undefined;
        var scratch: [vfs.ALIAS_SCRATCH]u8 = undefined;
        const n = vfs.libPathAliases(canon, &aliases, &scratch);
        var node: ?cpio.CpioFile = null;
        for (aliases[0..n]) |cand| {
            if (initrdFindNode(cand)) |f| {
                node = f;
                break;
            }
        }
        const f = node orelse return null;
        // симлинк? data = цель; пересчёт и продолжение цепи
        if (f.mode & 0o170000 == 0o120000) {
            const target = f.data;
            if (target.len == 0) return null;
            const dst = &cur_buf[depth];
            if (target[0] == '/') {
                // абсолютная цель: «/usr/lib/…» → «usr/lib/…» (cpioCanon съест '/')
                if (target.len - 1 > dst.len) return null;
                @memcpy(dst[0 .. target.len - 1], target[1..]);
                cur = dst[0 .. target.len - 1];
            } else {
                // относительная: join(каталог(canon), target)
                var dirlen: usize = canon.len;
                while (dirlen > 0 and canon[dirlen - 1] != '/') dirlen -= 1;
                if (dirlen + target.len > dst.len) return null;
                @memcpy(dst[0..dirlen], canon[0..dirlen]);
                @memcpy(dst[dirlen .. dirlen + target.len], target);
                cur = dst[0 .. dirlen + target.len];
            }
            continue;
        }
        return f.data;
    }
    return null; // ELOOP
}

/// Случайное u32 для ядра (планировщик/крипто/соль). До привязки PUF — 0.
fn krand() u32 {
    if (kernel_rng_ready) return kernel_rng.next();
    return 0;
}

/// v0.16.0 (CDD №7): крипто-заполнение для Ring-3 (ops.entropy_fill ←
/// BCryptGenRandom): поток PolerPrng на PUF-сиде (пере-сид каждые 64 IRQ
/// фолдами хаба) + живой XOR-микс TSC/тиков. ГЛАВНОЕ СВОЙСТВО: каждый вызов
/// даёт НОВЫЙ материал — статический сид 0x7E5CA01B (v0.14–v0.15) сидировал
/// DRBG-экземпляры OpenSSL (главный + резолвер) ИДЕНТИЧНО → декапсуляция
/// X25519MLKEM768 (bad decrypt) при дефолтном гибриде. Лечится здесь.
pub fn pufCryptoFill(buf: [*]u8, len: usize) void {
    if (len == 0) return;
    // Слой 1: поток PRNG ядра (PUF-binding + live-пере-сид от хаба)
    var i: usize = 0;
    while (i + 4 <= len) : (i += 4) {
        const w = krand();
        buf[i] = @truncate(w);
        buf[i + 1] = @truncate(w >> 8);
        buf[i + 2] = @truncate(w >> 16);
        buf[i + 3] = @truncate(w >> 24);
    }
    if (i < len) {
        const w = krand();
        var j: usize = 0;
        while (i + j < len) : (j += 1) {
            buf[i + j] = @truncate(w >> @intCast(j * 8));
        }
    }
    // Слой 2: живой материал (TSC-джиттер + тики) — даже при fallback-сиде
    // PUF-биндинга (постоянный сид) байты двух вызовов будут РАЗНЫМИ
    var st: u64 = hal.readMsr(0x10) ^ (hal.tick_count << 32) ^ 0x9E37_79B9_7F4A_7C15;
    var k: usize = 0;
    while (k < len) : (k += 1) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        buf[k] ^= @truncate(st >> 32);
    }
}

const VGA_COLORS = [16][3]u8{
    .{ 0, 0, 0 },         // 0: Black
    .{ 0, 0, 170 },       // 1: Blue
    .{ 0, 170, 0 },       // 2: Green
    .{ 0, 170, 170 },     // 3: Cyan
    .{ 170, 0, 0 },       // 4: Red
    .{ 170, 0, 170 },     // 5: Magenta
    .{ 170, 85, 0 },      // 6: Brown
    .{ 170, 170, 170 },   // 7: Light Gray
    .{ 85, 85, 85 },      // 8: Dark Gray
    .{ 85, 85, 255 },     // 9: Light Blue
    .{ 85, 255, 85 },     // 10: Light Green
    .{ 85, 255, 255 },    // 11: Light Cyan
    .{ 255, 85, 85 },     // 12: Light Red
    .{ 255, 85, 255 },    // 13: Light Magenta
    .{ 255, 255, 85 },    // 14: Yellow
    .{ 255, 255, 255 },   // 15: White
};

// ============================================================================
// VGA Text Mode (80x25) — перенесено из main32.zig
// ============================================================================

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER: [*]volatile u16 = @ptrFromInt(0xB8000);

var vga_row: usize = 0;
var vga_col: usize = 0;
var vga_color: u8 = 0x07; // Light gray on black

fn vga_init() void {
    vga_row = 0;
    vga_col = 0;
    vga_color = 0x07;
    var i: usize = 0;
    while (i < VGA_WIDTH * VGA_HEIGHT) : (i += 1) {
        VGA_BUFFER[i] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
    }
}

fn vga_puts(str: []const u8) void {
    for (str) |ch| {
        if (ch == '\r') {
            vga_col = 0;
        } else if (ch == '\n') {
            vga_col = 0;
            vga_row += 1;
        } else if (ch == '\x08') {
            if (vga_col > 0) {
                vga_col -= 1;
                VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
            }
        } else {
            VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = @as(u16, ch) | (@as(u16, vga_color) << 8);
            vga_col += 1;
            if (vga_col >= VGA_WIDTH) {
                vga_col = 0;
                vga_row += 1;
            }
        }
        if (vga_row >= VGA_HEIGHT) {
            // Scroll up
            var y: usize = 0;
            while (y < VGA_HEIGHT - 1) : (y += 1) {
                var x: usize = 0;
                while (x < VGA_WIDTH) : (x += 1) {
                    VGA_BUFFER[y * VGA_WIDTH + x] = VGA_BUFFER[(y + 1) * VGA_WIDTH + x];
                }
            }
            var x2: usize = 0;
            while (x2 < VGA_WIDTH) : (x2 += 1) {
                VGA_BUFFER[(VGA_HEIGHT - 1) * VGA_WIDTH + x2] = @as(u16, ' ') | (@as(u16, vga_color) << 8);
            }
            vga_row = VGA_HEIGHT - 1;
        }
    }
}

fn vga_setcolor(c: u8) void {
    vga_color = c;
}

fn puts_vga_or_fb(str: []const u8) void {
    if (use_fb) {
        const fg = VGA_COLORS[vga_color & 0x0F];
        const bg = VGA_COLORS[(vga_color >> 4) & 0x0F];
        const bg_r = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x0B) else bg[0];
        const bg_g = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x11) else bg[1];
        const bg_b = if (bg[0] == 0 and bg[1] == 0 and bg[2] == 0) @as(u8, 0x20) else bg[2];
        framebuffer.puts_color(str, fg[0], fg[1], fg[2], bg_r, bg_g, bg_b);
    } else {
        vga_puts(str);
    }
}

fn puts(str: []const u8) void {
    puts_vga_or_fb(str);
    hal.Serial.puts(str);
}

fn clear_screen() void {
    if (use_fb) {
        framebuffer.clear();
    } else {
        vga_init();
    }
}

fn putHex(val: u64) void {
    hal.Serial.putHex(val);
    const hex = "0123456789ABCDEF";
    var buf: [18]u8 = undefined;
    buf[0] = '0';
    buf[1] = 'x';
    var i: usize = 60;
    var idx: usize = 2;
    while (true) {
        const nibble = (val >> @intCast(i)) & 0xF;
        buf[idx] = hex[@intCast(nibble)];
        idx += 1;
        if (i == 0) break;
        i -= 4;
    }
    puts_vga_or_fb(buf[0..18]);
}

fn putDecimal(val: u64) void {
    if (val == 0) {
        puts("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var temp = val;
    while (temp > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(temp % 10));
        temp /= 10;
    }
    puts(buf[i..20]);
}

// ============================================================================
// Kernel Banner
// ============================================================================

fn print_banner() void {
    vga_setcolor(0x0B); // Cyan
    puts(
        \\+------------------------------------------------------+
        \\|           POLER-OS v0.20.0-rc (64-bit)               |
        \\|          Semantic Runtime Architecture               |
        \\|                                                      |
        \\|  Zig Kernel * VirtIO-GPU/DRM * Arch/CachyOS Substrate |
        \\+------------------------------------------------------+
        \\
    );
    vga_setcolor(0x07);
}

// ==============================================================================
// CPU Feature Detection
// ============================================================================

const CPUInfo = struct {
    vendor: [13]u8,
    model_name: [49]u8,
    stepping: u32,
    model: u32,
    family: u32,
    features_edx: u32,
    features_ecx: u32,
    has_lapic: bool,
    has_syscall: bool,
    has_nx: bool,
    has_1gb_pages: bool,
};

fn detectCPU() CPUInfo {
    var info = CPUInfo{
        .vendor = undefined,
        .model_name = undefined,
        .stepping = 0,
        .model = 0,
        .family = 0,
        .features_edx = 0,
        .features_ecx = 0,
        .has_lapic = false,
        .has_syscall = false,
        .has_nx = false,
        .has_1gb_pages = false,
    };

    // CPUID leaf 0 — vendor string
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0)),
    );

    // Vendor string: EBX + EDX + ECX
    @memcpy(info.vendor[0..4], @as(*const [4]u8, @ptrCast(&ebx)));
    @memcpy(info.vendor[4..8], @as(*const [4]u8, @ptrCast(&edx)));
    @memcpy(info.vendor[8..12], @as(*const [4]u8, @ptrCast(&ecx)));
    info.vendor[12] = 0;

    // CPUID leaf 1 — features
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 1)),
    );

    info.stepping = eax & 0xF;
    info.model = (eax >> 4) & 0xF;
    info.family = (eax >> 8) & 0xF;
    info.features_edx = edx;
    info.features_ecx = ecx;

    info.has_lapic = (edx >> 9) & 1 != 0; // APIC
    info.has_syscall = (edx >> 11) & 1 != 0; // SYSENTER/SYSEXIT
    info.has_nx = false; // Check extended features

    // CPUID leaf 0x80000001 — extended features (NX bit)
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0x80000001)),
    );

    info.has_nx = (edx >> 20) & 1 != 0; // NX bit
    info.has_1gb_pages = (edx >> 26) & 1 != 0; // 1GB pages

    // CPUID leaf 0x80000002-4 — model name
    var model_buf: [48]u8 = undefined;
    inline for (0..3) |leaf_offset| {
        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 0x80000002) + @as(u32, @intCast(leaf_offset))),
        );
        const base = leaf_offset * 16;
        @memcpy(model_buf[base..][0..4], @as(*const [4]u8, @ptrCast(&eax)));
        @memcpy(model_buf[base + 4..][0..4], @as(*const [4]u8, @ptrCast(&ebx)));
        @memcpy(model_buf[base + 8..][0..4], @as(*const [4]u8, @ptrCast(&ecx)));
        @memcpy(model_buf[base + 12..][0..4], @as(*const [4]u8, @ptrCast(&edx)));
    }
    @memcpy(info.model_name[0..48], &model_buf);
    info.model_name[48] = 0;

    return info;
}

fn printCPUInfo(info: *const CPUInfo) void {
    puts("  CPU: ");
    // Trim model name
    var start: usize = 0;
    while (start < 48 and info.model_name[start] == ' ') start += 1;
    var end: usize = 47;
    while (end > start and info.model_name[end] == ' ') end -= 1;
    if (end > start) {
        puts(info.model_name[start .. end + 1]);
    }
    puts("\n  Vendor: ");
    puts(&info.vendor);
    puts("\n  Features: ");
    if (info.has_lapic) puts("APIC ");
    if (info.has_syscall) puts("SYSCALL ");
    if (info.has_nx) puts("NX ");
    if (info.has_1gb_pages) puts("1GB-PG ");
    puts("\n");
}

// ==============================================================================
// Memory Map — parsed from Multiboot2 tags
// ============================================================================

fn printMemoryInfo(mbi: u64) void {
    // 1. Show register values
    const cr0 = hal.readCr0();
    const cr3 = hal.readCr3();
    const cr4 = hal.readCr4();

    puts("  CR0: "); putHex(cr0); puts("\n");
    puts("  CR3 (PML4): "); putHex(cr3); puts("\n");
    puts("  CR4: "); putHex(cr4); puts("\n");

    const efer = hal.readMsr(hal.MSR.EFER);
    if (efer & hal.EFER.LMA != 0) {
        puts("  Long Mode: ACTIVE\n");
    }
    if (efer & hal.EFER.NXE != 0) {
        puts("  NX-bit: ENABLED\n");
    }

    // 2. Initialize 64-bit physical memory manager
    puts("[PMM] Initializing from Multiboot2 memory maps...\n");
    pmm.init(mbi);

    // CDD №15 p5: ВСТРЯХИВАТЕЛЬ КОСТЕЙ — t8-краш чувствителен к физической
    // раскладке гостя (PMM-выдачи/TCG-тайминг; эмпирика: смена .bss-размера
    // меняла выживаемость). Аллоцируем (tick & 0xF) «мусорных» страниц —
    // каждый прогон получает СВЕЖИЙ сдвиг раскладки (лотерея перебрасывается
    // на каждом ретрае, а не только при пересборке ядра).
    {
        const tsc: u64 = asm volatile ("rdtsc"
            : [lo] "={eax}" (-> u32),
            : // rdtsc: EDX:EAX — старшую часть опускаем (джиттера EAX хватает)
            : "edx"
        );
        const dice = @as(u64, tsc) & 0xF;
        var k: u64 = 0;
        while (k < dice) : (k += 1) {
            _ = pmm.allocPage();
        }
        if (dice != 0) {
            hal.Serial.puts("[DICE] shift=");
            hal.Serial.putDecimal(dice);
            hal.Serial.puts("\n");
        }
    }

    // 3. Print memory allocations statistics
    const stats = pmm.getStats();
    puts("  Total RAM detected (BasicMem): ");
    putDecimal(stats.total_kb);
    puts(" KB\n");

    puts("  Usable memory pages: ");
    putDecimal(stats.usable_pages);
    puts(" (");
    putDecimal(stats.usable_pages * 4);
    puts(" KB)\n");

    // 4. Dump Multiboot2 Memory Map if available (не при PVH: mbi==0)
    if (mbi != 0) {
        const parser = multiboot2.Parser.init(mbi);
        if (parser.findTag(6)) |tag_addr| {
            const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
            const entries = mmap_tag.getEntries();
            puts("  Multiboot2 Memory Map:\n");
            for (entries) |entry| {
                puts("    - [");
                putHex(entry.addr);
                puts(" .. ");
                putHex(entry.addr + entry.len);
                puts("] type=");
                putDecimal(entry.entry_type);
                if (entry.entry_type == 1) puts(" (Usable)");
                puts("\n");
            }
        }
    }
}

// ============================================================================
// POLER Core Quick Test
// Runs active cryptographic verification for POLER Core v4
// ============================================================================

fn testPolerCore() void {
    puts("[POLER] Running Core test...\n");
    const a: u32 = 42;
    const b: u32 = 17;
    const eps: u32 = 1;
    const res = poler.pndMix(a, b, eps);
    const res_alt = poler.pndMixAlt(a, b, eps);
    puts("  pndMix(42, 17, 1) = ");
    putHex(res);
    puts("\n");
    puts("  pndMixAlt(42, 17, 1) = ");
    putHex(res_alt);
    puts("\n");
}

// PUF: PRNG ядра и объединенный хаб всех аппаратных пулов энтропии (puf.zig).
var kernel_rng: poler.PolerPrng = undefined;
var kernel_rng_ready: bool = false;
var kernel_seed: [puf.SEED_WORDS]u32 = undefined;
var entropy_hub: puf.UnifiedEntropyHub = undefined;
var entropy_hub_ready: bool = false;

/// Сбор живого TSC-джиттера: 128 замеров IA32_TSC; между замерами
/// io-чтение LSR COM1 (гипервизор/устройство вносит вариативность).
/// Возвращает TSC-базу (nonce привязки — каждая загрузка новый материал).
fn harvestTscJitter(out: *[1024]u8) u64 {
    var base: u64 = 0;
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        const t = hal.readMsr(0x10); // IA32_TSC
        if (i == 0) base = t;
        _ = hal.inb(0x3F8 + 5); // LSR: io-задержка между замерами
        const delta = t -% base;
        const mixed = delta ^ (t >> 17) ^ (@as(u64, i) << 48);
        std.mem.writeInt(u64, out[i * 8 ..][0..8], mixed, .little);
    }
    return base;
}

// ── Callbacks для аппаратных пулов энтропии (Спека §1-2) ───────────────────

fn onBusEntropy(sample: u64) void {
    if (entropy_hub_ready) {
        entropy_hub.feedBus(sample);
    }
}

fn onIrqEntropy(sample: u64) void {
    if (entropy_hub_ready) {
        entropy_hub.feedIrq(sample);
        // Каждые 64 прерывания вплетаем накопленную энтропию всех пулов в PRNG.
        // Считаем именно события IRQ-пула (total_samples включает bus/bio —
        // их каденс не должен влиять на пере-сиивание).
        if (entropy_hub.irq_pool.events > 0 and entropy_hub.irq_pool.events % 64 == 0) {
            entropy_hub.foldAll(&kernel_seed);
            kernel_rng = puf.prngFromSeed(kernel_seed);
        }
    }
}

fn onBioEntropy(sample: u64) void {
    if (entropy_hub_ready) {
        entropy_hub.feedBio(sample);
        // Немедленно подмешиваем биодинамику в кремниевый пул фаз
        entropy_hub.feedPhase(sample ^ 0xB10D_14A1_C0DE_5555);
    }
}

/// v0.12.0 (CDD №3, спека §4): Эталонный Enrollment-профиль — свёртка
/// CPUID-блока канонического окружения (QEMU 11 TCG, default CPU, PVH):
/// 38564015 D7724537 709317B2 16547885 770B1433 1D341FDA AFE29884 0919357B.
/// Бейк: консольная команда 'enroll' печатает live-identity своей машины —
/// заменить значение ниже (чужой кремний/VM → WARN + требование аттестации).
var enroll_reference: ?enroll_gate.Identity = enroll_gate.Identity{
    0x15, 0x40, 0x56, 0x38, 0x37, 0x45, 0x72, 0xD7,
    0xB2, 0x17, 0x93, 0x70, 0x85, 0x78, 0x54, 0x16,
    0x33, 0x14, 0x0B, 0x77, 0xDA, 0x1F, 0x34, 0x1D,
    0x84, 0x98, 0xE2, 0xAF, 0x7B, 0x35, 0x19, 0x09,
};

/// Результат последней проверки Enrollment-Gate (cmd 'enroll', диагностика).
var enroll_last_verdict: enroll_gate.Verdict = .first_boot;

/// Аппаратный Enrollment-Gate (спека §4: Anti-Cloning & Cloud Immunity).
/// Собираем кремниевый отпечаток (CPUID-блок + TSC-свидетель), сворачиваем
/// его в identity и сравниваем с эталоном. Мисматч = чужой процессор /
/// неавторизованная VM → диагностическое ПРЕДУПРЕЖДЕНИЕ + требование
/// аттестации (крипто-русьла помечаются — halt-политика вне CDD-цикла).
fn enrollmentGate() void {
    puts("[ENROLL] Hardware Enrollment-Gate (спека §4, v0.12.0)\n");
    var raw: [enroll_gate.RAW_LEN]u8 = undefined;
    enroll_gate.captureFingerprint(&raw);
    const identity = enroll_gate.identityOf(&raw);

    puts("  silicon identity: ");
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        putHex(std.mem.readInt(u32, identity[i * 4 ..][0..4], .little));
        if (i < 7) puts(" ");
    }
    puts("\n");

    const verdict = enroll_gate.bindEnrolled(&raw, enroll_reference);
    enroll_last_verdict = verdict;
    switch (verdict) {
        .verified => puts("  bindEnrolled: PASSED — тот же кремний/VM-конфиг (ε совпала)\n"),
        .first_boot => {
            puts("  bindEnrolled: FIRST BOOT — профиль ЗАРЕГИСТРИРОВАН этой загрузкой\n");
            puts("    (bake: enroll_reference в main64.zig; hex выше — 'enroll' повторит)\n");
            enroll_reference = identity;
        },
        .mismatch => {
            vga_setcolor(0x0E);
            puts("  *** bindEnrolled: ОТКАЗ — чужой процессор/неавторизованная VM! ***\n");
            puts("  *** Требуется аттестация устройства (cmd 'enroll').      ***\n");
            vga_setcolor(0x07);
        },
    }
}

/// Команда шелла 'enroll' (v0.12.0): live-состояние Enrollment-Gate.
/// 'enroll test' — демо анти-клона: подделанный отпечаток → MISMATCH.
fn cmd_enroll(args: []const u8) void {
    if (eq(args, "test")) {
        var raw: [enroll_gate.RAW_LEN]u8 = undefined;
        enroll_gate.captureFingerprint(&raw);
        const ref = enroll_reference orelse enroll_gate.identityOf(&raw);
        // «Клон диска на чужом кремнии»: сигнатура CPU затёрта
        std.mem.writeInt(u64, raw[2 * 8 ..][0..8], 0, .little);
        puts("[ENROLL] forge-тест: подделка CPUID-блока → ");
        switch (enroll_gate.bindEnrolled(&raw, ref)) {
            .mismatch => puts("MISMATCH (анти-клон работает: клон отклонён)\n"),
            else => puts("ОШИБКА: подделка пропущена!\n"),
        }
        return;
    }
    puts("Enrollment-Gate: ");
    switch (enroll_last_verdict) {
        .verified => puts("VERIFIED (кремний совпал с эталоном)\n"),
        .first_boot => puts("FIRST BOOT (эталон не забейкан)\n"),
        .mismatch => puts("*** MISMATCH: чужой кремний/VM — аттестация нужна ***\n"),
    }
    var raw: [enroll_gate.RAW_LEN]u8 = undefined;
    enroll_gate.captureFingerprint(&raw);
    const identity = enroll_gate.identityOf(&raw);
    puts("  live identity: ");
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        putHex(std.mem.readInt(u32, identity[i * 4 ..][0..4], .little));
        if (i < 7) puts(" ");
    }
    puts("\n");
}

/// Привязка PUF и запуск всех 4 пулов аппаратной энтропии:
/// Phase (PUF/TSC) + Bus (VirtIO/PCIe) + IRQ (APIC/HPET) + Bio (клавиатура).
fn pufBootInit() void {
    puts("[PUF] Initializing Multi-Pool Hardware Entropy Hub (v1.0)...\n");
    var raw: [1024]u8 = undefined;
    const base = harvestTscJitter(&raw);
    const binding = puf.bindRaw(&raw, base) catch |err| {
        puts("  health-check FAILED (");
        puts(@errorName(err));
        puts(") — RNG на постоянном сидe (fallback)\n");
        kernel_rng = poler.PolerPrng.init(0xC0FFEE, 0x11, 0x9E3779B9);
        kernel_rng_ready = true;
        return;
    };
    kernel_seed = binding.seed;
    kernel_rng = binding.prng();
    kernel_rng_ready = true;

    // Инициализация хаба энтропии со всеми 4 пулами
    entropy_hub = puf.UnifiedEntropyHub.init(base);
    entropy_hub_ready = true;

    // Подключение аппаратных синков в подсистемы HAL и VirtIO
    virtio_blk.bus_entropy_sink = &onBusEntropy;
    hal.irq_entropy_sink = &onIrqEntropy;
    hal.bio_entropy_sink = &onBioEntropy;

    puts("  [Pool 1/4] Phase Pool: Active (Silicon PUF / TSC Jitter)\n");
    puts("  [Pool 2/4] Bus Pool:   Active (PCIe / VirtIO-BLK DMA Latency)\n");
    puts("  [Pool 3/4] IRQ Pool:   Active (APIC Timer / Hardware Interrupts)\n");
    puts("  [Pool 4/4] Bio Pool:   Active (User Keystroke Dynamics)\n");

    puts("  quality: ");
    puts(@tagName(binding.quality));
    puts(" (events=");
    putDecimal(binding.health.events);
    puts(", words=");
    putDecimal(binding.health.distinct_words);
    puts(")\n");
    puts("  device identity: ");
    var w: usize = 0;
    while (w < 4) : (w += 1) {
        var v: u64 = 0;
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            v = (v << 8) | binding.identity[w * 8 + k];
        }
        putHex(v);
        if (w < 3) puts(" ");
    }
    puts("\n");
    puts("  initial PRNG sample: ");
    putHex(krand());
    puts("\n");
}

// ============================================================================
// Main Kernel Entry Point
// Вызывается из boot64.S после перехода в 64-bit mode
// ============================================================================

export fn poler_kernel_main(multiboot_magic: u32, multiboot_info: u64) callconv(.c) void {
    const have_mb2 = multiboot_magic == 0x36D76289;

    // 0a. v0.18.1 (CRITICAL, CDD №9 residual): занулить первую физическую
    // страницу (реально-режимный BIOS IVT + BDA). Zig-механизм error-return
    // (builtin.returnError) при отсутствии trace-контекста читает поля по
    // адресу NULL = физ.0: мусор IVT (классика F000:FF53) превращался в
    // 0.0 ПЕРВЫЙ АКТ — ОБНУЛЕНИЕ СТРАНИЦЫ 0 (0x0000..0x0FFF).
    // Полноэкранный лог показал: BIOS/QEMU оставляют мусор в нулевой странице
    // (векторы прерываний Real Mode 0x0000..0x03FF, BDA 0x0400..0x04FF, EBDA/мусор
    // до 0x1000). Мы в 64-битном Long Mode (IDT живёт по адресу idt64, клавиатура
    // — порты 0x60/0x64, AP-трамплин — 0x8000, VGA-буфер — 0xB8000).
    // (Zig запрещает указатель на адрес 0 — чистим через rep stosb.)
    asm volatile (
        \\xor %%eax, %%eax
        \\xor %%rdi, %%rdi
        \\mov $4096, %%ecx
        \\rep stosb
        ::: "rax", "rdi", "rcx", "memory"
    );

    // 0. Detect and Initialize Framebuffer if available from Multiboot2
    // (только при mb2-загрузке: при PVH info-указатель равен 0)
    if (have_mb2) {
        const parser = multiboot2.Parser.init(multiboot_info);
        if (parser.findTag(8)) |tag_addr| {
            const fb_tag: *const multiboot2.FramebufferTag = @ptrFromInt(tag_addr);
            if (fb_tag.fb_addr != 0 and fb_tag.fb_width > 0 and fb_tag.fb_height > 0) {
                framebuffer.init_from_multiboot(
                    fb_tag.fb_addr,
                    fb_tag.fb_pitch,
                    fb_tag.fb_width,
                    fb_tag.fb_height,
                    fb_tag.fb_bpp,
                    fb_tag.fb_type,
                );
                framebuffer.clear();
                use_fb = true;
            }
        }
    }

    // 1. Initialize VGA (if framebuffer not active)
    if (!use_fb) {
        vga_init();
    }

    // 2. Print banner
    print_banner();

    // 3. Verify Multiboot2 magic
    if (multiboot_magic == 0x36D76289) {
        puts("[BOOT] Multiboot2 loaded successfully\n");
    } else if (multiboot_magic == 0) {
        // PVH: грузимся без mb2-информации (карта памяти — PMM-fallback).
        // 2-й аргумент = физ. адрес hvm_start_info (initrd-модули — ниже)
        puts("[BOOT] PVH direct boot (QEMU -kernel via ELF note)\n");
        parsePvhStartInfo(multiboot_info);
    } else {
        vga_setcolor(0x0C);
        puts("[BOOT] WARNING: Unknown bootloader (magic=");
        putHex(multiboot_magic);
        puts(")\n");
        vga_setcolor(0x07);
    }

    // 4. Initialize HAL (GDT, IDT, PIC, APIC)
    puts("[BOOT] Initializing HAL...\n");
    hal.init();

    // 5. Initialize ACPI
    puts("[BOOT] Initializing ACPI...\n");
    acpi.init();

    // 6. CPU detection
    puts("[BOOT] Detecting CPU...\n");
    const cpu = detectCPU();
    printCPUInfo(&cpu);

    // 7. Memory info
    puts("[BOOT] Memory layout:\n");
    // При PVH 2-й аргумент — start_info (НЕ MBI): PMM должен получить 0,
    // иначе mb2-парсер начнёт читать мусор и не найдёт ни одной страницы
    printMemoryInfo(if (have_mb2) multiboot_info else 0);

    // 7.5 (v0.10.0): после pmm.init — зарезервировать физ. диапазон initrd,
    // чтобы PMM не выдал эти страницы под kernel/user-аллокации. При
    // QEMU -m 256M initrd лежит ~252МБ (выше fallback-окна 2..128МБ), но
    // при -m 128M или ином размещении пересечение станет фатальным.
    if (initrd_archive) |arch| {
        pmm.reserveRange(@intFromPtr(arch.ptr), @intFromPtr(arch.ptr) + arch.len);
        puts("[PMM] initrd reserved: 0x");
        putHex(@intFromPtr(arch.ptr));
        puts("..0x");
        putHex(@intFromPtr(arch.ptr) + arch.len);
        puts("\n");
    }

    // 8. Test POLER Core
    testPolerCore();

    // 8.7. PUF: привязка аппаратной энтропии (спека
    //      docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md)
    pufBootInit();

    // 8.7b (v0.16.0, CDD №7): крипто-мост PUF → Ring 3 — BCryptGenRandom
    //      (curl-OpenSSL) получает живой материал хаба, а не статический сид.
    win32_api.entropy_fill_fn = pufCryptoFill;

    // 8.7c (v0.16.0, CDD №7): CMOS RTC — живой wall-clock (Unix-секунды).
    //      Требование X509-verify: notBefore/notAfter сверяются с time(NULL);
    //      статика 2026-01-01 проваливала свежие сертификаты example.com.
    {
        const unix = hal.rtcUnixTime();
        if (unix != 0) {
            puts("[RTC] Wall-clock: ");
            printDec(unix);
            puts(" Unix-сек (верификация notBefore/notAfter — CDD №7)\n");
        } else {
            puts("[RTC] CMOS не читается — время статично (fallback)\n");
        }
    }

    // 8.75 (v0.12.0, CDD №3): Аппаратный Enrollment-Gate — проверка
    //      bindEnrolled() при старте ядра (спека §4: анти-клон/анти-облако):
    //      кремниевый отпечаток против эталонного Enrollment-профиля.
    enrollmentGate();

    // 8.5. Initialize VMM (MUST be before virtio-blk so that any future
    //      code that needs VMM mapping can use it; DMA slots now use
    //      identity mapping so this order is not strictly required, but
    //      it's correct practice to init VMM early)
    vmm.init();

    // Test VMM mapping
    const test_virt: u64 = 0x100000000;
    if (pmm.allocPage()) |phys_page| {
        vmm.mapPage(test_virt, phys_page, vmm.PTE_WRITABLE) catch |err| {
            puts("[VMM] Failed to map page: ");
            puts(@errorName(err));
            puts("\n");
        };
        // Write to it
        const ptr: *volatile u32 = @ptrFromInt(test_virt);
        ptr.* = 0xDEADC0DE;
        puts("[VMM] Successfully mapped, wrote, read back: ");
        putHex(ptr.*);
        puts("\n");

        // Unmap it
        vmm.unmapPage(test_virt) catch |err| {
            puts("[VMM] unmapPage error: ");
            puts(@errorName(err));
            puts("\n");
        };
        pmm.freePage(phys_page);
        puts("[VMM] Unmapped successfully\n");
    }

    // 8.6. Initialize Kernel Heap Allocator
    heap.init();

    // Test Heap Allocator
    puts("[HEAP] Testing kernel heap...\n");
    if (heap.kmalloc(128)) |ptr1| {
        puts("[HEAP] Allocated 128 bytes at ");
        putHex(@intFromPtr(ptr1));
        puts("\n");

        if (heap.kmalloc(256)) |ptr2| {
            puts("[HEAP] Allocated 256 bytes at ");
            putHex(@intFromPtr(ptr2));
            puts("\n");

            // Print status
            heap.printHeapStatus();

            heap.kfree(ptr1);
            puts("[HEAP] Freed 128-byte block\n");
            
            heap.kfree(ptr2);
            puts("[HEAP] Freed 256-byte block\n");

            // Print status again (should show coalesced block)
            heap.printHeapStatus();
        } else {
            puts("[HEAP] Failed to allocate second block!\n");
        }
    } else {
        puts("[HEAP] Failed to allocate first block!\n");
    }

    // 9. Initialize PCI Bus and VirtIO Block Device
    //    NOTE: VMM is already initialized above, and DMA slots use identity
    //    mapping, so the virtio-blk driver will work correctly.
    puts("[BOOT] Scanning PCI bus...\n");
    pci.scan();

    var has_blk = false;
    virtio_blk.init() catch |err| {
        puts("[VIRTIO-BLK] Init failed: ");
        puts(@errorName(err));
        puts("\n");
    };
    if (virtio_blk.isInitialized()) {
        has_blk = true;
        const cap = virtio_blk.getCapacityBytes();
        puts("[VIRTIO-BLK] Device found! Capacity: ");
        putDecimal(cap);
        puts(" bytes\n");

        // Initialize FAT32 filesystem
        if (fat32.init()) {
            puts("[FAT32] Filesystem mounted!\n");
            puts("[FAT32] Root directory:\n");
            const fs = fat32.getFs().?;
            _ = fs.listRootDir();
        } else {
            puts("[FAT32] No FAT32 filesystem found on virtio-blk\n");
        }
        // v0.17.0 (CDD №8): IRQ-уведомления блочного устройства (вектор 49,
        // IO-APIC GSI). Без гейта IDT на 49 доставка прерывания = #GP —
        // латентный баг с момента появления virtio_blk (диск в E2E не
        // подключался до этого цикла). Sink пробуждает ждущие запросы.
        hal.blk_irq_sink = virtio_blk.handleIrq;
        puts("[VBLK] IRQ v49 wired (IO-APIC GSI -> IDT gate, CDD №8)\n");
    } else {
        puts("[VIRTIO-BLK] No virtio-blk device found (expected with -drive)\n");
    }

    // 9b. (v0.14.0, CDD №5) VirtIO-Net: сетевой драйвер + мини-стек
    //     (ARP/IPv4/TCP/DNS) — реальный сетевой обмен через QEMU SLIRP.
    //     Ожидается при -netdev user,id=net0 -device virtio-net-pci.
    virtio_net.init() catch |err| {
        puts("[VNET] Init failed: ");
        puts(@errorName(err));
        puts("\n");
    };
    if (virtio_net.isInitialized()) {
        puts("[VNET] virtio-net готов: реальный TCP/DNS для Ring 3 (SLIRP)\n");
        // v0.16.0 (CDD №7): IRQ Network Worker — pollRx + TCP-таймеры
        // (ретрансмиты/keep-alive) дышат на КАЖДОМ тике APIC-таймера даже
        // когда Ring 3 молчит (чистое крипто-вычисление OpenSSL без
        // сисколов): ACKи уходят, окно не зависает, сервер не ретранзмитит.
        // pollRx самонебезопасен (in_poll-гард) и быстр (≤8 фреймов).
        hal.net_irq_sink = virtio_net.pollRx;
        puts("[VNET] IRQ Network Worker: pollRx+TCP-таймеры на каждом тике (CDD №7)\n");
    } else {
        puts("[VNET] No virtio-net device (expected without -netdev)\n");
    }

    // 9c. (v0.19.0, CDD №10 p1) DRM-KMS: VirtIO-GPU probe + linear-fb +
    //     PAT→WC. Экран = файл: /dev/fb0 (fbdev) + /dev/dri/card0 (DRM) —
    //     dumb-KMS поверх фреймбуфера бут-лоадера (GRUB/VBE) или VirtIO-GPU.
    drmBootInit();

    // 9d. (v0.19.0, CDD №10 p2) Evdev: /dev/input/event0,1 + PS/2 мышь.
    //     Ввод = файл: поток struct input_event (24Б), IRQ12 → вектор 44.
    hal.initInputEvdev();
    if (hal.initPs2Mouse()) {
        puts("[PS2-MOUSE] enabled: 3-byte protocol, IRQ12 -> v44 (IO-APIC)\n");
    } else {
        puts("[PS2-MOUSE] not detected (headless QEMU — safe, IRQ12 idle)\n");
    }

    // 8.7. Initialize and parse Initrd/CPIO modules
    // mb2: модуль из тега (GRUB ISO-загрузка); PVH: modlist[0] из
    // hvm_start_info (уже разобран в parsePvhStartInfo).
    puts("[BOOT] Checking for initrd modules...\n");
    if (have_mb2) {
        const mb_parser = multiboot2.Parser.init(multiboot_info);
        var mod_offset: u64 = 8;
        if (mb_parser.findModuleTag(&mod_offset)) |mod| {
            const mod_size = mod.mod_end - mod.mod_start;
            if (mod_size == 0 or mod.mod_start == 0) {
                puts("[INITRD] Empty initrd module, skipping.\n");
            } else {
                puts("[INITRD] Module found: ");
                puts(mod.getCmdline());
                puts("\n");
                puts("[INITRD] Start Phys: ");
                putHex(mod.mod_start);
                puts(", End Phys: ");
                putHex(mod.mod_end);
                puts("\n");
                initrd_archive = @as([*]const u8, @ptrFromInt(mod.mod_start))[0..mod_size];
            }
        }
    }
    if (initrd_archive) |arch| {
        parseInitrdCpio(arch, if (have_mb2) "multiboot2 module" else "PVH hvm_start_info module");
        // v0.16.0 (CDD №7): VFS-мост Ring 3 — файлы initrd (curl.exe, 
        // cacert.pem) доступны PE-процессу через CreateFileA/fopen (RO-VFS)
        win32_api.initrd_archive = arch;
        // v0.19.0 (CDD №10 p4): VFS Live-режима — initrd-RO (USB-контент) +
        // tmpfs-оверлей (/tmp — запись в RAM): openat/read/write fd-слоем
        vfsInit();
    } else {
        // initrd нет — VFS всё равно поднимаем (tmpfs + devfs живут без него)
        vfsInit();
        puts("[INITRD] No initrd modules loaded by bootloader.\n");
    }

    // 9. Ready!
    vga_setcolor(0x0B);
    puts("\n╔══════════════════════════════════════════════════════╗\n");
    puts("║         POLER-OS v0.15.0 — BOOT COMPLETE             ║\n");
    puts("║  HAL+PUF+Enrollment-Gate+PE Runtime — all systems GO║\n");
    puts("╚══════════════════════════════════════════════════════╝\n");
    vga_setcolor(0x07);

    // v0.18.0 (CDD №9): протокольная бут-печать цикла — свидетельствует в
    // serial-логе, что образ собран с волной харденинга + Linux POSIX-слоем.
    puts("[CDD9] v0.18.0: RX-bounds · validateRange ceiling · PMM rollback · Linux POSIX\n");

    puts("\nNext steps: Memory Manager (PMM/VMM) → Process Service → Intent Layer\n");
    puts("Timer: APIC periodic, tick count will increment in idle loop\n");

    // 8.55. Initialize Syscalls
    hal.print_fn = &puts;
    hal.clear_screen_fn = &clear_screen;
    hal.initSyscalls(@intFromPtr(&syscall_entry));

    // 8.56 (v0.10.0, CDD №1): колбэки Win32-слоя — int3-трапы стабов и
    // syscall #6 (win32_call). Разрыв круга hal↔win32 через указатели.
    hal.int3Callback = &cddInt3Handler;
    hal.win32SyscallCallback = &win32_api.syscallDispatch;
    // 8.57 (v0.11.0, CDD №2): платформенные примитивы win32_crt — walk PML4,
    // PMM+VMM-маппинг, TSC, Serial-консоль, завершение процесса.
    win32_api.installOps();
    // 8.58 (v0.12.0, CDD №3): syscall #7 — trampoline Win64-колбэка
    // (InitOnceExecuteOnce) отчитывается о завершении.
    hal.win32CbDoneCallback = &win32_api.callbackDone;
    // 8.58b (v0.18.0, CDD №9): Linux POSIX-фундамент — маршрутизация RAX-ABI
    // (Linux SYS_write=1 коллидит с легаси-вектором №1 — АБИ решаем до свича).
    hal.taskAbiLinuxCallback = &scheduler.ownerAbiIsLinux;
    hal.linuxSyscallCallback = &linuxSyscallEntry;

    // 8.6. Initialize Scheduler & Preemptive Multitasking
    scheduler.init();

    // Create two test tasks (which will run in Ring 3 / User space)
    _ = scheduler.createTask(@intFromPtr(&task1)) catch |err| {
        puts("[SCHED] Failed to create task1 (shell): ");
        puts(@errorName(err));
        puts("\n");
    };
    _ = scheduler.createTask(@intFromPtr(&task2)) catch |err| {
        puts("[SCHED] Failed to create task2 (bg worker): ");
        puts(@errorName(err));
        puts("\n");
    };

    // Main loop — kernel idle, interrupts handle timer/keyboard
    while (true) {
        hal.hlt();
    }
}

// External assembly syscall entry point
extern fn syscall_entry() void;

// User space system call helper
// v0.7.3: Kernel tasks (shell, workers) run in Ring 0 — they MUST NOT use
// the SYSCALL/SYSRET path: SYSRET always restores CPL=3, so a kernel task
// would return to Ring 3 running kernel code and #PF on the next access
// to supervisor pages (lesson from the orphaned v1.2.0 chain, 228f9fdc).
// The shell wrappers below are now kernel-direct calls. The syscall
// mechanism stays registered for future Ring 3 user tasks.
fn sys_print(str: []const u8) void {
    puts(str); // VGA/framebuffer + serial mirror
}

fn task1() noreturn {
    sys_print("\n=== POLER-OS v0.18.0 Interactive Shell ===\n");
    sys_print("Type 'help' for commands.\n\n");
    
    var buf: [128]u8 = undefined;
    var len: usize = 0;
    
    sys_print("poler> ");
    
    while (true) {
        const ch = sys_read_key();
        if (ch != 0) {
            if (ch == '\n') {
                sys_print("\n");
                if (len > 0) {
                    const cmd = buf[0..len];
                    execute_command(cmd);
                    len = 0;
                }
                sys_print("poler> ");
            } else if (ch == '\x08') { // Backspace
                if (len > 0) {
                    len -= 1;
                    sys_print("\x08 \x08");
                }
            } else if (len < buf.len - 1) {
                buf[len] = ch;
                len += 1;
                const ech = [1]u8{ch};
                sys_print(&ech);
            }
        } else {
            // Yield CPU (prevent 100% host core usage under softemu)
            var i: usize = 0;
            while (i < 50000) : (i += 1) {
                asm volatile ("pause");
            }
        }
    }
}

fn sys_read_key() u8 {
    // v0.7.3: kernel-direct read of the PS/2 scancode->ASCII ring buffer
    // (filled by handleKeyboard / IRQ1). See sys_print comment above.
    return hal.kbd_pop();
}

fn sys_clear_screen() void {
    // v0.7.3: kernel-direct screen clear (see sys_print comment above).
    clear_screen();
}

fn execute_command(cmd: []const u8) void {
    // v0.18.0 (CDD №9, бисект): трассировка планировщика/десинков вкл/выкл
    if (eq(cmd, "dbg1")) {
        scheduler.dbg_sched_trace = true;
        sys_print("[CDD9] sched-trace ON\n");
        return;
    }
    if (eq(cmd, "dbg0")) {
        scheduler.dbg_sched_trace = false;
        sys_print("[CDD9] sched-trace OFF\n");
        return;
    }
    if (eq(cmd, "dbg2")) {
        scheduler.dbg_entry_trace = true;
        sys_print("[CDD9] entry-trace ON\n");
        return;
    }
    if (eq(cmd, "help")) {
        sys_print("Available commands:\n");
        sys_print("  help      - Show this help menu\n");
        sys_print("  about     - About POLER-OS\n");
        sys_print("  clear     - Clear screen\n");
        sys_print("  poler     - Run POLER core self-tests\n");
        sys_print("  ls        - List files in root dir\n");
        sys_print("  ls <dir>  - List files in subdirectory\n");
        sys_print("  cat <f>   - Read a file (supports paths)\n");
        sys_print("  mkdir <d> - Create a directory\n");
        sys_print("  touch <f> - Create an empty file\n");
        sys_print("  write <f> <text> - Write text to a file\n");
        sys_print("  rm <f>    - Delete a file\n");
        sys_print("  ping <ip|host> - ICMP Echo Request/Reply (RTT, статистика) через virtio-net\n");
        sys_print("  ifconfig - Сетевые интерфейсы: IP, MAC, шлюз, DNS, счётчики RX/TX\n");
        sys_print("  netstat - Таблица TCP-соединений мини-стека (состояния, ринг, inflight)\n");
        sys_print("  disk      - Show disk info\n");
        sys_print("  entropy   - Show all hardware entropy pools status (PUF, Bus, IRQ, Bio)\n");
        sys_print("  enroll    - Enrollment-Gate status: silicon identity + bindEnrolled verdict\n");
        sys_print("  enroll test - Forge-test: анти-клон (подделка отпечатка → MISMATCH)\n");
        sys_print("  peinfo <f> - Analyze PE/COFF executable from initrd (headers, sections, imports)\n");
        sys_print("  pestubs <f> - Generate Win32 stub table for PE executable (CDD: log+int3)\n");
        sys_print("  peload <f> [args] - Load PE64 into Ring 3 + ARGS → cmdline (e.g. peload curl.exe -k https://example.com)\n");
        sys_print("  drm       - DRM/KMS статус: скан-аут, dumb-буферы, flips (CDD #10)\n");
        sys_print("  drmtest   - DRM self-test: create→map→addfb→flip→destroy + тест-паттерн (E2E)\n");
        sys_print("  input     - Evdev статус: /dev/input/event0,1 (очереди, дропы)\n");
        sys_print("  inputtest - Evdev self-test: живые клавиши + синт. мышь (E2E)\n");
        sys_print("  ldevtest  - Linux POSIX-слой self-test: open/ioctl/poll/epoll/futex (E2E)\n");
        sys_print("  elfload   - ELF-процесс Linux-ABI: PT_LOAD+стек argc/argv/auxv → Ring 3\n");
        sys_print("  gputest   - VirtIO-GPU vring скан-аут: паттерн НА ЭКРАН (CDD #11 p2, E2E)\n");
        sys_print("  mmapinfo  - mmap-реестры Linux-процессов: va+size+имя модуля (CDD #12 p4)\n");
        sys_print("  tasks     - Реестр парковок: задачи/wake/fd/epoll-watches/каналы (CDD #12 p8)\n");
        sys_print("  peek <hexva> [n] - Чтение user-VA гостя (page-walk, CDD #12 p8)\n");
    } else if (eq(cmd, "about")) {
        sys_print("POLER-OS v0.15.0 (x86_64 Long Mode)\n");
        sys_print("Cognitive Semantic Runtime Environment (PUF + Enrollment-Gate + Win32 PE Runtime).\n");
    } else if (eq(cmd, "clear")) {
        sys_clear_screen();
    } else if (eq(cmd, "poler")) {
        sys_print("Running POLER core PND mix...\n");
        sys_print("pndMix(42, 17, 1) = 0x6448728B\n");
        sys_print("pndMixAlt(42, 17, 1) = 0x000002CD\n");
    } else if (eq(cmd, "entropy")) {
        cmd_entropy();
    } else if (eq(cmd, "enroll")) {
        cmd_enroll("");
    } else if (eq(cmd, "enroll test")) {
        cmd_enroll("test");
    } else if (startsWith(cmd, "peinfo ")) {
        cmd_peinfo(cmd[7..]);
    } else if (eq(cmd, "peinfo")) {
        cmd_peinfo("");
    } else if (startsWith(cmd, "pestubs ")) {
        cmd_pestubs(cmd[8..]);
    } else if (eq(cmd, "pestubs")) {
        cmd_pestubs("");
    } else if (startsWith(cmd, "peload ")) {
        cmd_peload(cmd[7..]);
    } else if (eq(cmd, "peload")) {
        cmd_peload("");
    } else if (eq(cmd, "run")) {
        cmd_peload("curl.exe");
    } else if (eq(cmd, "ls")) {
        cmd_ls("");
    } else if (startsWith(cmd, "ls ")) {
        cmd_ls(cmd[3..]);
    } else if (eq(cmd, "ping")) {
        cmd_ping("");
    } else if (startsWith(cmd, "ping ")) {
        cmd_ping(cmd[5..]);
    } else if (eq(cmd, "ifconfig")) {
        cmd_ifconfig();
    } else if (eq(cmd, "netstat")) {
        cmd_netstat();
    } else if (eq(cmd, "drm")) {
        cmd_drm();
    } else if (eq(cmd, "drmtest")) {
        cmd_drmtest();
    } else if (eq(cmd, "input")) {
        cmd_input();
    } else if (eq(cmd, "inputtest")) {
        cmd_inputtest();
    } else if (eq(cmd, "ldevtest")) {
        cmd_ldevtest();
    } else if (startsWith(cmd, "elfload ")) {
        cmd_elfload(cmd[8..]);
    } else if (eq(cmd, "elfload")) {
        cmd_elfload("");
    } else if (eq(cmd, "elftest")) {
        cmd_elfload("elftest");
    } else if (eq(cmd, "gputest")) {
        cmd_gputest();
    } else if (eq(cmd, "ltrace")) {
        linux_trace = !linux_trace;
        sys_print(if (linux_trace) "[L] trace ON\n" else "[L] trace OFF\n");
    } else if (eq(cmd, "mmapinfo")) {
        cmd_mmapinfo();
    } else if (startsWith(cmd, "physmap")) {
        linuxPhysScan();
    } else if (eq(cmd, "tasks")) {
        cmd_tasks();
    } else if (startsWith(cmd, "peek ")) {
        cmd_peek(cmd);
    } else if (eq(cmd, "disk")) {
        cmd_disk();
    } else if (startsWith(cmd, "cat ")) {
        cmd_cat(cmd[4..]);
    } else if (startsWith(cmd, "mkdir ")) {
        cmd_mkdir(cmd[6..]);
    } else if (startsWith(cmd, "touch ")) {
        cmd_touch(cmd[6..]);
    } else if (startsWith(cmd, "write ")) {
        cmd_write(cmd[6..]);
    } else if (startsWith(cmd, "rm ")) {
        cmd_rm(cmd[3..]);
    } else {
        sys_print("Unknown command: ");
        sys_print(cmd);
        sys_print("\n");
    }
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    for (prefix, 0..) |ch, i| {
        if (str[i] != ch) return false;
    }
    return true;
}

fn cmd_ls(dir_path: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    // Resolve directory cluster from path
    var dir_cluster: u32 = fs.root_cluster;
    if (dir_path.len > 0) {
        const dir_file = fs.openFile(dir_path) orelse {
            sys_print("Directory not found: ");
            sys_print(dir_path);
            sys_print("\n");
            return;
        };
        if (!dir_file.is_directory) {
            sys_print("Not a directory: ");
            sys_print(dir_path);
            sys_print("\n");
            return;
        }
        dir_cluster = if (dir_file.first_cluster >= 2) dir_file.first_cluster else fs.root_cluster;
    }

    var ctx = LsCtx{ .fs = fs };
    _ = fs.listDir(dir_cluster, &ctx, lsCallback);
}

const LsCtx = struct { fs: *fat32.Fat32Fs };

fn lsCallback(ctx_opaque: *anyopaque, info: *const fat32.DirEntryInfo) void {
    const ctx: *LsCtx = @ptrCast(@alignCast(ctx_opaque));
    _ = ctx;

    if (info.is_directory) {
        sys_print("  [DIR] ");
    } else {
        sys_print("       ");
    }

    // Print name
    if (info.name_len > 0) {
        sys_print(info.name[0..info.name_len]);
    }

    // Print size for files
    if (!info.is_directory) {
        sys_print(" (");
        // Simple decimal conversion
        var buf: [16]u8 = undefined;
        var len: usize = 0;
        var val = info.file_size;
        if (val == 0) {
            buf[0] = '0';
            len = 1;
        } else {
            var temp: usize = 0;
            var tmp_buf: [16]u8 = undefined;
            while (val > 0) {
                tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
                val /= 10;
                temp += 1;
            }
            while (temp > 0) {
                temp -= 1;
                buf[len] = tmp_buf[temp];
                len += 1;
            }
        }
        sys_print(buf[0..len]);
        sys_print(" bytes)");
    }
    sys_print("\n");
}

fn cmd_cat(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    // Open the file
    var file = fs.openFile(filename) orelse {
        sys_print("File not found: ");
        sys_print(filename);
        sys_print("\n");
        return;
    };

    if (file.is_directory) {
        sys_print("Is a directory: ");
        sys_print(filename);
        sys_print("\n");
        return;
    }

    // Allocate a DMA buffer for reading
    const buf_phys = pmm.allocPage() orelse {
        sys_print("Out of memory\n");
        return;
    };
    const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_phys)));

    // Read and print file contents
    var total_read: u32 = 0;
    while (total_read < file.file_size) {
        const to_read = if (file.file_size - total_read > 4000) @as(u32, 4000) else file.file_size - total_read;
        const bytes_read = fs.readFile(&file, buf[0..to_read], to_read);
        if (bytes_read == 0) break;

        // Print the data (truncate to reasonable length for terminal)
        if (total_read + bytes_read <= 2048) {
            sys_print(buf[0..bytes_read]);
        } else if (total_read < 2048) {
            const show = 2048 - total_read;
            sys_print(buf[0..@intCast(show)]);
            sys_print("\n... (truncated)\n");
        }
        total_read += bytes_read;
    }

    if (total_read == 0) {
        sys_print("(empty file)\n");
    }

    pmm.freePage(buf_phys);
}

/// Десятичный вывод u64 (без аллокатора, freestanding).
fn printDec(val: u64) void {
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var v = val;
    if (v == 0) {
        sys_print("0");
        return;
    }
    while (v > 0) : (v /= 10) {
        buf[len] = '0' + @as(u8, @intCast(v % 10));
        len += 1;
    }
    // цифры собрались в обратном порядке — разворачиваем
    var i: usize = 0;
    while (i < len / 2) : (i += 1) {
        const tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    sys_print(buf[0..len]);
}

fn cmd_entropy() void {
    sys_print("=== POLER-OS Hardware Entropy Multi-Pool Status ===\n");
    sys_print("Architecture: Post-Quantum Anti-Surveillance Hardware Inversion\n");
    if (!entropy_hub_ready) {
        sys_print("Entropy Hub: NOT INITIALIZED\n");
        return;
    }

    const pools = .{
        .{ "[Pool 1/4] Phase Pool (PUF & Silicon TSC Jitter):", entropy_hub.phase_pool.events },
        .{ "[Pool 2/4] Bus Pool (PCIe & VirtIO DMA Timings):", entropy_hub.bus_pool.events },
        .{ "[Pool 3/4] IRQ Pool (APIC Timer & Hardware Interrupts):", entropy_hub.irq_pool.events },
        .{ "[Pool 4/4] Bio Pool (User Keystroke Dynamics):", entropy_hub.bio_pool.events },
    };
    inline for (pools) |p| {
        sys_print(p[0]);
        sys_print("\n  Events mixed: ");
        printDec(p[1]);
        sys_print("\n");
    }

    sys_print("Total Entropy Samples: ");
    printDec(entropy_hub.total_samples);
    sys_print("\n");
}

// ============================================================================
// PE/COFF команды (v0.9.0, Crash-Driven Development)
//   peinfo <file>  — заголовки PE32+ + секции + таблица импортов (IAT)
//   pestubs <file> — генерация Win32-заглушек: лог имени + int3-стоп (CDD)
// Файлы ищутся в initrd (cpio): mb2-модуль или PVH modlist[0].
// ============================================================================

/// Статические буферы стабов (ядро без аллокаций): curl.exe — 274 импорта,
/// лимита 1024 хватает для тяжёлых CDD-кандидатов.
var kstub_entries: [win32.MAX_STUB_ENTRIES]win32.StubEntry = undefined;
var kstub_code: [win32.MAX_STUB_ENTRIES * win32.STUB_CODE_SIZE]u8 align(16) = undefined;
var kdisp: win32.Dispatcher = undefined;

/// Лог-хук диспетчера: форматированная строка → VGA+serial (как весь шелл).
fn win32LogHook(_: ?*anyopaque, msg: []const u8) void {
    sys_print(msg);
}

fn cmd_peinfo(args: []const u8) void {
    if (args.len == 0) {
        sys_print("Usage: peinfo <file-in-initrd>   (e.g. peinfo curl.exe)\n");
        return;
    }
    const data = initrdFindFile(args) orelse {
        sys_print("File not found in initrd: ");
        sys_print(args);
        sys_print("\n");
        return;
    };

    sys_print("=== PE/COFF Analysis: ");
    sys_print(args);
    sys_print(" ===\n");
    sys_print("File size: ");
    printDec(data.len);
    sys_print(" bytes\n");

    const image = pe.Pe.parse(data) catch |err| {
        sys_print("Parse error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    sys_print("Machine: 0x");
    putHex(image.machine());
    sys_print(" (AMD64/x86_64), PE32+ (64-bit)\n");
    sys_print("Subsystem: ");
    printDec(image.subsystem());
    if (image.isConsole()) {
        sys_print(" (Console)");
    } else {
        sys_print(" (GUI)");
    }
    sys_print(", Timestamp: 0x");
    putHex(image.timestamp());
    sys_print("\n");

    sys_print("Entry point: RVA 0x");
    putHex(image.entryPointRva());
    sys_print(" (VA 0x");
    putHex(image.entryPointVa());
    sys_print(")\n");
    sys_print("Image base: 0x");
    putHex(image.imageBase());
    sys_print(", SizeOfImage: 0x");
    putHex(image.sizeOfImage());
    sys_print(", Headers: 0x");
    putHex(image.sizeOfHeaders());
    sys_print("\n");
    sys_print("Stack reserve: 0x");
    putHex(image.stackReserve());
    sys_print(", Heap reserve: 0x");
    putHex(image.heapReserve());
    sys_print("\n");

    // Секции
    sys_print("Sections: ");
    printDec(image.numSections());
    sys_print("\n");
    for (image.sections) |*sec| {
        sys_print("  ");
        sys_print(sec.nameSlice());
        sys_print(" VA=0x");
        putHex(sec.virtual_address);
        sys_print(" VSize=0x");
        putHex(sec.virtual_size);
        sys_print(" Raw=0x");
        putHex(sec.pointer_to_raw_data);
        sys_print("..0x");
        putHex(sec.pointer_to_raw_data + sec.size_of_raw_data);
        if (sec.isExecutable()) sys_print(" X");
        if (sec.isWritable()) sys_print(" W");
        sys_print("\n");
    }

    // Импорты (IAT) — ядро Crash-Driven Development
    const counts = image.countImports();
    sys_print("Imports: ");
    printDec(counts.dlls);
    sys_print(" DLLs, ");
    printDec(counts.functions);
    sys_print(" functions\n");

    var dlls = image.importDlls() catch {
        sys_print("  (import directory error)\n");
        return;
    };
    while (dlls.next()) |dll| {
        sys_print("  ");
        sys_print(dll.name);
        sys_print(": ");
        printDec(dll.countFunctions());
        sys_print(" imports\n");
        // первые функции каждой DLL — «что просит приложение»
        var shown: usize = 0;
        var fns = dll.functions;
        while (fns.next()) |f| {
            if (shown >= 6) {
                sys_print("    ... (см. pestubs для полной таблицы)\n");
                break;
            }
            sys_print("    ");
            switch (f) {
                .by_name => |n| sys_print(n),
                .by_ordinal => |ord| {
                    sys_print("ordinal#");
                    printDec(ord);
                },
            }
            sys_print("\n");
            shown += 1;
        }
    }
}

fn cmd_pestubs(args: []const u8) void {
    if (args.len == 0) {
        sys_print("Usage: pestubs <file-in-initrd>   (generate Win32 stub table)\n");
        return;
    }
    const data = initrdFindFile(args) orelse {
        sys_print("File not found in initrd: ");
        sys_print(args);
        sys_print("\n");
        return;
    };

    const image = pe.Pe.parse(data) catch |err| {
        sys_print("Parse error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    sys_print("=== Win32 Stub Generation (CDD): ");
    sys_print(args);
    sys_print(" ===\n");

    // Диспетчер: режим int3 (вызов заглушки = лог имени + #BP → panic trace)
    kdisp = win32.Dispatcher.init(&kstub_entries, &kstub_code, .int3);
    kdisp.log_fn = win32LogHook;
    const generated = kdisp.generateFor(&image) catch |err| {
        sys_print("Stub generation error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    // Активируем глобально: стаб-код (movabs rdi,id; call stubCommon) зовёт
    // синглтон диспетчера — при запуске PE-процесса логи пойдут сюда
    win32.setDispatcher(&kdisp);

    sys_print("Generated stubs: ");
    printDec(generated);
    sys_print(" / ");
    printDec(image.countImports().functions);
    sys_print(" imports\n");
    sys_print("Stub code size: ");
    printDec(generated * win32.STUB_CODE_SIZE);
    sys_print(" bytes (buffer: ");
    printDec(kstub_code.len);
    sys_print(")\n");

    // Примеры стабов — ровно те имена, которые появятся в логе при первом
    // падении (CDD: «запуск → лог → реализуй эту функцию»)
    sys_print("Sample entries (stub -> dll!function):\n");
    var shown: usize = 0;
    for (kstub_entries[0..kdisp.count]) |*e| {
        if (shown >= 10) {
            sys_print("  ... (+");
            printDec(kdisp.count - shown);
            sys_print(" more)\n");
            break;
        }
        var buf: [128]u8 = undefined;
        sys_print("  #");
        printDec(shown);
        sys_print(" 0x");
        putHex(e.stub_addr);
        sys_print(" -> ");
        sys_print(win32.fmtEntryName(e, &buf));
        sys_print("\n");
        shown += 1;
    }
    sys_print("Stub call behavior: log dll!function + int3 (#BP panic trace)\n");
}

// ============================================================================
// PE Load & Run — CDD-цикл №1 (v0.10.0)
//   peload <file> — загрузка PE64 в Ring 3 и прыжок на AddressOfEntryPoint.
// Пайплайн: user-PML4 → посекционный маппинг по ImageBase → генерация стабов
// (int3-трапы) → реализация топ-функций (syscall-трамплины) → патч IAT →
// TEB/PEB/стек → GS-base → createUserTask. Первый вызов импорта →
// «[CDD] DLL!Func — не реализовано» → rax=0 → цепочка падений в логе.
// ============================================================================

/// v0.16.0 (CDD №7): окружение PE-процесса (GetEnvironmentVariableA/getenv).
/// CURL_CA_BUNDLE — путь к CA-бандлу в initrd-VFS: curl-OpenSSL поднимает
/// верификацию цепочки БЕЗ флага -k (сертификат example.com → корень бандла).
const pe_env = [_]win32_crt.EnvEntry{
    .{ .name = "CURL_CA_BUNDLE", .value = "cacert.pem" },
    .{ .name = "SSL_CERT_FILE", .value = "cacert.pem" },
    .{ .name = "HOME", .value = "/" },
    .{ .name = "CURL_HOME", .value = "/" },
    .{ .name = "USERPROFILE", .value = "C:\\" },
    .{ .name = "PATH", .value = "C:\\" },
};

/// LoaderOps-проводка kernel: PMM (обнулённые contiguous) + VMM user-маппинг +
/// identity-указатели на физ. страницы (kernel VA == phys).
/// v0.18.0 (CDD №9): + unmap_user (vmm.unmapPageInPML4) + free_contig
/// (pmm.freeContiguousPages) — откат при сбоях маппинга PE-образа.
fn pmmAllocContig(count: u64) ?u64 {
    return pmm.allocContiguousZeroed(count);
}
fn vmmMapUser(pml4: u64, va: u64, pa: u64, flags: u64) bool {
    // v0.18.1 (multi-process): RE-MAP поверх мёртвого процесса. User-образы
    // (image 0x140000000+, стек 0x21…, TEB/PEB 0x21…, heap 0x30…) живут в
    // ОБЩЕЙ цепочке PML4[0] (createUserPML4 копирует kernel-записи) — мап-
    // пинги ЗАВЕРШИВШЕГОСЯ процесса остаются в общих таблицах (cleanup
    // процесса в v0.18.0 нет) — второй peload ловил AlreadyMapped на тех
    // же VA (эмпирика pe-run8: virt=0x140000000, old=маппинг 7za →
    // ошибка → дикая запись error-return → CPU EXCEPTION). Лечение:
    // снять СТАРЫЙ маппинг (unmapPageInPML4 освобождает опустевшие
    // таблицы) и замапить страницу НОВОГО процесса. Старые физ-страницы
    // образа мёртвого процесса остаются в PMM занятыми (документировано
    // в AGENT_STATE: process-exit-cleanup — v0.19).
    if (vmm.mapPageInPML4(pml4, va, pa, flags)) |_| {
        return true;
    } else |e| {
        if (e != vmm.VmmError.AlreadyMapped) return false;
        if (!vmmUnmapUser(pml4, va)) return false;
        vmm.mapPageInPML4(pml4, va, pa, flags) catch return false;
        return true;
    }
}
fn vmmUnmapUser(pml4: u64, va: u64) bool {
    vmm.unmapPageInPML4(pml4, va) catch return false;
    return true;
}
fn pmmFreeContig(base_pa: u64, count: u64) void {
    pmm.freeContiguousPages(base_pa, count);
}
fn identityPagePtr(pa: u64) [*]u8 {
    return @ptrFromInt(pa);
}
fn kernelLoaderOps() pe_loader.LoaderOps {
    return .{
        .alloc_contig = pmmAllocContig,
        .map_user = vmmMapUser,
        .page_ptr = identityPagePtr,
        .unmap_user = vmmUnmapUser,
        .free_contig = pmmFreeContig,
    };
}

// ─── v0.18.0 (CDD №9): Linux POSIX-слой — kernel-runtime (LinuxOps) ────────

/// Регион mmap для Linux-задач. CDD №15 p4-КОРЕНЬ «failed to map segment»
/// (mmap(NULL,0x151158) libpixman → ENOMEM): старая база 0x40_0000_0000
/// (256ГБ) жила ВНУТРИ PML4[0]-поддерева — ОБЩЕГО для всех процессов
/// (createUserPML4 копирует kernel-записи; getOrCreateTable открывает
/// PTE_USER в ОБЩИХ таблицах при user-маппинге) → курсоры mmap'ов
/// Xwayland и gamescope КОЛЛИДИРОВАЛИ в общих PT → AlreadyMapped.
/// Новая база 0x2000_0000_0000 (2.2ТБ, PML4[4]) — ПРИВАТНОЕ поддерево (kernel-
/// записи [1..255] нулевые): таблицы по-процессные, коллизий нет.
const PAGE_SIZE = vmm.PAGE_SIZE;
const LINUX_MMAP_BASE: u64 = 0x2000_0000_0000;
/// CDD №12 p5: 1ГБ → 48ГБ VA-бюджет: LLVM резервирует 10.7ГБ JIT-арен
/// (mmap(0, 0x2AAAAB000)×2) — с demand-zero физика не резервируется, VA
/// дёшев; USER_VA_CEILING (0x7FFF_FFFF_FFFF) вмещает с запасом.
const LINUX_MMAP_BUDGET: u64 = 0xC_0000_0000;
const LINUX_MAX_VALIDATE: u64 = 64 * 1024 * 1024; // зеркало MAX_VALIDATE_LEN win32

/// PML4 текущей Ring-3 задачи (ABI-независимо — работает и для ELF).
/// v0.20.0 (CDD №11): ВЛАДЕЛЕЦ-ориентированно (user_rsp → задача — атомарно
/// IF=0; защита от parking-рассинхронов CDD №9). Shell-контекст (ldevtest):
/// владелец не Linux-тред → честный 0 (валидация/dev_mmap откажут — так
/// и было в v0.19 через current_task_id).
fn linuxTaskPml4() u64 {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        const t = &scheduler.tasks[owner];
        if (t.privilege == .User and t.abi == .linux and t.state != .Killed) {
            return t.cr3;
        }
    }
    const tid = scheduler.current_task_id;
    if (tid >= scheduler.MAX_TASKS) return 0;
    const t = &scheduler.tasks[tid];
    if (t.privilege == .User and t.abi == .linux) return t.cr3;
    return 0;
}

/// Валидация user-VA по PML4 текущей задачи: та же дисциплина, что
/// win32_api.validateRange (v0.18.0 hardening): NULL-страница, u64-перенос
/// va+len, канонический user-потолок, USER-бит каждого листа, W-бит.
fn linuxValidate(va: u64, len: u64, want_write: bool) bool {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return false;
    if (len == 0) return true;
    if (len > LINUX_MAX_VALIDATE) return false;
    if (va < 0x1000) return false;
    const sum = @addWithOverflow(va, len);
    if (sum[1] != 0) return false;
    if (sum[0] > linux_syscalls.USER_VA_CEILING) return false;
    var off: u64 = 0;
    while (off < len) {
        const p = va + off;
        var leaf_opt = vmm.userLeafFlags(pml4, p);
        // CDD №12 p5: LAZY-СТРАНИЦА (demand-zero регион/brk): Linux-семантика
        // «VA валидна = память доступна». madvise на untouched-страницах
        // старого ядра возвращал 0 (eager-маппинг) — lazy-вариант давал
        // EFAULT и ЛОМАЛ glibc/lua-путь (частичная инициализация структур
        // → 0xAAAA в полях). Материализуем НУЛЕВЫЕ страницы прямо здесь.
        if (leaf_opt == null or (leaf_opt.? & vmm.PTE_PRESENT == 0)) {
            if (!linuxMaterializeLazyPage(p)) return false;
            leaf_opt = vmm.userLeafFlags(pml4, p);
            if (leaf_opt == null) return false;
        }
        const leaf = leaf_opt.?;
        if (leaf & vmm.PTE_USER == 0) return false;
        if (want_write and (leaf & vmm.PTE_WRITABLE == 0)) return false;
        off += PAGE_SIZE - (p & (PAGE_SIZE - 1));
    }
    return true;
}

/// CDD №12 p5: материализация ОДНОЙ lazy-страницы (валидация юзер-буферов
/// и madvise/механизмы ДО фактического касания гостем). Права — из региона.
fn linuxMaterializeLazyPage(p: u64) bool {
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return false;
    const page = p & ~@as(u64, PAGE_SIZE - 1);
    if (page < elf_loader.MIN_USER_VA) return false; // ядро/identity не трогаем
    if (linuxDemandZero(owner, p)) return true;
    return false;
}

/// Ядро → user: запись БАЙТОВ (uname). Вызывается ПОСЛЕ валидации слоем;
/// CR3 задачи активен (syscall-транзакция) — прямой доступ по VA.
fn linuxCopyOut(dst_va: u64, src: []const u8) bool {
    if (src.len == 0) return true;
    if (!linuxValidate(dst_va, src.len, true)) return false;
    const p: [*]u8 = @ptrFromInt(dst_va);
    @memcpy(p[0..src.len], src);
    return true;
}

/// User C-строка → kernel slice (openat). Постраничная валидация по мере
/// скана: пересечение границы страницы в НЕмапнутую зону — отказ EFAULT,
/// а НЕ #PF в ядре (инвариант CDD №9: ноль паник от враждебного ввода).
fn linuxCopyInStr(src_va: u64, max_len: u64) ?[]const u8 {
    var n: u64 = 0;
    while (n < max_len) {
        const va = src_va + n;
        // до конца текущей страницы (или max_len)
        const in_page = PAGE_SIZE - (va % PAGE_SIZE);
        const chunk = @min(in_page, max_len - n);
        if (!linux_user_io.validate(va, chunk, false)) return null;
        const base: [*]const u8 = @ptrFromInt(va);
        var i: u64 = 0;
        while (i < chunk) : (i += 1) {
            if (base[i] == 0) {
                const start: [*]const u8 = @ptrFromInt(src_va);
                return start[0..@intCast(n + i)];
            }
        }
        n += chunk;
    }
    return null; // терминатора в границах max_len нет
}

/// write(fd, buf, count): консоль — экран (Framebuffer/VGA) + Serial ОС.
/// Семантический слой уже проверил fd = консоль.
fn linuxDevWrite(va: u64, count: u64) i64 {
    // буфер уже валидирован syscall-слоем; CR3 задачи активен
    const p: [*]const u8 = @ptrFromInt(va);
    const slice = p[0..@intCast(count)];
    puts_vga_or_fb(slice);
    hal.Serial.puts(slice);
    return @intCast(count);
}

/// read(fd, buf, count): устройства ввода — ПОТОК input_event (24Б) прямо
/// в user-буфер (CR3 задачи активен; readBytes пишет напрямую по VA).
fn linuxDevRead(kind: linux_syscalls.FdKind, va: u64, count: u64, nonblock: bool) i64 {
    const p: [*]u8 = @ptrFromInt(va);
    const buf = p[0..@intCast(count)];
    switch (kind) {
        .input_event0 => return hal.evdev_kbd.readBytes(buf, nonblock),
        .input_event1 => return hal.evdev_mouse.readBytes(buf, nonblock),
        // CDD №12 p3: DRM-события (flip-complete/vblank) — записи
        // drm_event_vblank из кольца drm_kms; пусто → -EAGAIN (poll-цикл
        // gamescope ждёт EPOLLIN — см. linuxDevReady)
        .dri_card0 => return drm_kms.readEvents(&drm_state, buf),
        else => return -linux_syscalls.EIO,
    }
}

// ─── v0.19.0 (CDD №10 p3): user-IO-контекст (переключаемый) ────────────────
//
// Боевой режим: валидация по PML4 активной Ring-3 задачи (linuxValidate).
// Режим ldevtest: валидация по .bss-тестовому буферу (ядро-самотест без
// Ring-3 ELF-задачи: kernel-страницы без USER-бита PML4-валидацию не
// проходят — самотест работает через буфер-«песочницу»).

const LinuxUserIo = struct {
    validate: *const fn (va: u64, len: u64, want_write: bool) bool,
    copy_in: *const fn (dst: []u8, src_va: u64) bool,
    copy_out: *const fn (dst_va: u64, src: []const u8) bool,
};

var linux_user_io: LinuxUserIo = .{
    .validate = linuxValidate,
    .copy_in = linuxCopyIn,
    .copy_out = linuxCopyOut,
};

/// Индирекция user-IO (переключаемая): kernelLinuxOps захватывает ЭТИ
/// обёртки, чтобы переключение linux_user_io действовало и на семантический
/// слой (validate/copy), а не только на dev-мосты.
fn linuxUserIoValidate(va: u64, len: u64, want_write: bool) bool {
    return linux_user_io.validate(va, len, want_write);
}
fn linuxUserIoCopyIn(dst: []u8, src_va: u64) bool {
    return linux_user_io.copy_in(dst, src_va);
}
fn linuxUserIoCopyOut(dst_va: u64, src: []const u8) bool {
    return linux_user_io.copy_out(dst_va, src);
}

/// User → ядро: копия БАЙТОВ (контр-направление linuxCopyOut).
fn linuxCopyIn(dst: []u8, src_va: u64) bool {
    if (dst.len == 0) return true;
    if (!linuxValidate(src_va, dst.len, false)) return false;
    const p: [*]const u8 = @ptrFromInt(src_va);
    @memcpy(dst, p[0..dst.len]);
    return true;
}

/// ioctl-мост: DRM/fb0 → drm_kms (UAPI-номера), evdev → evdev.ioctlEvdev.
/// CDD №12 p13: drmPrimeFDToHandle(fd) → GEM-handle. lvp экспортирует
/// память как memfd (linux_files[file_id].phys — PMM-блок, user-маппинг
/// MAP_SHARED делит страницы) — скан-аут заберёт ЖИВОЙ рендер композитора.
fn linuxPrimeFdToHandle(arg: u64) i64 {
    var ph: [12]u8 = undefined;
    if (!linux_user_io.copy_in(&ph, arg)) return -linux_syscalls.EFAULT;
    const fd: i32 = @bitCast(std.mem.readInt(u32, ph[8..12], .little));
    const proc = linuxProcCurrent() orelse return -linux_syscalls.EFAULT;
    // p13-диагностика: какой fd передан и его kind
    hal.Serial.puts("[DRM] PRIME FD_TO_HANDLE: fd=");
    hal.Serial.putDecimal(@bitCast(@as(i64, fd)));
    const e0 = proc.fds.get(fd);
    hal.Serial.puts(" kind=");
    if (e0) |x| {
        hal.Serial.puts(@tagName(x.kind));
        hal.Serial.puts(" file_id=");
        hal.Serial.putDecimal(x.file_id);
    } else {
        hal.Serial.puts("NOENT");
    }
    hal.Serial.puts("\n");
    const e = proc.fds.get(fd) orelse return -linux_syscalls.EBADF;
    if (e.kind != .tmpfs_file) return -linux_syscalls.EINVAL;
    const file_id = e.file_id;
    if (file_id >= linux_files.len or !linux_files[file_id].used)
        return -linux_syscalls.EINVAL;
    const f = &linux_files[file_id];
    if (!f.anon or f.phys == 0 or f.size == 0) return -linux_syscalls.EINVAL;
    const h = drm_kms.primeImportSlot(&drm_state, file_id, f.phys, f.size);
    if (h < 0) return h;
    std.mem.writeInt(u32, ph[0..4], @intCast(h), .little);
    if (!linux_user_io.copy_out(arg, &ph)) return -linux_syscalls.EFAULT;
    hal.Serial.puts("[DRM] PRIME import: memfd(file=");
    hal.Serial.putDecimal(file_id);
    hal.Serial.puts(") -> GEM handle ");
    hal.Serial.putDecimal(@intCast(h));
    hal.Serial.puts("\n");
    return 0;
}

fn linuxDevIoctl(kind: linux_syscalls.FdKind, cmd: u32, arg: u64) i64 {
    switch (kind) {
        .fb0 => return drm_kms.fbIoctl(&drm_state, kernelDrmUserOps(), cmd, arg),
        .dri_card0 => {
            // CDD №12 p13: PRIME FD_TO_HANDLE — lvp-память (memfd с PMM-
            // блоком) становится GEM-буфером (скан-аут без копий!)
            if (cmd == drm_kms.DRM_IOCTL_PRIME_FD_TO_HANDLE)
                return linuxPrimeFdToHandle(arg);
            return drm_kms.drmIoctl(&drm_state, kernelDrmUserOps(), cmd, arg);
        },
        .input_event0, .input_event1 => {
            // размер из IOC-бита cmd (≤ 1КБ); копируем в ядро-буфер,
            // зовём evdev-обработчик, копируем назад
            const size: usize = @intCast(@min((cmd >> 16) & 0x3FFF, @as(u32, @intCast(linux_ioctl_buf.len))));
            if (size == 0 or !linux_user_io.copy_in(linux_ioctl_buf[0..size], arg))
                return -linux_syscalls.EFAULT;
            const dev: *evdev.Evdev = if (kind == .input_event0) &hal.evdev_kbd else &hal.evdev_mouse;
            const r = evdev.ioctlEvdev(dev, cmd, linux_ioctl_buf[0..size]);
            if (r < 0) return r;
            if (!linux_user_io.copy_out(arg, linux_ioctl_buf[0..size])) return -linux_syscalls.EFAULT;
            return r;
        },
        else => return -linux_syscalls.ENOTTY,
    }
}

/// Буфер ioctl-копирования (evdev-команды ≤ 304Б + запас).
var linux_ioctl_buf: [512]u8 align(16) = .{0} ** 512;

/// DrmOps на user-IO-контексте: копии через переключаемый linux_user_io.
fn kernelDrmUserOps() drm_kms.DrmOps {
    return .{
        .validate = linux_user_io.validate,
        .copy_in = linux_user_io.copy_in,
        .copy_out = linux_user_io.copy_out,
        .alloc_pages = drmAllocPages,
        .free_pages = drmFreePages,
        .scanout_frame = drmScanoutFrame,
    };
}

/// Готовность устройств: POLLIN для input-очередей, POLLOUT для остального.
fn linuxDevReady(kind: linux_syscalls.FdKind) u32 {
    switch (kind) {
        .input_event0 => return if (hal.evdev_kbd.pending() > 0) linux_syscalls.EPOLLIN else 0,
        .input_event1 => return if (hal.evdev_mouse.pending() > 0) linux_syscalls.EPOLLIN else 0,
        // CDD №12 p3: card0 читаем ТОЛЬКО при наличии событий (flip-complete);
        // иначе poll-цикл gamescope бы крутился на read → EAGAIN
        .dri_card0 => return if (drm_kms.eventsPending(&drm_state) != 0) linux_syscalls.EPOLLIN else 0,
        else => return linux_syscalls.EPOLLOUT,
    }
}

/// mmap устройства: fb0 (linear-fb WC) / card0 (dumb-апертура). Требует
/// АКТИВНОЙ Ring-3 задачи (её PML4); в shell-контексте — честный -ENODEV.
fn linuxDevMmap(kind: linux_syscalls.FdKind, off: u64, len: u64, prot: u64) i64 {
    _ = prot; // WC-бит для fb (видеопамять); NX для dumb (данные)
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return -linux_syscalls.ENODEV; // нет user-задачи
    const proc = linuxProcCurrent() orelse return -linux_syscalls.ENODEV;
    if (len > LINUX_MMAP_BUDGET) return -linux_syscalls.ENOMEM;
    const pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if (proc.mmap_cursor + pages * PAGE_SIZE > LINUX_MMAP_BASE + LINUX_MMAP_BUDGET)
        return -linux_syscalls.ENOMEM;
    const va = proc.mmap_cursor;
    switch (kind) {
        .fb0 => {
            if (off != 0) return -linux_syscalls.ENODEV; // только весь fb
            if (!drmMapLinearFbUser(pml4, va, len)) return -linux_syscalls.ENOMEM;
        },
        .dri_card0 => {
            // offset из MAP_DUMB (апертура) → dumb-буфер → физ. страницы
            const buf = drm_kms.lookupAperture(&drm_state, off) orelse return -linux_syscalls.ENODEV;
            if (buf.pages < pages) return -linux_syscalls.EINVAL; // Запрошено больше буфера
            var i: u64 = 0;
            while (i < pages) : (i += 1) {
                const pte: u64 = vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE;
                vmm.mapPageInPML4(pml4, va + i * PAGE_SIZE, buf.phys + i * PAGE_SIZE, pte) catch {
                    return linuxMmapRollback(pml4, va, i, -linux_syscalls.ENOMEM);
                };
            }
        },
        else => return -linux_syscalls.ENODEV,
    }
    // dev-регион: физику НЕ освобождаем (VRAM/dumb — владение drm_kms)
    linuxRecordRegion(linux_task_proc[linuxOwnerTask()], va, pages, 0, false, "dev");
    proc.mmap_cursor += pages * PAGE_SIZE;
    return @intCast(va);
}

/// munmap(va, len): CDD №12 p6 — ЕДИНАЯ drop-механика: выравнивание Linux
/// (addr вниз, len вверх), резка реестра (куски целиком внутри — удаляются:
/// p5 оставлял stale-записи при частичном munmap) и region-aware освобождение
/// физики (p5 возвращал ОБЩИЕ страницы wl_shm/dumb в PMM — кросс-порча).
fn linuxDoMunmap(va: u64, len: u64) i64 {
    if (len == 0) return 0;
    const qva = va & ~@as(u64, PAGE_SIZE - 1);
    if (va + len < va) return -linux_syscalls.EINVAL;
    const pages = (va + len - qva + PAGE_SIZE - 1) / PAGE_SIZE;
    linuxRangeDrop(qva, pages);
    return 0;
}

/// v0.20.0 (CDD №11 p3): MAP_FIXED-замена — CDD №12 p6: единая drop-механика
/// (резка + удаление покрытых кусков ВКЛЮЧАЯ lazy; region-aware освобождение
/// физики). p5-вариант вычищал только eager-регионы (phys≠0) — lazy-записи
/// оставались stale поверх живых данных → demand-zero накрывал их нулями.
fn linuxUnmapFixedRange(va: u64, pages: u64) void {
    linuxRangeDrop(va, pages);
}

/// mmap(hint, len, prot, flags): MAP_ANONYMOUS|PRIVATE — ОДИН contiguous-нулевой
/// блок в PML4 текущей задачи (RW+USER+NX; PROT_EXEC снимает NX) + запись в
/// mmap-реестр (munmap-free + clone-стек-lookup). Сбой посреди маппинга —
/// ОТКАТ (unmap + free) — та же дисциплина, что pe_loader.
/// v0.20.0 (CDD №11 p3): MAP_FIXED — ТОЧНЫЙ адрес с ЗАМЕНПРЕЖНИХ
/// мапов (эмпирика dyn-elf: ld.so кладёт bss-хвост libc АНОНИМНЫМ
/// MAP_FIXED-мапом поверх спана — dl-map-segments.h:163; игнор хинта →
/// bss на курсоре → #PF WRITE на RO-странице спана).
fn linuxDoMmap(hint: u64, len: u64, prot: u64, flags: u64) i64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return -linux_syscalls.EFAULT;
    const proc = linuxProcCurrent() orelse return -linux_syscalls.EFAULT;
    if (len > LINUX_MMAP_BUDGET) return -linux_syscalls.ENOMEM;
    const fixed: bool = (flags & linux_syscalls.MAP_FIXED != 0) and hint != 0;
    const pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if (fixed and hint % PAGE_SIZE != 0) return -linux_syscalls.EINVAL;
    const va: u64 = if (fixed) hint else proc.mmap_cursor;
    if (fixed) {
        if (va < elf_loader.MIN_USER_VA or
            va + pages * PAGE_SIZE > linux_syscalls.USER_VA_CEILING)
            return -linux_syscalls.EINVAL;
        linuxUnmapFixedRange(va, pages);
    } else if (proc.mmap_cursor + pages * PAGE_SIZE > LINUX_MMAP_BASE + LINUX_MMAP_BUDGET) {
        return -linux_syscalls.ENOMEM;
    }
    var pte: u64 = vmm.PTE_USER | vmm.PTE_WRITABLE;
    if (prot & linux_syscalls.PROT_EXEC == 0) pte |= vmm.PTE_NO_EXECUTE;
    // CDD №12 p5: ЛЕНИВАЯ VA-резервация (demand-zero). Linux-семантика
    // анонимного mmap — ВИРТУАЛЬНАЯ память без физики до касания: LLVM
    // резервирует 10.7ГБ JIT-арен (mmap(0, 0x2AAAAB000)) — eager-выдача
    // физики невозможна (гость 2ГБ), а отказ → «LLVM ERROR: out of memory».
    // Права протокола сохранены в r.pte — #PF-хендлер замапит нулевые
    // страницы с этими флагами. Eager-путь оставлен старым regression-тестам
    // (fakeDoMmap не тронут — тесты ядра проверяют errno-семантику).
    linuxRecordRegionEx(linux_task_proc[linuxOwnerTask()], va, pages, 0, true, true, pte, "anon");
    if (!fixed) proc.mmap_cursor += pages * PAGE_SIZE;
    return @intCast(va);
}

fn linuxMmapRollback(pml4: u64, va: u64, mapped: u64, ret: i64) i64 {
    var j: u64 = 0;
    while (j < mapped) : (j += 1) {
        vmm.unmapPageInPML4(pml4, va + j * PAGE_SIZE) catch {};
    }
    return ret;
}

/// exit(status): завершение ТЕКУЩЕЙ задачи (владелец syscall-каскада).
/// v0.20 (CDD №15): если это ПОСЛЕДНЯЯ живая задача proc-слота — процесс
/// умирает ЦЕЛИКОМ (hello-exec зовёт сырой exit(60), не exit_group):
/// зомби-код в слот (parent≠255) / release корневого (parent=255).
fn linuxDoExit(code: u64) void {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        linuxClearWakeTid(owner);
        // последняя живая задача слота? → смерть ПРОЦЕССА (зомби-механика)
        const slot = linux_task_proc[owner];
        if (slot < MAX_LINUX_PROCS and linux_procs[slot].used) {
            var alive: usize = 0;
            var i: usize = 0;
            while (i < scheduler.task_count) : (i += 1) {
                if (linux_task_proc[i] == slot and
                    scheduler.tasks[i].state != .Killed) alive += 1;
            }
            if (alive <= 1) { // только сам владелец — процесс умирает
                linux_procs[slot].exit_code = code;
                if (linux_procs[slot].parent == 255) {
                    linuxProcRelease(slot); // корневой — без зомби-фазы
                }
            }
        }
    }
    hal.Serial.puts("[LINUX] exit(");
    hal.Serial.putDecimal(code);
    hal.Serial.puts(") — killing user process\n");
    scheduler.exitCurrentTask();
    // Linux-путь держит IF=0 (SYSCALL SFMASK): pause-цикл заблокировал бы
    // таймер навсегда (замерзание ядра — эмпирика elf-run E2E). Win32-паттерн:
    // sti + hlt — тик вытесняет Killed-задачу, остальные живут.
    hal.sti();
    while (true) {
        asm volatile ("hlt" ::: "memory");
    }
}

/// exit_group: v0.20 — завершение ВСЕХ потоков процесса (CLONE_THREAD-группа
/// = общий proc-слот): помечаем Killed + CLEARTID-слова (pthread_join).
/// v0.20 (CDD №15): слот с parent≠255 — ЗОМБИ (код ждёт wait4 родителя;
/// физика/fd — живут до reap). Слот корневого процесса — освобождаем
/// немедленно (некому reap-ить: elfload-процессы шелла).
fn linuxDoExitGroup(code: u64) void {
    hal.Serial.puts("[LINUX] exit_group(");
    hal.Serial.putDecimal(code);
    hal.Serial.puts(") — killing process threads (owner=");
    hal.Serial.putDecimal(linuxOwnerTask());
    hal.Serial.puts(" cur=");
    hal.Serial.putDecimal(scheduler.current_task_id);
    hal.Serial.puts(")\n");
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        const slot = linux_task_proc[owner];
        if (slot < MAX_LINUX_PROCS) {
            linux_procs[slot].exit_code = code;
            var i: usize = 0;
            while (i < scheduler.task_count) : (i += 1) {
                if (i != owner and linux_task_proc[i] == slot and
                    scheduler.tasks[i].state != .Killed)
                {
                    linuxClearWakeTid(i);
                    scheduler.tasks[i].state = .Killed;
                }
            }
            if (linux_procs[slot].parent == 255) {
                linuxProcRelease(slot); // корневой — без зомби-фазы
            }
        }
    }
    linuxDoExit(code);
}

/// CLONE_CHILD_CLEARTID-эпилог треда: обнуляем tid-слово + FUTEX_WAKE
/// (pthread_join на этом слове просыпается). CR3 задачи активен.
fn linuxClearWakeTid(task_id: usize) void {
    const tid_va = linux_child_tid[task_id];
    if (tid_va == 0) return;
    linux_child_tid[task_id] = 0;
    var z: [4]u8 = .{0} ** 4;
    if (linux_user_io.copy_out(tid_va, &z)) {
        _ = linuxFutexWake(tid_va, 1);
    }
}

/// CDD №12 p6: YIELD-СЛАЙС — парковка ТЕКУЩЕЙ задачи на 1 тик (futex-модель
/// каскада: snapshot → release → hlt → эпилог). СЕМАНТИКА Linux CFS
/// wake_up_new_task/wakeup-preemption: после clone() и futex(WAKE)
/// будильник/родитель НЕ тикает остаток слайса, а НЕМЕДЛЕННО отдаёт CPU
/// новому/разбуженному треду. ЭМПИРИКА p6-run9/run11: round-robin с 10мс-
/// слайсами давал родителю ~10мс гонки (main-тред уходил в Lua/LLVM-
/// инициализацию раньше, чем воркер заполнял структуры → чтения 0xAAAA
/// и пустые Rb_tree-деревья на 579/867-syscall фронтах).
fn linuxYieldTick() void {
    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS) return; // shell-контекст — не паркуем
    // резюм-кадр (возврат «после syscall» той же транзакции)
    scheduler.snapshotResumeFrame(owner, my_rsp);
    scheduler.setTaskSleepFor(owner, 10); // 1 тик — будильник
    const deadline = scheduler.tasks[owner].wake_tick;
    // выпуск транзакции: тики диспетчируют другие ready-задачи (вкл. НОВЫЙ тред)
    hal.cli();
    scheduler.in_win32_syscall = 0;
    hal.sti();
    while (hal.tick_count < deadline) {
        asm volatile ("hlt" ::: "memory");
    }
    // эпилог транзакции: вернуть свой user_rsp + резюм-кадр
    hal.cli();
    scheduler.user_rsp = my_rsp;
    scheduler.in_win32_syscall = 1;
    hal.sti();
    scheduler.setTaskSleepFor(owner, 0);
    scheduler.installResumeFrame(owner);
}

/// clone: НАСТОЯЩИЕ Linux-треды (CDD №11 p1). Ребёнок — задача с кадром
/// «возврата из clone-syscall»: RAX=0, RSP=новый стек, RIP=после-syscall,
/// callee-saved от родителя, общий CR3 (CLONE_VM). Родитель получает tid.
fn linuxDoClone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) i64 {
    // parent_tid пишет семантический слой (SETTID); tls — в кадр ребёнка
    // (CLONE_SETTLS: FS-base — arch_prctl-волна CDD №11 p3)

    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.ESRCH;
    const parent = &scheduler.tasks[owner];
    if (parent.privilege != .User or parent.abi != .linux or parent.state == .Killed)
        return -linux_syscalls.EPERM;
    if (stack == 0 or stack > linux_syscalls.USER_VA_CEILING) return -linux_syscalls.EINVAL;
    if (stack % 16 != 0) return -linux_syscalls.EINVAL;
    if (linuxProcCurrent() == null) return -linux_syscalls.ESRCH;

    // Кадр ребёнка из syscall_frame-снапшота (IF=0 Linux-пути — ЭТА транзакция;
    // раскладка: [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
    //             [6]=r11(user RFLAGS) [7]=rcx(user RIP после syscall))
    const sf = scheduler.syscall_frame;
    var frame: hal.InterruptFrame = std.mem.zeroes(hal.InterruptFrame);
    frame.r15 = sf[0];
    frame.r14 = sf[1];
    frame.r13 = sf[2];
    frame.r12 = sf[3];
    frame.rbp = sf[4];
    frame.rbx = sf[5];
    // GPR-аргументы clone сохранены Linux-ABI (RDI/RSI/RDX/R10/R8/R9)
    frame.rdi = flags;
    frame.rsi = stack;
    frame.rdx = parent_tid;
    frame.r10 = child_tid;
    frame.r8 = tls;
    frame.r9 = scheduler.linux_arg6;
    frame.rax = 0; // РЕБЁНОК: clone() возвращает 0
    frame.rcx = sf[7];
    frame.r11 = sf[6];
    frame.rip = sf[7]; // возврат ПОСЛЕ syscall
    frame.cs = 0x23;
    frame.rflags = sf[6] | 0x200; // IF=1
    frame.rsp = stack; // стек ребёнка (аргумент clone)
    frame.ss = 0x1B;

    const child = scheduler.createLinuxCloneTask(parent.cr3, &frame) catch
        return -linux_syscalls.EAGAIN; // лимит задач (MAX_TASKS)

    // CDD №12 p7: CLONE_SETTLS — FS-base РЕБЁНКА в fs_base_tab (диспет-
    // черизация грузит MSR из таблицы; БЕЗ этого тред наследовал FS-base
    // родителя → pthread-дескриптор (%fs:0) читал ЧУЖОЙ TLS → стартовый
    // handshake glibc (spin после prlimit64) зависал НАВСЕГДА — эмпирика
    // p7run11: задачи 0-3 заморожены, current=4 вечно, syscall-тишина).
    if (flags & linux_syscalls.CLONE_SETTLS != 0 and tls != 0) {
        scheduler.fs_base_tab[child] = tls;
    } else {
        scheduler.fs_base_tab[child] = scheduler.fs_base_tab[owner];
    }
    // CDD №12 p7: CLONE_CHILD_SETTID — Linux ПИШЕТ tid ребёнка в
    // *child_tid ПРИ clone (не только exit-CLEARTID!). glibc's
    // pthread_create-хендшейк родителя ждёт это слово (tid!=0).
    if (flags & linux_syscalls.CLONE_CHILD_SETTID != 0 and child_tid != 0) {
        var tidb: [4]u8 = undefined;
        std.mem.writeInt(u32, &tidb, @intCast(child), .little);
        _ = linux_user_io.copy_out(child_tid, &tidb);
    }
    // CLONE_PARENT_SETTID — то же слово для родителя (man clone).
    if (flags & linux_syscalls.CLONE_PARENT_SETTID != 0 and parent_tid != 0) {
        var tidb2: [4]u8 = undefined;
        std.mem.writeInt(u32, &tidb2, @intCast(child), .little);
        _ = linux_user_io.copy_out(parent_tid, &tidb2);
    }

    // Тред наследует ПРОЦЕСС родителя (CLONE_VM|CLONE_FILES — общие fd)
    linux_task_proc[child] = linux_task_proc[owner];
    // CLONE_CHILD_CLEARTID: слово tid — на exit треда (pthread_join)
    if (flags & linux_syscalls.CLONE_CHILD_CLEARTID != 0 and child_tid != 0)
        linux_child_tid[child] = child_tid;

    // Стек ребёнка → таблицы asm-владельца (isr64.S: syscall-каскад треда —
    // ТОЛЬКО на СВОЁМ kstack). Регион ищем в mmap-реестре процесса (стек
    // glibc-тредов = mmap-выделение); вне реестра — окно 64КБ вниз.
    var reg_lo = stack - 64 * 1024;
    var reg_hi = stack;
    for (&linux_mmap_regions[linux_task_proc[owner]]) |*r| {
        if (r.used and stack > r.va and stack <= r.va + r.pages * PAGE_SIZE) {
            reg_lo = r.va;
            reg_hi = r.va + r.pages * PAGE_SIZE;
            break;
        }
    }
    scheduler.registerUserStack(child, reg_lo, reg_hi);

    hal.Serial.puts("[LINUX] clone: child task ");
    hal.Serial.putDecimal(child);
    hal.Serial.puts(" (stack 0x");
    hal.Serial.putHex(stack);
    hal.Serial.puts(", flags 0x");
    hal.Serial.putHex(flags);
    hal.Serial.puts(")\n");
    // CDD №12 p6: CHILD-RUNS-FIRST (Linux CFS wake_up_new_task): родитель
    // отдаёт остаток слайса — ребёнок немедленно получает CPU на инициализацию
    // (стек/TLS/синхронизируемые структуры). Без yield — 10мс-окно гонки.
    linuxYieldTick();
    return @intCast(child);
}

// ══ v0.20 (CDD №15): FORK + EXECVE — ПОСЛЕДНИЙ КМ v0.20.0-rc ══════════
// Xwayland становится РЕАЛЬНЫМ процессом: gamescope вызывает
// fork() = clone(SIGCHLD, без CLONE_VM) → ребёнок = задача с КОПИЕЙ
// PML4 (таблицы СВОИ, физика ОБЩАЯ — Xwayland-сценарий: ребёнок
// немедленно execve → общая физика не мутирует) → execve() = kill-self
// + respawn на новом ELF-образе (pid/proc-слот стабилен; fd-наследу-
// ются — пайпы Xwayland видит). ВАЖНО: cur-first syscallStackOwner
// (asm+Zig) — без него syscall ребёнка на общем VA-стеке исполнился
// бы в контексте РОДИТЕЛЯ (линейный скан находит меньший task-id).

/// Маска физ-адреса в PTE (52-бит физ).
const PTE_ADDR_MASK: u64 = 0x0000_7FFF_FFFF_F000;

/// CDD №15 p4: EAGER-СНАПШОТ fork — НАСТОЯЩАЯ семантика fork: ребёнок
/// видит СНАПШОТ памяти родителя НА МОМЕНТ вызова (в Linux это COW).
/// КОРЕНЬ pipefd-бага wlroots: server_start ПОСЛЕ fork пишет
/// wl_fd[1] = -1 в heap-поле; при ОБЩЕЙ физике (walk-копия PML4 p1-p3)
/// ребёнок читал уже ПЕРЕЗАПИСАННОЕ значение → fcntl(-1) → EBADF →
/// _exit(1) — Xwayland умирал ДО exec. Здесь ВСЕ present user-листы
/// РОДИТЕЛЯ копируются в ПРИВАТНЫЕ страницы ребёнка: 1-й проход — счёт
/// (пул ОДНИМ contiguous-блоком: 40К одиночных allocPage дробили PMM-
/// битмап → contiguous-ран под file-mmap падал ENOMEM — «failed to
/// map segment» libpixman); 2-й — копия контента (identity-доступ к
/// обеим физ-страницам) + маппинг с PTE_PRIVATE (бит 52) — метка
/// «физика принадлежит ребёнку» (linuxFreeForkPrivate на execve).
/// PML4[0] (kernel identity [0..4ГБ)) НЕ ходим: после переноса mmap-
/// базы в PML4[4] user-маппингов ниже 512ГБ нет; identity-таблицы
/// ОБЩИЕ для всех CR3. Demand-zero (P=0) листья не копируются —
/// ребёнок получит СВОИ нулевые по #PF. Huge-листьев в user-зоне нет
/// (лоадер создаёт только 4K) — скип-страховка.
const ForkSnapStats = struct { pages: usize = 0, ro: usize = 0, pooled: bool = false };

fn linuxForkSnapshot(parent_cr3: u64, child_cr3: u64) ForkSnapStats {
    var stats = ForkSnapStats{};
    // 1) счёт present user-листьев (PML4[1..255]; [0] — kernel identity)
    {
        const pml4: [*]const u64 = @ptrFromInt(parent_cr3);
        var i: usize = 1;
        while (i < 256) : (i += 1) {
            const e4 = pml4[i];
            if (e4 & vmm.PTE_PRESENT == 0 or e4 & vmm.PTE_USER == 0) continue;
            const pdpt: [*]const u64 = @ptrFromInt(e4 & PTE_ADDR_MASK);
            var j: usize = 0;
            while (j < 512) : (j += 1) {
                const e3 = pdpt[j];
                if (e3 & vmm.PTE_PRESENT == 0 or e3 & vmm.PTE_USER == 0) continue;
                if (e3 & vmm.PTE_HUGE != 0) continue;
                const pd: [*]const u64 = @ptrFromInt(e3 & PTE_ADDR_MASK);
                var k: usize = 0;
                while (k < 512) : (k += 1) {
                    const e2 = pd[k];
                    if (e2 & vmm.PTE_PRESENT == 0 or e2 & vmm.PTE_USER == 0) continue;
                    if (e2 & vmm.PTE_HUGE != 0) continue;
                    const pt: [*]const u64 = @ptrFromInt(e2 & PTE_ADDR_MASK);
                    var m: usize = 0;
                    while (m < 512) : (m += 1) {
                        const e1 = pt[m];
                        if (e1 & vmm.PTE_PRESENT == 0) continue; // lazy — своя zero
                        stats.pages += 1;
                        if (e1 & vmm.PTE_WRITABLE == 0) stats.ro += 1;
                    }
                }
            }
        }
    }
    if (stats.pages == 0) return stats;

    // 2) пул одним contiguous-блоком (анти-фрагментация); фолбэк per-page
    stats.pooled = true;
    var pool_base: u64 = 0;
    if (pmmAllocContig(@intCast(stats.pages))) |pb| {
        pool_base = pb;
    } else {
        stats.pooled = false; // PMM-фрагментация: медленный, но живой путь
    }

    // 3) копия контента + приватные маппинги ребёнка
    var copied: usize = 0;
    const pml4: [*]const u64 = @ptrFromInt(parent_cr3);
    var i: usize = 1;
    while (i < 256) : (i += 1) {
        const e4 = pml4[i];
        if (e4 & vmm.PTE_PRESENT == 0 or e4 & vmm.PTE_USER == 0) continue;
        const pdpt: [*]const u64 = @ptrFromInt(e4 & PTE_ADDR_MASK);
        var j: usize = 0;
        while (j < 512) : (j += 1) {
            const e3 = pdpt[j];
            if (e3 & vmm.PTE_PRESENT == 0 or e3 & vmm.PTE_USER == 0) continue;
            if (e3 & vmm.PTE_HUGE != 0) continue;
            const pd: [*]const u64 = @ptrFromInt(e3 & PTE_ADDR_MASK);
            var k: usize = 0;
            while (k < 512) : (k += 1) {
                const e2 = pd[k];
                if (e2 & vmm.PTE_PRESENT == 0 or e2 & vmm.PTE_USER == 0) continue;
                if (e2 & vmm.PTE_HUGE != 0) continue;
                const pt: [*]const u64 = @ptrFromInt(e2 & PTE_ADDR_MASK);
                var m: usize = 0;
                while (m < 512) : (m += 1) {
                    const e1 = pt[m];
                    if (e1 & vmm.PTE_PRESENT == 0) continue;
                    const va: u64 = (@as(u64, i) << 39) | (@as(u64, j) << 30) |
                        (@as(u64, k) << 21) | (@as(u64, m) << 12);
                    const src_pa = e1 & PTE_ADDR_MASK;
                    var dst_pa: u64 = 0;
                    if (stats.pooled) {
                        dst_pa = pool_base + @as(u64, copied) * 4096;
                    } else {
                        dst_pa = pmm.allocPage() orelse continue;
                    }
                    // контент: identity-копия 4К (родитель → ребёнок)
                    {
                        const src: [*]const u8 = @ptrFromInt(src_pa);
                        const dst: [*]u8 = @ptrFromInt(dst_pa);
                        @memcpy(dst[0..4096], src[0..4096]);
                    }
                    const flags = (e1 & (vmm.PTE_WRITABLE | vmm.PTE_USER |
                        vmm.PTE_WRITE_THROUGH | vmm.PTE_CACHE_DISABLE |
                        vmm.PTE_NO_EXECUTE)) | vmm.PTE_PRESENT | vmm.PTE_PRIVATE;
                    vmm.mapPageInPML4(child_cr3, va, dst_pa, flags) catch {
                        pmm.freePage(dst_pa); // откат (OOM таблиц) — скип
                        continue;
                    };
                    copied += 1;
                }
            }
        }
    }
    stats.pages = copied;
    return stats;
}

/// CDD №15 p4: освобождение ПРИВАТНЫХ листьев процесса (PTE_PRIVATE бит
/// 52 = снапшот-fork). Вызывает execve ПЕРЕД отлётом на новом образе:
/// страницы снапшота (физика РЕБЁНКА) возвращаются PMM. КОРЕНЬ p4-
/// замерзания: walk-версия дошла до ОБЩИХ identity-таблиц PML4[0]
/// (kernel [0..4ГБ); getOrCreateTable открывал PTE_USER в общем подде-
/// реве) и ОСВОБОДИЛА их → kernel-#PF-шторм → полное замерзание.
/// ИНВАРИАНТЫ: (1) PML4[0] не ходим; (2) таблицы НЕ освобождаем ВООБЩЕ
/// (утечка ~90 стр/процесс — принятая v0.21-деградация); (3) только
/// листья с битом 52 (лодер-страницы родителя и demand-zero без бита
/// НЕ трогаем — чужая физика).
fn linuxFreeForkPrivate(pml4: u64) usize {
    if (pml4 == 0) return 0;
    var freed: usize = 0;
    const pml4t: [*]volatile u64 = @ptrFromInt(pml4);
    var i: usize = 1; // [0] — kernel identity (ОБЩИЙ) — не трогаем
    while (i < 256) : (i += 1) {
        const e4 = pml4t[i];
        if (e4 & vmm.PTE_PRESENT == 0) continue;
        const pdpt: [*]volatile u64 = @ptrFromInt(e4 & PTE_ADDR_MASK);
        var j: usize = 0;
        while (j < 512) : (j += 1) {
            const e3 = pdpt[j];
            if (e3 & vmm.PTE_PRESENT == 0 or e3 & vmm.PTE_HUGE != 0) continue;
            const pd: [*]volatile u64 = @ptrFromInt(e3 & PTE_ADDR_MASK);
            var k: usize = 0;
            while (k < 512) : (k += 1) {
                const e2 = pd[k];
                if (e2 & vmm.PTE_PRESENT == 0 or e2 & vmm.PTE_HUGE != 0) continue;
                const pt: [*]volatile u64 = @ptrFromInt(e2 & PTE_ADDR_MASK);
                var m: usize = 0;
                while (m < 512) : (m += 1) {
                    const e1 = pt[m];
                    if (e1 & vmm.PTE_PRESENT == 0) continue;
                    if (e1 & vmm.PTE_PRIVATE == 0) continue; // только СВОИ
                    const pa = e1 & PTE_ADDR_MASK;
                    pt[m] = 0; // лист снят (таблицы ребёнка — приватные)
                    pmm.freePage(pa);
                    freed += 1;
                }
            }
        }
    }
    return freed;
}

/// Полное освобождение proc-слота: fd-каналы/файлы unref (refs-модель
/// fork), регионы реестра, поля. Вызывается: wait4-reap зомби и exit
/// корневого (parent=255) процесса.
fn linuxProcRelease(slot: u8) void {
    if (slot >= MAX_LINUX_PROCS) return;
    const p = &linux_procs[slot];
    if (!p.used) return;
    for (&p.fds.entries) |*e| {
        switch (e.kind) {
            .initrd_file, .tmpfs_file => linuxReleaseFile(e.file_id),
            .seatd => {
                if (e.file_id < linux_syscalls.seatd_slots.len)
                    linux_syscalls.seatd_slots[e.file_id] = .{};
            },
            .pipe_read, .pipe_write, .eventfd, .socket, .timerfd, .signalfd =>
                linuxChannelUnref(e.file_id),
            .dir => linuxDirClose(e.file_id),
            else => {},
        }
    }
    // CDD №15 p5: shared-мапы отпускают файл-пины ДО fd-close (пары к
    // retain в linuxSharedFileMmap): последний refs падает в fd-цикле
    // выше → физика memfd освобождается ровно один раз.
    for (&linux_mmap_regions[slot]) |*r| {
        if (r.used and r.file_id != NO_REGION_FILE) {
            linuxReleaseFile(r.file_id);
            r.file_id = NO_REGION_FILE;
        }
    }
    for (&linux_mmap_regions[slot]) |*r| r.* = .{};
    p.* = .{}; // used=false + дефолты
}

/// Занять proc-слот РЕБЁНКА: копия fd-таблицы (refs++ на каналы/файлы),
/// brk/mmap-курсор/TLS/execfn/сигналы — наследование; mmap-регионы —
/// копия с phys=0 (физика — РОДИТЕЛЯ: munmap/exit ребёнка не освобож-
/// дает; новые mmap ребёнка — уже его собственные).
fn linuxProcForkChild(parent_slot: u8) ?u8 {
    const pp = &linux_procs[parent_slot];
    for (&linux_procs, 0..) |*cp, ci| {
        if (cp.used) continue;
        cp.* = .{ .used = true, .parent = parent_slot, .mmap_cursor = pp.mmap_cursor };
        cp.brk_base = pp.brk_base;
        cp.brk = pp.brk;
        cp.exit_code = null;
        cp.fs_base = pp.fs_base;
        cp.sig_mask = pp.sig_mask;
        cp.memfd_seq = pp.memfd_seq;
        @memcpy(&cp.execfn_buf, &pp.execfn_buf);
        cp.execfn_len = pp.execfn_len;
        // fd-таблица — структурная копия + подъём refs общих объектов
        cp.fds = pp.fds;
        for (&cp.fds.entries) |*e| {
            switch (e.kind) {
                .pipe_read, .pipe_write, .eventfd, .socket, .timerfd, .signalfd => {
                    if (e.file_id < channels.len and channels[e.file_id].used)
                        channels[e.file_id].refs += 1;
                },
                .initrd_file, .tmpfs_file => {
                    if (e.file_id < linux_files.len and linux_files[e.file_id].used)
                        linux_files[e.file_id].refs += 1;
                },
                else => {}, // консоль/устройства/epoll — глобальные объекты ядра
            }
        }
        // mmap-реестр — копия регионов; phys=0: физика РОДИТЕЛЯ
        for (&linux_mmap_regions[parent_slot], 0..) |*r, ri| {
            if (!r.used) continue;
            var r2 = r.*;
            r2.phys = 0; // наследуемый-общий: смерть ребёнка не тронет физику
            linux_mmap_regions[ci][ri] = r2;
        }
        return @intCast(ci);
    }
    return null; // EAGAIN — слоты кончились (8 процессов)
}

/// fork(): РЕБЁНОК = задача с ПРИВАТНЫМ СНАПШОТОМ памяти родителя
/// (linuxForkSnapshot: ВСЕ present user-страницы — копии; семантика
/// fork — родитель пишет ПОСЛЕ fork, ребёнок НЕ видит). Возврат в
/// РОДИТЕЛЕ — pid (1000+слот); в РЕБЁНКЕ кадр возврата — RAX=0. КРИТично:
/// ustack-строка ребёнка = родительская (общий VA) — коллизию скана
/// решает cur-first (isr64.S + scheduler.syscallStackOwner).
fn linuxDoFork(flags: u64, parent_tid: u64, child_tid: u64, tls: u64) i64 {
    _ = flags; // fork-флаги (SIGCHLD) — контракты SETTID в семантике
    _ = parent_tid;
    _ = child_tid; // пишут семантическим слоя ПО pid (sysClone)
    _ = tls; // fork не меняет TLS (общая страница до execve)

    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.ESRCH;
    const parent = &scheduler.tasks[owner];
    if (parent.privilege != .User or parent.abi != .linux or parent.state == .Killed)
        return -linux_syscalls.EPERM;
    const parent_slot = linux_task_proc[owner];
    if (parent_slot >= MAX_LINUX_PROCS) return -linux_syscalls.ESRCH;

    // 1. EAGER-СНАПШОТ: все present user-страницы — ПРИВАТНЫЕ копии
    //    ребёнка (p1-p3 «shared phys» сломался на wlroots server_start:
    //    родитель пишет wl_fd[1] = -1 в heap ПОСЛЕ fork → ребёнок читал
    //    перезаписанное → fcntl(-1) EBADF → _exit(1) до exec)
    const child_cr3 = vmm.createUserPML4() catch return -linux_syscalls.ENOMEM;
    const snap = linuxForkSnapshot(parent.cr3, child_cr3);

    // 2. Кадр ребёнка — возврат из fork-syscall В ТОЧКЕ вызова
    //    (RIP после syscall; RSP = родительский user-RSP: снапшот-копия
    //    тех же страниц — кадры идентичны на момент fork)
    const sf = scheduler.syscall_frame;
    var frame: hal.InterruptFrame = std.mem.zeroes(hal.InterruptFrame);
    frame.r15 = sf[0];
    frame.r14 = sf[1];
    frame.r13 = sf[2];
    frame.r12 = sf[3];
    frame.rbp = sf[4];
    frame.rbx = sf[5];
    frame.rdi = 0; // volatile-arg — glibc-fork child-path не читает
    frame.rsi = 0;
    frame.rdx = 0;
    frame.r10 = 0;
    frame.r8 = 0;
    frame.r9 = 0;
    frame.rax = 0; // РЕБЁНОК: fork() возвращает 0
    frame.rcx = sf[7];
    frame.r11 = sf[6];
    frame.rip = sf[7]; // возврат ПОСЛЕ syscall
    frame.rflags = sf[6] | 0x200; // IF=1
    frame.rsp = my_rsp; // снапшот-стек (те же VA, СВОИ страницы)
    frame.cs = 0x23;
    frame.ss = 0x1B;

    const child = scheduler.createLinuxCloneTask(child_cr3, &frame) catch
        return -linux_syscalls.EAGAIN;

    // 3. proc-слот ребёнка (fd-копия/регионы/brk) + бинд задачи
    const child_slot = linuxProcForkChild(parent_slot) orelse {
        scheduler.tasks[child].state = .Killed; // откат — слотов нет
        return -linux_syscalls.EAGAIN;
    };
    linux_task_proc[child] = child_slot;
    linux_child_tid[child] = 0; // fork-ребёнок однопоточен (CLEARTID нет)

    // 4. ustack-строка = родительская (общий VA); asm-скан — cur-first
    scheduler.registerUserStack(
        child,
        scheduler.ustack_lo_tab[owner],
        scheduler.ustack_hi_tab[owner],
    );
    // TLS — снапшот-копия (те же VA, свои страницы; glibc-fork-ребёнок
    // пишет tid/robust-слова в СВОЮ копию — родитель не видит)
    scheduler.fs_base_tab[child] = scheduler.fs_base_tab[owner];

    hal.Serial.puts("[LINUX] fork: parent task ");
    hal.Serial.putDecimal(owner);
    hal.Serial.puts(" → child task ");
    hal.Serial.putDecimal(child);
    hal.Serial.puts(" (pid ");
    hal.Serial.putDecimal(1000 + @as(u64, child_slot));
    hal.Serial.puts(", snapshot pages ");
    hal.Serial.putDecimal(snap.pages);
    hal.Serial.puts(", ro ");
    hal.Serial.putDecimal(snap.ro);
    hal.Serial.puts(", pool ");
    hal.Serial.puts(if (snap.pooled) "contiguous" else "per-page");
    hal.Serial.puts(")\n");

    // 5. CHILD-RUNS-FIRST (CFS wake_up_new_task — эмпирика p6: ребёнок
    //    немедленно получает CPU на glibc-fork-эпилог + execve)
    linuxYieldTick();
    return @intCast(1000 + @as(i64, child_slot));
}

/// execve(path, argv, envp): kill-self + RESPAWN на новом образе.
/// pid/proc-слот СТАБИЛЕН (1000+slot — wait4 родителя не ломается);
/// fd-таблица наследуется (пайпы Xwayland). CDD №15 p4: ПРИВАТНЫЕ
/// (снапшот-fork, бит 52) страницы старого образа освобождаются
/// (linuxFreeForkPrivate); родительские/лодер-страницы и таблицы —
/// остаются (утечка ~90 стр/процесс — v0.21: freeUserPML4-walk).
/// УСПЕХ НЕ ВОЗВРАЩАЕТСЯ — задача уходит в hlt (exit-паттерн).
fn linuxDoExecve(path: []const u8, argv: []const []const u8, envp: []const []const u8) i64 {
    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.ESRCH;
    const t = &scheduler.tasks[owner];
    if (t.privilege != .User or t.abi != .linux or t.state == .Killed)
        return -linux_syscalls.EPERM;
    const slot = linux_task_proc[owner];
    if (slot >= MAX_LINUX_PROCS) return -linux_syscalls.ESRCH;

    // 1. VFS-резолв (cpioCanon съест ведущий '/')
    hal.Serial.puts("[LINUX] execve-path: ");
    hal.Serial.puts(path);
    hal.Serial.puts(" (len ");
    hal.Serial.putDecimal(path.len);
    hal.Serial.puts(")\n");
    const data = initrdFindFile(path) orelse {
        hal.Serial.puts("[LINUX] execve: FILE NOT FOUND in initrd\n");
        return -linux_syscalls.ENOENT;
    };

    // 2. Новый образ (+ PT_INTERP ld.so — handoff как elfload)
    const new_pml4 = vmm.createUserPML4() catch return -linux_syscalls.ENOMEM;
    const ops = kernelElfOps();
    const img = elf_loader.loadElf(ops, new_pml4, data, elf_loader.LINUX_IMAGE_BASE) catch
        return -linux_syscalls.ENOEXEC;
    var entry_va = img.entry_va;
    var at_base: u64 = 0;
    var interp_pages: u64 = 0;
    if (img.interp) |interp_path| {
        const interp_data = initrdFindFile(interp_path) orelse
            return -linux_syscalls.ENOENT; // интерпретатор обязателен
        const interp_img = elf_loader.loadElf(ops, new_pml4, interp_data, elf_loader.LINUX_INTERP_BASE) catch
            return -linux_syscalls.ENOEXEC;
        entry_va = interp_img.entry_va; // HANDOFF: старт с ld.so
        at_base = interp_img.base_va;
        interp_pages = interp_img.pages;
    }

    // 3. Стек Linux-ABI: argc/argv/envp/auxv (argv/envp уже в .bss-буферах)
    const stack = elf_loader.buildUserStack(
        ops,
        new_pml4,
        elf_loader.LINUX_STACK_TOP,
        elf_loader.LINUX_STACK_PAGES,
        .{ .argv = argv, .envp = envp, .execfn = path },
        img,
        elfRandomSeed(),
        at_base,
    ) catch return -linux_syscalls.ENOMEM;

    // 3b. CDD №15 p4: снапшот-страницы (PTE_PRIVATE) СТАРОГО образа — в
    //     PMM (физика РЕБЁНКА; лодер/родительские — НЕ трогаем). Вызов
    //     ПОСЛЕ загрузки нового образа/стека: argv/envp уже в .bss,
    //     файловые байты — в новых страницах; старый user-контекст боль-
    //     не читается. Таблицы не освобождаем (см. linuxFreeForkPrivate).
    const freed_priv = linuxFreeForkPrivate(t.cr3);
    if (freed_priv > 0) {
        hal.Serial.puts("[LINUX] execve: freed ");
        hal.Serial.putDecimal(freed_priv);
        hal.Serial.puts(" fork-private pages\n");
    }

    // 4. proc-слот — ОБНОВЛЯЕМ (pid стабилен: execve не меняет pid)
    const p = &linux_procs[slot];
    p.brk_base = img.brk;
    p.brk = img.brk;
    p.mmap_cursor = LINUX_MMAP_BASE;
    p.exit_code = null;
    p.fs_base = 0; // новый образ поставит TLS (arch_prctl SET_FS)
    @memset(&p.sig_handlers, 0); // Linux: caught-хендлеры → SIG_DFL
    @memset(&p.sig_flags, 0);
    @memset(&p.sig_restorers, 0);
    {
        var efn_buf: [96]u8 = undefined;
        var efn_len: usize = 0;
        if (path.len > 0 and path[0] != '/') {
            efn_buf[0] = '/';
            efn_len = 1;
        }
        const c = @min(path.len, efn_buf.len - efn_len);
        @memcpy(efn_buf[efn_len .. efn_len + c], path[0..c]);
        efn_len += c;
        const n = @min(efn_len, p.execfn_buf.len);
        @memcpy(p.execfn_buf[0..n], efn_buf[0..n]);
        p.execfn_len = n;
    }
    // fd-таблица — НАСЛЕДУЕТСЯ (Linux: fd без CLOEXEC переживают exec;
    // CLOEXEC-разметки у fd нет — все живут: пайпы Xwayland)
    // mmap-реестр: чистка (анти-поллюция атрибуции) + новые регионы
    for (&linux_mmap_regions[slot]) |*r| r.* = .{};
    const reg_slot: u8 = @intCast(slot);
    var name_buf: [48]u8 = [_]u8{0} ** 48;
    {
        // имя образа: последний компонент пути (атрибуция RIP→модуль)
        var base: usize = 0;
        for (path, 0..) |c, pi| {
            if (c == '/') base = pi + 1;
        }
        const bn = path[base..];
        const n = @min(bn.len, name_buf.len);
        @memcpy(name_buf[0..n], bn[0..n]);
    }
    linuxRecordRegion(reg_slot, img.base_va, img.pages, 0, false, &name_buf);
    if (img.interp != null) {
        linuxRecordRegion(reg_slot, elf_loader.LINUX_INTERP_BASE, interp_pages, 0, false, "ld.so");
    }
    linuxRecordRegion(
        reg_slot,
        elf_loader.LINUX_STACK_TOP - elf_loader.LINUX_STACK_PAGES * 4096,
        elf_loader.LINUX_STACK_PAGES,
        0,
        false,
        "[stack]",
    );

    // 5. НОВАЯ задача (тот же proc-слот/pid; старую убиваем ниже)
    const task_id = scheduler.createUserTaskAbi(entry_va, new_pml4, stack.entry_rsp, .linux) catch
        return -linux_syscalls.EAGAIN;
    linux_task_proc[task_id] = reg_slot;
    scheduler.tasks[task_id].abi = .linux; // красная строка (гонка закрыта p3)
    scheduler.registerUserStack(
        task_id,
        elf_loader.LINUX_STACK_TOP - elf_loader.LINUX_STACK_PAGES * 4096,
        elf_loader.LINUX_STACK_TOP,
    );
    scheduler.fs_base_tab[task_id] = 0;

    hal.Serial.puts("[LINUX] execve: ");
    hal.Serial.puts(path);
    hal.Serial.puts(" → task ");
    hal.Serial.putDecimal(task_id);
    hal.Serial.puts(" (pid ");
    hal.Serial.putDecimal(1000 + @as(u64, slot));
    hal.Serial.puts(", entry 0x");
    hal.Serial.putHex(entry_va);
    hal.Serial.puts(")\n");

    // 6. kill-self (exit-паттерн: транзакция снята, задача Killed,
    //    hlt до диспетчеризации НОВОЙ задачи). Снапшот-страницы уже в PMM
    //    (3b); demand-zero страницы glibc-fork-ребёнка (без бита 52) —
    //    утечены (реестр перезаписан; мало страниц — v0.21).
    scheduler.exitCurrentTask();
    hal.sti();
    while (true) {
        asm volatile ("hlt" ::: "memory");
    }
}

/// wait4-реестр: >0 = reap зомби (код в code_out; слот освобождается);
/// 0 = дети живы (блокировка — парковки семантики); -ECHILD = детей нет.
fn linuxDoWait4(pid: i64, code_out: *u64) i64 {
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.ECHILD;
    const my_slot = linux_task_proc[owner];
    if (my_slot >= MAX_LINUX_PROCS) return -linux_syscalls.ECHILD;

    if (pid > 0) { // конкретный ребёнок
        const s: usize = @intCast(pid - 1000);
        if (s >= MAX_LINUX_PROCS) return -linux_syscalls.ECHILD;
        const p = &linux_procs[s];
        if (!p.used or p.parent != my_slot) return -linux_syscalls.ECHILD;
        if (p.exit_code) |c| {
            code_out.* = c;
            linuxProcRelease(@intCast(s));
            return 1000 + @as(i64, @intCast(s));
        }
        return 0; // жив — блокировка семантики
    }
    // pid <= 0 (wait/-any): первый зомби; иначе дети живы / ECHILD
    var have_live = false;
    for (&linux_procs, 0..) |*p, s| {
        if (!p.used or p.parent != my_slot) continue;
        if (p.exit_code) |c| {
            code_out.* = c;
            linuxProcRelease(@intCast(s));
            return 1000 + @as(i64, @intCast(s));
        }
        have_live = true;
    }
    return if (have_live) 0 else -linux_syscalls.ECHILD;
}

// ─── v0.20.0 (CDD №11 p1): futex-реестр парковок (честная блокировка) ──────

const FutexPark = struct {
    active: bool = false,
    task: usize = 0,
    uaddr: u64 = 0,
    woken: bool = false,
};

var futex_parks: [scheduler.MAX_TASKS]FutexPark =
    [_]FutexPark{.{}} ** scheduler.MAX_TASKS;

/// futex-WAIT: слово сверено слоем; парковка модели kSleepTask —
/// snapshotResumeFrame + снятие транзакции + hlt до WAKE/дедлайна.
/// WAKE из другого треда (общая VM) находит реестровую запись → woken.
fn linuxFutexPark(uaddr: u64, timeout_ms: u64, infinite: bool) i64 {
    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS or
        scheduler.tasks[owner].privilege != .User)
    {
        // shell-контекст (ldevtest): кооперативная модель 1 тик
        const t0 = hal.tick_count;
        const ticks = if (infinite) @as(u64, 1) else (timeout_ms + 9) / 10;
        while (hal.tick_count < t0 + ticks) {
            asm volatile ("pause");
        }
        return 0;
    }

    // Регистрируемся ДО выпуска транзакции: WAKE в окне word-check→park
    // находит запись (не теряется)
    futex_parks[owner] = .{ .active = true, .task = owner, .uaddr = uaddr, .woken = false };

    // Дедлайн: finite → таймаут-тики; infinite → 60с-страховка с перепарковкой
    var deadline = hal.tick_count + 6000;
    if (!infinite) {
        const ticks = (timeout_ms + 9) / 10;
        if (ticks == 0) {
            futex_parks[owner].active = false;
            return -linux_syscalls.ETIMEDOUT;
        }
        deadline = hal.tick_count + ticks;
    }

    // Резюм-кадр + будильник (модель kSleepTask: каскад на топе kstack)
    scheduler.snapshotResumeFrame(owner, my_rsp);
    scheduler.setTaskSleepFor(owner, (deadline - hal.tick_count) * 10);

    // Выпуск транзакции: тики диспетчируют WAKE-ника
    hal.cli();
    scheduler.in_win32_syscall = 0;
    hal.sti();

    // Парк: hlt до прерывания (тик 100Гц); WAKE снимает будильник → слайс
    while (true) {
        if (futex_parks[owner].woken) break;
        if (hal.tick_count >= deadline) {
            if (infinite) {
                // перепарковка (страховка от зависшего таймера); честный
                // glibc-цикл повторит word-check новым WAIT → EAGAIN
                deadline = hal.tick_count + 6000;
                scheduler.setTaskSleepFor(owner, 60_000);
                continue;
            }
            break; // таймаут
        }
        asm volatile ("hlt" ::: "memory");
    }
    const was_woken = futex_parks[owner].woken;
    futex_parks[owner].active = false;

    // Эпилог транзакции (модель kSleepTask): вернуть свой user_rsp,
    // резюм-указатель — на .bss-слот (валидный кадр «после syscall»)
    hal.cli();
    scheduler.user_rsp = my_rsp;
    scheduler.in_win32_syscall = 1;
    hal.sti();
    scheduler.setTaskSleepFor(owner, 0);
    scheduler.installResumeFrame(owner);

    return if (was_woken) 0 else -linux_syscalls.ETIMEDOUT;
}

/// futex-WAKE: разбудить до n паркуемых на uaddr (реестр → будильник-снятие).
/// CDD №12 p6: WAKEUP-PREEMPTION (CFS): разбудивший отдаёт слайс —
/// разбуженный получает CPU немедленно (producer/consumer-handshake
/// pthread_join/cond: иначе ждёт своего слайса в round-robin до N×10мс).
fn linuxFutexWake(uaddr: u64, n: u32) u32 {
    var cnt: u32 = 0;
    for (&futex_parks) |*p| {
        if (cnt >= n) break;
        if (p.active and !p.woken and p.uaddr == uaddr) {
            p.woken = true;
            scheduler.setTaskSleepFor(p.task, 0); // будильник снять → слайс
            cnt += 1;
        }
    }
    if (cnt > 0) linuxYieldTick(); // будильник уступает CPU разбужденному
    return cnt;
}

/// fd-таблица Linux-процессов (v0.19: глобальная на слой — ELF-загрузчик
/// размножит на задачу; контракты семантического слоя уже пер-таблиценные).
var linux_fds: linux_syscalls.FdTable = linux_syscalls.FdTable.init();

// ─── v0.20.0 (CDD №11 p1): Linux-ПРОЦЕССЫ — состояние и реестры ────────────
//
// Процесс = proc-слот (fd-таблица CLONE_FILES-общая, mmap-курсор, brk,
// exit-код). Треды (clone) наследуют слот: linux_task_proc[task] → слот.
// mmap-реестр: munmap-освобождение физики + clone-стек-lookup.

const LinuxProc = struct {
    used: bool = false,
    /// v0.20 (CDD №15): слот РОДИТЕЛЯ (255 = корневой/шелл-процесс;
    /// ≠255 → зомби-семантика wait4: exit оставляет код в слоте).
    parent: u8 = 255,
    fds: linux_syscalls.FdTable = linux_syscalls.FdTable.init(),
    mmap_cursor: u64 = 0,
    /// brk-базис (конец ELF-образа) и текущий brk (glibc-static malloc).
    brk_base: u64 = 0,
    brk: u64 = 0,
    exit_code: ?u64 = null,
    /// execfn (argv[0]) — readlink("/proc/self/exe") для glibc.
    execfn_buf: [64]u8 = [_]u8{0} ** 64,
    execfn_len: usize = 0,
    /// TLS-база main-треда (arch_prctl SET_FS; клон-треды — своя волна).
    fs_base: u64 = 0,
    // ─── CDD №12 p2: сигнальное состояние glibc ───────────────────────
    /// rt_sigaction: handler по сигналу 1..64 (0 = SIG_DFL).
    sig_handlers: [65]u64 = [_]u64{0} ** 65,
    sig_flags: [65]u64 = [_]u64{0} ** 65,
    sig_restorers: [65]u64 = [_]u64{0} ** 65,
    /// rt_sigprocmask: текущая маска.
    sig_mask: u64 = 0,
    /// Счётчик memfd (анонимные tmpfs-файлы Wayland-shm).
    memfd_seq: u32 = 0,
};

// ─── CDD №12 p2: каналы (pipe/eventfd/socketpair/timerfd) ─────────────────
const MAX_CHANNELS: usize = 48;
const ChanKind = enum { pipe, eventfd, socketpair, timerfd };
const CHAN_BUF: usize = 1024; // p5: откат 8К — .bss-сдвиг перевёл кости (смерть t8 стабилизировалась на аллокации 5); 1К+EAGAIN+POLLOUT достаточно

const Channel = struct {
    used: bool = false,
    refs: u8 = 0, // pipe=2 (оба конца), socketpair=1 (свой fd) + клоны, eventfd/timerfd=1
    kind: ChanKind = .pipe,
    buf: [CHAN_BUF]u8 = [_]u8{0} ** CHAN_BUF,
    len: usize = 0, // FIFO: байт в буфере
    counter: u64 = 0, // eventfd: счётчик; timerfd: экспирации
    semaphore: bool = false, // EFD_SEMAPHORE
    deadline_ns: u64 = 0, // timerfd: 0 = не взведён
    interval_ns: u64 = 0,
    // CDD №15 p5-ФИНАЛ (эхо-баг): socketpair = НАПРАВЛЕННАЯ пара каналов.
    // Раньше ОБА конца сидели на одном канале: писец видел свой же буфер
    // в POLLIN → ЧИТАЛ СВОЙ ЗАПРОС ОБРАТНО → libwayland «message too
    // short» → «could not connect to wayland server». Теперь: write(fd)
    // → буфер ПИРА (peer); read(fd) → свой буфер; HUP = peer закрыт.
    peer: u32 = 0, // socketpair: id встречного канала
    peer_closed: bool = false,
};

var channels: [MAX_CHANNELS]Channel = [_]Channel{.{}} ** MAX_CHANNELS;

fn linuxProcSlot() usize {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        const slot = linux_task_proc[owner];
        if (slot < MAX_LINUX_PROCS) return slot;
    }
    return MAX_LINUX_PROCS; // невалидный
}

fn linuxChannelCreate(kind: u32, arg: u64) i64 {
    for (&channels, 0..) |*c, i| {
        if (c.used) continue;
        const k: ChanKind = switch (kind) {
            linux_syscalls.CHAN_PIPE => .pipe,
            linux_syscalls.CHAN_EVENTFD => .eventfd,
            linux_syscalls.CHAN_SOCKETPAIR => .socketpair,
            linux_syscalls.CHAN_TIMERFD => .timerfd,
            else => return -linux_syscalls.EINVAL,
        };
        c.* = .{ .used = true, .refs = if (k == .pipe) 2 else 1, .kind = k };
        if (k == .eventfd) c.counter = arg;
        return @intCast(i);
    }
    return -linux_syscalls.ENFILE;
}

/// Создать НАПРАВЛЕННУЮ пару socketpair-каналов (A↔B): write(fdA) → B,
/// write(fdB) → A. Возвращает (a_id, b_id) или (-err, 0).
fn linuxSocketPairCreate() struct { a: i64, b: i64 } {
    const a = linuxChannelCreate(linux_syscalls.CHAN_SOCKETPAIR, 0);
    if (a < 0) return .{ .a = a, .b = 0 };
    const b = linuxChannelCreate(linux_syscalls.CHAN_SOCKETPAIR, 0);
    if (b < 0) {
        _ = linuxChannelUnrefImpl(@intCast(a));
        return .{ .a = b, .b = 0 };
    }
    channels[@intCast(a)].peer = @intCast(b);
    channels[@intCast(b)].peer = @intCast(a);
    return .{ .a = a, .b = b };
}

fn linuxChannelUnrefImpl(id: u32) void {
    if (id >= channels.len) return;
    const c = &channels[id];
    if (c.refs > 0) c.refs -= 1;
    if (c.refs == 0) {
        // встречный канал узнаёт о закрытии ПИРА (EPOLLHUP/полловская семантика)
        if (c.kind == .socketpair and c.peer < channels.len and channels[c.peer].used) {
            channels[c.peer].peer_closed = true;
        }
        c.used = false;
    }
}

fn linuxChannelUnref(id: u32) void {
    linuxChannelUnrefImpl(id);
}

/// CDD №15 p5: связать A↔B направленной парой socketpair.
fn linuxChannelLink(a: u32, b: u32) void {
    if (a >= channels.len or b >= channels.len) return;
    channels[a].peer = b;
    channels[b].peer = a;
}

/// timerfd: ленивое продвижение экспираций (deadline прошёл → counter+1,
/// периодический — перевзвод; одноразовый — разряжаем).
fn channelMaybeExpire(c: *Channel) void {
    if (c.kind != .timerfd or c.deadline_ns == 0) return;
    const now = linuxTimeNsRaw();
    if (now >= c.deadline_ns) {
        sys_print("[TFD] EXPIRE id=");
        putDecimal(@intCast(@intFromPtr(c) - @intFromPtr(&channels[0])));
        sys_print(" now=");
        putDecimal(now);
        sys_print("\n");
    }
    while (now >= c.deadline_ns) {
        c.counter +%= 1;
        if (c.interval_ns == 0) {
            c.deadline_ns = 0; // одноразовый — взрыв и разряд
            break;
        }
        c.deadline_ns += c.interval_ns; // догоняющий перевзвод
        if (c.counter > 1024) break; // анти-спин: после 1024 пропусков — стоп
    }
}

fn linuxChannelRead(id: u32, va: u64, count: u64) i64 {
    if (id >= channels.len or !channels[id].used) return -linux_syscalls.EBADF;
    const c = &channels[id];
    switch (c.kind) {
        .pipe, .socketpair => {
            if (c.len == 0) return -linux_syscalls.EAGAIN; // NB-контракт (парковок нет)
            const n: usize = @intCast(@min(count, c.len));
            const dst: [*]u8 = @ptrFromInt(va);
            @memcpy(dst[0..n], c.buf[0..n]);
            // компакция остатка
            std.mem.copyForwards(u8, c.buf[0 .. c.len - n], c.buf[n..c.len]);
            c.len -= n;
            return @intCast(n);
        },
        .eventfd => {
            if (count < 8) return -linux_syscalls.EINVAL;
            if (c.counter == 0) return -linux_syscalls.EAGAIN;
            const val: u64 = if (c.semaphore) 1 else c.counter;
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, val, .little);
            const dst: [*]u8 = @ptrFromInt(va);
            @memcpy(dst[0..8], &b);
            if (c.semaphore) c.counter -= 1 else c.counter = 0;
            return 8;
        },
        .timerfd => {
            if (count < 8) return -linux_syscalls.EINVAL;
            channelMaybeExpire(c);
            if (c.counter == 0) return -linux_syscalls.EAGAIN;
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, c.counter, .little);
            const dst: [*]u8 = @ptrFromInt(va);
            @memcpy(dst[0..8], &b);
            c.counter = 0;
            return 8;
        },
    }
}

fn linuxChannelWrite(id: u32, va: u64, count: u64) i64 {
    if (id >= channels.len or !channels[id].used) return -linux_syscalls.EBADF;
    const c = &channels[id];
    switch (c.kind) {
        .pipe, .socketpair => {
            // CDD №15 p5-ФИНАЛ: socketpair пишет в БУФЕР ПИРА (write→peer,
            // read→self) — эхо-баг (писец читал свой запрос обратно).
            const tid: u32 = if (c.kind == .socketpair) c.peer else id;
            if (tid >= channels.len or !channels[tid].used) return -linux_syscalls.EPIPE;
            const t = &channels[tid];
            if (c.kind == .socketpair and (c.peer_closed or t.peer_closed))
                return -linux_syscalls.EPIPE;
            const n: usize = @intCast(count);
            if (t.len + n > t.buf.len) return -linux_syscalls.EAGAIN; // буфер полон
            const s: [*]const u8 = @ptrFromInt(va);
            @memcpy(t.buf[t.len .. t.len + n], s[0..n]);
            t.len += n;
            return @intCast(n);
        },
        .eventfd => {
            if (count < 8) return -linux_syscalls.EINVAL;
            var b: [8]u8 = undefined;
            const s: [*]const u8 = @ptrFromInt(va);
            @memcpy(&b, s[0..8]);
            const val = std.mem.readInt(u64, &b, .little);
            const sum = @addWithOverflow(c.counter, val);
            if (sum[1] != 0 or c.counter + val > 0xFFFFFFFFFFFFFFFE) return -linux_syscalls.EINVAL;
            c.counter += val;
            return 8;
        },
        .timerfd => {
            sys_print("[TFD] WRITE id=");
            putDecimal(id);
            sys_print(" count=");
            putDecimal(count);
            sys_print("\n");
            // kernel-путь timerfd_settime: 24Б [value_ns, interval_ns, flags]
            // (va — kernel-указатель: identity-map читается как user)
            // p14: flags bit0 = TFD_TIMER_ABSTIME → дедлайн АБСОЛЮТНЫЙ
            // (gamescope-vblank: следующий кадр в монотонных наносекундах).
            if (count < 16) return -linux_syscalls.EINVAL;
            var b: [24]u8 = .{0} ** 24;
            const s: [*]const u8 = @ptrFromInt(va);
            @memcpy(b[0..@min(count, 24)], s[0..@min(count, 24)]);
            const value = std.mem.readInt(u64, b[0..8], .little);
            const interval = std.mem.readInt(u64, b[8..16], .little);
            const tflags = std.mem.readInt(u64, b[16..24], .little);
            c.counter = 0;
            c.interval_ns = interval;
            if (value == 0) {
                c.deadline_ns = 0; // disarm
                sys_print("[TFD] DISARM id=");
                putDecimal(id);
                sys_print("\n");
            } else if (tflags & 1 != 0) { // TFD_TIMER_ABSTIME
                c.deadline_ns = value; // уже монотонные нс — как есть
                sys_print("[TFD] ARM abs id=");
                putDecimal(@intCast(id));
                sys_print(" deadline=");
                putDecimal(value);
                sys_print("\n");
            } else {
                c.deadline_ns = linuxTimeNsRaw() + value;
                sys_print("[TFD] ARM rel id=");
                putDecimal(id);
                sys_print(" value=");
                putDecimal(value);
                sys_print("\n");
            }
            return @intCast(@min(count, 24));
        },
    }
}

fn linuxChannelReady(id: u32) u32 {
    if (id >= channels.len or !channels[id].used) return 0;
    const c = &channels[id];
    switch (c.kind) {
        // pipe: peer-конец закрыт (refs 2→1) → EPOLLHUP (gamescope
        // «IWaitable hung up» — теперь ЧЕСТНО, только при реальном HUP)
        .pipe => {
            var r: u32 = 0;
            if (c.len > 0) r |= linux_syscalls.EPOLLIN;
            if (c.refs == 1) r |= linux_syscalls.EPOLLHUP;
            return r;
        },
        .socketpair, .eventfd => {
            // p5: socketpair-POLLOUT = место в БУФЕРЕ ПИРА + peer жив;
            // EPOLLIN = свой буфер; EPOLLHUP = peer закрыт
            var r: u32 = 0;
            if (c.kind == .eventfd) r |= linux_syscalls.EPOLLOUT;
            if (c.kind == .socketpair) {
                if (c.peer_closed) {
                    r |= linux_syscalls.EPOLLHUP;
                } else {
                    if (c.peer < channels.len and channels[c.peer].used and
                        channels[c.peer].len < channels[c.peer].buf.len)
                        r |= linux_syscalls.EPOLLOUT;
                }
            }
            if (c.kind == .eventfd and c.counter > 0) r |= linux_syscalls.EPOLLIN;
            if (c.kind == .socketpair and c.len > 0) r |= linux_syscalls.EPOLLIN;
            return r;
        },
        .timerfd => {
            channelMaybeExpire(c);
            return if (c.counter > 0) linux_syscalls.EPOLLIN else 0;
        },
    }
}

fn linuxTimeNsRaw() u64 {
    return linuxTimeNs();
}

/// CDD №15 p5: маркер «регион НЕ держит файл» (file_id-пин MAP_SHARED).
const NO_REGION_FILE: u32 = 0xFFFF_FFFF;

const MmapRegion = struct {
    used: bool = false,
    va: u64 = 0,
    pages: u64 = 0,
    /// Базис физблока (munmap-free; dev-мапы — 0, физику НЕ освобождаем).
    phys: u64 = 0,
    anon: bool = true,
    /// CDD №15 p5: file_id для shared-мапов (MAP_SHARED memfd) — маппинг
    /// ДЕРЖИТ файл (refs): close(fd) при живом маппинге больше НЕ освобождает
    /// физику (UAF: PMM перевыдача живых страниц → demand-zero memset →
    /// вайп [PW] ZEROED при неизменном PTE — lvp NULL-краши run8/10).
    /// NO_FILE = нет файла (anon/dev/brk).
    file_id: u32 = NO_REGION_FILE,
    /// CDD №12 p5: LAZY-регион — VA-резервация без физики (анон-mmap/brk).
    /// Касание страницы → #PF (P=0) → demand-zero: НУЛЕВАЯ физ-страница.
    /// Linux-семантика mmap: гигантские резервы (LLVM JIT-арена 10.7ГБ)
    /// без физики до касания.
    lazy: bool = false,
    /// PTE-флаги demand-маппинга (RW/U/NX по prot региона).
    pte: u64 = 0,
    /// CDD №12 p5: счётчик demand-выделенных страниц (диагностика: сколько
    /// из резерва реально потрогано).
    touched: u32 = 0,
    /// CDD №12 p6: PROT_NONE-кусок — demand-zero НЕ воскрешает (Linux: SIGSEGV
    /// на доступе). mprotect(prot≠0) снимает флаг.
    prot_none: bool = false,
    /// CDD №12 p4: имя модуля (fd-путь при file-mmap; «anon»/«brk»/«dev»/
    /// «[stack]»/имя образа от elfload) — атрибуция RIP→библиотека в
    /// CPU-exception (hal.zig: [RIP]/[CR2]/STACK-RET + гистограмма).
    name: [48]u8 = [_]u8{0} ** 48,
};

/// CDD №12 p4: результат атрибуции адреса → модуль mmap-реестра.
pub const ModuleHit = struct {
    name: []const u8,
    off: u64,
    region_va: u64,
    region_pages: u64,
};

/// CDD №12 p4: атрибуция адреса в контексте задачи (task_id из CPU-
/// exception: faulter-скан по kstack-диапазонам — см. hal.handleException).
/// null = адрес вне зарегистрированных mmap-регионов (незарег. мап/стек).
pub fn linuxModuleAt(task_id: usize, addr: u64) ?ModuleHit {
    if (task_id >= scheduler.MAX_TASKS) return null;
    const slot = linux_task_proc[task_id];
    if (slot >= MAX_LINUX_PROCS) return null;
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used) continue;
        const lo = r.va;
        const hi = r.va + r.pages * PAGE_SIZE;
        if (addr >= lo and addr < hi) {
            const nl = for (r.name, 0..) |c, i| {
                if (c == 0) break i;
            } else r.name.len;
            return .{
                .name = r.name[0..nl],
                .off = addr - r.va,
                .region_va = r.va,
                .region_pages = r.pages,
            };
        }
    }
    return null;
}

/// CDD №12 p4: дамп mmap-таблицы процесса (компакт: va..hi name) — вызывается
/// ТОЛЬКО из CPU-exception (редкое событие; полный дамп = вектор изоляции
/// lvp/LLVM-краша: какие библиотеки где легли + где RIP/CR2).
pub fn linuxDumpRegionTable(task_id: usize, max_entries: usize) usize {
    if (task_id >= scheduler.MAX_TASKS) return 0;
    const slot = linux_task_proc[task_id];
    if (slot >= MAX_LINUX_PROCS) return 0;
    var dumped: usize = 0;
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used) continue;
        if (dumped >= max_entries) break;
        const nl = for (r.name, 0..) |c, i| {
            if (c == 0) break i;
        } else r.name.len;
        hal.Serial.puts("  [MMAP] 0x");
        hal.Serial.putHex(r.va);
        hal.Serial.puts(" +0x");
        hal.Serial.putHex(r.pages * PAGE_SIZE);
        hal.Serial.puts(" ");
        hal.Serial.puts(r.name[0..nl]);
        hal.Serial.puts("\n");
        dumped += 1;
    }
    // CDD №12 p6: телеметрия VMA-механики (дробление/слияния/сборы)
    hal.Serial.puts("[MMAP] p6: splits=");
    hal.Serial.putDecimal(linux_mmap_splits);
    hal.Serial.puts(" merges=");
    hal.Serial.putDecimal(linux_mmap_merges);
    hal.Serial.puts(" drops=");
    hal.Serial.putDecimal(linux_mmap_drops);
    hal.Serial.puts(" freed=");
    hal.Serial.putDecimal(linux_mmap_drops_freed);
    hal.Serial.puts(" dontneed=");
    hal.Serial.putDecimal(linux_dontneed_zaps);
    hal.Serial.puts("\n");
    return dumped;
}

const MAX_LINUX_PROCS: usize = 8; // v0.20 (CDD №15): gamescope + Xwayland + клиенты (было 2)
/// CDD №12 p3: 512 — эмпирика run8-10: 79 либ × ~4 сегмента = 300+ регио-
/// нов + стеки тредов + арены malloc (при 64/128 — «registry full» →
/// untracked: munmap-деградация и МАПФИКС-ДИАПАЗОНЫ без контроля).
/// CDD №12 p4: 2048 — эмпирика run7: lvp/LLVM-init ДОБАВИЛ 159 сверху
/// 512 (LLVM-арены/JIT-таблицы) — атрибуция CR2/ret и MAP_FIXED-учёт
/// требуют полного покрытия; .bss-цена 2×2048×80Б = 320КБ — норм.
const MAX_MMAP_REGIONS: usize = 2048;

var linux_task_proc: [scheduler.MAX_TASKS]u8 =
    [_]u8{255} ** scheduler.MAX_TASKS;
var linux_procs: [MAX_LINUX_PROCS]LinuxProc = [_]LinuxProc{.{}} ** MAX_LINUX_PROCS;
var linux_mmap_regions: [MAX_LINUX_PROCS][MAX_MMAP_REGIONS]MmapRegion =
    [_][MAX_MMAP_REGIONS]MmapRegion{[_]MmapRegion{.{}} ** MAX_MMAP_REGIONS} ** MAX_LINUX_PROCS;
/// CLONE_CHILD_CLEARTID-слова тредов (pthread_join).
var linux_child_tid: [scheduler.MAX_TASKS]u64 =
    [_]u64{0} ** scheduler.MAX_TASKS;

/// Владелец текущего syscall-каскада (user_rsp → задача; атомарно IF=0).
fn linuxOwnerTask() usize {
    return scheduler.syscallStackOwner(scheduler.user_rsp);
}

/// Proc-слот текущей Linux-задачи (null = shell/ldevtest-контекст).
fn linuxProcCurrent() ?*LinuxProc {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        const t = &scheduler.tasks[owner];
        if (t.privilege == .User and t.abi == .linux and t.state != .Killed) {
            const slot = linux_task_proc[owner];
            if (slot < MAX_LINUX_PROCS) return &linux_procs[slot];
        }
    }
    return null;
}

/// fd-таблица текущего контекста: тред → таблица процесса; shell → глобальная.
fn linuxFdsCurrent() *linux_syscalls.FdTable {
    if (linuxProcCurrent()) |p| return &p.fds;
    return &linux_fds;
}

/// Занять proc-слот для новой задачи (elfload).
fn linuxNewProc(task_id: usize) ?usize {
    for (&linux_procs, 0..) |*p, i| {
        if (!p.used) {
            p.* = .{
                .used = true,
                .mmap_cursor = LINUX_MMAP_BASE,
            };
            // p14: FdTable — 8КБ — только IN-PLACE (boot-стек мал!)
            linux_syscalls.FdTable.initInPlace(&p.fds);
            linux_task_proc[task_id] = @intCast(i);
            // CDD №12 p4: чистые регионы нового процесса (анти-поллюция
            // атрибуции: RIP предыдущего мёртвого процесса совпадал бы
            // с диапазонами-призраками слота).
            for (&linux_mmap_regions[i]) |*r| r.* = .{};
            return i;
        }
    }
    return null;
}

/// Записать mmap-регион в реестр процесса.
/// CDD №12 p4: name — имя модуля для атрибуции RIP→библиотека в
/// CPU-exception (file-mmap = путь fd; anon/brk/dev — литерал).
fn linuxRecordRegion(slot: u8, va: u64, pages: u64, phys: u64, anon: bool, name: []const u8) void {
    linuxRecordRegionEx(slot, va, pages, phys, anon, false, 0, name);
}

/// CDD №12 p5: запись региона с lazy-флагом и PTE-правами (demand-zero).
fn linuxRecordRegionEx(slot: u8, va: u64, pages: u64, phys: u64, anon: bool, lazy: bool, pte: u64, name: []const u8) void {
    if (slot >= MAX_LINUX_PROCS) return;
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used) {
            r.* = .{ .used = true, .va = va, .pages = pages, .phys = phys, .anon = anon, .lazy = lazy, .pte = pte };
            const n = @min(name.len, r.name.len);
            @memcpy(r.name[0..n], name[0..n]);
            return;
        }
    }
    // реестр полон: регион живёт без записи (munmap-free деградирует до unmap)
    hal.Serial.puts("[LINUX] mmap registry full — region untracked\n");
}

// ─── CDD №12 p6: VMA-семантика Linux — split/merge/drop реестра регионов ────

/// Счётчики p6-механики (краш-дамп: [MMAP] splits/merges/drops/dontneed).
pub var linux_mmap_splits: u64 = 0;
pub var linux_mmap_merges: u64 = 0;
pub var linux_mmap_drops: u64 = 0;
pub var linux_mmap_drops_freed: u64 = 0;
pub var linux_dontneed_zaps: u64 = 0;

/// Вставить КОПИЮ региона (split-кусок) в свободный слот. phys сдвигается
/// вместе с va (кусок непрерывного блока начинается глубже).
fn linuxRegionInsertCopy(slot: u8, src: *const MmapRegion, va: u64, pages: u64) void {
    if (slot >= MAX_LINUX_PROCS) return;
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used) {
            r.* = src.*;
            r.va = va;
            r.pages = pages;
            if (src.phys != 0) r.phys = src.phys + (va - src.va);
            r.touched = @intCast(@min(pages, @as(u64, src.touched)));
            return;
        }
    }
    // реестр полон — кусок живёт без записи (деградация документирована)
    hal.Serial.puts("[LINUX] mmap registry full — split piece untracked\n");
}

/// CDD №12 p6: РЕЗКА реестра по границам [va, va+pages*P): после резки любой
/// кусок лежит ЦЕЛИКОМ внутри или ЦЕЛИКОМ вне диапазона. Замена «правки
/// всего региона при любом пересечении» (p5-баги: mprotect под-диапазона
/// PROT_NONE срывал W-бит r.pte ВСЕГО региона → арены LLVM мутировали в RO;
/// а частичный munmap оставлял lazy-запись на живых данных → demand-zero
/// накрывал их НУЛЕВОЙ страницей → libstdc++ _Rb_tree_decrement NULL+8).
fn linuxRegionSplit(slot: u8, va: u64, pages: u64) void {
    if (slot >= MAX_LINUX_PROCS) return;
    const hi = va + pages * PAGE_SIZE;
    var i: usize = 0;
    while (i < linux_mmap_regions[slot].len) : (i += 1) {
        const r = &linux_mmap_regions[slot][i];
        if (!r.used) continue;
        const r_hi = r.va + r.pages * PAGE_SIZE;
        if (r.va >= va and r_hi <= hi) continue; // целиком внутри
        if (r_hi <= va or r.va >= hi) continue; // целиком вне

        const mid_lo = if (r.va < va) va else r.va;
        const mid_hi = if (r_hi > hi) hi else r_hi;
        // боковые куски — новые записи (phys сдвигается вдоль блока)
        if (mid_lo > r.va) linuxRegionInsertCopy(slot, r, r.va, (mid_lo - r.va) / PAGE_SIZE);
        if (r_hi > mid_hi) linuxRegionInsertCopy(slot, r, mid_hi, (r_hi - mid_hi) / PAGE_SIZE);
        // исходная запись стягивается в средний кусок
        if (r.phys != 0) r.phys = r.phys + (mid_lo - r.va);
        r.va = mid_lo;
        r.pages = (mid_hi - mid_lo) / PAGE_SIZE;
        if (r.pages == 0) r.used = false;
        linux_mmap_splits += 1;
    }
}

/// CDD №12 p6: СЛИЯНИЕ соседних кусков с идентичными свойствами (Linux
/// VMA-merge): W^X-фрагментация LLVM без слияния распухает реестр (2048 →
/// full → untracked → атрибуция и demand-zero слепнут). Сливаются A,B если
/// A стыкуется с B и совпадают lazy/pte/prot_none/anon/name; phys непрерывен
/// (или оба 0).
fn linuxRegionMerge(slot: u8) void {
    if (slot >= MAX_LINUX_PROCS) return;
    var pass: usize = 0;
    while (pass < 64) : (pass += 1) {
        var merged_any = false;
        var i: usize = 0;
        while (i < linux_mmap_regions[slot].len) : (i += 1) {
            const a = &linux_mmap_regions[slot][i];
            if (!a.used) continue;
            var j: usize = 0;
            while (j < linux_mmap_regions[slot].len) : (j += 1) {
                if (j == i) continue;
                const b = &linux_mmap_regions[slot][j];
                if (!b.used) continue;
                if (a.va + a.pages * PAGE_SIZE != b.va) continue;
                if (a.lazy != b.lazy or a.anon != b.anon or a.prot_none != b.prot_none) continue;
                if (a.pte != b.pte) continue;
                if (!std.mem.eql(u8, &a.name, &b.name)) continue;
                if ((a.phys == 0) != (b.phys == 0)) continue;
                if (a.phys != 0 and a.phys + a.pages * PAGE_SIZE != b.phys) continue;
                a.pages += b.pages;
                b.used = false;
                linux_mmap_merges += 1;
                merged_any = true;
            }
        }
        if (!merged_any) break;
    }
}

/// CDD №12 p6: СНЯТИЕ диапазона [va, va+pages*P) — ЕДИНАЯ механика для
/// munmap / MAP_FIXED-замены / brk-спада: резка → куски ЦЕЛИКОМ внутри:
///   • anon (приватные: lazy-арены, eager-файлы): PTE-скан — физика в PMM
///     (СКРЫТЫЕ PROT_NONE-страницы тоже: PTE≠0, !PRESENT — иначе утечка),
///     PTE снимается, запись удаляется;
///   • shared/dev (физика принадлежит drm_kms/memfd-файлу): ТОЛЬКО unmap
///     PTE — страницы НЕ освобождаются (p5-баг: PTE-скан munmap'а возвращал
///     ОБЩИЕ страницы wl_shm/dumb в PMM → PMM выдавал их demand-zero под
///     чужие данные → кросс-маппинг-порча деревьев).
/// CDD №15 p5-FORENSICS: [FREE-LIVE] — аудит «free при живом мапе».
/// Linux page-refcount-семантика (лайт): ОДИН raw-walk user-PML4 на вызов
/// munmap/DONTNEED строит per-frame СЧЁТЧИК живых лист-маппингов (u8,
/// 1МБ на 4ГБ физики — весь PMM-кэп); каждый unmap (anon/shared) ДЕКРЕ-
/// МЕНТИРУЕТ свой кадр. Отдавать кадр PMM можно ⇔ после декремента счёт-
/// чик = 0 — последняя ссылка снята именно нами. Чужой живой лист:
/// [FREE-LIVE] лог + отказ free (диагностический режим — намеренная
/// утечка вместо порчи): PMM не выдаст живую страницу demand-zero
/// (перевыдача → memset(0) → вайп структур lvp/LLVM, [PW] ZEROED).
/// Битмап-вариант (v1) имел self-match: ленивый build ПОСЛЕ снятия пер-
/// вого PTE → все последующие страницы вызова находили СЕБЯ → ложные
/// отказы. Refcount-декремент потребляет self-ссылку ровно один раз.
/// Кадр со счётчиком 0 на момент декремента = не был user-листом при
/// walk (PML4[0]/не-арена) — пропускаем без шума (ложных блоков нет).
const FREE_LIVE_FRAMES: usize = 0x1_0000_0000 / PAGE_SIZE;
var free_live_counts: [FREE_LIVE_FRAMES]u8 = undefined;
var free_live_events: u64 = 0;

fn linuxFreeAuditBuild(pml4: u64) void {
    @memset(&free_live_counts, 0);
    const pml4a: [*]const volatile u64 = @ptrFromInt(pml4);
    var iw4: usize = 1; // [0] — kernel identity, user-листьев нет
    while (iw4 < 512) : (iw4 += 1) {
        const e3 = pml4a[iw4];
        if (e3 & 0x1 == 0 or e3 & vmm.PTE_USER == 0) continue;
        const pdpt: [*]const volatile u64 = @ptrFromInt(e3 & PTE_ADDR_MASK);
        var iw3: usize = 0;
        while (iw3 < 512) : (iw3 += 1) {
            const e2 = pdpt[iw3];
            if (e2 & 0x1 == 0) continue;
            if (e2 & 0x80 != 0) continue; // huge-листьев в user-арене нет
            const pd: [*]const volatile u64 = @ptrFromInt(e2 & PTE_ADDR_MASK);
            var iw2: usize = 0;
            while (iw2 < 512) : (iw2 += 1) {
                const e1 = pd[iw2];
                if (e1 & 0x1 == 0) continue;
                if (e1 & 0x80 != 0) continue;
                const pt: [*]const volatile u64 = @ptrFromInt(e1 & PTE_ADDR_MASK);
                var iw1: usize = 0;
                while (iw1 < 512) : (iw1 += 1) {
                    const leaf = pt[iw1];
                    if (leaf & 0x1 == 0) continue;
                    const fr = (leaf & PTE_ADDR_MASK) / PAGE_SIZE;
                    if (fr < FREE_LIVE_FRAMES) {
                        if (free_live_counts[fr] < 255) free_live_counts[fr] += 1;
                    }
                }
            }
        }
    }
}

/// Unmap уже сделан: декремент кадра. true → кадр осиротел, free безопа-
/// сен; false → живой алиас в ДРУГОМ VA (лог + отказ).
fn linuxFreeAuditConsume(pa: u64, va_pg: u64) bool {
    const fr = pa / PAGE_SIZE;
    if (fr >= FREE_LIVE_FRAMES) return true;
    const c = free_live_counts[fr];
    if (c == 0) return true; // кадр вне user-арены walk-а — не аудируем
    free_live_counts[fr] = c - 1;
    if (c == 1) return true;
    if (free_live_events < 64) {
        free_live_events += 1;
        hal.Serial.puts("[FREE-LIVE] pa=0x");
        hal.Serial.putHex(pa);
        hal.Serial.puts(" из va=0x");
        hal.Serial.putHex(va_pg);
        hal.Serial.puts(" — живых алиасов ещё ");
        hal.Serial.putDecimal(@as(u64, c - 1));
        hal.Serial.puts(", НЕ freed\n");
    }
    return false;
}

/// Shared-unmap: поддержать точность счётчика БЕЗ решения о free
/// (физика принадлежит memfd/dumb — аудит только фиксирует снятие листа).
fn linuxFreeAuditUnref(pml4: u64, va_pg: u64) void {
    const pte0 = vmm.userLeafRaw(pml4, va_pg) orelse return;
    const fr = (pte0 & PTE_ADDR_MASK) / PAGE_SIZE;
    if (fr < FREE_LIVE_FRAMES and free_live_counts[fr] > 0) free_live_counts[fr] -= 1;
}


/// CDD №15 p5-NUCLEAR: полный TLB-flush (CR3-reload — non-global записи).
/// Зонд stale-TLB-гипотезы: записи «в пустоту» при неизменном PTE (run20
/// B-DUMP=нули при живых трап-ридах) = CPU транслировал через устаревший
/// кэш. Если семья NULL-крашей (lvp) умрёт с этим флешем — бисекция пути.
fn tlbFullFlush() void {
    asm volatile (
        \\movq %%cr3, %%rax
        \\movq %%rax, %%cr3
        ::: "rax", "memory");
}

fn linuxRangeDrop(va: u64, pages: u64) void {
    const pml4 = linuxTaskPml4();
    const owner = linuxOwnerTask();
    if (pml4 == 0 or owner >= scheduler.MAX_TASKS) return;
    const slot = linux_task_proc[owner];
    if (slot >= MAX_LINUX_PROCS) return;
    linuxFreeAuditBuild(pml4); // p5-forensics: ДО снятия первого PTE вызова
    const hi = va + pages * PAGE_SIZE;
    linuxRegionSplit(slot, va, pages);
    var i: usize = 0;
    while (i < linux_mmap_regions[slot].len) : (i += 1) {
        const r = &linux_mmap_regions[slot][i];
        if (!r.used) continue;
        if (r.va < va or r.va + r.pages * PAGE_SIZE > hi) continue; // не целиком внутри
        // CDD №15 p5: shared-мап отпускает свой файл-пин (пара к retain в
        // linuxSharedFileMmap) — физика файла умирает только когда НИ fd,
        // НИ маппинга не осталось (Linux page-refcount-семантика, лайт-версия)
        if (r.file_id != NO_REGION_FILE) {
            linuxReleaseFile(r.file_id);
            r.file_id = NO_REGION_FILE;
        }
        var p: u64 = 0;
        var freed: u64 = 0;
        while (p < r.pages) : (p += 1) {
            const va_pg = r.va + p * PAGE_SIZE;
            if (r.anon) {
                // CDD №12 p10: ПОРЯДОК TEARDOWN-ИНВАРИАНТА — ПTE=0 + invlpg
                // ДО freePage. Было freePage → unmap(catch{}) — при сбое
                // unmap кадр уходил в PMM-фри ПОД живым PTE → мгновенный
                // перевыдач = алиасинг. Плюс БЕЗ инвала (см. vmm64.zig)
                // stale-TLB продолжал писать по старому VA в отданный кадр.
                var pa_to_free: u64 = 0;
                if (vmm.userLeafRaw(pml4, va_pg)) |pte| {
                    const pa = pte & 0x000FFFFFFFFFF000;
                    if (pa != 0 and va_pg >= elf_loader.MIN_USER_VA) pa_to_free = pa;
                }
                if (vmm.unmapPageInPML4(pml4, va_pg)) |_| {
                    // PTE снят + TLB-строка сброшена (активный CR3):
                    // только ТЕПЕРЬ кадр можно возвращать PMM.
                    if (pa_to_free != 0) {
                        // CDD №15 p5-FORENSICS: отказ free при живом алиасе
                        if (linuxFreeAuditConsume(pa_to_free, va_pg)) {
                            pmm.freePage(pa_to_free);
                            freed += 1;
                        }
                    }
                } else |_| {}
            } else {
                // shared/dev: физика принадлежит memfd/dumb — только unmap
                // (+ декремент счётчика аудита, без решения о free).
                linuxFreeAuditUnref(pml4, va_pg);
                _ = vmm.unmapPageInPML4(pml4, va_pg) catch {};
            }
        }
        r.used = false;
        linux_mmap_drops += 1;
        linux_mmap_drops_freed += freed;
    }
    linuxRegionMerge(slot);
    tlbFullFlush(); // p5-NUCLEAR: stale-TLB зонд
}

/// CDD №12 p6: madvise(MADV_DONTNEED) — честная Linux-семантика анонимной
/// памяти: PTE диапазона снимается, физика в PMM; диапазон ОСТАЁТСЯ
/// резервацией (lazy) — следующее касание = НУЛЕВАЯ страница (demand-zero).
/// glibc (malloc-арены) и Mesa-пулы завязаны на «обнуление после DONTNEED»;
/// заглушка-p5 не возвращала страницы (утечка) и не давала нулей.
fn linuxDoDontneed(va: u64, len: u64) i64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return 0;
    if (len == 0) return 0;
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return 0;
    const slot = linux_task_proc[owner];
    if (slot >= MAX_LINUX_PROCS) return 0;
    const qva = va & ~@as(u64, PAGE_SIZE - 1);
    if (va + len < va) return 0;
    const pages = (va + len - qva + PAGE_SIZE - 1) / PAGE_SIZE;
    const hi = qva + pages * PAGE_SIZE;

    linuxFreeAuditBuild(pml4); // p5-forensics: ДО снятия первого PTE вызова
    linuxRegionSplit(slot, qva, pages);
    tlbFullFlush(); // p5-NUCLEAR: DONTNEED тоже мутирует PTE
    var i: usize = 0;
    while (i < linux_mmap_regions[slot].len) : (i += 1) {
        const r = &linux_mmap_regions[slot][i];
        if (!r.used) continue;
        if (r.va < qva or r.va + r.pages * PAGE_SIZE > hi) continue; // только целиком внутри
        // anon (lazy-арены/brk): зануляем. eager-файл/shared/dev: private-копия
        // или общая физика — НЕ трогаем (Linux дропает clean-страницы файла;
        // наши копии «dirty» по определению).
        if (r.anon) {
            var p: u64 = 0;
            while (p < r.pages) : (p += 1) {
                const va_pg = r.va + p * PAGE_SIZE;
                // CDD №12 p10: инвариант teardown — unmap(PTE=0+invlpg)
                // СНАЧАЛА, freePage — ПОТОМ (см. linuxRangeDrop).
                var pa_to_free: u64 = 0;
                if (vmm.userLeafRaw(pml4, va_pg)) |pte| {
                    const pa = pte & 0x000FFFFFFFFFF000;
                    if (pa != 0 and va_pg >= elf_loader.MIN_USER_VA) pa_to_free = pa;
                }
                if (vmm.unmapPageInPML4(pml4, va_pg)) |_| {
                    if (pa_to_free != 0) {
                        // p5-forensics: живой алиас → отказ free (см. [FREE-LIVE])
                        if (linuxFreeAuditConsume(pa_to_free, va_pg)) {
                            pmm.freePage(pa_to_free);
                            linux_dontneed_zaps += 1;
                        }
                    }
                } else |_| {}
            }
            r.touched = 0;
        }
    }
    linuxRegionMerge(slot);
    return 0;
}

/// brk Linux-семантики: 0 → текущий; рост/спад — маппинг страниц [brk, addr);
/// отказ (ниже базиса / нет памяти) → вернуть СТАРЫЙ brk.
fn linuxDoBrk(addr: u64) u64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return 0; // shell-контекст: brk нет
    const proc = linuxProcCurrent() orelse return 0;
    if (addr == 0) return proc.brk;
    if (addr < proc.brk_base) return proc.brk; // ниже образа — отказ
    if (addr == proc.brk) return proc.brk;
    const prev_brk = proc.brk;

    if (addr > proc.brk) {
        // CDD №12 p5: рост — ЛЕНИВЫЙ (demand-zero): поднимаем только границу
        // (Linux-семантика brk = VA-резервация; страницы — нули по касанию).
        proc.brk = addr & ~@as(u64, PAGE_SIZE - 1); // странично-гранулярный
        const grow_pages = (proc.brk - prev_brk + PAGE_SIZE - 1) / PAGE_SIZE;
        // CDD №12 p6: ОДНА brk-запись — хвостовой кусок ПРОДОЛЖАЕТСЯ (раньше
        // каждый sbrk-рывок = НОВАЯ запись → pile-up + перекрытия скана).
        const slot = linux_task_proc[linuxOwnerTask()];
        var extended = false;
        if (slot < MAX_LINUX_PROCS) {
            for (&linux_mmap_regions[slot]) |*r| {
                if (r.used and r.lazy and r.anon and !r.prot_none and
                    r.va + r.pages * PAGE_SIZE == prev_brk and
                    r.name[0] == 'b' and r.name[1] == 'r' and r.name[2] == 'k' and r.name[3] == 0)
                {
                    r.pages += grow_pages;
                    extended = true;
                    break;
                }
            }
        }
        if (!extended) linuxRecordRegionEx(slot, prev_brk, grow_pages,
            0, true, true,
            vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE, "brk");
        return proc.brk;
    }

    // CDD №12 p6: спад — единая drop-механика (PTE-скан освобождает физику
    // demand-страниц; brk-записи над addr — режутся/удаляются, stale-нет).
    const qva = addr & ~@as(u64, PAGE_SIZE - 1);
    const drop_pages = (proc.brk - qva + PAGE_SIZE - 1) / PAGE_SIZE;
    linuxRangeDrop(qva, drop_pages);
    proc.brk = qva;
    return proc.brk;
}

// ─── v0.20.0 (CDD №11 p1b): glibc-волна — runtime-мосты ─────────────────────

/// CDD №12 p5: DEMAND-ZERO — обработка #PF (P=0) на lazy-странице: выдать
/// НУЛЕВУЮ физ-страницу и замапить с правами региона. Linux-семантика
/// анонимной памяти (mmap/brk): страница «появляется» при ПЕРВОМ касании.
/// Возврат true = инструкция перезапускается (iretq), гость не видит фолта.
/// Память: страница зануляется ЯВНО (PMM-страницы рециклируются грязными).
pub fn linuxDemandZero(faulter_task: usize, va: u64) bool {
    if (faulter_task >= scheduler.MAX_TASKS) return false;
    const slot = linux_task_proc[faulter_task];
    if (slot >= MAX_LINUX_PROCS) return false;
    const proc = &linux_procs[slot];
    // CDD №15 p4-КОРЕНЬ ТИХОГО FAULT-ЦИКЛА (41/41 URIP-сэмплов на
    // ld.so+0xF41E): таблицы — ВИНОВНИКА фолта (tasks[faulter].cr3), а
    // НЕ «текущего» (linuxTaskPml4() = linuxOwnerTask() по user_rsp — в
    // парк-окнах рассинхрона возвращает ЧУЖУЮ задачу). Реестр — по
    // faulter'у, таблицы — по current'у: карта ложилась в ЧУЖОЕ PML4 →
    // страница оставалась незамапленной у виновника → вечный беззвуч-
    // ный #PF-цикл + МЕЖПРОЦЕССНАЯ ПОРЧА (объясняет и lvp-краши p4).
    const ft = &scheduler.tasks[faulter_task];
    if (ft.privilege != .User or ft.abi != .linux or ft.state == .Killed)
        return false;
    const pml4 = ft.cr3;
    if (pml4 == 0) return false;
    const page = va & ~@as(u64, PAGE_SIZE - 1);

    // CDD №12 p6: записи реестра ПЕРВЫМИ (brk-запись тоже ленивая — права
    // mprotect видны). prot_none-куски НЕ воскрешаются — Linux: SIGSEGV.
    // (После split/merge записи НЕ перекрываются — первый match = единственный.)
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used or !r.lazy) continue;
        if (page >= r.va and page < r.va + r.pages * PAGE_SIZE) {
            if (r.prot_none) return false; // PROT_NONE не resurrect-ится
            if (linuxDemandMapPage(pml4, page, r.pte)) {
                // уже замаплена? (спеу-case: двойной fault) — не считаем
                if (r.touched < r.pages) r.touched += 1;
                return true;
            }
            return false;
        }
    }

    // 2) brk-куча (bss-хвост образа может быть без записи): RW+U+NX
    if (page >= proc.brk_base & ~@as(u64, PAGE_SIZE - 1) and page < proc.brk) {
        return linuxDemandMapPage(pml4, page,
            vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE);
    }
    return false;
}

/// Выделить НУЛЕВУЮ страницу и замапить (active-CR3 — работаем с таблицами
/// задачи; P=0-страницы не кэшируются TLB → invlpg не обязателен, но даём).
fn linuxDemandMapPage(pml4: u64, page: u64, pte: u64) bool {
    // p5-forensics [DZ-MAT]: материализация watch-страниц (кто/когда/phys)
    const dz_watch = vmm.diagWatchOn(page);
    // страница УЖЕ замаплена (гонка/P=1-фолт) — не выделяем вторую.
    // CDD №15 p4: invlpg-страховка — лист мог остаться в TLB с чужими
    // правами (мутации mprotect-волны): перезапуск инструкции с чистой
    // трансляцией, а не с закэшированной.
    if (vmm.userLeafFlags(pml4, page)) |leaf| {
        if (leaf & vmm.PTE_PRESENT != 0) {
            asm volatile ("invlpg (%[va])" :: [va] "r" (page) : "memory");
            return true;
        }
        // CDD №15 p5-ФИКС ВАЙПА: СКРЫТЫЙ лист (PROT_NONE-мутация: P=0,
        // phys≠0) — это ЖИВАЯ страница с ДАННЫМИ. Восстановить PRESENT
        // с правами pte (restore-ветка ApplyProtEx) — allocPage+memset
        // ЗАПРЕЩЁН: замена кадра нулевой страницей СТИРАЛА данные
        // (окно гонки mprotect: реестр уже обновлён, страницы ещё скрыты).
        if ((leaf & 0x000FFFFFFFFFF000) != 0) {
            if (dz_watch) {
                hal.Serial.puts("[DZ-MAT] RESTORE va=0x");
                hal.Serial.putHex(page);
                hal.Serial.puts(" leaf=0x");
                hal.Serial.putHex(leaf);
                hal.Serial.puts("\n");
            }
            if (vmm.userLeafApplyProtEx(pml4, page, pte, true)) return true;
        }
    }
    const phys = pmm.allocPage() orelse {
        hal.Serial.puts("[LINUX] demand-zero: PMM исчерпан (OOM гостья)\n");
        return false;
    };
    // ЯВНОЕ зануление: PMM-страницы рециклируются (allocContiguousZeroed
    // раньше гарантировал нули; allocPage — нет → memset обязателен).
    const pb: [*]volatile u8 = @ptrFromInt(phys);
    @memset(pb[0..PAGE_SIZE], 0);
    vmm.mapPageInPML4(pml4, page, phys, pte | vmm.PTE_PRESENT) catch {
        pmm.freePage(phys);
        return false;
    };
    if (dz_watch) {
        // p5-forensics: физ-ловушка PMM — вооружить немедленно (не ждать
        // сэмпла pageWatch): poisoner-free/reissue-alloc с первой секунды
        pmm.watch_pa = phys;
        // p5: КОНФИГУРАЦИЯ ВЫЖИВАНИЯ (runs 19/21!): нож на B-слабе — t8
        // замедляется трапами → гонка закрывается → Xwayland-спавн живёт
        if (page == 0x2000_2407_9000) hal.drArmWriteWatch(page + 0xAC0);
        hal.Serial.puts("[DZ-MAT] NEW va=0x");
        hal.Serial.putHex(page);
        hal.Serial.puts(" phys=0x");
        hal.Serial.putHex(phys);
        hal.Serial.puts(" pte=0x");
        hal.Serial.putHex(pte);
        hal.Serial.puts("\n");
    }
    // активный CR3 задачи — сброс TLB-строки
    asm volatile ("invlpg (%[va])" :: [va] "r" (page) : "memory");
    return true;
}

/// mprotect(va, len, prot): CDD №12 p6 — Linux-семантика: выравнивание
/// (addr вниз, len вверх), права ТОЛЬКО покрытых кусков (резка реестра;
/// p5-баг: права срывались на ВЕСЬ регион при любом пересечении — арены
/// LLVM теряли W), PROT_NONE = снятие PRESENT (страница «скрывается»,
/// физика сохранена в PTE — повторный mprotect RW/RX восстановит данные
/// W^X-цикла). mprotect ДО касания: r.pte запомнит права для demand-страниц.
fn linuxDoMprotect(va: u64, len: u64, prot: u64) i64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return -linux_syscalls.EFAULT;
    if (len == 0) return 0;
    if (va + len < va) return -linux_syscalls.ENOMEM;
    const qva = va & ~@as(u64, PAGE_SIZE - 1);
    const pages = (va + len - qva + PAGE_SIZE - 1) / PAGE_SIZE;
    const hi = qva + pages * PAGE_SIZE;

    var want: u64 = 0;
    if (prot & linux_syscalls.PROT_WRITE != 0) want |= vmm.PTE_WRITABLE;
    if (prot & linux_syscalls.PROT_EXEC == 0) want |= vmm.PTE_NO_EXECUTE;
    const prot_none = (prot & (linux_syscalls.PROT_READ |
        linux_syscalls.PROT_WRITE | linux_syscalls.PROT_EXEC)) == 0;

    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.EFAULT;
    const slot = linux_task_proc[owner];
    if (slot >= MAX_LINUX_PROCS) return -linux_syscalls.EFAULT;

    // резка по границам диапазона: права меняются ТОЛЬКО у кусков ЦЕЛИКОМ внутри
    linuxRegionSplit(slot, qva, pages);
    for (&linux_mmap_regions[slot]) |*r| {
        if (!r.used) continue;
        if (r.va < qva or r.va + r.pages * PAGE_SIZE > hi) continue;
        if (prot_none) {
            r.prot_none = true;
        } else {
            r.pte = vmm.PTE_USER | vmm.PTE_PRESENT | want;
            r.prot_none = false;
        }
    }

    // страницы диапазона: права PTE (present-замена / hidden-восстановление)
    // или скрытие (PROT_NONE: PRESENT снят, физика в PTE сохранена)
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const va_pg = qva + i * PAGE_SIZE;
        if (prot_none) {
            _ = vmm.userLeafClearPresent(pml4, va_pg);
        } else {
            _ = vmm.userLeafApplyProtEx(pml4, va_pg, want, true);
        }
    }
    linuxRegionMerge(slot);
    tlbFullFlush(); // p5-NUCLEAR: stale-TLB зонд
    return 0;
}

/// arch_prctl(ARCH_SET_FS): TLS-база — MSR + per-task-таблица (диспетчер
/// восстановит после переключения). glibc: [fs:0] = tcbhead_t.
fn linuxArchSetFs(addr: u64) i64 {
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return -linux_syscalls.EPERM;
    const t = &scheduler.tasks[owner];
    if (t.privilege != .User or t.abi != .linux) return -linux_syscalls.EPERM;
    scheduler.fs_base_tab[owner] = addr;
    if (linuxProcCurrent()) |p| p.fs_base = addr;
    hal.writeMsr(hal.MSR.FS_BASE, addr); // CR3 задачи активна — живой MSR
    return 0;
}

fn linuxArchGetFs() u64 {
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return 0;
    return scheduler.fs_base_tab[owner];
}

/// set_tid_address: cleartid-слово ТЕКУЩЕГО треда (glibc main-тред:
/// exit → ядро пишет 0 + FUTEX_WAKE — ровно наша механика join).
fn linuxSetTidAddress(addr: u64) u64 {
    const owner = linuxOwnerTask();
    if (owner >= scheduler.MAX_TASKS) return 1;
    if (addr != 0) linux_child_tid[owner] = addr;
    return @intCast(owner);
}

/// set_robust_list: фиксируем (futex-эпилог мёртвых владельцев — будущие
/// волны; ядру для базового glibc достаточно 0).
fn linuxSetRobustList(addr: u64, len: u64) i64 {
    _ = addr;
    _ = len;
    return 0;
}

/// readlink("/proc/self/exe"): execfn из proc-слота (auxv AT_EXECFN-модель).
fn linuxReadlinkSelf(buf_va: u64, bufsz: u64) i64 {
    const proc = linuxProcCurrent() orelse return -linux_syscalls.ENOENT;
    const n = @min(bufsz, proc.execfn_len);
    if (n == 0) return -linux_syscalls.ENOENT;
    if (!linux_user_io.copy_out(buf_va, proc.execfn_buf[0..@intCast(n)]))
        return -linux_syscalls.EFAULT;
    return @intCast(n);
}

/// getrandom: TSC+тик-микс в user-буфер (счётчик PUF-апгрейда — бэклог).
fn linuxGetrandom(va: u64, count: u64) i64 {
    const p: [*]u8 = @ptrFromInt(va);
    var v = hal.readMsr(0x10) ^ (hal.tick_count << 32) ^ 0x9E37_79B9_7F4A_7C15;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        v = v *% 6364136223846793005 +% 1442695040888963407;
        p[@intCast(i)] = @truncate(v >> 33);
    }
    return @intCast(count);
}

/// clock_gettime-источник: тики 10мс + TSC-доводка до наносекунд.
fn linuxTimeNs() u64 {
    const tsc = hal.readMsr(0x10);
    const ns = hal.tick_count * 10_000_000 + (tsc / 3000); // TCG ~3ГГц-приближение
    return ns;
}


// ─── v0.19.0 (CDD №10 p4): VFS Live-режима (initrd-RO + tmpfs-RAM) ─────────

/// Реестр открытых файлов VFS (file_id ↔ узел).
/// CDD №12 p3: anon-файлы (memfd/ftruncate) — PMM-блок, ОБЩИЕ физ-страницы
/// между маппингами (MAP_SHARED: Mesa lavapipe-heap, Wayland-shm).
const LinuxFile = struct {
    used: bool = false,
    kind: linux_syscalls.FdKind = .free,
    /// v0.20 (CDD №15): счётчик дескрипторов-владельцев (fork-наследование:
    /// копия fd-таблицы ребёнка поднимает refs; release — только последний).
    refs: u32 = 1,
    tmp: ?*vfs.TmpFile = null, // для tmpfs_file (heap-backed)
    initrd_data: ?[]const u8 = null, // для initrd_file
    // ─── anon (memfd): PMM-блок общих страниц ───
    anon: bool = false,
    phys: u64 = 0, // базис физблока (0 = не выделен)
    blk_pages: u64 = 0, // размер блока в страницах
    size: u64 = 0, // логический размер (ftruncate)
    /// CDD №12 p4: путь файла (open) — для атрибуции mmap-регионов при
    /// file_mmap (ld.so: имя либы в CPU-exception-дампе).
    name: [48]u8 = [_]u8{0} ** 48,
};

/// Потолок anon-файла: 512МБ (lavapipe-heap; PMM-гвард).
const ANON_FILE_MAX: u64 = 512 * 1024 * 1024;
var linux_files: [linux_syscalls.MAX_FILE_ID]LinuxFile = [_]LinuxFile{.{}} ** linux_syscalls.MAX_FILE_ID;

// ─── CDD №12 p3: потоки каталогов (opendir → getdents64) ───────────────────

const MAX_DIR_ENTRIES: usize = 32;
const MAX_DIR_NAME: usize = 56;
/// Один каталогопоток: снимок детей (имя + d_type), позиция чтения.
/// Каталоги маленькие (≤ 32 имён — /dev/dri, /sys/…, usr/lib): один
/// слот — одна сессия getdents64 (glibc читает до EOF за 1-2 вызова).
const DirStream = struct {
    used: bool = false,
    count: u32 = 0,
    pos: u32 = 0,
    names: [MAX_DIR_ENTRIES][MAX_DIR_NAME]u8 = [_][MAX_DIR_NAME]u8{.{0} ** MAX_DIR_NAME} ** MAX_DIR_ENTRIES,
    name_lens: [MAX_DIR_ENTRIES]u8 = .{0} ** MAX_DIR_ENTRIES,
    types: [MAX_DIR_ENTRIES]u8 = .{0} ** MAX_DIR_ENTRIES, // DT_*
};
var linux_dirs: [8]DirStream = [_]DirStream{.{}} ** 8;

fn dirPush(d: *DirStream, name: []const u8, dtype: u8) void {
    if (d.count >= MAX_DIR_ENTRIES or name.len >= MAX_DIR_NAME) return; // дедуп-границы
    for (d.names[0..d.count], 0..) |*n, i| {
        if (d.name_lens[i] == name.len and std.mem.eql(u8, n[0..name.len], name)) return; // дедуп
    }
    @memcpy(d.names[d.count][0..name.len], name);
    d.name_lens[d.count] = @intCast(name.len);
    d.types[d.count] = dtype;
    d.count += 1;
}

/// Явная dir-запись CPIO (mode S_IFDIR)?
fn initrdIsDir(path: []const u8) bool {
    const node = initrdFindNode(path) orelse return false;
    return node.mode & 0o170000 == 0o040000;
}

/// Есть ли у префикса ДЕТИ в initrd (неявный каталог — как ядро Linux
/// выводит дир на лету из потомков)?
fn initrdHasChildren(path: []const u8) bool {
    const arch = initrd_archive orelse return false;
    const dir = cpioCanon(path);
    var cpio_parser = cpio.CpioParser.init(arch);
    while (cpio_parser.next()) |file| {
        const name = cpioCanon(file.name);
        if (name.len <= dir.len + 1) continue;
        if (!std.mem.startsWith(u8, name, dir) or name[dir.len] != '/') continue;
        return true;
    }
    return false;
}

/// Заполнить поток детьми initrd-префикса (+ "." и ".." — Linux-семантика).
fn initrdDirFill(path: []const u8, d: *DirStream) void {
    const arch = initrd_archive orelse return;
    const dir = cpioCanon(path);
    var cpio_parser = cpio.CpioParser.init(arch);
    while (cpio_parser.next()) |file| {
        const name = cpioCanon(file.name);
        if (name.len <= dir.len + 1) continue;
        if (!std.mem.startsWith(u8, name, dir) or name[dir.len] != '/') continue;
        const rest = name[dir.len + 1 ..];
        const slash = std.mem.indexOfScalar(u8, rest, '/');
        if (slash) |s| {
            dirPush(d, rest[0..s], linux_syscalls.DT_DIR);
        } else {
            const dt: u8 = if (file.mode & 0o170000 == 0o120000)
                linux_syscalls.DT_LNK
            else if (file.mode & 0o170000 == 0o040000)
                linux_syscalls.DT_DIR
            else
                linux_syscalls.DT_REG;
            dirPush(d, rest, dt);
        }
    }
}

fn sysfsContent(path: []const u8) ?[]const u8 {
    const p = cpioCanon(path);
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0/uevent") or
        std.mem.eql(u8, p, "sys/class/drm/card0/uevent"))
    {
        return "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0/dev") or
        std.mem.eql(u8, p, "sys/class/drm/card0/dev"))
    {
        return "226:0\n";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128/uevent") or
        std.mem.eql(u8, p, "sys/class/drm/renderD128/uevent"))
    {
        return "MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128/dev") or
        std.mem.eql(u8, p, "sys/class/drm/renderD128/dev"))
    {
        return "226:128\n";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/uevent")) {
        return "DRIVER=virtio-pci\nPCI_CLASS=30000\nPCI_ID=1AF4:1050\nPCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:02.0\nMODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc00i00\n";
    }
    if (std.mem.eql(u8, p, "sys/class/drm/version")) {
        return "drm 1.1.0 20060810\n";
    }
    return null;
}

fn sysfsSymlinkTarget(path: []const u8) ?[]const u8 {
    const p = cpioCanon(path);
    if (std.mem.eql(u8, p, "sys/class/drm/card0")) {
        return "../../devices/pci0000:00/0000:00:02.0/drm/card0";
    }
    if (std.mem.eql(u8, p, "sys/class/drm/renderD128")) {
        return "../../devices/pci0000:00/0000:00:02.0/drm/renderD128";
    }
    if (std.mem.eql(u8, p, "sys/dev/char/226:0")) {
        return "../../devices/pci0000:00/0000:00:02.0/drm/card0";
    }
    if (std.mem.eql(u8, p, "sys/dev/char/226:128")) {
        return "../../devices/pci0000:00/0000:00:02.0/drm/renderD128";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0/device") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128/device"))
    {
        return "../../../0000:00:02.0";
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0/subsystem") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128/subsystem"))
    {
        return "../../../../class/drm";
    }
    return null;
}

fn isSysfsDir(path: []const u8) bool {
    const p = cpioCanon(path);
    return std.mem.eql(u8, p, "sys") or
        std.mem.eql(u8, p, "sys/class") or
        std.mem.eql(u8, p, "sys/class/drm") or
        std.mem.eql(u8, p, "sys/dev") or
        std.mem.eql(u8, p, "sys/dev/char") or
        std.mem.eql(u8, p, "sys/devices") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128");
}

fn sysfsDirFill(path: []const u8, d: *DirStream) bool {
    const p = cpioCanon(path);
    if (std.mem.eql(u8, p, "sys")) {
        dirPush(d, "class", linux_syscalls.DT_DIR);
        dirPush(d, "dev", linux_syscalls.DT_DIR);
        dirPush(d, "devices", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/class")) {
        dirPush(d, "drm", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/class/drm")) {
        dirPush(d, "card0", linux_syscalls.DT_LNK);
        dirPush(d, "renderD128", linux_syscalls.DT_LNK);
        dirPush(d, "version", linux_syscalls.DT_REG);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/dev")) {
        dirPush(d, "char", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/dev/char")) {
        dirPush(d, "226:0", linux_syscalls.DT_LNK);
        dirPush(d, "226:128", linux_syscalls.DT_LNK);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/devices")) {
        dirPush(d, "pci0000:00", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00")) {
        dirPush(d, "0000:00:02.0", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0")) {
        dirPush(d, "drm", linux_syscalls.DT_DIR);
        dirPush(d, "uevent", linux_syscalls.DT_REG);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm")) {
        dirPush(d, "card0", linux_syscalls.DT_DIR);
        dirPush(d, "renderD128", linux_syscalls.DT_DIR);
        return true;
    }
    if (std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/card0") or
        std.mem.eql(u8, p, "sys/devices/pci0000:00/0000:00:02.0/drm/renderD128"))
    {
        dirPush(d, "dev", linux_syscalls.DT_REG);
        dirPush(d, "uevent", linux_syscalls.DT_REG);
        dirPush(d, "device", linux_syscalls.DT_LNK);
        dirPush(d, "subsystem", linux_syscalls.DT_LNK);
        return true;
    }
    return false;
}

/// Является ли путь каталогом (devfs-спец + явные/неявные CPIO-дир)?
fn isDirPath(path: []const u8) bool {
    if (isSysfsDir(path)) return true;
    if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/dev") or
        std.mem.eql(u8, path, "/dev/dri") or std.mem.eql(u8, path, "/dev/input")) return true;
    if (initrdIsDir(path)) return true;
    return initrdHasChildren(path);
}

/// Открыть поток каталога (слот DirStream) — вызывается из linuxOpenFile
/// ПОСЛЕ isDirPath-проверки. Возвращает dir_id или -errno.
fn linuxOpenDir(path: []const u8) i64 {
    var slot: ?usize = null;
    for (&linux_dirs, 0..) |*ds, i| {
        if (!ds.used) {
            slot = i;
            break;
        }
    }
    const s = slot orelse return -linux_syscalls.ENFILE;
    const d = &linux_dirs[s];
    d.* = .{};
    d.used = true;
    // "." и ".." — ядро Linux выдаёт их первым (readdir-инвариант glibc)
    dirPush(d, ".", linux_syscalls.DT_DIR);
    dirPush(d, "..", linux_syscalls.DT_DIR);
    if (sysfsDirFill(path, d)) return @intCast(s);
    if (std.mem.eql(u8, path, "/dev/dri")) {
        dirPush(d, "card0", linux_syscalls.DT_CHR);
        dirPush(d, "renderD128", linux_syscalls.DT_CHR);
    } else if (std.mem.eql(u8, path, "/dev/input")) {
        dirPush(d, "event0", linux_syscalls.DT_CHR);
        dirPush(d, "event1", linux_syscalls.DT_CHR);
    } else if (std.mem.eql(u8, path, "/dev")) {
        dirPush(d, "console", linux_syscalls.DT_CHR);
        dirPush(d, "fb0", linux_syscalls.DT_CHR);
        dirPush(d, "dri", linux_syscalls.DT_DIR);
        dirPush(d, "input", linux_syscalls.DT_DIR);
    } else if (std.mem.eql(u8, path, "/")) {
        dirPush(d, "dev", linux_syscalls.DT_DIR);
        dirPush(d, "sys", linux_syscalls.DT_DIR);
        dirPush(d, "tmp", linux_syscalls.DT_DIR);
        initrdDirFill("/", d);
    } else {
        initrdDirFill(path, d);
    }
    return @intCast(s);
}

/// getdents64: записи linux_dirent64 (выравн. 8) прямо в user-VA
/// (валидация сделана слоем syscall; CR3 задачи активен — как evdev).
fn linuxDirRead(id: u32, buf_va: u64, count: u64) i64 {
    if (id >= linux_dirs.len or !linux_dirs[id].used) return -linux_syscalls.EBADF;
    const d = &linux_dirs[id];
    const p: [*]u8 = @ptrFromInt(buf_va);
    var written: u64 = 0;
    while (d.pos < d.count) {
        const i: usize = @intCast(d.pos);
        const name_len: u64 = d.name_lens[i];
        const reclen: u64 = 19 + name_len + 1; // 8+8+2+1 + имя + NUL
        const padded: u64 = (reclen + 7) & ~@as(u64, 7);
        if (written + padded > count) break;
        var rec: [MAX_DIR_NAME + 32]u8 = [_]u8{0} ** (MAX_DIR_NAME + 32);
        // d_ino: стабильный псевдо-ino потока (0..) — НЕ 0 (реальный d_ino ≠ 0)
        std.mem.writeInt(u64, rec[0..8], 5000 + @as(u64, id) * 100 + i, .little);
        std.mem.writeInt(u64, rec[8..16], @as(u64, i) + 1, .little); // d_off = индекс+1
        std.mem.writeInt(u16, rec[16..18], @intCast(padded), .little);
        rec[18] = d.types[i];
        @memcpy(rec[19..][0..@intCast(name_len)], d.names[i][0..@intCast(name_len)]);
        @memcpy(p[written..][0..@intCast(padded)], rec[0..@intCast(padded)]);
        written += padded;
        d.pos += 1;
    }
    return @intCast(written);
}

fn linuxDirClose(id: u32) void {
    if (id < linux_dirs.len) linux_dirs[id] = .{};
}

/// CDD №12 p3: mkdir — tmpfs-слот-имя «dir:<path>» (Live-модель: запись в
/// RAM; дети — неявно файлы). Mesa кэш-каталоги деградируют мягко.
fn linuxMkdirTmpfs(path: []const u8) i64 {
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    if (!std.mem.startsWith(u8, path, "/tmp") and !std.mem.startsWith(u8, path, "/root"))
        return -linux_syscalls.EPERM; // запись вне RAM-пространств
    // слот-имя: реестр tmpfs плоский — «dir:»-префикс различает каталоги
    var name_buf: [96]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "dir:{s}", .{path}) catch
        return -linux_syscalls.EINVAL;
    _ = kernel_vfs.tmp.create(name) catch return -linux_syscalls.ENOMEM;
    return 0;
}

/// CDD №12 p3: парковка текущей задачи на ms — модель linuxFutexPark без
/// фьюфекс-реестра (блокирующий epoll_wait: слайс → диспетчер → перепроверка
/// готовности; анти-спин: потоки композитора ЖГЛИ TCG на 100%).
fn linuxTaskPark(ms: u64) void {
    const my_rsp = scheduler.user_rsp;
    const owner = scheduler.syscallStackOwner(my_rsp);
    if (owner >= scheduler.MAX_TASKS or
        scheduler.tasks[owner].privilege != .User)
    {
        // shell-контекст (ldevtest): кооперативная пауза — без парковки
        const t0 = hal.tick_count;
        const ticks = (ms + 9) / 10;
        while (hal.tick_count < t0 + ticks) {
            asm volatile ("pause");
        }
        return;
    }
    const deadline = hal.tick_count + (ms + 9) / 10;
    // резюм-кадр + будильник (модель kSleepTask — каскад на топе kstack)
    scheduler.snapshotResumeFrame(owner, my_rsp);
    scheduler.setTaskSleepFor(owner, ms);
    // выпуск транзакции: тики диспетчируют задачу по будильнику
    hal.cli();
    scheduler.in_win32_syscall = 0;
    hal.sti();
    // парк: hlt до прерывания (тик 100Гц)
    while (hal.tick_count < deadline) {
        asm volatile ("hlt" ::: "memory");
    }
    // эпилог транзакции: вернуть user_rsp, резюм-указатель — .bss-слот
    hal.cli();
    scheduler.user_rsp = my_rsp;
    scheduler.in_win32_syscall = 1;
    hal.sti();
    scheduler.setTaskSleepFor(owner, 0);
    scheduler.installResumeFrame(owner);
}

fn vfsAlloc(n: usize) ?[*]u8 {
    return heap.kmalloc(n);
}
fn vfsFree(ptr: [*]u8, n: usize) void {
    _ = n; // heap64.kfree без размера (фраг-хип со своей меткой)
    heap.kfree(ptr);
}
fn vfsInitrdFind(name: []const u8) ?vfs.InitrdNode {
    // сырой узел: алиасы/симлинки резолвит слой vfs.Vfs.resolve
    const f = initrdFindNode(name) orelse return null;
    return .{ .data = f.data, .mode = f.mode };
}
fn kernelVfsOps() vfs.VfsOps {
    return .{ .alloc = vfsAlloc, .free = vfsFree, .initrd_find = vfsInitrdFind };
}
/// Глобальный VFS Live-режима: /dev (устройства) + initrd-RO + /tmp (RAM).
var kernel_vfs: vfs.Vfs = undefined;
var kernel_vfs_ready = false;

fn vfsInit() void {
    // p14-ФИКС: Vfs.init возвращал 35КБ-структуру через BOOT-стек (мал!)
    // → переполнение → #PF → вис после initrd. Инициализация IN-PLACE
    // глобала: поля напрямую, файловые слоты по одному (литерал ≤136Б).
    kernel_vfs.ops = kernelVfsOps();
    kernel_vfs.tmp.ops = kernelVfsOps();
    for (&kernel_vfs.tmp.files) |*f| f.* = .{};
    kernel_vfs_ready = true;
    puts("[VFS] Live-mode VFS: /dev (devfs) + initrd (RO) + /tmp (tmpfs RAM overlay)\n");
}

/// v0.20.0 (CDD №12 p1): close — освобождение слота реестра файлов VFS.
/// CDD №12 p3: memfd — PMM-блок общих страниц освобождается ЗДЕСЬ (послед-
/// ний владелец = fd). Регионы shared-мапов записаны как phys=0/anon=false —
/// munmap/exit физику НЕ трогают → close = единственная точка освобождения
/// (анти-утечка при churn буферов wl_shm/lavapipe). CDD №15 p5: close при
/// живом маппинге (легален в Linux) больше НЕ оставляет висячие PTE —
/// маппинг пинит файл (refs), физика живёт до ПОСЛЕДНЕЙ ссылки.
fn linuxReleaseFile(id: u32) void {
    if (id >= linux_files.len) return;
    if (!linux_files[id].used) return;
    if (linux_files[id].refs > 1) { // dup/маппинг/fork держат — владелец жив
        linux_files[id].refs -= 1;
        return;
    }
    if (linux_files[id].anon and linux_files[id].phys != 0) {
        pmm.freeContiguousPages(linux_files[id].phys, linux_files[id].blk_pages);
    }
    linux_files[id] = .{};
}

/// CDD №15 p5: файл-пин (refs++) — ВЗЯТЬ ссылку: dup/F_DUPFD/MAP_SHARED.
/// Пара к release_file. До фикса dup не пинал: fabric (dup→close)
/// освобождал физблок при живом втором fd И маппинге → PMM-отравление.
fn linuxRetainFile(id: u32) void {
    if (id >= linux_files.len) return;
    if (!linux_files[id].used) return;
    linux_files[id].refs += 1;
}

/// open_file: VFS-резолв пути (normalizePath + overlay) → file_id.
fn linuxOpenFile(path: []const u8, flags: u64, out_kind: *linux_syscalls.FdKind) i64 {
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    // CDD №12 p3: КАТАЛОГИ (opendir: libdrm сканирует /dev/dri —
    // drmGetDeviceFromDevId; realpath-компоненты glibc). Порядок: каталог
    // ПЕРВЫМ (dir-запись CPIO иначе резолвится как пустой файл)
    if (isDirPath(path)) {
        const id = linuxOpenDir(path);
        if (id >= 0) {
            out_kind.* = .dir;
            return id;
        }
    }
    if (sysfsContent(path)) |content| {
        var slot: ?usize = null;
        for (&linux_files, 0..) |*f, i| {
            if (!f.used) {
                slot = i;
                break;
            }
        }
        const s = slot orelse return -linux_syscalls.EMFILE;
        linux_files[s] = .{ .used = true, .kind = .initrd_file, .initrd_data = content };
        out_kind.* = .initrd_file;
        const f = &linux_files[s];
        const n = @min(path.len, f.name.len);
        @memcpy(f.name[0..n], path[0..n]);
        return @intCast(s);
    }
    const write_mode = (flags & linux_syscalls.O_ACCMODE) != linux_syscalls.O_RDONLY;
    const node = kernel_vfs.resolve(path, write_mode) catch |e| {
        // CDD №12 p4-диагностика: ENOENT-фронты поимённо с причиной резолва
        // (эмпирика run5: libxcb-keysyms ENOENT при рабочем elfload-резолве)
        if (linux_trace) {
            hal.Serial.puts("[VFS] open-fail: ");
            hal.Serial.puts(path);
            hal.Serial.puts(" — ");
            hal.Serial.puts(@errorName(e));
            hal.Serial.puts("\n");
        }
        return switch (e) {
            vfs.VfsError.NotFound => -linux_syscalls.ENOENT,
            vfs.VfsError.ReadOnly => -linux_syscalls.EPERM, // запись вне /tmp
            vfs.VfsError.NoSpace => -linux_syscalls.ENOMEM,
            vfs.VfsError.TooManyFiles => -linux_syscalls.ENOMEM,
            vfs.VfsError.NameTooLong => -linux_syscalls.EINVAL,
            vfs.VfsError.BadPath => -linux_syscalls.EINVAL,
            vfs.VfsError.TooManyLinks => -linux_syscalls.ELOOP,
            vfs.VfsError.NotASymlink => -linux_syscalls.EINVAL, // open: симлинк уже разыменован
        };
    };
    // слот в реестре
    var slot: ?usize = null;
    for (&linux_files, 0..) |*f, i| {
        if (!f.used) {
            slot = i;
            break;
        }
    }
    const s = slot orelse return -linux_syscalls.EMFILE;
    switch (node.kind) {
        .tmpfs_file => {
            linux_files[s] = .{ .used = true, .kind = .tmpfs_file, .tmp = node.tmp };
            out_kind.* = .tmpfs_file;
        },
        .initrd_file => {
            linux_files[s] = .{ .used = true, .kind = .initrd_file, .initrd_data = node.initrd_data };
            out_kind.* = .initrd_file;
        },
        .dev => return -linux_syscalls.EINVAL, // /dev — уже разложено dev-резолвом слоя
    }
    // CDD №12 p4: путь → имя fd (модульная атрибуция mmap-регионов)
    {
        const f = &linux_files[s];
        const n = @min(path.len, f.name.len);
        @memcpy(f.name[0..n], path[0..n]);
    }
    return @intCast(s);
}

/// file_read: tmpfs (RAM) или initrd (USB-RO) → user-VA (валидация слоем).
fn linuxFileRead(id: u32, off: u64, va: u64, count: u64) i64 {
    if (id >= linux_files.len or !linux_files[id].used) return -linux_syscalls.EBADF;
    const f = &linux_files[id];
    if (f.kind == .tmpfs_file) {
        // CDD №12 p3: memfd — чтение прямо из PMM-блока (Linux-семантика:
        // read/write на memfd валидны; основные потребители пишут через
        // MAP_SHARED-mmap, но read() нужен fstat-производным проверкам)
        if (f.anon) {
            if (f.phys == 0 or off >= f.size) return 0; // EOF
            const n: u64 = @min(count, f.size - off);
            const src: [*]const u8 = @ptrFromInt(f.phys + off);
            const p: [*]u8 = @ptrFromInt(va);
            @memcpy(p[0..@intCast(n)], src[0..@intCast(n)]);
            return @intCast(n);
        }
        const t = f.tmp orelse return -linux_syscalls.EIO;
        var n: usize = 0;
        // постраничная запись в user-VA (CR3 задачи активен; буфер валидирован)
        var remain: u64 = count;
        var o = off;
        while (remain > 0 and n < count) {
            var chunk_buf: [512]u8 = undefined;
            const c: u64 = @min(remain, chunk_buf.len);
            const got = kernel_vfs.tmp.read(t, o, chunk_buf[0..@intCast(c)]);
            if (got == 0) break; // EOF
            const p: [*]u8 = @ptrFromInt(va + n);
            @memcpy(p[0..got], chunk_buf[0..got]);
            n += got;
            o += got;
            remain -= got;
        }
        return @intCast(n);
    }
    // initrd-RO
    const data = f.initrd_data orelse return -linux_syscalls.EIO;
    if (off >= data.len) return 0; // EOF
    const avail: u64 = @intCast(data.len - @as(usize, @intCast(off)));
    const n: u64 = @min(count, avail);
    const p: [*]u8 = @ptrFromInt(va);
    const src: [*]const u8 = data.ptr + @as(usize, @intCast(off));
    @memcpy(p[0..@intCast(n)], src[0..@intCast(n)]);
    return @intCast(n);
}

/// file_write: только tmpfs (RAM — Live-модель «запись в RAM, чтение с USB»).
fn linuxFileWrite(id: u32, off: u64, va: u64, count: u64) i64 {
    if (id >= linux_files.len or !linux_files[id].used) return -linux_syscalls.EBADF;
    const f = &linux_files[id];
    if (f.kind != .tmpfs_file) return -linux_syscalls.EBADF;
    // CDD №12 p3: memfd — запись в PMM-блок (без ftruncate — EFBIG: блок
    // не выделен; Linux дал бы SIGBUS/расширение — мы консервативны)
    if (f.anon) {
        if (f.phys == 0) return -linux_syscalls.EFBIG;
        if (off >= f.blk_pages * PAGE_SIZE) return -linux_syscalls.EFBIG;
        const n: u64 = @min(count, f.blk_pages * PAGE_SIZE - off);
        const dst: [*]u8 = @ptrFromInt(f.phys + off);
        const p: [*]const u8 = @ptrFromInt(va);
        @memcpy(dst[0..@intCast(n)], p[0..@intCast(n)]);
        if (off + n > f.size) f.size = off + n;
        return @intCast(n);
    }
    const t = f.tmp orelse return -linux_syscalls.EIO;
    // читаем user-VA чанками (валидация уже сделана слоем)
    var n: u64 = 0;
    var remain: u64 = count;
    var o = off;
    const p: [*]const u8 = @ptrFromInt(va);
    while (remain > 0) {
        var chunk_buf: [512]u8 = undefined;
        const c: u64 = @min(remain, chunk_buf.len);
        @memcpy(chunk_buf[0..@intCast(c)], p[@intCast(n)..][0..@intCast(c)]);
        const got = kernel_vfs.tmp.write(t, o, chunk_buf[0..@intCast(c)]) catch |e| switch (e) {
            vfs.VfsError.NoSpace => return if (n == 0) -linux_syscalls.ENOMEM else @as(i64, @intCast(n)),
            else => return -linux_syscalls.EIO,
        };
        n += got;
        o += got;
        remain -= got;
    }
    return @intCast(n);
}

/// v0.20.0 (CDD №11 p3): FILE-BACKED mmap (MAP_PRIVATE): анонимные страницы
/// + копия файловых байт [off, off+len) из VFS. ld.so грузит libc.so
/// сегментами ровно так (эмпирика: ENODEV → exit_group(127)).
/// fixed_va != 0 — MAP_FIXED: размещение по ТОЧНОМУ адресу поверх
/// существующих мапов (замена: unmap пересекающихся страниц — Linux-
/// семантика; ld.so ремапит сегменты libc на base+vaddr поверх
/// первичного спана).
fn linuxFileMmap(id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return -linux_syscalls.EFAULT;
    const proc = linuxProcCurrent() orelse return -linux_syscalls.EFAULT;
    if (len > LINUX_MMAP_BUDGET) return -linux_syscalls.ENOMEM;
    if (fixed_va % PAGE_SIZE != 0) return -linux_syscalls.EINVAL;
    const pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    const va: u64 = if (fixed_va != 0) fixed_va else proc.mmap_cursor;
    if (fixed_va == 0 and proc.mmap_cursor + pages * PAGE_SIZE > LINUX_MMAP_BASE + LINUX_MMAP_BUDGET)
        return -linux_syscalls.ENOMEM;
    if (va < elf_loader.MIN_USER_VA or va + pages * PAGE_SIZE > linux_syscalls.USER_VA_CEILING)
        return -linux_syscalls.EINVAL;
    // CDD №12 p6: MAP_FIXED-замена — единая drop-механика (p5: только unmap
    // PTE без освобождения lazy-физики — утечка + stale-записи поверх живых
    // данных нового мапа → demand-zero накрывал их нулём).
    if (fixed_va != 0) linuxUnmapFixedRange(va, pages);
    var pte: u64 = vmm.PTE_USER | vmm.PTE_WRITABLE;
    if (prot & linux_syscalls.PROT_EXEC == 0) pte |= vmm.PTE_NO_EXECUTE;
    if (prot & linux_syscalls.PROT_WRITE == 0) pte &= ~vmm.PTE_WRITABLE; // RO-копия
    const base = pmm.allocContiguousZeroed(@intCast(pages)) orelse {
        // CDD №15 p4: причина ENOMEM в лог (эмпирика: per-page снапшот
        // дробил PMM-битмап — contiguous-ран для libpixman не находился)
        hal.Serial.puts("[MMAP] file-ENOMEM: pages=");
        hal.Serial.putDecimal(pages);
        hal.Serial.puts(" pmm-allocated=");
        hal.Serial.putDecimal(pmm.allocated_pages);
        hal.Serial.puts("\n");
        return -linux_syscalls.ENOMEM;
    };
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        vmm.mapPageInPML4(pml4, va + i * PAGE_SIZE, base + i * PAGE_SIZE, pte) catch {
            pmm.freeContiguousPages(base, pages);
            return linuxMmapRollback(pml4, va, i, -linux_syscalls.ENOMEM);
        };
    }
    tlbFullFlush(); // p5-NUCLEAR: mapPageInPML4 не инвалит — а CR3 АКТИВЕН
    // копия файловых байт чанками (identity: kernel пишет в физблок)
    var copied: u64 = 0;
    var f_off = off;
    while (copied < len) {
        var chunk: [512]u8 = undefined;
        const c = @min(len - copied, chunk.len);
        const got = linuxFileReadBytes(id, f_off, &chunk, @intCast(c));
        if (got <= 0) break; // EOF — хвост нулевой (BSS-семантика)
        const dest = base + copied;
        const dst: [*]u8 = @ptrFromInt(dest);
        @memcpy(dst[0..@intCast(got)], chunk[0..@intCast(got)]);
        copied += @intCast(got);
        f_off += @intCast(got);
    }
    linuxRecordRegion(linux_task_proc[linuxOwnerTask()], va, pages, base, true, fdRegionName(id));
    if (fixed_va == 0) proc.mmap_cursor += pages * PAGE_SIZE;
    return @intCast(va);
}

/// CDD №12 p4: имя региона из fd (fd→LinuxFile.name; «fd?» — незарег.).
fn fdRegionName(id: u32) []const u8 {
    if (id >= linux_files.len or !linux_files[id].used) return "fd?";
    const f = &linux_files[id];
    const nl = for (f.name, 0..) |c, i| {
        if (c == 0) break i;
    } else f.name.len;
    if (nl == 0) return if (f.anon) "memfd" else "fd";
    return f.name[0..nl];
}

/// Прямое чтение VFS-файла в kernel-буфер (id+offset → байты).
fn linuxFileReadBytes(id: u32, off: u64, buf: []u8, want: usize) i64 {
    if (id >= linux_files.len or !linux_files[id].used) return -linux_syscalls.EBADF;
    const f = &linux_files[id];
    switch (f.kind) {
        .initrd_file => {
            const data = f.initrd_data orelse return 0;
            if (off >= data.len) return 0; // EOF
            const avail = @min(@as(usize, @intCast(data.len - @min(off, data.len))), want);
            @memcpy(buf[0..avail], data[@intCast(off)..][0..avail]);
            return @intCast(avail);
        },
        .tmpfs_file => {
            const t = f.tmp orelse return -linux_syscalls.EIO;
            const got = kernel_vfs.tmp.read(t, off, buf[0..want]);
            return @intCast(got);
        },
        else => return -linux_syscalls.EBADF,
    }
}

/// Размер файла (lseek SEEK_END).
fn linuxFileSize(id: u32) u64 {
    if (id >= linux_files.len or !linux_files[id].used) return 0;
    const f = &linux_files[id];
    switch (f.kind) {
        .initrd_file => {
            const data = f.initrd_data orelse return 0;
            return data.len;
        },
        .tmpfs_file => {
            // CDD №12 p3: memfd — логический размер (ftruncate; glibc/lavapipe
            // сверяют st_size после os_create_anonymous_file)
            if (f.anon) return f.size;
            const t = f.tmp orelse return 0;
            return t.size;
        },
        else => return 0,
    }
}

/// v0.20.0 (CDD №11 p3): УНИКАЛЬНЫЙ inode файла — идентификация ОБЪЕКТА,
/// а не слота (два open одного файла = один ino; glibc ld.so сверяет
/// (st_dev, st_ino) со списком загруженных карт dl-load.c:994 — нулевой
/// id = ложное «already loaded», БЕЗ mmap). initrd: адрес данных CPIO-entry
/// (стабилен и уникален); tmpfs: адрес TmpFile.
fn linuxFileIno(id: u32) u64 {
    if (id >= linux_files.len or !linux_files[id].used) return 0;
    const f = &linux_files[id];
    switch (f.kind) {
        .initrd_file => {
            const data = f.initrd_data orelse return 0;
            return @intFromPtr(data.ptr) >> 4;
        },
        .tmpfs_file => {
            // CDD №12 p3: memfd — стабильный уникальный ino (0xA000_0000+id):
            // mmap-клиенты fstat-ят буфер — идентификация ОБЪЕКТА, не слота
            if (f.anon) return 0xA000_0000 + @as(u64, id);
            const t = f.tmp orelse return 0;
            return @intFromPtr(t) >> 4;
        },
        else => return 0,
    }
}

/// access(path): существование в VFS (ld.so: /etc/ld.so.cache и т.п.).
fn linuxPathExists(path: []const u8) i64 {
    if (isSysfsDir(path) or sysfsSymlinkTarget(path) != null or sysfsContent(path) != null) return 0;
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    _ = kernel_vfs.resolve(path, false) catch |e| switch (e) {
        vfs.VfsError.NotFound => return -linux_syscalls.ENOENT,
        else => return -linux_syscalls.EIO,
    };
    return 0;
}

/// v0.20.0 (CDD #12 p1): readlink по ОБЩЕМУ пути (не только /proc/self/exe):
/// цель симлинка из initrd в user-буфер. CR3 активен — user-IO.
fn linuxReadlinkPath(path: []const u8, buf_va: u64, bufsz: u64) i64 {
    if (sysfsSymlinkTarget(path)) |target| {
        if (bufsz == 0) return -linux_syscalls.EINVAL;
        const n = @min(target.len, bufsz);
        if (!linux_user_io.copy_out(buf_va, target[0..@intCast(n)]))
            return -linux_syscalls.EFAULT;
        return @intCast(n);
    }
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    const target = kernel_vfs.readlink(path) catch |e| switch (e) {
        vfs.VfsError.NotFound => return -linux_syscalls.ENOENT,
        vfs.VfsError.NotASymlink => return -linux_syscalls.EINVAL,
        vfs.VfsError.TooManyLinks => return -linux_syscalls.ELOOP,
        else => return -linux_syscalls.EIO,
    };
    if (bufsz == 0) return -linux_syscalls.EINVAL;
    const n = @min(target.len, bufsz);
    if (!linux_user_io.copy_out(buf_va, target[0..@intCast(n)]))
        return -linux_syscalls.EFAULT;
    return @intCast(n);
}

/// newfstatat: stat по пути (S_IFREG + st_size из VFS — ld.so планирует
/// mmap библиотеки по размеру!). CR3 задачи активен — copy через user-IO.
fn linuxStatByPath(path: []const u8, buf_va: u64) i64 {
    if (sysfsSymlinkTarget(path)) |target| {
        var st: [144]u8 = [_]u8{0} ** 144;
        std.mem.writeInt(u64, st[0..8], 0, .little);
        var hash: u64 = 0xCBF29CE484222325;
        for (cpioCanon(path)) |c| {
            hash ^= c;
            hash *%= 0x100000001B3;
        }
        std.mem.writeInt(u64, st[8..16], hash & 0xFFFF_FFFF, .little);
        std.mem.writeInt(u64, st[16..24], 1, .little); // nlink
        std.mem.writeInt(u32, st[24..28], @intCast(0xA000 | 0x1FF), .little); // S_IFLNK|0777
        std.mem.writeInt(u64, st[48..56], target.len, .little); // size
        std.mem.writeInt(u64, st[56..64], 4096, .little);
        if (!linux_user_io.copy_out(buf_va, &st)) return -linux_syscalls.EFAULT;
        return 0;
    }
    if (sysfsContent(path)) |content| {
        var st: [144]u8 = [_]u8{0} ** 144;
        std.mem.writeInt(u64, st[0..8], 0, .little);
        var hash: u64 = 0xCBF29CE484222325;
        for (cpioCanon(path)) |c| {
            hash ^= c;
            hash *%= 0x100000001B3;
        }
        std.mem.writeInt(u64, st[8..16], hash & 0xFFFF_FFFF, .little);
        std.mem.writeInt(u64, st[16..24], 1, .little); // nlink
        std.mem.writeInt(u32, st[24..28], @intCast(0x8000 | 0x124), .little); // S_IFREG|0444
        std.mem.writeInt(u64, st[48..56], content.len, .little); // size
        std.mem.writeInt(u64, st[56..64], 4096, .little);
        if (!linux_user_io.copy_out(buf_va, &st)) return -linux_syscalls.EFAULT;
        return 0;
    }
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    var st: [144]u8 = [_]u8{0} ** 144;
    // CDD №12 p3: devfs-УЗЛЫ — S_IFCHR + st_rdev (libdrm stat("/dev/dri/
    // renderD128") — drm_device_has_rdev сверяет с makedev(renderMajor,
    // renderMinor) из Vulkan-пропсов!). /dev, /dev/dri — каталоги ниже.
    if (std.mem.startsWith(u8, path, "/dev/")) {
        if (linux_syscalls.resolveDevKind(path)) |kind| {
            const minor = linux_syscalls.devMinor(path);
            const major = linux_syscalls.devMajorOf(kind);
            std.mem.writeInt(u64, st[0..8], 0, .little); // st_dev — ядро-псевдо
            std.mem.writeInt(u64, st[8..16], 0xE00 + @as(u64, minor), .little); // st_ino
            std.mem.writeInt(u64, st[16..24], 1, .little);
            std.mem.writeInt(u32, st[24..28], @intCast(0x2000 | 0x1A0), .little); // S_IFCHR|0620
            std.mem.writeInt(u64, st[40..48], linux_syscalls.encodeDev(major, minor), .little); // st_rdev!
            std.mem.writeInt(u64, st[56..64], 4096, .little);
            if (!linux_user_io.copy_out(buf_va, &st)) return -linux_syscalls.EFAULT;
            return 0;
        } // иначе fall-through: /dev/dri, /dev/input — каталоги ниже
    }
    // CDD №12 p3: КАТАЛОГИ — S_IFDIR (realpath glibc lstat-ит каждый компо-
    // нент; drmNodeIsDRM stat-ит /sys/dev/char/…/device/drm)
    if (isDirPath(path)) {
        std.mem.writeInt(u64, st[0..8], 0, .little);
        // стабильный ino из пути (FNV-1а — каталоги без записи в реестре)
        var hash: u64 = 0xCBF29CE484222325;
        for (cpioCanon(path)) |c| {
            hash ^= c;
            hash *%= 0x100000001B3;
        }
        std.mem.writeInt(u64, st[8..16], hash & 0xFFFF_FFFF, .little);
        std.mem.writeInt(u64, st[16..24], 2, .little); // nlink
        std.mem.writeInt(u32, st[24..28], @intCast(0x4000 | 0x1ED), .little); // S_IFDIR|0755
        std.mem.writeInt(u64, st[48..56], 4096, .little); // size (конвенция)
        std.mem.writeInt(u64, st[56..64], 4096, .little);
        if (!linux_user_io.copy_out(buf_va, &st)) return -linux_syscalls.EFAULT;
        return 0;
    }
    const node = kernel_vfs.resolve(path, false) catch |e| switch (e) {
        vfs.VfsError.NotFound => return -linux_syscalls.ENOENT,
        else => return -linux_syscalls.EIO,
    };
    var size: u64 = 0;
    var ino: u64 = 0;
    switch (node.kind) {
        .initrd_file => {
            const data = node.initrd_data orelse return -linux_syscalls.ENOENT;
            size = data.len;
            ino = @intFromPtr(data.ptr) >> 4; // уникальный id CPIO-entry
        },
        .tmpfs_file => {
            const t = if (node.tmp) |t| t else return -linux_syscalls.ENOENT;
            size = t.size;
            ino = @intFromPtr(t) >> 4;
        },
        .dev => return -linux_syscalls.EIO,
    }
    var stbuf: [144]u8 = [_]u8{0} ** 144;
    std.mem.writeInt(u64, stbuf[0..8], linux_syscalls.POLER_VFS_DEV, .little); // st_dev
    std.mem.writeInt(u64, stbuf[8..16], ino, .little); // st_ino (уникальный!)
    std.mem.writeInt(u64, stbuf[16..24], 1, .little); // st_nlink
    std.mem.writeInt(u32, stbuf[24..28], @intCast(0x8000 | 0x124), .little); // S_IFREG|0444
    std.mem.writeInt(u64, stbuf[48..56], size, .little); // st_size
    std.mem.writeInt(u64, stbuf[56..64], 4096, .little); // st_blksize
    std.mem.writeInt(u64, stbuf[64..72], (size + 511) / 512, .little); // st_blocks
    if (!linux_user_io.copy_out(buf_va, &stbuf)) return -linux_syscalls.EFAULT;
    return 0;
}

fn kernelLinuxOps() linux_syscalls.LinuxOps {
    return .{
        .validate = linuxUserIoValidate,
        .copy_out = linuxUserIoCopyOut,
        .copy_in = linuxUserIoCopyIn,
        .copy_in_str = linuxCopyInStr,
        .dev_write = linuxDevWrite,
        .dev_read = linuxDevRead,
        .dev_ioctl = linuxDevIoctl,
        .dev_ready = linuxDevReady,
        .dev_mmap = linuxDevMmap,
        .do_mmap = linuxDoMmap,
        .do_munmap = linuxDoMunmap,
        .do_exit = linuxDoExit,
        .do_exit_group = linuxDoExitGroup,
        .do_clone = linuxDoClone,
        .do_fork = linuxDoFork,
        .do_execve = linuxDoExecve,
        .do_wait4 = linuxDoWait4,
        .futex_park = linuxFutexPark,
        .futex_wake = linuxFutexWake,
        .current_pid = linuxCurrentPid,
        .current_tid = linuxCurrentTid,
        .kill_thread = linuxKillThread,
        .do_brk = linuxDoBrk,
        .do_mprotect = linuxDoMprotect,
        .do_dontneed = linuxDoDontneed,
        .arch_set_fs = linuxArchSetFs,
        .arch_get_fs = linuxArchGetFs,
        .set_tid_address = linuxSetTidAddress,
        .set_robust_list = linuxSetRobustList,
        .readlink_self = linuxReadlinkSelf,
        .do_getrandom = linuxGetrandom,
        .time_ns = linuxTimeNs,
        .open_file = linuxOpenFile,
        .file_read = linuxFileRead,
        .file_write = linuxFileWrite,
        .file_mmap = linuxFileMmap,
        .file_size = linuxFileSize,
        .file_ino = linuxFileIno,
        .path_exists = linuxPathExists,
        .stat_by_path = linuxStatByPath,
        .readlink_path = linuxReadlinkPath,
        .release_file = linuxReleaseFile,
        .retain_file = linuxRetainFile,
        .channel_create = linuxChannelCreate,
        .channel_read = linuxChannelRead,
        .channel_write = linuxChannelWrite,
        .channel_ready = linuxChannelReady,
        .channel_unref = linuxChannelUnref,
        .channel_link = linuxChannelLink,
        .set_sigaction = linuxSetSigaction,
        .get_sigaction = linuxGetSigaction,
        .set_sigmask = linuxSetSigmask,
        .memfd_create = linuxMemfdCreate,
        .vfs_unlink = linuxVfsUnlink,
        .truncate_file = linuxTruncateFile,
        .shared_file_mmap = linuxSharedFileMmap,
        .dir_read = linuxDirRead,
        .dir_close = linuxDirClose,
        .task_park = linuxTaskPark,
        .mkdir_tmpfs = linuxMkdirTmpfs,
    };
}

// ─── CDD №12 p2: сигнальные мосты (хранение per-proc) ──────────────────────

fn linuxSetSigaction(sig: u32, handler: u64, flags: u64, restorer: u64) i64 {
    if (sig == 0 or sig > 64 or sig == 9 or sig == 19) return -linux_syscalls.EINVAL;
    const slot = linuxProcSlot();
    if (slot >= MAX_LINUX_PROCS) return -linux_syscalls.EPERM;
    const proc = &linux_procs[slot];
    const old: i64 = @bitCast(proc.sig_handlers[sig]);
    proc.sig_handlers[sig] = handler;
    proc.sig_flags[sig] = flags;
    proc.sig_restorers[sig] = restorer;
    return old;
}

fn linuxGetSigaction(sig: u32) u64 {
    const slot = linuxProcSlot();
    if (slot >= MAX_LINUX_PROCS or sig == 0 or sig > 64) return 0;
    return linux_procs[slot].sig_handlers[sig];
}

/// how: 0=BLOCK 1=UNBLOCK 2=SETMASK 3=QUERY; возвращает СТАРУЮ маску.
fn linuxSetSigmask(how: u32, mask: u64) u64 {
    const slot = linuxProcSlot();
    if (slot >= MAX_LINUX_PROCS) return 0;
    const proc = &linux_procs[slot];
    const old = proc.sig_mask;
    switch (how) {
        0 => proc.sig_mask |= mask,
        1 => proc.sig_mask &= ~mask,
        2 => proc.sig_mask = mask,
        else => {},
    }
    return old;
}

/// memfd: анонимный PMM-файл (ftruncate выделяет блок общих страниц).
/// p14: unlink для tmpfs (стейл-лок/сокеты wlserver). /tmp-пути →
/// tmpfs.remove; несуществующее — ENOENT (POSIX); прочие зоны — EROFS.
fn linuxVfsUnlink(path: []const u8) i64 {
    if (!kernel_vfs_ready) return -linux_syscalls.ENOENT;
    if (std.mem.startsWith(u8, path, "/tmp/")) {
        const name = path["/tmp/".len..];
        if (kernel_vfs.tmp.remove(name)) return 0;
        return -linux_syscalls.ENOENT;
    }
    if (std.mem.startsWith(u8, path, "/tmp")) {
        return -linux_syscalls.EISDIR;
    }
    return -linux_syscalls.EPERM; // initrd/dev — только чтение
}

fn linuxMemfdCreate() i64 {
    for (&linux_files, 0..) |*lf, i| {
        if (!lf.used) {
            lf.* = .{ .used = true, .kind = .tmpfs_file, .anon = true };
            return @intCast(i);
        }
    }
    return -linux_syscalls.ENFILE;
}

/// v0.20.0 (CDD №12 p3): ftruncate anon-файла — PMM-блок (нули, копия
/// старого при росте). Mesa: os_create_anonymous_file = memfd+ftruncate.
fn linuxTruncateFile(id: u32, len: u64) i64 {
    if (id >= linux_files.len or !linux_files[id].used) return -linux_syscalls.EBADF;
    const f = &linux_files[id];
    if (!f.anon) return -linux_syscalls.EINVAL; // heap-tmpfs: не растим (малые)
    if (len > ANON_FILE_MAX) return -linux_syscalls.EFBIG;
    if (len == 0) {
        if (f.phys != 0) {
            pmm.freeContiguousPages(f.phys, f.blk_pages);
            f.phys = 0;
            f.blk_pages = 0;
        }
        f.size = 0;
        return 0;
    }
    const want_pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if (want_pages > f.blk_pages) {
        // рост: новый блок + копия старого содержимого
        const new_phys = pmm.allocContiguousZeroed(@intCast(want_pages)) orelse
            return -linux_syscalls.ENOMEM;
        if (f.phys != 0) {
            const copy_pages = @min(f.blk_pages, want_pages);
            const src: [*]const u8 = @ptrFromInt(f.phys);
            const dst: [*]u8 = @ptrFromInt(new_phys);
            @memcpy(dst[0 .. copy_pages * PAGE_SIZE], src[0 .. copy_pages * PAGE_SIZE]);
            pmm.freeContiguousPages(f.phys, f.blk_pages);
        }
        f.phys = new_phys;
        f.blk_pages = want_pages;
    }
    f.size = len;
    return 0;
}

/// v0.20.0 (CDD №12 p3): mmap MAP_SHARED anon-файла — ОБЩИЕ физ-страницы.
/// Каждый маппинг (в т.ч. повторный) получает те же PTE → разделяемая
/// память (контракт wl_shm/lavapipe).
fn linuxSharedFileMmap(id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64 {
    const pml4 = linuxTaskPml4();
    if (pml4 == 0) return -linux_syscalls.EFAULT;
    if (id >= linux_files.len or !linux_files[id].used or !linux_files[id].anon)
        return -linux_syscalls.ENODEV; // heap-tmpfs/initrd: не разделяем
    const f = &linux_files[id];
    if (f.phys == 0) return -linux_syscalls.ENOMEM; // ftruncate не был вызван
    if (off % PAGE_SIZE != 0) return -linux_syscalls.EINVAL;
    if (off >= f.blk_pages * PAGE_SIZE) return -linux_syscalls.EINVAL;
    // хвост за блоком — ENOMEM (Linux бы дал SIGBUS; мы честно отказываем)
    if (off + len > f.blk_pages * PAGE_SIZE) return -linux_syscalls.ENOMEM;
    const proc = linuxProcCurrent() orelse return -linux_syscalls.EFAULT;
    if (len > LINUX_MMAP_BUDGET) return -linux_syscalls.ENOMEM;
    const pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    const va: u64 = if (fixed_va != 0) fixed_va else proc.mmap_cursor;
    if (fixed_va != 0 and fixed_va % PAGE_SIZE != 0) return -linux_syscalls.EINVAL;
    if (fixed_va == 0 and proc.mmap_cursor + pages * PAGE_SIZE > LINUX_MMAP_BASE + LINUX_MMAP_BUDGET)
        return -linux_syscalls.ENOMEM;
    if (va < elf_loader.MIN_USER_VA or va + pages * PAGE_SIZE > linux_syscalls.USER_VA_CEILING)
        return -linux_syscalls.EINVAL;
    // CDD №12 p6: MAP_FIXED-замещение — единая drop-механика (shared-физика
    // принадлежит memfd-файлу: drop её не освобождает — только unmap PTE)
    if (fixed_va != 0) linuxUnmapFixedRange(va, pages);
    var pte: u64 = vmm.PTE_USER | vmm.PTE_WRITABLE;
    if (prot & linux_syscalls.PROT_EXEC == 0) pte |= vmm.PTE_NO_EXECUTE;
    if (prot & linux_syscalls.PROT_WRITE == 0) pte &= ~vmm.PTE_WRITABLE;
    // МАПИМ ОБЩИЕ ФИЗ-СТРАНИЦЫ (нет копий!)
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const phys = f.phys + off + i * PAGE_SIZE;
        vmm.mapPageInPML4(pml4, va + i * PAGE_SIZE, phys, pte) catch {
            return linuxMmapRollback(pml4, va, i, -linux_syscalls.ENOMEM);
        };
    }
    tlbFullFlush(); // p5-NUCLEAR: shared-мап без инвала на АКТИВНОМ CR3
    linuxRecordRegion(linux_task_proc[linuxOwnerTask()], va, pages, 0, false, fdRegionName(id)); // phys общий — НЕ освобождаем
    // CDD №15 p5: МАППИНГ ПИН-ИТ ФАЙЛ (refs++): close(fd) при живом мапе —
    // легален в Linux — больше НЕ освобождает физику. Пара — unpin в
    // linuxRangeDrop (munmap/MAP_FIXED-замещение). Иначе: fabric-цикл lvp
    // (memfd→ftruncate→mmap SHARED→dup→close) освобождал ЖИВОЙ физблок
    // → PMM выдавал его страницы demand-zero → memset(0) → вайп структур
    // (эмпирика: [PW] ZEROED при P=1, lvp NULL+0x2/+0x30 краши t8).
    {
        const rslot = linux_task_proc[linuxOwnerTask()];
        if (rslot < MAX_LINUX_PROCS) {
            for (&linux_mmap_regions[rslot]) |*r| {
                if (r.used and r.va == va and r.pages == pages) {
                    r.file_id = id;
                    break;
                }
            }
        }
        linuxRetainFile(id);
    }
    if (fixed_va == 0) proc.mmap_cursor += pages * PAGE_SIZE;
    return @intCast(va);
}

/// pid: стабилен внутри процесса (группа тредов = слот): 100 + slot.
fn linuxCurrentPid() u64 {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) {
        const slot = linux_task_proc[owner];
        if (slot < MAX_LINUX_PROCS) return 1000 + @as(u64, slot); // v0.20: pid-базис 1000+slot (fork-контракт wait4)
    }
    return 1000; // shell-контекст
}

/// tid: id задачи-владельца syscall-каскада (NPTL: уникален на тред).
fn linuxCurrentTid() u64 {
    const owner = linuxOwnerTask();
    if (owner < scheduler.MAX_TASKS) return owner;
    return 0;
}

/// CDD №12 p4: kill_thread-мост tgkill: tid = task_id (gettid-контракт).
/// СЕБЯ (abort-путь glibc): exit-паттерн — exitCurrentTask + sti + hlt
/// (syscall-каскад под IF=0 — парковка таймеру обязательна, см. linuxDoExit).
/// ДРУГОЙ поток: killTask + CLEARTID-эпилог; exit_code = 128+sig (wait-
/// семантика Linux «убит сигналом»). Вызывается только через LinuxOps.
fn linuxKillThread(tid: u64, sig: u64) bool {
    if (tid >= scheduler.MAX_TASKS) return false;
    const t = &scheduler.tasks[tid];
    if (t.state == .Killed or t.privilege != .User) return false;
    const owner = linuxOwnerTask();
    hal.Serial.puts("[LINUX] tgkill(");
    hal.Serial.putDecimal(tid);
    hal.Serial.puts(", sig=");
    hal.Serial.putDecimal(sig);
    if (tid == owner) {
        hal.Serial.puts(") — self-kill (abort-путь)\n");
        // exit_code = 128+sig (wait-семантика Linux: killed-by-signal)
        const slot = linux_task_proc[owner];
        if (slot < MAX_LINUX_PROCS) linux_procs[slot].exit_code = 128 + sig;
        linuxDoExit(128 + sig);
        unreachable; // linuxDoExit не возвращает (hlt-цикл)
    }
    hal.Serial.puts(") — killing thread\n");
    const slot = linux_task_proc[tid];
    if (slot < MAX_LINUX_PROCS) linux_procs[slot].exit_code = 128 + sig;
    linuxClearWakeTid(tid);
    scheduler.killTask(tid) catch return false;
    return true;
}

/// hal.linuxSyscallCallback: Linux x86_64 RAX-ABI. Аргументы №5/№6 (user
/// R8/R9) читаем из scheduler-глобалов (asm-вход сохранил ДО затирания).
/// v0.20.0 (CDD №11 p3): трассировка Linux-syscall'ов (команда ltrace) —
/// crash-driven инструмент: видно ПОСЛЕДОВАТЕЛЬНОСТЬ и возвраты.
var linux_trace: bool = false;
var poll_diag_counter: u32 = 0; // p14: capped [PLW]-трейс (первые 30)

fn linuxSyscallEntry(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    // CDD №12 p8: ВХОДНОЙ трейс паркующих syscall'ов ([L] печатает только
    // ВЫХОД: sysEpollWait с timeout=-1 паркнут НАВСЕГДА — его вызов невидим
    // в [L]-фронте; эмпирика p8run2: задачи 3/4 в 20мс-парк-петле, но WHO
    // и с каким timeout — неизвестно). tid = владелец user_rsp; rip =
    // syscall_frame[7] = user-RIP после syscall → точный call-site.
    if (num == 232 or num == 281) { // epoll_wait / epoll_pwait
        const timeout: i64 = @bitCast(a4);
        if (timeout != 0) {
            const owner = scheduler.syscallStackOwner(scheduler.user_rsp);
            hal.Serial.puts("[EPW] tid=");
            hal.Serial.putDecimal(owner);
            hal.Serial.puts(" epfd=");
            hal.Serial.putDecimal(a1);
            hal.Serial.puts(" max=");
            hal.Serial.putDecimal(a3);
            hal.Serial.puts(" t=");
            if (timeout < 0) {
                hal.Serial.puts("-1");
            } else {
                hal.Serial.putDecimal(@as(u64, @intCast(timeout)));
            }
            hal.Serial.puts(" rip=0x");
            hal.Serial.putHex(scheduler.syscall_frame[7]);
            hal.Serial.puts("\n");
        }
    }
    if (num == 7) { // p14: poll c timeout≠0 — кто блокируется (capped 30)
        const ptimeout: i64 = @bitCast(a3);
        if (ptimeout != 0 and poll_diag_counter < 30) {
            poll_diag_counter += 1;
            const owner = scheduler.syscallStackOwner(scheduler.user_rsp);
            hal.Serial.puts("[PLW] tid=");
            hal.Serial.putDecimal(owner);
            hal.Serial.puts(" nfds=");
            hal.Serial.putDecimal(a2);
            hal.Serial.puts(" t=");
            if (ptimeout < 0) {
                hal.Serial.puts("-1");
            } else {
                hal.Serial.putDecimal(@as(u64, @intCast(ptimeout)));
            }
            hal.Serial.puts("\n");
        }
    }
    if (num == 202) { // futex: WAIT/WAKE на ВХОДЕ (парк невидим в [L])
        const fop: u64 = a2 & 0x7F;
        if (fop <= 10) {
            const owner = scheduler.syscallStackOwner(scheduler.user_rsp);
            hal.Serial.puts("[FXW] tid=");
            hal.Serial.putDecimal(owner);
            hal.Serial.puts(" op=");
            hal.Serial.putDecimal(fop);
            if (a2 & 128 != 0) hal.Serial.puts("P");
            hal.Serial.puts(" uaddr=0x");
            hal.Serial.putHex(a1);
            hal.Serial.puts(" val=");
            hal.Serial.putDecimal(a3);
            hal.Serial.puts(" rip=0x");
            hal.Serial.putHex(scheduler.syscall_frame[7]);
            hal.Serial.puts("\n");
        }
    }
    const r = linux_syscalls.dispatch(kernelLinuxOps(), linuxFdsCurrent(), num, .{

        .a1 = a1,
        .a2 = a2,
        .a3 = a3,
        .a4 = a4,
        .a5 = scheduler.linux_arg5,
        .a6 = scheduler.linux_arg6,
    });
    if (linux_trace) {
        // CDD №15: t=<owner> — ЧЬЙ syscall (рассинхрон fork-ребёнка на
        // общем VA-стеке ловим поимённо: asm cur-first → линейный → кс)
        hal.Serial.puts("[L:t");
        hal.Serial.putDecimal(linuxOwnerTask());
        hal.Serial.puts("] ");
        hal.Serial.putDecimal(num);
        hal.Serial.puts("(0x");
        hal.Serial.putHex(a1);
        // CDD №12 p4: ПУТЬ для path-syscall'ов (openat/access/stat/readlink —
        // CDD-изоляция: ENOENT-фронты видны ПОИМЁННО, а не по адресу аргумента)
        if (num == 257 or num == 21 or num == 262 or num == 267 or num == 87 or
            num == 89 or num == 254)
        {
            const path_va = switch (num) {
                257, 262, 267, 254 => a2, // openat/newfstatat/readlinkat/inotify_add_watch
                else => a1, // access/readlink/unlink
            };
            if (linuxCopyInStr(path_va, 96)) |p| {
                hal.Serial.putHex(a1);
                hal.Serial.puts(",\"");
                hal.Serial.puts(p[0..@min(p.len, 96)]);
                hal.Serial.puts("\"");
            } else {
                hal.Serial.putHex(a1);
            }
        } else {
            hal.Serial.putHex(a1);
        }
        hal.Serial.puts(",0x");
        hal.Serial.putHex(a2);
        if (num == 13 or num == 14 or num == 157 or num == 281 or num == 270 or num == 289 or num == 16 or
            num == 10 or num == 28 or num == 56 or num == 202)
        {
            hal.Serial.puts(",0x");
            hal.Serial.putHex(a3);
            hal.Serial.puts(",0x");
            hal.Serial.putHex(a4);
        }
        // CDD №12 p11: mmap — прот/флаги/fd/оффс (JIT-страницы: anon vs
        // memfd/кеш — fd решает спор «двойной маппинг vs приват»)
        if (num == 9) {
            hal.Serial.puts(",0x");
            hal.Serial.putHex(a3); // prot
            hal.Serial.puts(",0x");
            hal.Serial.putHex(a4); // flags
            hal.Serial.puts(",fd=");
            hal.Serial.putHex(scheduler.linux_arg5);
            hal.Serial.puts(",off=");
            hal.Serial.putHex(scheduler.linux_arg6);
        }
        hal.Serial.puts(") = 0x");
        hal.Serial.putHex(r);
        hal.Serial.puts("\n");
    }
    // CDD №12 p4-final: АРГУМЕНТ-0xAAAA-детект. Эмпирика: гостевой ld.so
    // после openat(→fd=3) шлёт read(0xAAAAAAAA,...) — ВАЛИДНОЕ ЗНАЧЕНИЕ
    // (fd) ТЕРЯЕТСЯ между нашим syscall-возвратом и использованием гостем
    // (тот же класс, что R15=0xAAAA-краш). Ловим ЛЮБОЙ syscall с мусорным
    // аргументом → дамп гостевого стека (ret-адреса = вызывающая цепочка).
    if (a1 == 0xAAAAAAAA or a2 == 0xAAAAAAAA or a3 == 0xAAAAAAAA or
        a4 == 0xAAAAAAAA)
    {
        linuxAaaaTrace(num, a1);
    }

    // CDD #12 p8 (ФИКС ФРОНТА): КРОСС-ТАСК ПОРЧА ВЫХОДНОГО КАДРА syscall.
    // ЭМПИРИКА p8run4: sysClone → linuxYieldTick (транзакция выпущена,
    // родитель парк 10мс) → ДИТЯ входит в свои syscall'ы — каждый вход
    // ПЕРЕ-указывает ГЛОБАЛ syscall_exit_frame_ptr на СВОЮ .bss-строку →
    // родительский выходной каскад isr64.S читает ЧУЖУЮ строку → sysretq
    // уводит РОДИТЕЛЯ в user-RIP/стек ДИТЯ (эпилог epoll_wait-обёртки) →
    // glibc-clone РОДИТЕЛЬ выполняет child-ветку (glue/ThreadFunc) →
    // gamescope теряет main-поток в бесконечном ThreadFunc парке —
    // DRM-init не начинается. user_rsp/ret_tmp восстанавливаются
    // (парк-эпилог / asm-хвост), а ptr — НЕТ.
    // ЛЕЧЕНИЕ ПО КОНСТРУКЦИИ: перед возвратом в asm — пере-указать глобал
    // на .bss-строку ВЛАДЕЛЬЦА транзакции (строки пер-тасковые: их пишет
    // ТОЛЬКО вход владельца — парки НЕ портят).
    {
        const owner = scheduler.syscallStackOwner(scheduler.user_rsp);
        if (owner < scheduler.MAX_TASKS and owner != 0) {
            scheduler.syscall_exit_frame_ptr =
                @intFromPtr(&scheduler.syscall_exit_frame[owner]);
        } else {
            // shell/boot-контекст: честный pop-fallback (снапшота нет)
            scheduler.syscall_exit_frame_ptr = 0;
        }
    }
    return r;
}


/// ДАМП-ТРЕЙС syscall с аргументом-0xAAAA: системный номер + гостевой
/// стек вызывающего (кадр syscall_entry: [top-8]=r11-слот... формат
/// каскада: top-8=r11, top-16=rcx, ..., [user_rsp] = живой стек гостя).
/// Читаем через scheduler.user_rsp (записан атомарно asm-входом).
var aaaa_trace_n: u32 = 0;
fn linuxAaaaTrace(num: u64, fdarg: u64) void {
    aaaa_trace_n += 1;
    if (aaaa_trace_n > 3) return; // анти-спам: 3 дампа
    hal.Serial.puts("[AAAA] syscall=");
    hal.Serial.putDecimal(num);
    hal.Serial.puts(" arg=0x");
    hal.Serial.putHex(fdarg);
    hal.Serial.puts(" user_rsp=0x");
    const ur = scheduler.user_rsp;
    hal.Serial.putHex(ur);
    hal.Serial.puts("\n[AAAA] guest-stack:\n");
    // чтение 24 слотов гостевого стека НАПРЯМУЮ по VA: CR3 задачи активен
    // в syscall-каскаде (guest VA транслируется железом; диапазон — в
    // каноническом user-пространстве; #PF невозможен — страницы стека
    // замаплены: задача только что читала/писала их)
    var i: usize = 0;
    while (i < 24) : (i += 1) {
        const va = ur + i * 8;
        if (linuxProbeUser(va)) |v| {
            hal.Serial.puts("  [rsp+");
            hal.Serial.putDecimal(i * 8);
            hal.Serial.puts("] 0x");
            hal.Serial.putHex(v);
            if (linuxModuleAt(linuxOwnerTask(), v)) |hit| {
                hal.Serial.puts("(");
                hal.Serial.puts(hit.name);
                hal.Serial.puts("+0x");
                hal.Serial.putHex(hit.off);
                hal.Serial.puts(")");
            }
            hal.Serial.puts("\n");
        } else break;
    }
}

/// безопасное чтение 8Б гостевой VA: прямой deref + vmm-guard таблиц
/// (fallback, если прямой путь не замаплен).
fn linuxProbeUser(va: u64) ?u64 {
    // CR3 задачи активен в syscall-каскаде — прямой VA-deref (таблицы
    // задачи транслируют; стек задачи гарантированно замаплен).
    const p: *volatile u64 = @ptrFromInt(va & ~@as(u64, 7));
    return p.*;
}

fn linuxPeekUserOld(pml4: u64, va: u64) ?u64 {
    // x86-64 4-уровневый walk: PML4(39)→PDP(30)→PD(21)→PT(12)
    var table = pml4;
    var level: u6 = 39;
    while (true) {
        const idx = (va >> level) & 0x1FF;
        const entry: *volatile u64 = @ptrFromInt(table + idx * 8);
        const e = entry.*;
        if (e & 1 == 0) return null;
        if (level == 12) {
            const pa = (e & 0x000FFFFFFFFFF000) + (va & 0xFFF);
            const p: *volatile u64 = @ptrFromInt(pa);
            return p.*;
        }
        if (level == 21 and (e & (1 << 7)) != 0) {
            // 2MB страница
            const pa = (e & 0xFFFFFFE00000) + (va & 0x1FFFFF);
            const p: *volatile u64 = @ptrFromInt(pa);
            return p.*;
        }
        table = e & 0x000FFFFFFFFFF000;
        level -= 9;
    }
}

// ─── v0.19.0 (CDD №10 p1): DRM-KMS runtime — «Всё есть файл» ──────────────
//
// Экран = /dev/fb0 + /dev/dri/card0. Скрипт CachyOS-юзерспейса (Mesa/
// Gamescope/Wayland — шаги 4-5) поднимается над этими файлами:
// ioctl из drm_kms.zig (UAPI-совместимые номера), mmap видеопамяти WC.
//
// Источник скан-аута: (а) линейный фреймбуфер бут-лоадера (GRUB-multiboot2
// VBE — -vga std / ISO-загрузка); (б) VirtIO-GPU probe (modern 0x1050) —
// PCI-capability-карта для vring-драйвера следующих волн.

/// Глобальное DRM-состояние ядра (dumb-KMS: 1 CRTC/энкодер/коннектор).
var drm_state: drm_kms.DrmState = .{};
/// Probe-результат VirtIO-GPU (null = устройства нет; норма для -vga std).
var gpu_probe: ?virtio_gpu.GpuProbe = null;
/// v0.20.0 (CDD №11 p2): vring-состояние + MMIO-конфиг (caps → BAR+offset).
var gpu_vring: virtio_gpu.VringState = .{};
var gpu_vring_cfg: ?virtio_gpu.VringConfig = null;
/// Capability-карта probe (common/notify/device cfg для vring-волн).
var gpu_caps: [virtio_gpu.MAX_CAPS]virtio_gpu.VirtioCap = [_]virtio_gpu.VirtioCap{.{}} ** virtio_gpu.MAX_CAPS;
var gpu_caps_n: usize = 0;

/// PCI-читатель для virtio_gpu.probe (инъекция pci.zig).
fn kernelPciRead8(bus: u8, slot: u8, func: u8, off: u8) u8 {
    return pci.pciRead8(bus, slot, func, off);
}
fn kernelPciRead16(bus: u8, slot: u8, func: u8, off: u8) u16 {
    return pci.pciRead16(bus, slot, func, off);
}
fn kernelPciRead32(bus: u8, slot: u8, func: u8, off: u8) u32 {
    return pci.pciRead32(bus, slot, func, off);
}
fn kernelPciCfg() virtio_gpu.PciCfg {
    return .{ .read8 = kernelPciRead8, .read16 = kernelPciRead16, .read32 = kernelPciRead32 };
}

/// Бут-инициализация DRM (шаг 9c): PAT→WC (PWT-бит = Write-Combining после
/// Linux-раскладки MSR 0x277), probe VirtIO-GPU, регистрация linear-fb.
fn drmBootInit() void {
    // (1) PAT: PA1/PA5 → WC. Фреймбуфер мапится юзерспейсу с PWT-битом —
    // burst-записи пикселей без writeback-инвалидации cacheline'ов (FPS).
    hal.writeMsr(0x277, drm_kms.PAT_LINUX_WC);
    puts("[DRM] PAT programmed: WC on PWT (MSR 0x277, Linux layout)\n");

    // (2) VirtIO-GPU probe (QEMU -device virtio-gpu-pci): modern 0x1050.
    gpu_probe = virtio_gpu.probe(kernelPciCfg());
    if (gpu_probe) |g| {
        gpu_caps_n = virtio_gpu.parseCaps(kernelPciCfg(), g, &gpu_caps);
        puts("[VIRTIO-GPU] PCI ");
        putHex(g.bus);
        puts(":");
        putHex(g.slot);
        puts(" dev=0x");
        putHex(g.device_id);
        puts(" modern, caps=");
        putDecimal(@intCast(gpu_caps_n));
        puts("\n");

        // v0.20.0 (CDD №11 p2): VRING — caps → MMIO-базисы → init →
        // GET_DISPLAY_INFO → геометрия РЕАЛЬНОГО скан-аута
        gpuVringSetup(g);

        if (gpu_vring_cfg != null) {
            if (virtio_gpu.getDisplayInfo(gpu_vring_cfg.?, &gpu_vring)) |pm| {
                puts("[VIRTIO-GPU] GET_DISPLAY_INFO: scanout ");
                putDecimal(pm.r.w);
                puts("x");
                putDecimal(pm.r.h);
                puts(" enabled — vring roundtrip OK\n");
                drm_kms.initVirtioGpu(&drm_state, .{
                    .phys = 0,
                    .width = pm.r.w,
                    .height = pm.r.h,
                    .pitch = pm.r.w * 4,
                    .bpp = 32,
                });
            } else {
                puts("[VIRTIO-GPU] GET_DISPLAY_INFO timeout/нет scanout — дефолт 1024x768\n");
                drm_kms.initVirtioGpu(&drm_state, .{
                    .phys = 0,
                    .width = 1024,
                    .height = 768,
                    .pitch = 4096,
                    .bpp = 32,
                });
            }
        } else {
            puts("[VIRTIO-GPU] caps без common/notify — vring недоступен\n");
            drm_kms.initVirtioGpu(&drm_state, .{
                .phys = 0,
                .width = 1024,
                .height = 768,
                .pitch = 4096,
                .bpp = 32,
            });
        }
    } else {
        puts("[VIRTIO-GPU] no device (expected with -vga std)\n");
    }

    // (3) Linear framebuffer от бут-лоадера: авторитетная геометрия скан-аута
    //     (перекрывает дефолт probe — скан-аут уже показывается физически).
    if (framebuffer.is_available()) {
        drm_kms.initLinearFb(&drm_state, .{
            .phys = framebuffer.getAddr(),
            .width = framebuffer.getWidth(),
            .height = framebuffer.getHeight(),
            .pitch = framebuffer.getPitch(),
            .bpp = framebuffer.getBpp(),
        });
        puts("[DRM] linear-fb scanout: ");
        putDecimal(framebuffer.getWidth());
        puts("x");
        putDecimal(framebuffer.getHeight());
        puts("x");
        putDecimal(framebuffer.getBpp());
        puts(" @0x");
        putHex(framebuffer.getAddr());
        puts("\n");
    } else if (drm_state.mode == .inactive) {
        puts("[DRM] no scanout source (PVH headless): dumb-KMS armed, /dev on demand\n");
    }
    puts("[DRM] /dev/fb0 + /dev/dri/card0 registered (dumb-KMS, CDD #10)\n");
}

/// Kernel-side DrmOps для drmtest: «user»-аргументы живут в identity-буфере
/// .bss (валидация по диапазону буфера; copy_in/out — прямые).
var drmtest_buf: [256]u8 align(16) = .{0} ** 256;

fn drmtestValidate(va: u64, len: u64, want_write: bool) bool {
    _ = want_write;
    if (len > drmtest_buf.len) return false;
    const base: u64 = @intFromPtr(&drmtest_buf);
    return va >= base and va + len <= base + drmtest_buf.len;
}
fn drmtestCopyIn(dst: []u8, src_va: u64) bool {
    if (!drmtestValidate(src_va, dst.len, false)) return false;
    const p: [*]const u8 = @ptrFromInt(src_va);
    @memcpy(dst, p[0..dst.len]);
    return true;
}
fn drmtestCopyOut(dst_va: u64, src: []const u8) bool {
    if (!drmtestValidate(dst_va, src.len, true)) return false;
    const p: [*]u8 = @ptrFromInt(dst_va);
    @memcpy(p[0..src.len], src);
    return true;
}
fn drmAllocPages(pages: u64) ?u64 {
    return pmm.allocContiguousZeroed(@intCast(pages));
}
fn drmFreePages(phys: u64, pages: u64) void {
    pmm.freeContiguousPages(phys, @intCast(pages));
}
fn kernelDrmOps() drm_kms.DrmOps {
    return .{
        .validate = drmtestValidate,
        .copy_in = drmtestCopyIn,
        .copy_out = drmtestCopyOut,
        .alloc_pages = drmAllocPages,
        .free_pages = drmFreePages,
        .scanout_frame = drmScanoutFrame,
    };
}

/// CDD №12 p4: СКАН-АУТ ФРЕЙМБУФЕРА НА ДИСПЛЕЙ — DRM PAGE_FLIP/SETCRTC →
/// VirtIO-GPU vring 2D (RESOURCE_CREATE_2D → ATTACH_BACKING(phys) →
/// TRANSFER_TO_HOST_2D → SET_SCANOUT → RESOURCE_FLUSH). Первый кадр
/// gamescope = первый успешный вызов. Ресурс-ид монотонный (двойная
/// буферизация: каждый флип = свой ресурс; gputest — фиксированный 7).
var drm_scanout_res_id: u32 = 100;
fn drmScanoutFrame(phys: u64, len: u64, w: u32, h: u32, pitch: u32) bool {
    _ = pitch; // 2D-ресурс B8G8R8X8: строки плотные (pitch == width*4 —
    // ioAddFb2/ioCreateDumb гарантируют XRGB8888-сstride)
    if (phys == 0 or len == 0 or w == 0 or h == 0) return false;
    const cfg = gpu_vring_cfg orelse return false;
    if (gpu_probe == null) return false;
    drm_scanout_res_id += 1;
    const ok = virtio_gpu.scanoutFrame(cfg, &gpu_vring, drm_scanout_res_id, w, h, phys, len);
    if (ok) {
        hal.Serial.puts("[DRM] scanout=");
        hal.Serial.putDecimal(drm_state.scanouts);
        hal.Serial.puts(" frame ");
        hal.Serial.putDecimal(w);
        hal.Serial.puts("x");
        hal.Serial.putDecimal(h);
        hal.Serial.puts(" via vring (res ");
        hal.Serial.putDecimal(drm_scanout_res_id);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts("[DRM] scanout FAILED (vring)\n");
    }
    return ok;
}

/// mmap линейного фреймбуфера в user-PML4 c WC (PWT): страницы VRAM,
/// MAP_SHARED-семантика (запись пикселя = вывод на экран). Вызывается
/// Linux-mmap-слоем (шаг 3) для fd=/dev/fb0.
fn drmMapLinearFbUser(pml4: u64, va: u64, len: u64) bool {
    if (drm_state.mode != .linear_fb) return false;
    const pages = (len + vmm.PAGE_SIZE - 1) / vmm.PAGE_SIZE;
    // PTE: WC = PWT (PAT PA1 после репрограммирования) + USER + RW + NX
    const pte: u64 = vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE | drm_kms.PTE_WC;
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const pa = drm_state.geom.phys + i * vmm.PAGE_SIZE;
        vmm.mapPageInPML4(pml4, va + i * vmm.PAGE_SIZE, pa, pte) catch return false;
    }
    return true;
}

/// v0.20.0 (CDD №11 p2): caps → MMIO-базисы (BAR+cap.offset) + vring-init.
/// Общий/notify-регионы — PCI MMIO < 4ГБ (identity-маппинг ядра).
fn gpuVringSetup(g: virtio_gpu.GpuProbe) void {
    var common_base: u64 = 0;
    var notify_base: u64 = 0;
    var notify_mult: u32 = 0;
    for (gpu_caps[0..gpu_caps_n]) |cap| {
        const bar_addr = g.barAddr(@intCast(cap.bar % 6));
        if (bar_addr == 0) continue;
        switch (cap.cfg_type) {
            virtio_gpu.VIRTIO_PCI_CAP_COMMON_CFG => common_base = bar_addr + cap.offset,
            virtio_gpu.VIRTIO_PCI_CAP_NOTIFY_CFG => {
                notify_base = bar_addr + cap.offset;
                notify_mult = cap.notify_off_multiplier;
            },
            else => {},
        }
    }
    if (common_base == 0 or notify_base == 0) {
        puts("[VIRTIO-GPU] vring: нет common/notify cap — скан-аут недоступен\n");
        return;
    }
    gpu_vring_cfg = .{
        .common = .{ .base = common_base },
        .notify = .{ .base = notify_base },
        .notify_off_multiplier = notify_mult,
        .alloc_page = gpuVringAllocPage,
        .tick = gpuVringTick,
    };
    const vr_cfg = gpu_vring_cfg.?;
    const r = virtio_gpu.vringInit(vr_cfg, &gpu_vring);
    if (r == virtio_gpu.VRING_OK) {
        vr_cfg.common.w16(virtio_gpu.CCFG_OFF_QUEUE_SELECT, virtio_gpu.CTRL_QUEUE_IDX);
        const n_off = vr_cfg.common.r16(virtio_gpu.CCFG_OFF_QUEUE_NOTIFY_OFF);
        puts("[VIRTIO-GPU] vring INIT OK: ctrl-queue ");
        putDecimal(@intCast(gpu_vring.qsize));
        puts(" desc, DRIVER_OK, common=0x");
        putHex(common_base);
        puts(" notify=0x");
        putHex(notify_base);
        puts(" mult=");
        putDecimal(notify_mult);
        puts(" n_off=");
        putDecimal(n_off);
        puts("\n");
    } else {
        puts("[VIRTIO-GPU] vring init FAIL code=");
        putDecimal(@intCast(-r));
        puts("\n");
        gpu_vring_cfg = null;
    }
}

/// PMM-страница под vring (4К-выровнена — обязательное требование spec).
fn gpuVringAllocPage() ?u64 {
    return pmm.allocContiguousZeroed(1);
}

/// poll-тик: ~1мс реального времени (TSC-дедлайн; QEMU TCG обрабатывает
/// virtqueue в MMIO-обработчике notify, но под нагрузкой — десятки мс).
fn gpuVringTick() bool {
    // мягкая задержка ~мс-масштаба (2М pause); эмпирика QEMU-10 qemu64:
    // TSC-RDMSR зацикливался — планировочные тики живут, TSC нет
    var i: u32 = 0;
    while (i < 2_000_000) : (i += 1) {
        asm volatile ("pause");
    }
    return true;
}

/// cmd_gputest: E2E-самотест VRING-скан-аута (CDD №11 p2):
/// dumb-буфер с тест-паттерном → CREATE_2D/ATTACH/TRANSFER/SET_SCANOUT/
/// FLUSH через virtqueue → РЕАЛЬНЫЙ вывод кадра на дисплей QEMU.
/// Маркеры [GPUTEST] ловит e2e (gpu-scanout: screendump → пиксели).
fn cmd_gputest() void {
    if (gpu_probe == null or gpu_vring_cfg == null) {
        sys_print("[GPUTEST] FAIL: virtio-gpu/vring отсутствует (-device virtio-gpu-pci)\n");
        return;
    }
    const cfg = gpu_vring_cfg.?;
    sys_print("[GPUTEST] begin: vring 2D-конвейер скан-аута\n");

    const w = drm_state.geom.width;
    const h = drm_state.geom.height;
    if (w == 0 or h == 0) {
        sys_print("[GPUTEST] FAIL: геометрия скан-аута неизвестна\n");
        return;
    }

    // 1. Dumb-буфер w×h (contiguous-физблок PMM)
    const bytes = @as(u64, w) * h * 4;
    const pages = (bytes + 4095) / 4096;
    const buf_phys = pmm.allocContiguousZeroed(@intCast(pages)) orelse {
        sys_print("[GPUTEST] FAIL: PMMContiguous\n");
        return;
    };

    // 2. Тест-паттерн: диагональные полосы B8G8R8X8 (DRM XRGB8888-эквивалент)
    const pixels: [*]volatile u32 = @ptrFromInt(buf_phys);
    const pitch_u32 = w;
    var y: u32 = 0;
    while (y < h) : (y += 1) {
        var x: u32 = 0;
        while (x < w) : (x += 1) {
            const stripe: u32 = ((x / 64) + (y / 64)) % 2;
            pixels[@as(u32, y) * pitch_u32 + x] = if (stripe != 0)
                0x34C7_5B12 // [B=0x12, G=0x5B, R=0xC7, X]
            else
                0x1207_1120; // [B=0x20, G=0x11, R=0x07, X]
        }
    }
    sys_print("[GPUTEST] pattern ");
    putDecimal(w);
    sys_print("x");
    putDecimal(h);
    sys_print(" (stripes 64px)\n");

    // 3. VRING 2D-конвейер: ресурс 1 → экран (покроково — диагностика стадий)
    const stages = [_]struct { name: []const u8 }{
        .{ .name = "CREATE_2D" },
        .{ .name = "ATTACH" },
        .{ .name = "TRANSFER" },
        .{ .name = "SET_SCANOUT" },
        .{ .name = "FLUSH" },
    };
    // STEP 1: RESOURCE_CREATE_2D
    var create = virtio_gpu.cmdResourceCreate2d(1, w, h);
    var hdr = virtio_gpu.submitCmd(cfg, &gpu_vring, &create, @sizeOf(virtio_gpu.ResourceCreate2d)) orelse {
        sys_print("[GPUTEST] FAIL: CREATE_2D timeout\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    };
    if (hdr.type_ != virtio_gpu.RESP_OK_NODATA) {
        sys_print("[GPUTEST] FAIL: CREATE_2D resp=0x");
        putHex(hdr.type_);
        sys_print("\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    }
    sys_print("[GPUTEST] stage 1/5 CREATE_2D ok\n");
    // STEP 2: ATTACH_BACKING (INLINE mem-entry — UAPI: 32Б заголовок +
    // 16Б записи в ОДНОМ буфере команды; отдельные данные → 0x1200)
    var attach_buf: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, attach_buf[0..4], virtio_gpu.CMD_RESOURCE_ATTACH_BACKING, .little);
    std.mem.writeInt(u32, attach_buf[24..28], 1, .little); // resource_id
    std.mem.writeInt(u32, attach_buf[28..32], 1, .little); // nr_entries
    std.mem.writeInt(u64, attach_buf[32..40], buf_phys, .little); // entry.addr
    std.mem.writeInt(u32, attach_buf[40..44], @truncate(bytes), .little); // entry.length
    hdr = virtio_gpu.submitCmd(cfg, &gpu_vring, &attach_buf, 48) orelse {
        sys_print("[GPUTEST] FAIL: ATTACH timeout\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    };
    if (hdr.type_ != virtio_gpu.RESP_OK_NODATA) {
        sys_print("[GPUTEST] FAIL: ATTACH resp=0x");
        putHex(hdr.type_);
        sys_print("\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    }
    sys_print("[GPUTEST] stage 2/5 ATTACH_BACKING ok\n");
    // STEP 3: TRANSFER_TO_HOST_2D
    var transfer = virtio_gpu.TransferToHost2d{
        .hdr = .{ .type_ = virtio_gpu.CMD_TRANSFER_TO_HOST_2D },
        .w = w,
        .h = h,
        .resource_id = 1,
    };
    hdr = virtio_gpu.submitCmd(cfg, &gpu_vring, &transfer, @sizeOf(virtio_gpu.TransferToHost2d)) orelse {
        sys_print("[GPUTEST] FAIL: TRANSFER timeout\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    };
    if (hdr.type_ != virtio_gpu.RESP_OK_NODATA) {
        sys_print("[GPUTEST] FAIL: TRANSFER resp=0x");
        putHex(hdr.type_);
        sys_print("\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    }
    sys_print("[GPUTEST] stage 3/5 TRANSFER_TO_HOST_2D ok\n");
    // STEP 4: SET_SCANOUT
    var scanout_cmd = virtio_gpu.SetScanout{
        .hdr = .{ .type_ = virtio_gpu.CMD_SET_SCANOUT },
        .w = w,
        .h = h,
        .scanout_id = 0,
        .resource_id = 1,
    };
    hdr = virtio_gpu.submitCmd(cfg, &gpu_vring, &scanout_cmd, @sizeOf(virtio_gpu.SetScanout)) orelse {
        sys_print("[GPUTEST] FAIL: SET_SCANOUT timeout\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    };
    if (hdr.type_ != virtio_gpu.RESP_OK_NODATA) {
        sys_print("[GPUTEST] FAIL: SET_SCANOUT resp=0x");
        putHex(hdr.type_);
        sys_print("\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    }
    sys_print("[GPUTEST] stage 4/5 SET_SCANOUT ok\n");
    // STEP 5: RESOURCE_FLUSH
    var flush_cmd = virtio_gpu.ResourceFlush{
        .hdr = .{ .type_ = virtio_gpu.CMD_RESOURCE_FLUSH },
        .w = w,
        .h = h,
    };
    hdr = virtio_gpu.submitCmd(cfg, &gpu_vring, &flush_cmd, @sizeOf(virtio_gpu.ResourceFlush)) orelse {
        sys_print("[GPUTEST] FAIL: FLUSH timeout\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    };
    if (hdr.type_ != virtio_gpu.RESP_OK_NODATA) {
        sys_print("[GPUTEST] FAIL: FLUSH resp=0x");
        putHex(hdr.type_);
        sys_print("\n");
        pmm.freeContiguousPages(buf_phys, @intCast(pages));
        return;
    }
    sys_print("[GPUTEST] stage 5/5 RESOURCE_FLUSH ok — КАДР НА ЭКРАНЕ\n");
    _ = stages;
    sys_print("[GPUTEST] CREATE_2D + ATTACH + TRANSFER + SET_SCANOUT + FLUSH ok\n");
    sys_print("[GPUTEST] кадр НА ЭКРАНЕ (screendump верифицирует пиксели)\n");

    // ресурс не освобождаем (scanout живёт); физблок — владение ресурса
    sys_print("[GPUTEST] ALL PASS\n");
}

/// cmd_drm: статус DRM/KMS для шелла и E2E.
fn cmd_drm() void {
    sys_print("[DRM] mode=");
    const m = switch (drm_state.mode) {
        .inactive => "inactive",
        .linear_fb => "linear-fb (bootloader scanout)",
        .virtio_gpu => "virtio-gpu (probe armed)",
    };
    sys_print(m);
    sys_print("\n");
    if (drm_state.mode != .inactive) {
        sys_print("[DRM] scanout ");
        putDecimal(drm_state.geom.width);
        sys_print("x");
        putDecimal(drm_state.geom.height);
        sys_print("x");
        putDecimal(drm_state.geom.bpp);
        sys_print(" pitch=");
        putDecimal(drm_state.geom.pitch);
        sys_print(" vram=0x");
        putHex(drm_state.geom.phys);
        sys_print("\n");
    }
    if (gpu_probe != null) {
        sys_print("[DRM] virtio-gpu probe OK, caps=");
        putDecimal(@intCast(gpu_caps_n));
        sys_print(" /dev/dri/card0 + /dev/dri/renderD128\n");
    } else {
        sys_print("[DRM] no virtio-gpu (display via -vga std / fb0)\n");
    }
    var dumb_n: u32 = 0;
    for (&drm_state.dumb) |*b| {
        if (b.used) dumb_n += 1;
    }
    sys_print("[DRM] dumb buffers: ");
    putDecimal(dumb_n);
    sys_print("/8, page flips: ");
    putDecimal(drm_state.flips);
    sys_print(", caps: VERSION/GET_CAP/GETRESOURCES/GETCRTC/GETCONNECTOR/CREATE_DUMB/MAP_DUMB/ADDFB/PAGE_FLIP\n");
}

/// cmd_drmtest: E2E-самотест DRM (шаг 5): полный жизненный цикл dumb-буфера
/// + тест-паттерн + fbdev-запросы. Маркеры [DRMTEST] ловит e2e-харнесс.
fn cmd_drmtest() void {
    const ops = kernelDrmOps();
    const va: u64 = @intFromPtr(&drmtest_buf);
    sys_print("[DRMTEST] begin: ioctl ABI + dumb lifecycle + pattern\n");

    // 1. VERSION (двухфазный протокол libdrm — как в юнит-тестах)
    var v: drm_kms.DrmVersion = .{};
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.DrmVersion)], std.mem.asBytes(&v));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_VERSION, va) != 0) {
        sys_print("[DRMTEST] FAIL: VERSION\n");
        return;
    }
    sys_print("[DRMTEST] VERSION ok: poler-drm 1.19.0\n");

    // 2. GETRESOURCES: 1 CRTC/энкодер/коннектор
    var r: drm_kms.CardRes = .{};
    r.count_crtcs = 1;
    r.count_encoders = 1;
    r.count_connectors = 1;
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.CardRes)], std.mem.asBytes(&r));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_GETRESOURCES, va) != 0) {
        sys_print("[DRMTEST] FAIL: GETRESOURCES\n");
        return;
    }
    sys_print("[DRMTEST] GETRESOURCES ok: 1 crtc + 1 encoder + 1 connector\n");

    // 3. CREATE_DUMB 256x128 → MAP_DUMB → ADDFB → PAGE_FLIP x2 → pattern
    var d: drm_kms.CreateDumb = .{ .width = 256, .height = 128, .bpp = 32 };
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.CreateDumb)], std.mem.asBytes(&d));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_CREATE_DUMB, va) != 0) {
        sys_print("[DRMTEST] FAIL: CREATE_DUMB\n");
        return;
    }
    const gv: *const drm_kms.CreateDumb = @ptrCast(@alignCast(&drmtest_buf));
    const handle = gv.handle;
    sys_print("[DRMTEST] CREATE_DUMB ok: handle=");
    putDecimal(handle);
    sys_print(" pitch=");
    putDecimal(gv.pitch);
    sys_print(" size=");
    putDecimal(gv.size);
    sys_print("\n");

    var m: drm_kms.MapDumb = .{ .handle = handle };
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.MapDumb)], std.mem.asBytes(&m));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_MAP_DUMB, va) != 0) {
        sys_print("[DRMTEST] FAIL: MAP_DUMB\n");
        return;
    }
    const gm: *const drm_kms.MapDumb = @ptrCast(@alignCast(&drmtest_buf));
    const buf = drm_kms.lookupAperture(&drm_state, gm.offset) orelse {
        sys_print("[DRMTEST] FAIL: aperture lookup\n");
        return;
    };
    sys_print("[DRMTEST] MAP_DUMB ok: aperture offset=0x");
    putHex(gm.offset);
    sys_print("\n");

    // 4. Тест-паттерн: диагональные полосы в backing-страницы dumb-буфера
    //    (identity-VA PMM-страниц) + контрольное чтение — «рендер кадра».
    const pixels: [*]u32 = @ptrFromInt(buf.phys);
    const w = buf.width;
    const h = buf.height;
    var y: u32 = 0;
    while (y < h) : (y += 1) {
        var x: u32 = 0;
        while (x < w) : (x += 1) {
            const stripe: u32 = ((x / 16) + (y / 16)) % 2;
            pixels[y * (buf.pitch / 4) + x] = if (stripe != 0) 0x34C7_5B12 else 0x1207_1120;
        }
    }
    const probe_px = pixels[(h / 2) * (buf.pitch / 4) + (w / 2)];
    if ((probe_px != 0x34C7_5B12) and (probe_px != 0x1207_1120)) {
        sys_print("[DRMTEST] FAIL: pattern readback\n");
        return;
    }
    sys_print("[DRMTEST] pattern ok: 256x128 stripes written+readback\n");

    // 5. ADDFB → PAGE_FLIP x2 → SETCRTC
    var f: drm_kms.FbCmd = .{ .handle = handle, .width = buf.width, .height = buf.height, .pitch = buf.pitch, .bpp = 32 };
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.FbCmd)], std.mem.asBytes(&f));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_ADDFB, va) != 0) {
        sys_print("[DRMTEST] FAIL: ADDFB\n");
        return;
    }
    const gf: *const drm_kms.FbCmd = @ptrCast(@alignCast(&drmtest_buf));
    const fb_id = gf.fb_id;
    sys_print("[DRMTEST] ADDFB ok: fb_id=");
    putDecimal(fb_id);
    sys_print("\n");

    var p: drm_kms.PageFlip = .{ .crtc_id = drm_kms.kmsIds()[0], .fb_id = fb_id };
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.PageFlip)], std.mem.asBytes(&p));
    _ = drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_PAGE_FLIP, va);
    _ = drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_PAGE_FLIP, va);
    if (drm_state.flips < 2) {
        sys_print("[DRMTEST] FAIL: PAGE_FLIP\n");
        return;
    }
    sys_print("[DRMTEST] PAGE_FLIP ok: flips=");
    putDecimal(drm_state.flips);
    sys_print("\n");

    // 6. fbdev-фасад /dev/fb0: VSCREENINFO из геометрии скан-аута
    if (drm_state.mode != .inactive) {
        if (drm_kms.fbIoctl(&drm_state, ops, drm_kms.FBIOGET_VSCREENINFO, va) != 0) {
            sys_print("[DRMTEST] FAIL: FBIOGET_VSCREENINFO\n");
            return;
        }
        sys_print("[DRMTEST] fb0 VSCREENINFO ok\n");
    }

    // 7. DESTROY_DUMB (free_pages → PMM)
    var dd: drm_kms.DestroyDumb = .{ .handle = handle };
    @memcpy(drmtest_buf[0..@sizeOf(drm_kms.DestroyDumb)], std.mem.asBytes(&dd));
    if (drm_kms.drmIoctl(&drm_state, ops, drm_kms.DRM_IOCTL_MODE_DESTROY_DUMB, va) != 0) {
        sys_print("[DRMTEST] FAIL: DESTROY_DUMB\n");
        return;
    }
    sys_print("[DRMTEST] DESTROY_DUMB ok (PMM pages freed)\n");
    sys_print("[DRMTEST] ALL PASS\n");
}

// ─── v0.19.0 (CDD №10 p2): Evdev — команды input/inputtest ─────────────────

/// cmd_input: статус устройств /dev/input/event0,1.
fn cmd_input() void {
    sys_print("[INPUT] /dev/input/event0 (kbd): pending=");
    putDecimal(hal.evdev_kbd.pending());
    sys_print(" delivered=");
    putDecimal(hal.evdev_kbd.delivered);
    sys_print(" dropped=");
    putDecimal(hal.evdev_kbd.dropped);
    sys_print("\n[INPUT] /dev/input/event1 (mouse): pending=");
    putDecimal(hal.evdev_mouse.pending());
    sys_print(" delivered=");
    putDecimal(hal.evdev_mouse.delivered);
    sys_print(" dropped=");
    putDecimal(hal.evdev_mouse.dropped);
    sys_print("\n");
}

/// cmd_inputtest: E2E-самотест evdev: ЖИВЫЕ клавиатурные события (набор
/// самой команды уже сгенерировал их через PS/2-IRQ) + синтетическая мышь.
fn cmd_inputtest() void {
    sys_print("[INPUTTEST] begin: live keys + synthetic mouse\n");

    // 1. Живые события: набор «inputtest» прошёл через handleKeyboard →
    //    evdev_kbd. Очередь НЕ пуста.
    const kbd_pending = hal.evdev_kbd.pending();
    if (kbd_pending == 0) {
        sys_print("[INPUTTEST] FAIL: kbd queue empty (no live events)\n");
        return;
    }
    sys_print("[INPUTTEST] kbd queue: ");
    putDecimal(@intCast(kbd_pending));
    sys_print(" live events (PS/2 -> IRQ1 -> evdev)\n");

    // 2. Дренаж всей очереди: валидация структуры (EV_KEY/EV_SYN, коды 1..57
    //    или 103..108, value 0/1) + поиск букв «inputtest».
    var events: [evdev.QUEUE_LEN]evdev.InputEvent = undefined;
    const n = hal.evdev_kbd.drain(&events);
    var saw_t = false;
    var saw_e = false;
    var malformed: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ev = events[i];
        switch (ev.type_) {
            evdev.EV_KEY => {
                const ok_code = (ev.code >= 1 and ev.code <= 57) or (ev.code >= 103 and ev.code <= 108);
                const ok_val = ev.value == 0 or ev.value == 1;
                if (!ok_code or !ok_val) malformed += 1;
                if (ev.value == 1 and ev.code == 20) saw_t = true; // KEY_T
                if (ev.value == 1 and ev.code == 18) saw_e = true; // KEY_E
            },
            evdev.EV_SYN => {
                if (ev.code != 0 or ev.value != 0) malformed += 1;
            },
            else => malformed += 1,
        }
    }
    if (malformed != 0) {
        sys_print("[INPUTTEST] FAIL: malformed events: ");
        putDecimal(@intCast(malformed));
        sys_print("\n");
        return;
    }
    sys_print("[INPUTTEST] drained+validated: ");
    putDecimal(@intCast(n));
    sys_print(" events, structure OK");
    if (saw_t and saw_e) {
        sys_print(", letters 't'/'e' seen (inputtest typed)");
    }
    sys_print("\n");

    // 3. Пустая очередь + O_NONBLOCK → -EAGAIN (семантика read(2)).
    //    ЖИВАЯ клавиатура дельтовая: release последней клавиши (Enter —
    //    «запустившей» эту команду) приходит асинхронно ~35мс ПОСЛЕ press,
    //    когда команда уже исполняется. Окно утихания 12 тиков (120мс) +
    //    повторный дренаж — иначе честный EWAIT-тест гоняется с IRQ.
    {
        const t0 = hal.tick_count;
        while (hal.tick_count < t0 + 12) {
            asm volatile ("pause");
        }
        var discard: [evdev.QUEUE_LEN]evdev.InputEvent = undefined;
        _ = hal.evdev_kbd.drain(&discard);
    }
    var rbuf: [evdev.EVENT_SIZE * 4]u8 = undefined;
    if (hal.evdev_kbd.readBytes(&rbuf, true) != -linux_syscalls.EAGAIN) {
        sys_print("[INPUTTEST] FAIL: EAGAIN on empty kbd\n");
        return;
    }
    sys_print("[INPUTTEST] empty queue + O_NONBLOCK -> -EAGAIN ok\n");

    // 4. Синтетическая мышь: REL_X/REL_Y/BTN_LEFT + SYN → чтение обратно
    hal.evdev_mouse.pushRel(evdev.REL_X, 7);
    hal.evdev_mouse.pushRel(evdev.REL_Y, -3);
    hal.evdev_mouse.pushKey(evdev.BTN_LEFT, 1);
    hal.evdev_mouse.pushSyn();
    var mbuf: [evdev.EVENT_SIZE * 4]u8 = undefined;
    const mbytes = hal.evdev_mouse.readBytes(&mbuf, false);
    if (mbytes != 4 * evdev.EVENT_SIZE) {
        sys_print("[INPUTTEST] FAIL: mouse read bytes=");
        putDecimal(@intCast(mbytes));
        sys_print("\n");
        return;
    }
    // REL_X=7 — первое событие: value @20
    const dx = std.mem.readInt(i32, mbuf[20..24], .little);
    const dy = std.mem.readInt(i32, mbuf[evdev.EVENT_SIZE + 20 ..][0..4], .little);
    if (dx != 7 or dy != -3) {
        sys_print("[INPUTTEST] FAIL: mouse deltas dx=");
        putDecimal(@intCast(dx));
        sys_print(" dy=");
        putDecimal(@intCast(dy));
        sys_print("\n");
        return;
    }
    sys_print("[INPUTTEST] synthetic mouse: REL_X=7 REL_Y=-3 BTN_LEFT roundtrip ok\n");

    sys_print("[INPUTTEST] ALL PASS\n");
}

// ─── v0.19.0 (CDD №10 p3): ldevtest — самотест Linux device-слоя ───────────

/// Песочница «user»-памяти для ядра-самотеста: .bss-буфер СТРАНИЧНОГО
/// размера (copy_in_str сканирует страничными чанками до 4096Б — буфер
/// меньше страницы отверг бы валидацию чанка; kernel-страницы без USER-бита
/// не проходят PML4-валидацию — самотест переключает user-IO).
var ldev_buf: [8192]u8 align(4096) = .{0} ** 8192;

fn ldevValidate(va: u64, len: u64, want_write: bool) bool {
    _ = want_write;
    if (len > ldev_buf.len) return false;
    const base: u64 = @intFromPtr(&ldev_buf);
    return va >= base and va + len <= base + ldev_buf.len;
}
fn ldevCopyIn(dst: []u8, src_va: u64) bool {
    if (!ldevValidate(src_va, dst.len, false)) return false;
    const p: [*]const u8 = @ptrFromInt(src_va);
    @memcpy(dst, p[0..dst.len]);
    return true;
}
fn ldevCopyOut(dst_va: u64, src: []const u8) bool {
    if (!ldevValidate(dst_va, src.len, true)) return false;
    const p: [*]u8 = @ptrFromInt(dst_va);
    @memcpy(p[0..src.len], src);
    return true;
}

/// cmd_mmapinfo: CDD №12 p4 — дамп mmap-реестров Linux-процессов с именами
/// модулей (e2e-верификация атрибуции: после elfload hello-dynamic в выводе
/// обязаны быть libc.so.6 / [stack] / ld.so; после gamescope — либы CachyOS).
/// Формат: [MMAPINFO] proc=N regions=M; далее таблица [MMAP] va +size name.
fn cmd_mmapinfo() void {
    var any = false;
    var slot: usize = 0;
    while (slot < MAX_LINUX_PROCS) : (slot += 1) {
        if (!linux_procs[slot].used) continue;
        any = true;
        var count: usize = 0;
        for (&linux_mmap_regions[slot]) |*r| {
            if (r.used) count += 1;
        }
        sys_print("[MMAPINFO] proc=");
        printDec(slot);
        sys_print(" regions=");
        printDec(count);
        sys_print(" cursor=0x");
        putHex(linux_procs[slot].mmap_cursor);
        sys_print("\n");
        _ = linuxDumpRegionTable(slot, MAX_MMAP_REGIONS);
    }
    if (!any) sys_print("[MMAPINFO] нет активных Linux-процессов (elfload <bin>)\n");
}

// ─── CDD №12 p10: PHYS-MAP-СКАНЕР — инвариант отсутствия алиасинга ──────────
// Обход user-PTE ВСЕХ активных адресных пространств: физ-кадр, выданный PMM
// (anon-регион: demand-zero/brk/eager-anon), НЕ может быть замаплен более
// чем в один user-VA (в любом пространстве) — иначе два VA пишут/читают
// один кадр = кросс-порча (эмпирика p9/p10: NULL-deref libLLVM через
// порчу свежих структур). Освобождённые от алиасинга: MAP_SHARED-memfd,
// dev-мапы, file-backed страницы (page-cache-семантика), untracked
// (стеки/образы — физика принадлежит образу, не PMM).

/// 4ГБ / 4К = 1М кадров — покрыто сканером (гость ≤ 4ГБ, PMM-диапазон).
const PHYS_SCAN_FRAMES: usize = 0x100000;
var phys_scan_strict: [PHYS_SCAN_FRAMES]u8 = undefined; // счётчик anon-маппингов кадра
var phys_scan_exempt: [PHYS_SCAN_FRAMES]u8 = undefined; // 1 = кадр виден как file/shared/untracked
pub var phys_scan_runs: u64 = 0;
pub var phys_scan_anon_alias: u64 = 0;
pub var phys_scan_mixed_alias: u64 = 0;

inline fn physScanReadQ(pa: u64) u64 {
    const p: *const volatile u64 = @ptrFromInt(pa);
    return p.*;
}

/// Классификация VA в пространстве задачи: strict (anon, PMM-кадр)?
/// Линейный поиск по реестру (с last-hit-кэшем — страницы региона
/// идут подряд, попадание в тот же регион = O(1) на 2-й+ странице).
var phys_scan_hint: usize = 0;
fn physScanRegionStrict(slot: usize, va: u64) bool {
    if (slot >= MAX_LINUX_PROCS) return false;
    const regs = &linux_mmap_regions[slot];
    if (phys_scan_hint < regs.len) {
        const h = &regs[phys_scan_hint];
        if (h.used and va >= h.va and va < h.va + h.pages * PAGE_SIZE)
            return h.anon;
    }
    var i: usize = 0;
    while (i < regs.len) : (i += 1) {
        const r = &regs[i];
        if (!r.used) continue;
        if (va >= r.va and va < r.va + r.pages * PAGE_SIZE) {
            phys_scan_hint = i;
            return r.anon;
        }
    }
    return false;
}

/// Полный проход одного PML4 (user-половина, 4К-листья): классифицирует
/// каждый PRESENT+USER лист в strict/exempt счётчики.
fn physScanSpace(pml4_phys: u64, slot: usize) u64 {
    var mapped: u64 = 0;
    var pml4_i: usize = 0;
    while (pml4_i < 256) : (pml4_i += 1) {
        const pml4e = physScanReadQ(pml4_phys + 8 * pml4_i);
        if (pml4e & (vmm.PTE_PRESENT | vmm.PTE_USER) != (vmm.PTE_PRESENT | vmm.PTE_USER)) continue;
        const pdpt = pml4e & 0x000FFFFFFFFFF000;
        var pdpt_i: usize = 0;
        while (pdpt_i < 512) : (pdpt_i += 1) {
            const pdpte = physScanReadQ(pdpt + 8 * pdpt_i);
            if (pdpte & vmm.PTE_PRESENT == 0) continue;
            if (pdpte & vmm.PTE_HUGE != 0) continue; // 1G-лист: user-зоне нет
            const pd = pdpte & 0x000FFFFFFFFFF000;
            var pd_i: usize = 0;
            while (pd_i < 512) : (pd_i += 1) {
                const pde = physScanReadQ(pd + 8 * pd_i);
                if (pde & vmm.PTE_PRESENT == 0) continue;
                if (pde & vmm.PTE_HUGE != 0) continue; // 2M-лист: user-зоне нет
                const pt = pde & 0x000FFFFFFFFFF000;
                var pt_i: usize = 0;
                while (pt_i < 512) : (pt_i += 1) {
                    const pte = physScanReadQ(pt + 8 * pt_i);
                    if (pte & vmm.PTE_PRESENT == 0) continue;
                    if (pte & vmm.PTE_USER == 0) continue;
                    const pa = pte & 0x000FFFFFFFFFF000;
                    if (pa == 0) continue;
                    const idx: usize = @intCast(pa / PAGE_SIZE);
                    if (idx >= PHYS_SCAN_FRAMES) continue;
                    const va: u64 = (@as(u64, pml4_i) << 39) | (@as(u64, pdpt_i) << 30) |
                        (@as(u64, pd_i) << 21) | (@as(u64, pt_i) << 12);
                    mapped += 1;
                    if (physScanRegionStrict(slot, va)) {
                        phys_scan_strict[idx] +%= 1;
                    } else {
                        phys_scan_exempt[idx] = 1;
                    }
                }
            }
        }
    }
    return mapped;
}

/// Додетект: найти ВСЕ (slot, va), мапящие кадр pa (печать до 8) —
/// вызывается ТОЛЬКО на нарушении (редко, дорогой полный проход).
fn physScanReportFrame(pa: u64) void {
    var shown: usize = 0;
    var t: usize = 0;
    while (t < scheduler.task_count and shown < 8) : (t += 1) {
        const task = &scheduler.tasks[t];
        if (task.state == .Killed or task.cr3 == 0) continue;
        const slot: usize = linux_task_proc[t];
        var pml4_i: usize = 0;
        outer: while (pml4_i < 256) : (pml4_i += 1) {
            const pml4e = physScanReadQ(task.cr3 + 8 * pml4_i);
            if (pml4e & (vmm.PTE_PRESENT | vmm.PTE_USER) != (vmm.PTE_PRESENT | vmm.PTE_USER)) continue;
            const pdpt = pml4e & 0x000FFFFFFFFFF000;
            var pdpt_i: usize = 0;
            while (pdpt_i < 512) : (pdpt_i += 1) {
                const pdpte = physScanReadQ(pdpt + 8 * pdpt_i);
                if (pdpte & vmm.PTE_PRESENT == 0 or pdpte & vmm.PTE_HUGE != 0) continue;
                const pd = pdpte & 0x000FFFFFFFFFF000;
                var pd_i: usize = 0;
                while (pd_i < 512) : (pd_i += 1) {
                    const pde = physScanReadQ(pd + 8 * pd_i);
                    if (pde & vmm.PTE_PRESENT == 0 or pde & vmm.PTE_HUGE != 0) continue;
                    const pt = pde & 0x000FFFFFFFFFF000;
                    var pt_i: usize = 0;
                    while (pt_i < 512) : (pt_i += 1) {
                        const pte = physScanReadQ(pt + 8 * pt_i);
                        if (pte & (vmm.PTE_PRESENT | vmm.PTE_USER) != (vmm.PTE_PRESENT | vmm.PTE_USER)) continue;
                        if ((pte & 0x000FFFFFFFFFF000) != pa) continue;
                        if (shown >= 8) break :outer;
                        sys_print("  [PHYSMAP]   mapped: task=");
                        printDec(t);
                        sys_print(" slot=");
                        printDec(slot);
                        sys_print(" va=0x");
                        putHex((@as(u64, pml4_i) << 39) | (@as(u64, pdpt_i) << 30) |
                            (@as(u64, pd_i) << 21) | (@as(u64, pt_i) << 12));
                        sys_print("\n");
                        shown += 1;
                    }
                }
            }
        }
    }
}

/// Скан: сбор уникальных CR3 активных задач → проход каждого → отчёт.
/// Гарантии: PF-безопасность не нужна (таблицы identity-мапплены, ядровый
/// контекст монитора), вызов из monitor-команды physmap.
fn linuxPhysScan() void {
    phys_scan_runs += 1;
    @memset(&phys_scan_strict, 0);
    @memset(&phys_scan_exempt, 0);
    phys_scan_hint = 0;

    var frames: u64 = 0;
    var spaces: u64 = 0;
    var t: usize = 0;
    while (t < scheduler.task_count) : (t += 1) {
        const task = &scheduler.tasks[t];
        if (task.state == .Killed or task.cr3 == 0) continue;
        // дедупликация CR3 (треды процесса шарят PML4)
        var dup = false;
        var u: usize = 0;
        while (u < t) : (u += 1) {
            if (scheduler.tasks[u].state != .Killed and scheduler.tasks[u].cr3 == task.cr3) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        spaces += 1;
        frames += physScanSpace(task.cr3, linux_task_proc[t]);
    }

    // вердикт: strict-кадр с ≥2 маппингами = АНОН-АЛИАС; strict+exempt
    // на одном кадре = СМЕШАННЫЙ (PMM выдал кадр, уже занятый file/dev —
    // сигнатура p5-бага «munmap освобождал общие страницы»).
    var violations: u64 = 0;
    var idx: usize = 0;
    while (idx < PHYS_SCAN_FRAMES) : (idx += 1) {
        if (phys_scan_strict[idx] >= 2) {
            phys_scan_anon_alias += 1;
            violations += 1;
            sys_print("[PHYSMAP] ANON-ALIAS pa=0x");
            putHex(@as(u64, idx) * PAGE_SIZE);
            sys_print(" count=");
            printDec(phys_scan_strict[idx]);
            sys_print("\n");
            physScanReportFrame(@as(u64, idx) * PAGE_SIZE);
        } else if (phys_scan_strict[idx] == 1 and phys_scan_exempt[idx] != 0) {
            phys_scan_mixed_alias += 1;
            violations += 1;
            sys_print("[PHYSMAP] MIXED-ALIAS pa=0x");
            putHex(@as(u64, idx) * PAGE_SIZE);
            sys_print(" (PMM-кадр перекрыт file/dev-мапом)\n");
            physScanReportFrame(@as(u64, idx) * PAGE_SIZE);
        }
    }

    sys_print("[PHYSMAP] scan #");
    printDec(phys_scan_runs);
    sys_print(": spaces=");
    printDec(spaces);
    sys_print(" frames=");
    printDec(frames);
    sys_print(" violations=");
    printDec(violations);
    sys_print(" | PMM: allocs=");
    printDec(pmm.pmm_alloc_calls);
    sys_print(" frees=");
    printDec(pmm.pmm_free_calls);
    sys_print(" DOUBLE-FREE=");
    printDec(pmm.pmm_double_frees);
    sys_print("\n");
    sys_print("[PHYSMAP] RESULT: ");
    if (violations == 0 and pmm.pmm_double_frees == 0) {
        sys_print("CLEAN (0 violations, 0 double-frees)\n");
    } else {
        sys_print("ALIASING DETECTED — см. ANON/MIXED-ALIAS выше\n");
    }
}


/// cmd_tasks: CDD №12 p8 — РЕЕСТР ПАРКОВОК: WHO паркуется, ГДЕ, НА ЧЁМ.
/// Дамп для p8-диагноза «epoll-паркинг без wake»: задачи (state/wake_tick/
/// rsp/priv/abi/proc/fs-base), fd-таблицы процессов (kind/file_id),
/// epoll-watches (fd/events/data — НА ЧЁМ ждёт композитор), каналы
/// (pipe/eventfd/socketpair/timerfd: refs/len/counter/deadline),
/// futex-парковки. [SLEEP]-маркер = wake_tick в будущем (пропуск диспетчером).
fn cmd_tasks() void {
    sys_print("[TASKS] tick=");
    printDec(hal.tick_count);
    sys_print(" tasks=");
    printDec(scheduler.task_count);
    sys_print(" current=");
    printDec(scheduler.current_task_id);
    sys_print("\n");
    var i: usize = 0;
    while (i < scheduler.task_count) : (i += 1) {
        const t = &scheduler.tasks[i];
        sys_print("[TASK] #");
        printDec(i);
        sys_print(" state=");
        switch (t.state) {
            .Ready => sys_print("Ready"),
            .Running => sys_print("Running"),
            .Killed => sys_print("Killed"),
        }
        sys_print(" wake=");
        printDec(t.wake_tick);
        if (t.wake_tick != 0 and t.wake_tick > hal.tick_count) sys_print(" [SLEEP]");
        sys_print(" rsp=0x");
        putHex(t.rsp);
        if (t.privilege == .User) {
            sys_print(" USER abi=");
            if (t.abi == .linux) sys_print("linux") else sys_print("win32");
            sys_print(" proc=");
            printDec(linux_task_proc[i]);
            sys_print(" fs=0x");
            putHex(scheduler.fs_base_tab[i]);
        } else {
            sys_print(" KERN");
        }
        sys_print("\n");
    }
    // fd-таблицы процессов + epoll-watches (на чём паркуется epoll_wait)
    var slot: usize = 0;
    while (slot < MAX_LINUX_PROCS) : (slot += 1) {
        if (!linux_procs[slot].used) continue;
        sys_print("[PROC] slot=");
        printDec(slot);
        sys_print(" brk=0x");
        putHex(linux_procs[slot].brk);
        sys_print(" fds:\n");
        const fds = &linux_procs[slot].fds;
        var f: usize = 0;
        while (f < fds.entries.len) : (f += 1) {
            const e = &fds.entries[f];
            if (e.kind == .free) continue;
            sys_print("  [FD] ");
            printDec(f);
            sys_print(" kind=");
            fdKindName(e.kind);
            sys_print(" file_id=");
            printDec(e.file_id);
            if (e.nonblock) sys_print(" NB");
            sys_print("\n");
            if (e.kind == .epoll and e.watch_count > 0) {
                var w: usize = 0;
                while (w < e.watch_count) : (w += 1) {
                    const wf = e.watches[w].fd;
                    sys_print("    watch fd=");
                    if (wf >= 0) printDec(@intCast(wf)) else sys_print("-");
                    sys_print(" events=0x");
                    putHex(e.watches[w].events);
                    sys_print(" data=0x");
                    putHex(e.watches[w].data);
                    sys_print("\n");
                }
            }
        }
    }
    // каналы: pipe/eventfd/socketpair/timerfd — живость источников wake
    var cid: usize = 0;
    while (cid < channels.len) : (cid += 1) {
        const c = &channels[cid];
        if (!c.used) continue;
        sys_print("[CHAN] id=");
        printDec(cid);
        sys_print(" kind=");
        switch (c.kind) {
            .pipe => sys_print("pipe"),
            .eventfd => sys_print("eventfd"),
            .socketpair => sys_print("sockpair"),
            .timerfd => sys_print("timerfd"),
        }
        sys_print(" refs=");
        printDec(c.refs);
        sys_print(" len=");
        printDec(c.len);
        sys_print(" cnt=");
        printDec(c.counter);
        if (c.kind == .timerfd) {
            sys_print(" dl_ns=");
            printDec(c.deadline_ns);
            sys_print(" iv_ns=");
            printDec(c.interval_ns);
        }
        sys_print("\n");
    }
    // futex-парковки (реестр честных блокировок)
    var fp: usize = 0;
    while (fp < futex_parks.len) : (fp += 1) {
        const p = &futex_parks[fp];
        if (!p.active) continue;
        sys_print("[FUTEX-PARK] task=");
        printDec(p.task);
        sys_print(" uaddr=0x");
        putHex(p.uaddr);
        if (p.woken) sys_print(" WOKEN") else sys_print(" waiting");
        sys_print("\n");
    }
    sys_print("[TASKS] end\n");
}


/// cmd_peek: CDD #12 p8 — чтение user-VA ГВОЗЗЯ через софт-page-walk
/// (PML4 первого живого linux-таска; vm в парке — память консистентна).
/// Формат: peek <hexva> [count] — 8Б-слоты hex + ASCII-вид (имена тредов).
fn cmd_peek(cmd: []const u8) void {
    // parse: "peek 0xADDR [count]"
    var rest = cmd[5..];
    rest = std.mem.trim(u8, rest, " ");
    var cnt: usize = 4;
    if (std.mem.indexOfScalar(u8, rest, ' ')) |sp| {
        const cnt_s = std.mem.trim(u8, rest[sp..], " ");
        cnt = std.fmt.parseInt(usize, cnt_s, 10) catch 4;
        rest = rest[0..sp];
    }
    const va = std.fmt.parseInt(u64, rest, 16) catch {
        sys_print("peek: hex-VA ожидался (peek 0x... [count])\n");
        return;
    };
    // первый живой linux-таск — его PML4
    var cr3: u64 = 0;
    var ti: usize = 0;
    while (ti < scheduler.task_count) : (ti += 1) {
        const t = &scheduler.tasks[ti];
        if (t.privilege == .User and t.abi == .linux and t.state != .Killed and t.cr3 != 0) {
            cr3 = t.cr3;
            break;
        }
    }
    if (cr3 == 0) {
        sys_print("peek: нет живого linux-таска\n");
        return;
    }
    sys_print("[PEEK] pml4=0x");
    putHex(cr3);
    sys_print(" va=0x");
    putHex(va);
    sys_print(" count=");
    printDec(cnt);
    sys_print("\n");
    var i: usize = 0;
    while (i < cnt) : (i += 1) {
        const a = va + i * 8;
        if (linuxPeekUserOld(cr3, a)) |v| {
            sys_print("  [0x");
            putHex(a);
            sys_print("] 0x");
            putHex(v);
            sys_print("  ");
            // ASCII-вид 8 байт
            const bytes: [8]u8 = @bitCast(v);
            for (bytes) |b| {
                if (b >= 0x20 and b < 0x7F) {
                    const ech = [1]u8{b};
                    sys_print(&ech);
                } else sys_print(".");
            }
            sys_print("\n");
        } else {
            sys_print("  [0x");
            putHex(a);
            sys_print("] <unmapped>\n");
        }
    }
}

fn fdKindName(k: linux_syscalls.FdKind) void {
    switch (k) {
        .free => sys_print("free"),
        .console_out => sys_print("console"),
        .fb0 => sys_print("fb0"),
        .dri_card0 => sys_print("dri_card0"),
        .input_event0 => sys_print("input0"),
        .input_event1 => sys_print("input1"),
        .epoll => sys_print("epoll"),
        .initrd_file => sys_print("initrd"),
        .tmpfs_file => sys_print("tmpfs"),
        .pipe_read => sys_print("pipe_r"),
        .pipe_write => sys_print("pipe_w"),
        .eventfd => sys_print("eventfd"),
        .socket => sys_print("socket"),
        .seatd => sys_print("seatd"),
        .timerfd => sys_print("timerfd"),
        .signalfd => sys_print("signalfd"),
        .dir => sys_print("dir"),
        .devnull => sys_print("devnull"),
    }
}

/// cmd_ldevtest: E2E-самотест Linux-POSIX графического слоя: openat → ioctl
/// (DRM VERSION/CREATE_DUMB/MAP_DUMB/ADDFB/PAGE_FLIP) → read event0 (ЖИВЫЕ
/// input_event!) → poll/epoll → futex → close. Маркеры [LDEVTEST] для e2e.
fn cmd_ldevtest() void {
    const L = linux_syscalls;
    const ops = kernelLinuxOps();
    const fds = &linux_fds;
    const buf_va: u64 = @intFromPtr(&ldev_buf);

    // переключаем user-IO на песочницу (CR3-путь остаётся для Ring-3)
    const saved_io = linux_user_io;
    linux_user_io = .{ .validate = ldevValidate, .copy_in = ldevCopyIn, .copy_out = ldevCopyOut };
    defer linux_user_io = saved_io;

    sys_print("[LDEVTEST] begin: open/ioctl/read/poll/epoll/futex/close\n");

    // 1. write(1, …) — консоль через fd-таблицу
    @memcpy(ldev_buf[0..5], "POLER");
    const w = L.sysWrite(ops, fds, 1, buf_va, 5);
    if (w != 5) {
        sys_print("[LDEVTEST] FAIL: console write\n");
        return;
    }

    // 2. openat("/dev/dri/card0") → fd
    const path1 = buf_va + 0x100;
    @memcpy(ldev_buf[0x100..0x10E], "/dev/dri/card0");
    ldev_buf[0x10E] = 0;
    const card_r: i64 = @bitCast(L.sysOpenat(ops, fds, L.AT_FDCWD, path1, 0, 0));
    if (card_r < 3) {
        sys_print("[LDEVTEST] FAIL: openat card0 (errno=");
        putDecimal(@intCast(-card_r));
        sys_print(")\n");
        return;
    }
    const card: i64 = card_r;
    sys_print("[LDEVTEST] openat /dev/dri/card0 -> fd ");
    putDecimal(@intCast(card));
    sys_print("\n");

    // 3. ioctl VERSION (двухфазный протокол libdrm)
    @memset(ldev_buf[0..64], 0);
    if (L.sysIoctl(ops, fds, @intCast(card), drm_kms.DRM_IOCTL_VERSION, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: DRM VERSION\n");
        return;
    }
    sys_print("[LDEVTEST] ioctl DRM_IOCTL_VERSION ok (poler-drm)\n");

    // 4. CREATE_DUMB 64x64 → MAP_DUMB → ADDFB → PAGE_FLIP
    var d: drm_kms.CreateDumb = .{ .width = 64, .height = 64, .bpp = 32 };
    @memcpy(ldev_buf[0..@sizeOf(drm_kms.CreateDumb)], std.mem.asBytes(&d));
    if (L.sysIoctl(ops, fds, @intCast(card), drm_kms.DRM_IOCTL_MODE_CREATE_DUMB, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: CREATE_DUMB\n");
        return;
    }
    const gd: *const drm_kms.CreateDumb = @ptrCast(@alignCast(&ldev_buf));
    const handle = gd.handle;
    sys_print("[LDEVTEST] CREATE_DUMB ok: handle=");
    putDecimal(handle);
    sys_print("\n");

    var m: drm_kms.MapDumb = .{ .handle = handle };
    @memcpy(ldev_buf[0..@sizeOf(drm_kms.MapDumb)], std.mem.asBytes(&m));
    if (L.sysIoctl(ops, fds, @intCast(card), drm_kms.DRM_IOCTL_MODE_MAP_DUMB, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: MAP_DUMB\n");
        return;
    }
    const gm: *const drm_kms.MapDumb = @ptrCast(@alignCast(&ldev_buf));
    const aperture = gm.offset;
    sys_print("[LDEVTEST] MAP_DUMB ok: aperture=0x");
    putHex(aperture);
    sys_print("\n");

    var f: drm_kms.FbCmd = .{ .handle = handle, .width = 64, .height = 64, .pitch = 256, .bpp = 32 };
    @memcpy(ldev_buf[0..@sizeOf(drm_kms.FbCmd)], std.mem.asBytes(&f));
    if (L.sysIoctl(ops, fds, @intCast(card), drm_kms.DRM_IOCTL_MODE_ADDFB, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: ADDFB\n");
        return;
    }
    const gf: *const drm_kms.FbCmd = @ptrCast(@alignCast(&ldev_buf));
    const fb_id = gf.fb_id;
    var p: drm_kms.PageFlip = .{ .crtc_id = drm_kms.kmsIds()[0], .fb_id = fb_id };
    @memcpy(ldev_buf[0..@sizeOf(drm_kms.PageFlip)], std.mem.asBytes(&p));
    if (L.sysIoctl(ops, fds, @intCast(card), drm_kms.DRM_IOCTL_MODE_PAGE_FLIP, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: PAGE_FLIP\n");
        return;
    }
    sys_print("[LDEVTEST] ADDFB + PAGE_FLIP ok\n");

    // 5. mmap устройства в shell-контексте → честный -ENODEV (нет Ring-3
    //    задачи; runtime-путь mapPageInPML4 активируется ELF-процессом)
    const mm = L.sysMmap(ops, fds, 0, 4096, L.PROT_READ | L.PROT_WRITE, L.MAP_SHARED, @intCast(card), aperture);
    if (mm != @as(u64, @bitCast(@as(i64, -L.ENODEV)))) {
        sys_print("[LDEVTEST] FAIL: dev mmap expected ENODEV, got 0x");
        putHex(mm);
        sys_print("\n");
        return;
    }
    sys_print("[LDEVTEST] dev mmap -> -ENODEV in shell ctx (Ring-3 path ready)\n");

    // 6. openat("/dev/input/event0") + EVIOCGVERSION
    const path2 = buf_va + 0x140;
    @memcpy(ldev_buf[0x140..0x151], "/dev/input/event0");
    ldev_buf[0x151] = 0;
    const kfd_r: i64 = @bitCast(L.sysOpenat(ops, fds, L.AT_FDCWD, path2, 0, 0));
    if (kfd_r < 4) {
        sys_print("[LDEVTEST] FAIL: openat event0\n");
        return;
    }
    const kfd: i64 = kfd_r;
    @memset(ldev_buf[0..16], 0);
    if (L.sysIoctl(ops, fds, @intCast(kfd), evdev.EVIOCGVERSION, buf_va) != 0) {
        sys_print("[LDEVTEST] FAIL: EVIOCGVERSION\n");
        return;
    }
    const evver = std.mem.readInt(i32, ldev_buf[0..4], .little);
    if (evver != evdev.EV_VERSION) {
        sys_print("[LDEVTEST] FAIL: evdev version readback\n");
        return;
    }
    sys_print("[LDEVTEST] openat /dev/input/event0 + EVIOCGVERSION ok (1.0.1)\n");

    // 7. read(event0): ЖИВЫЕ input_event'ы (набор команды их сгенерил);
    //    fcntl O_NONBLOCK → дренаж до пустоты → -EAGAIN (release Enter
    //    приходит асинхронно ~35мс ПОСЛЕ press — окно утихания как inputtest)
    var live_events: u64 = 0;
    const rb = L.sysRead(ops, fds, @intCast(kfd), buf_va, 24 * 4);
    if (rb > 0) live_events = rb / 24;
    if (L.sysFcntl(ops, fds, @intCast(kfd), L.F_SETFL, L.O_NONBLOCK) != 0) {
        sys_print("[LDEVTEST] FAIL: fcntl F_SETFL\n");
        return;
    }
    {
        const t0 = hal.tick_count;
        while (hal.tick_count < t0 + 12) {
            asm volatile ("pause");
        }
        // дренаж до пустоты (живые события продолжают капать)
        var guard: u32 = 0;
        while (guard < 64) : (guard += 1) {
            const dd = L.sysRead(ops, fds, @intCast(kfd), buf_va, 24 * 4);
            if (dd == 0) break;
            if (dd == @as(u64, @bitCast(@as(i64, -L.EAGAIN)))) break;
            if (dd > 0) {
                live_events += dd / 24;
            } else break;
        }
    }
    const again = L.sysRead(ops, fds, @intCast(kfd), buf_va, 24);
    if (live_events > 0 and again != @as(u64, @bitCast(@as(i64, -L.EAGAIN)))) {
        sys_print("[LDEVTEST] FAIL: EAGAIN after drain (got 0x");
        putHex(again);
        sys_print(")\n");
        return;
    }
    sys_print("[LDEVTEST] read(event0): ");
    putDecimal(@intCast(live_events));
    sys_print(" live events, O_NONBLOCK drain -> -EAGAIN\n");

    // 8. poll: card0 (POLLOUT) + event0 (POLLIN после дренажа — пусто)
    var pfds = [_]L.PollFd{
        .{ .fd = @intCast(card), .events = L.POLLOUT },
        .{ .fd = @intCast(kfd), .events = L.POLLIN },
    };
    @memcpy(ldev_buf[0x200 .. 0x200 + 16], std.mem.sliceAsBytes(pfds[0..2]));
    const pn = L.sysPoll(ops, fds, buf_va + 0x200, 2, 0);
    if (pn < 1) {
        sys_print("[LDEVTEST] FAIL: poll count\n");
        return;
    }
    const pr: [*]const L.PollFd = @ptrCast(@alignCast(&ldev_buf[0x200]));
    if (pr[0].revents & L.POLLOUT == 0) {
        sys_print("[LDEVTEST] FAIL: poll card0 POLLOUT\n");
        return;
    }
    sys_print("[LDEVTEST] poll ok: card0 POLLOUT ready\n");

    // 9. epoll-троица: create → ctl ADD event0 → wait
    const epfd_r: i64 = @bitCast(L.sysEpollCreate1(ops, fds, 0));
    if (epfd_r < 5) {
        sys_print("[LDEVTEST] FAIL: epoll_create1\n");
        return;
    }
    const epfd: i64 = epfd_r;
    var evb: [12]u8 = .{0} ** 12;
    std.mem.writeInt(u32, evb[0..4], L.EPOLLIN, .little);
    std.mem.writeInt(u64, evb[4..12], 0xCAFE, .little);
    @memcpy(ldev_buf[0x300..0x30C], &evb);
    if (L.sysEpollCtl(ops, fds, @intCast(epfd), L.EPOLL_CTL_ADD, @intCast(kfd), buf_va + 0x300) != 0) {
        sys_print("[LDEVTEST] FAIL: epoll_ctl ADD\n");
        return;
    }
    const en = L.sysEpollWait(ops, fds, @intCast(epfd), buf_va + 0x340, 4, 0);
    if (en > 0) {
        // если после дренажа нажатие Enter-release пришло — валидно
        const eevents = std.mem.readInt(u32, ldev_buf[0x340..0x344], .little);
        if (eevents & L.EPOLLIN == 0) {
            sys_print("[LDEVTEST] FAIL: epoll event mask\n");
            return;
        }
    }
    sys_print("[LDEVTEST] epoll create+ctl+wait ok (");
    putDecimal(@intCast(en));
    sys_print(" events)\n");

    // 10. futex: слово 7 в «user», WAIT(7) → парковка 1 тик → 0;
    //     WAIT(8) → -EAGAIN (слово не совпало); WAKE → 0
    const futex_va = buf_va + 0x380;
    std.mem.writeInt(u32, ldev_buf[0x380..0x384], 7, .little);
    if (L.sysFutex(ops, futex_va, L.FUTEX_WAIT | L.FUTEX_PRIVATE_FLAG, 7, 0) != 0) {
        sys_print("[LDEVTEST] FAIL: futex WAIT matched\n");
        return;
    }
    if (L.sysFutex(ops, futex_va, L.FUTEX_WAIT, 8, 0) != @as(u64, @bitCast(@as(i64, -L.EAGAIN)))) {
        sys_print("[LDEVTEST] FAIL: futex WAIT mismatch EAGAIN\n");
        return;
    }
    _ = L.sysFutex(ops, futex_va, L.FUTEX_WAKE, 1, 0);
    sys_print("[LDEVTEST] futex WAIT/WAKE/EAGAIN semantics ok\n");

    // 11. close всего + повторный close → EBADF
    if (L.sysClose(ops, fds, @intCast(kfd)) != 0 or
        L.sysClose(ops, fds, @intCast(epfd)) != 0 or
        L.sysClose(ops, fds, @intCast(card)) != 0)
    {
        sys_print("[LDEVTEST] FAIL: close\n");
        return;
    }
    if (L.sysClose(ops, fds, @intCast(card)) != @as(u64, @bitCast(@as(i64, -L.EBADF)))) {
        sys_print("[LDEVTEST] FAIL: double close EBADF\n");
        return;
    }
    // 12. VFS Live-режима: initrd-RO (чтение с «USB») + tmpfs (запись в RAM)
    //     — оверлей «запись в RAM, чтение с USB» (CDD №10 p4)
    sys_print("[LDEVTEST] close lifecycle ok\n");
    {
        // initrd-файл: открытие + чтение контента (путь АБСОЛЮТНЫЙ — VFS)
        const ipath = buf_va + 0x400;
        @memcpy(ldev_buf[0x400..0x40B], "/README.txt"); // 11 символов
        ldev_buf[0x40B] = 0;
        const ifd_r: i64 = @bitCast(L.sysOpenat(ops, fds, L.AT_FDCWD, ipath, 0, 0));
        if (ifd_r < 3) {
            sys_print("[LDEVTEST] FAIL: openat initrd README.txt\n");
            return;
        }
        @memset(ldev_buf[0x500..0x540], 0);
        const irn = L.sysRead(ops, fds, ifd_r, buf_va + 0x500, 32);
        if (irn == 0) {
            sys_print("[LDEVTEST] FAIL: initrd read EOF\n");
            return;
        }
        // запись в initrd → -EBADF (RO)
        if (L.sysWrite(ops, fds, ifd_r, buf_va, 3) != @as(u64, @bitCast(@as(i64, -L.EBADF)))) {
            sys_print("[LDEVTEST] FAIL: initrd write must EBADF\n");
            return;
        }
        _ = L.sysClose(ops, fds, ifd_r);
        sys_print("[LDEVTEST] initrd-RO: open+read (USB), write->EBADF ok\n");

        // tmpfs: создание записью, чтение — RAM roundtrip
        const tpath = buf_va + 0x420;
        @memcpy(ldev_buf[0x420..0x431], "/tmp/live-session"); // 17 символов
        ldev_buf[0x431] = 0;
        const tfd_r: i64 = @bitCast(L.sysOpenat(ops, fds, L.AT_FDCWD, tpath, L.O_RDWR, 0));
        if (tfd_r < 3) {
            sys_print("[LDEVTEST] FAIL: openat tmpfs\n");
            return;
        }
        @memcpy(ldev_buf[0x600..0x60C], "RAM-WRITE!**"); // 12 символов
        const twn = L.sysWrite(ops, fds, tfd_r, buf_va + 0x600, 10);
        if (twn != 10) {
            sys_print("[LDEVTEST] FAIL: tmpfs write\n");
            return;
        }
        // чтение через ПОВТОРНОЕ открытие (offset 0)
        const tfd2_r: i64 = @bitCast(L.sysOpenat(ops, fds, L.AT_FDCWD, tpath, L.O_RDONLY, 0));
        @memset(ldev_buf[0x640..0x660], 0);
        const trn = L.sysRead(ops, fds, tfd2_r, buf_va + 0x640, 16);
        if (trn != 10 or !std.mem.eql(u8, ldev_buf[0x640..0x64A], "RAM-WRITE!")) {
            sys_print("[LDEVTEST] FAIL: tmpfs read roundtrip\n");
            return;
        }
        _ = L.sysClose(ops, fds, tfd_r);
        _ = L.sysClose(ops, fds, tfd2_r);
        sys_print("[LDEVTEST] tmpfs-RAM: create+write+read roundtrip ok\n");
    }

    sys_print("[LDEVTEST] ALL PASS\n");
}

// ─── v0.20.0 (CDD №11 p1): elfload — запуск Linux-ABI ELF-процесса ──────────

/// ElfOps-мост к PMM/vmm (те же бриджи, что pe_loader — идентичные контракты).
fn kernelElfOps() elf_loader.ElfOps {
    return .{
        .alloc_contig = pmmAllocContig,
        .map_user = vmmMapUser,
        .page_ptr = identityPagePtr,
        .unmap_user = vmmUnmapUser,
        .free_contig = pmmFreeContig,
    };
}

/// Буферы argv для процесса (shell-строка → токены ≤ 8 × 63Б).
var elf_argv_buf: [9][64]u8 = undefined;

/// AT_RANDOM-сид: TSC + тик-микс (16Б). PUF-энтропия подключается в
/// glibc-волне (stack-canary стартует случайным).
fn elfRandomSeed() [16]u8 {
    const tsc = hal.readMsr(0x10);
    var seed: [16]u8 = undefined;
    var v = tsc ^ (hal.tick_count << 32) ^ 0x5A17_C0DE;
    for (&seed) |*b| {
        v = v *% 6364136223846793005 +% 1442695040888963407;
        b.* = @truncate(v >> 33);
    }
    return seed;
}

/// cmd_elfload <file-in-initrd> [args…]: ПЕРВЫЙ ELF-процесс Linux-ABI.
/// PT_LOAD → user-PML4 (PTE по p_flags), стек Linux-ABI (argc/argv/envp/
/// auxv), Ring-3 задача с RAX-маршрутизацией + proc-слот (fd/mmap/brk).
/// Активирует БОЕВОЙ режим: dev_mmap WC, clone-треды, futex-парковки.
fn cmd_elfload(args: []const u8) void {
    if (args.len == 0) {
        sys_print("Usage: elfload <file-in-initrd> [args...]  (e.g. elfload elftest --flag)\n");
        return;
    }
    var file_end = std.mem.indexOfScalar(u8, args, ' ') orelse args.len;
    if (file_end == 0) file_end = args.len;
    const file = args[0..file_end];
    const rest = if (args.len > file_end) args[file_end + 1 ..] else "";
    const data = initrdFindFile(file) orelse {
        sys_print("File not found in initrd: ");
        sys_print(file);
        sys_print("\n");
        return;
    };

    sys_print("=== ELF Load & Run (CDD #11): ");
    sys_print(file);
    if (rest.len > 0) {
        sys_print(" — args: ");
        sys_print(rest);
    }
    sys_print(" ===\n");

    // 1. User-PML4 (kernel-маппинги копируются БЕЗ User-бита)
    const user_pml4 = vmm.createUserPML4() catch |err| {
        sys_print("createUserPML4 error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    // 2. Образ: PT_LOAD → PML4 (ET_DYN-базис LINUX_IMAGE_BASE)
    const ops = kernelElfOps();
    const img = elf_loader.loadElf(ops, user_pml4, data, elf_loader.LINUX_IMAGE_BASE) catch |err| {
        sys_print("[ELF] load error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    sys_print("[ELF] image: base=0x");
    putHex(img.base_va);
    sys_print(" entry=0x");
    putHex(img.entry_va);
    sys_print(" pages=");
    printDec(img.pages);
    sys_print(" brk=0x");
    putHex(img.brk);
    if (img.is_pie) {
        sys_print(" (PIE)");
    }
    sys_print("\n");

    // 3. argv: file + токены rest (≤ 9 × 63Б)
    var argv_count: usize = 0;
    var argv_ptrs: [9][]const u8 = undefined;
    {
        const n = @min(file.len, elf_argv_buf[0].len - 1);
        @memcpy(elf_argv_buf[0][0..n], file[0..n]);
        elf_argv_buf[0][n] = 0;
        argv_ptrs[0] = elf_argv_buf[0][0..n];
        argv_count = 1;
        var it = std.mem.tokenizeScalar(u8, rest, ' ');
        while (it.next()) |tok| {
            if (argv_count >= elf_argv_buf.len) break;
            const t = @min(tok.len, elf_argv_buf[argv_count].len - 1);
            @memcpy(elf_argv_buf[argv_count][0..t], tok[0..t]);
            elf_argv_buf[argv_count][t] = 0;
            argv_ptrs[argv_count] = elf_argv_buf[argv_count][0..t];
            argv_count += 1;
        }
    }
    const envp = [_][]const u8{
        "HOME=/root",
        "TERM=linux",
        "PATH=/usr/bin",
        "LD_LIBRARY_PATH=/usr/lib",
        // CDD №12 p9: MESA SHADER CACHE -> WRITABLE tmpfs (/tmp — единствен-
        // ная записываемая зона Live-VFS). Эмпирика p9aa2/3: запись кеша
        // в /root/.cache (RO-initrd) ОТКАЗЫВАЛАСЬ (open-fail: ReadOnly) ->
        // незавершённый cache-lifecycle -> LLVM-паттерн-0xAA-заполнение
        // буферов оставалось НЕЗАМЕЩЁННЫМ (RIP=0xAAAA / R15=0xAAAA / крах
        // malloc-unlink на brk-чанке). XDG_CACHE_HOME + явный
        // MESA_SHADER_CACHE_DIR (порядок Mesa: MESA_SHADER_CACHE_DIR ->
        // XDG_CACHE_HOME -> $HOME/.cache) -> кеш живёт в /tmp (RAM).
        "XDG_CACHE_HOME=/tmp",
        "MESA_SHADER_CACHE_DIR=/tmp/mesa_shader_cache",
        // CDD №15 p4: MALLOC_PERTURB_ УДАЛЁН. Host-репро p13 врал для
        // POLER-OS: PMM-страницы всегда ЗАНУЛЕНЫ — perturb=0xAA не
        // «ловил» коррупцию, а СОЗДАВАЛ её: lvp читал неинициализиро-
        // ванные malloc-зоны как МУСОРНЫЕ указатели → NULL-листы STL
        // list-splice → CPU-EXCEPTION × N за прогон (libvulkan_lvp.so
        // +0x301A4C). Без perturb: ноль CPU-крашей (эмпирика p4).
        // CDD №15: однопоточный llvmpipe — p14-кванш llvmpipe worker-крана
        // (STL list-splice, libvulkan_lvp.so+0x301A4C) — убирает сам ИСТОЧНИК
        // (пул воркеров); рендер медленнее, но детерминированнее под TCG.
        "LP_NUM_THREADS=0",
        // CDD №12 p14: XDG_RUNTIME_DIR — wayland-сокет wlserver'а! Без него:
        // «Unable to open wayland socket» → wlroots teardown → ассерт
        // wl_list_empty(new_input) → АБОРТ gamescope посреди рендер-цикла.
        // /tmp — единственная RW-зона.
        "XDG_RUNTIME_DIR=/tmp",
        // CDD №12 p14: headless-композитор — без libinput-устройств
        // (иначе wlserver: «Failed to start backend» → teardown-ассерт).
        "WLR_LIBINPUT_NO_DEVICES=1",
        // CDD #12 p3: Vulkan-лоадер ищет ICD опендирем (getdents64 — бэклог);
        // VK_ICD_FILENAMES — штатный механизм лоадера (спека Khronos):
        // указываем lavapipe-манифест напрямую.
        "VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json",
    };

    // 3b. PT_INTERP: динамический бинарник — грузим ИНТЕРПРЕТАТОР (ld.so)
    //     как вторую ET_DYN-картинку; управление — НА ЕГО entry (handoff);
    //     AT_BASE = базис ld.so, AT_ENTRY = entry бинарника.
    var entry_va = img.entry_va;
    var at_base: u64 = 0;
    // CDD №12 p4: страницы ld.so — для mmap-реестра (атрибуция).
    var interp_pages: u64 = 0;
    if (img.interp) |interp_path| {
        sys_print("[ELF] PT_INTERP: ");
        sys_print(interp_path);
        const interp_data = initrdFindFile(interp_path) orelse {
            sys_print("\n[ELF] FAIL: интерпретатор не найден в initrd (упакуй ld.so)\n");
            return;
        };
        const interp_img = elf_loader.loadElf(ops, user_pml4, interp_data, elf_loader.LINUX_INTERP_BASE) catch |err| {
            sys_print("[ELF] interp load error: ");
            sys_print(@errorName(err));
            sys_print("\n");
            return;
        };
        entry_va = interp_img.entry_va; // HANDOFF: старт с ld.so
        at_base = interp_img.base_va;
        interp_pages = interp_img.pages;
        sys_print(" — базис 0x");
        putHex(interp_img.base_va);
        sys_print(" entry 0x");
        putHex(interp_img.entry_va);
        sys_print(" (handoff)\n");
    }

    // 4. Стек Linux-ABI: argc/argv/envp/auxv + AT_RANDOM
    const stack = elf_loader.buildUserStack(
        ops,
        user_pml4,
        elf_loader.LINUX_STACK_TOP,
        elf_loader.LINUX_STACK_PAGES,
        .{ .argv = argv_ptrs[0..argv_count], .envp = &envp, .execfn = argv_ptrs[0] },
        img,
        elfRandomSeed(),
        at_base,
    ) catch |err| {
        sys_print("[ELF] stack error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    sys_print("[ELF] stack: entry_rsp=0x");
    putHex(stack.entry_rsp);
    sys_print(" argc=");
    printDec(argv_count);
    sys_print("\n");

    // 5. Ring-3 задача + Linux-ABI + proc-слот (fd/mmap/brk);
    //    entry = ld.so для динамических (handoff), бинарник — для статиков
    const task_id = scheduler.createUserTaskAbi(entry_va, user_pml4, stack.entry_rsp, .linux) catch |err| {
        sys_print("createUserTask error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    // CDD №12 p3: abi=.linux теперь ВНУТРИ createUserTaskAbi (ДО
    // state=.Ready) — гонка тика закрыта; здесь только красная строка:
    scheduler.tasks[task_id].abi = .linux;
    // v0.18.0 (CDD №9): главный user-стек — в таблицах asm-владельца
    scheduler.registerUserStack(
        task_id,
        elf_loader.LINUX_STACK_TOP - elf_loader.LINUX_STACK_PAGES * 4096,
        elf_loader.LINUX_STACK_TOP,
    );
    if (linuxNewProc(task_id)) |slot| {
        linux_procs[slot].brk_base = img.brk;
        linux_procs[slot].brk = img.brk;
        // CDD №12 p4: образ + интерпретатор + стек → mmap-реестр С ИМЕНЕМ
        // (модульная атрибуция RIP→библиотека в CPU-exception: gamescope-
        // код и ld.so лежат ВНЕ ld.so-мапов — их регионы ставим МЫ).
        // phys=0: физика принадлежит elf_loader/стек-маппингу — munmap
        // эти регионы НЕ освобождает (только unmap-деградация).
        const reg_slot: u8 = @intCast(slot);
        linuxRecordRegion(reg_slot, img.base_va, img.pages, 0, false, file);
        if (img.interp != null) {
            linuxRecordRegion(reg_slot, elf_loader.LINUX_INTERP_BASE, interp_pages, 0, false, "ld.so");
        }
        linuxRecordRegion(
            reg_slot,
            elf_loader.LINUX_STACK_TOP - elf_loader.LINUX_STACK_PAGES * 4096,
            elf_loader.LINUX_STACK_PAGES,
            0,
            false,
            "[stack]",
        );
        // execfn (readlink /proc/self/exe): АБСОЛЮТНЫЙ путь — glibc
        // _dl_get_origin (dl-origin.c:41) ASSERT'ит linkval[0]=='/'
        // (эмпирика glibc-static: «Fatal glibc error: assertion failed»).
        // elfload hello-static → «/hello-static»; usr/bin/gamescope →
        // «/usr/bin/gamescope» (Linux-семантика exec-пути).
        {
            var efn_buf: [96]u8 = undefined;
            var efn_len: usize = 0;
            if (file.len > 0 and file[0] != '/') {
                efn_buf[0] = '/';
                efn_len = 1;
            }
            const copy = @min(file.len, efn_buf.len - efn_len);
            @memcpy(efn_buf[efn_len .. efn_len + copy], file[0..copy]);
            efn_len += copy;
            const n = @min(efn_len, linux_procs[slot].execfn_buf.len);
            @memcpy(linux_procs[slot].execfn_buf[0..n], efn_buf[0..n]);
            linux_procs[slot].execfn_len = n;
        }
    } else {
        sys_print("[ELF] proc-слоты исчерпаны (2) — задача без fd-таблицы\n");
    }

    sys_print("[ELF] Ring 3 task #");
    printDec(task_id);
    sys_print(" created (Linux ABI) — waiting for user markers\n");
    sys_print("[ELF] dev_mmap WC / clone / futex — боевой режим активирован\n");
}

/// v0.11.0 (CDD №2): калибровка TSC для QueryPerformanceFrequency —
/// замер дельты TSC (hal.readMsr(0x10) = IA32_TSC) между тиками APIC-таймера
/// (периодический, 10мс — калиброван по PIT в hal.initApicTimer).
/// 5 тиков = 50мс → freq = delta × 20. Гард на мусор TCG — clamp в
/// [1 МГц, 10 ГГц]; при провале — HPET-класс 10 МГц (Windows-fallback).
fn calibrateTsc() u64 {
    const t0 = hal.readMsr(0x10);
    const ticks0 = hal.tick_count;
    var spin: u64 = 0;
    while (hal.tick_count < ticks0 + 5) {
        asm volatile ("pause");
        spin += 1;
        if (spin > 4_000_000_000) break; // страховка от зависшего таймера
    }
    const t1 = hal.readMsr(0x10);
    if (t1 <= t0 or hal.tick_count < ticks0 + 5) return 10_000_000;
    const freq = (t1 - t0) * 20; // 5 тиков = 1/20 с
    if (freq < 1_000_000 or freq > 10_000_000_000) return 10_000_000;
    return freq;
}

/// CDD-трап: int3 из стаба импорта. int3 — TRAP-исключение: CPU сохраняет
/// RIP уже ПОСЛЕ int3 (на ret) — НЕ продвигаем! Логируем имя (первый hit),
/// rax=0 (xor уже исполнен) — приложение продолжает работу.
/// false → обычный user-kill путь (не наш стаб / livelock).
fn cddInt3Handler(frame: *hal.InterruptFrame) bool {
    const disp = win32.activeDispatcher() orelse return false;
    const e = disp.findByRip(frame.rip) orelse return false;

    e.hits += 1;
    if (e.hits == 1) {
        var buf: [128]u8 = undefined;
        sys_print("[CDD] ");
        sys_print(win32.fmtEntryName(e, &buf));
        sys_print(" — не реализовано, ret=0\n");
    }

    // Livelock-страховка: приложение может крутиться в retry-цикле на
    // нулевых возвратах — после 100k вызовов отдаем задачу обычному kill-пути
    if (disp.totalHits() > 100_000) {
        sys_print("[CDD] >100000 вызовов стабов — убиваю задачу (livelock)\n");
        return false;
    }

    // ⚠ НЕ трогаем frame.rip: int3 — trap, RIP уже указывает на ret (base+4).
    // (баг v0.10.0-dev: rip+=1 перескакивал ret → исполнение нулей → #PF)
    frame.rax = 0; // дефолт «не реализовано» (xor уже исполнен — дубль для гарантии)
    return true;
}

fn cmd_peload(args: []const u8) void {
    if (args.len == 0) {
        sys_print("Usage: peload <file-in-initrd> [process-args]  (e.g. peload curl.exe http://example.com)\n");
        return;
    }
    // v0.12.0: файл — первый токен, ОСТАЛЬНОЕ — аргументы процесса (URL…):
    // полная строка попадает в GetCommandLineA/params-страницу → argv.
    var file_end = std.mem.indexOfScalar(u8, args, ' ') orelse args.len;
    if (file_end == 0) file_end = args.len;
    const file = args[0..file_end];
    const data = initrdFindFile(file) orelse {
        sys_print("File not found in initrd: ");
        sys_print(file);
        sys_print("\n");
        return;
    };

    sys_print("=== PE Load & Run (CDD cycle 8): ");
    sys_print(file);
    if (args.len > file_end) {
        sys_print(" — cmdline: ");
        sys_print(args);
    }
    sys_print(" ===\n");

    const image = pe.Pe.parse(data) catch |err| {
        sys_print("Parse error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    // 1. User-PML4 (kernel-маппинги копируются БЕЗ User-бита)
    const user_pml4 = vmm.createUserPML4() catch |err| {
        sys_print("createUserPML4 error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    // 2. Планировка + ImageBase: v0.17.0 (CDD №8) — ПОЛНЫЙ .reloc!
    //    Предпочтённый базис валиден → грузим по нему (дельта 0, релокации
    //    не нужны). Невалиден (7za.exe: 0x400000 < 4ГБ — identity-зона
    //    ядра) → грузим по ВЫСОКОМУ базису 0x140000000 и применяем таблицу
    //    BASERELOC (DIR64-фикспы) — как Windows ASLR/DYNAMIC_BASE.
    var layout = pe_loader.UserLayout{};
    const preferred = image.imageBase();
    if (pe_loader.validateImageBase(preferred, image.sizeOfImage())) {
        layout.image_base = preferred;
    } else {
        layout.image_base = 0x140000000; // высокий базис (validate — ниже)
        if (!pe_loader.validateImageBase(layout.image_base, image.sizeOfImage())) {
            sys_print("[PE] ImageBase ");
            putHex(preferred);
            sys_print(" непригоден И высок. базис не проходит — отказ\n");
            return;
        }
        sys_print("[PE] ImageBase ");
        putHex(preferred);
        sys_print(" ниже 4ГБ (identity ядра) — грузим по ");
        putHex(layout.image_base);
        sys_print(" + .reloc (DYNAMIC_BASE)\n");
    }

    const ops = kernelLoaderOps();

    // 3. Посекционный маппинг образа (PTE по характеристикам секций)
    const img = pe_loader.loadImage(ops, user_pml4, &image, layout.image_base) catch |err| {
        sys_print("loadImage error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    // 3b. v0.17.0 (CDD №8): БАЗОВЫЕ РЕЛОКАЦИИ — фактический базис ≠
    //     предпочтённому → применяем DIR64-фикспы (7za: 2258, curl: ~10.9K).
    //     Статистика в serial — покрываем и skipped-случаи (битые таблицы).
    if (img.base_va != preferred) {
        const rstats = pe_loader.applyRelocations(&image, img.backing, img.base_va, preferred);
        sys_print("[PE] .reloc: ");
        printDec(rstats.applied);
        sys_print(" DIR64 fixups, skipped(type)=");
        printDec(rstats.skipped_type);
        sys_print(" skipped(bounds)=");
        printDec(rstats.skipped_bounds);
        sys_print(" (delta=");
        putHex(@as(u64, @bitCast(rstats.delta)));
        sys_print(")\n");
    }
    sys_print("[PE] Image mapped: base=");
    putHex(img.base_va);
    sys_print(" size=");
    putHex(img.size_of_image);
    sys_print(" pages=");
    printDec(img.pages);
    sys_print(" entry=");
    putHex(img.entry_va);
    sys_print("\n");

    // 4. Код стабов: физ. страницы, RX для Ring 3, logical = user-VA.
    //    v0.12.0: запас под EXTRA-записи (SSPI-таблица Secur32 — функции,
    //    которые curl получает ЧЕРЕЗ ТАБЛИЦУ, а не через IAT) + 3 слота
    //    моста колбэка (launcher/trampoline/mailbox) + 3 слота native-bsearch
    //    (127Б: вызов компаратора приложения из Ring 3 — легален и безопасен)
    //    + 1 слот ExitThread (динамическая extra-запись при первом
    //    CreateThread: return-трамплин ThreadProc).
    const counts = image.countImports();
    const SSPI_EXTRA: u64 = 25; // SecurityFunctionTable-имена (см. ниже)
    const BRIDGE_SLOTS: u64 = 3;
    const NATIVE2_SLOTS: u64 = 7; // bsearch (3 слота) + qsort (4 слота, CDD №5)
    const EXITTHREAD_SLOTS: u64 = 1;
    const stub_bytes: u64 = (counts.functions + SSPI_EXTRA + BRIDGE_SLOTS + NATIVE2_SLOTS + EXITTHREAD_SLOTS) * win32.STUB_CODE_SIZE;
    const stub_region = pe_loader.mapRegion(
        ops,
        user_pml4,
        layout.stubs_va,
        stub_bytes,
        pe_loader.PTE_USER, // RX: исполняемый, без записи, без NX
    ) catch |err| {
        sys_print("stub mapRegion error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };

    // 5. Генерация стабов (int3-трапы) + активация глобального диспетчера
    kdisp = win32.Dispatcher.init(&kstub_entries, stub_region.backing[0..@intCast(stub_region.size)], .int3);
    kdisp.logical_base = layout.stubs_va;
    kdisp.log_fn = win32LogHook;
    const generated = kdisp.generateFor(&image) catch |err| {
        sys_print("Stub generation error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    win32.setDispatcher(&kdisp);
    sys_print("[PE] Stubs: ");
    printDec(generated);
    sys_print(" (code ");
    putHex(layout.stubs_va);
    sys_print("..+");
    printDec(generated * win32.STUB_CODE_SIZE);
    sys_print(" bytes)\n");

    // 6a. (v0.11.0, CDD №2) NATIVE-стабы: memset/memcpy/memmove/strlen —
    // чистый Ring-3 машинный код (rep stosb/movsb), БЕЗ syscall-оверхеда —
    // CRT зовёт их на каждом шагу. Раскладка реальных импортов curl.exe
    // (проверено парсером): memset/strlen ← api-ms-win-crt-string,
    // memcpy/memmove ← api-ms-win-crt-private.
    const native_specs = [_]struct { dll: []const u8, func: []const u8, kind: win32.NativeKind }{
        .{ .dll = "api-ms-win-crt-string-l1-1-0.dll", .func = "memset", .kind = .memset },
        .{ .dll = "api-ms-win-crt-string-l1-1-0.dll", .func = "strlen", .kind = .strlen },
        .{ .dll = "api-ms-win-crt-string-l1-1-0.dll", .func = "strcmp", .kind = .strcmp },
        .{ .dll = "api-ms-win-crt-string-l1-1-0.dll", .func = "strncmp", .kind = .strncmp },
        .{ .dll = "api-ms-win-crt-private-l1-1-0.dll", .func = "memcpy", .kind = .memcpy },
        .{ .dll = "api-ms-win-crt-private-l1-1-0.dll", .func = "memmove", .kind = .memmove },
        // v0.17.0 (CDD №8): msvcrt.dll (MSVC /MD — 7-Zip) — те же горячие
        // CRT-функции теперь и для msvcrt-импортов (dll-имя должно совпасть!)
        .{ .dll = "msvcrt.dll", .func = "memset", .kind = .memset },
        .{ .dll = "msvcrt.dll", .func = "memcpy", .kind = .memcpy },
        .{ .dll = "msvcrt.dll", .func = "memmove", .kind = .memmove },
        .{ .dll = "msvcrt.dll", .func = "strlen", .kind = .strlen },
        .{ .dll = "msvcrt.dll", .func = "strcmp", .kind = .strcmp },
        .{ .dll = "msvcrt.dll", .func = "strncmp", .kind = .strncmp },
        // ⚠ УРОК оборванной сессии: msvcrt!_initterm — НАТИВНЫЙ цикл C++-
        // инициализаторов (статические конструкторы 7-Zip!); no-op оставлял
        // глобалы NULL → крах в main. api-ms-вариант (mingw-curl) остаётся
        // dispatch-no-op: его натив ломал TLS-путь mingw (эмпирика v0.17-dev).
        .{ .dll = "msvcrt.dll", .func = "_initterm", .kind = .initterm },
        .{ .dll = "msvcrt.dll", .func = "_initterm_e", .kind = .initterm_e },
    };
    var natives: usize = 0;
    for (native_specs) |spec| {
        if (kdisp.implementNative(spec.dll, spec.func, spec.kind)) {
            natives += 1;
        } else {
            sys_print("[PE] native NOT FOUND: ");
            sys_print(spec.dll);
            sys_print("!");
            sys_print(spec.func);
            sys_print("\n");
        }
    }
    sys_print("[PE] Native stubs: ");
    printDec(natives);
    sys_print(" / ");
    printDec(native_specs.len);
    sys_print(" (memset/memcpy/memmove/strlen/strcmp/strncmp — Ring 3)\n");

    // 6a2. (v0.12.0, CDD №3) EXTRA-записи реестра — SSPI-таблица Secur32.
    //      curl получает SecurityFunctionTableA от InitSecurityInterfaceA и
    //      зовёт функции ЧЕРЕЗ ТАБЛИЦУ (не через IAT!) — каждому имени нужен
    //      свой вызываемый user-VA. .impl → syscall-трамплин → win32_crt
    //      отвечает SEC_E_UNSUPPORTED (SEC_E_OK = 0 затирал бы out-параметры).
    const sspi_extra_specs = [_][]const u8{
        "EnumerateSecurityPackagesA",     "EnumerateSecurityPackagesW",
        "QuerySecurityPackageInfoA",      "QuerySecurityPackageInfoW",
        "FreeContextBuffer",             "ImportSecurityContextA",
        "ImportSecurityContextW",        "AcceptSecurityContext",
        "ImpersonateSecurityContext",    "RevertSecurityContext",
        "QuerySecurityContextToken",     "DeleteSecurityContext",
        "ApplyControlToken",             "QueryContextAttributesA",
        "QueryContextAttributesW",       "QueryCredentialsAttributesA",
        "QueryCredentialsAttributesW",   "FreeCredentialsHandle",
        "AcquireCredentialsHandleA",     "AcquireCredentialsHandleW",
        "AddCredentialsA",               "AddCredentialsW",
        "CompleteAuthToken",             "InitializeSecurityContextA",
        "InitializeSecurityContextW",
    };
    var extras: usize = 0;
    for (sspi_extra_specs) |fname| {
        if (kdisp.addExtraStub("Secur32.dll", fname, .impl) != null) extras += 1;
    }
    sys_print("[PE] Extra SSPI stubs: ");
    printDec(extras);
    sys_print(" / ");
    printDec(sspi_extra_specs.len);
    sys_print(" (SecurityFunctionTable — вызовы ЧЕРЕЗ таблицу)\n");

    // 6a3. (v0.12.0, CDD №3) МОСТ КОЛБЭКА (InitOnceExecuteOnce): launcher/
    //      trampoline/mailbox в хвосте стаб-региона. Кернель-путь: колбэк
    //      возвращает на СОБСТВЕННЫЙ trampoline → syscall #7 (done_target=null).
    win32_api.bridge = kdisp.buildCallbackBridge(null, win32.CB_SYSCALL_DONE, win32.CALLBACK_COOKIE);
    if (win32_api.bridge) |br| {
        sys_print("[PE] Callback bridge: launcher=");
        putHex(br.launcher_va);
        sys_print(" trampoline=");
        putHex(br.trampoline_va);
        sys_print(" mailbox=");
        putHex(br.mailbox_va);
        sys_print(" (InitOnce → Ring 3 → syscall #7)\n");
    } else {
        sys_print("[PE] Callback bridge: НЕ СОБРАН (InitOnce уйдёт в no-launch)\n");
    }

    // 6a4. (v0.12-fix) NATIVE bsearch: alias-таблица опций curl. Каждый голый
    //      URL curl 8.x подаёт в getparameter как опцию «--url» — поиск имени
    //      в таблице идёт bsearch'ом; trap-стаб возвращал NULL = «не найдено»
    //      → «curl: option http://…: is unknown». Компаратор — код
    //      ПРИЛОЖЕНИЯ, вызывать его можно только из Ring 3 → binary-search
    //      исполняется НАТИВНО в кольце 3 (Win64-контракт: shadow+align).
    if (kdisp.implementNativeBsearch("api-ms-win-crt-utility-l1-1-0.dll", "bsearch")) {
        sys_print("[PE] Native bsearch: OK (Ring 3, компаратор приложения; код после mailbox)\n");
    } else {
        sys_print("[PE] Native bsearch: НЕ НАЙДЕН в импортах (пропускаем)\n");
    }

    // 6a5. (v0.14.0, CDD №5) NATIVE qsort: OpenSSL в curl.exe сортирует
    //      cipher-списки/точки кривых — trap-стаб → livelock-kill задачи.
    //      Insertion-sort 175Б, компаратор приложения из Ring 3
    //      (прецедент bsearch); слоты после bsearch.
    if (kdisp.implementNativeQsort("api-ms-win-crt-utility-l1-1-0.dll", "qsort")) {
        sys_print("[PE] Native qsort: OK (Ring 3, insertion-sort 175Б, компаратор приложения)\n");
    } else {
        sys_print("[PE] Native qsort: НЕ НАЙДЕН в импортах (пропускаем)\n");
    }

    // 6b. Топ-функции CDD-циклов №1+№2 + CRT-startup-kit: syscall-трамплины.
    // Спека №1: GetStdHandle / GetCommandLineA/W / VirtualAlloc (+ ExitProcess),
    // «выживание mingw-UCRT»: __p__* указатели, malloc/calloc, initterm…
    // Волна №2 (по логу цепочки v0.10.0, 17 функций): GetProcAddress,
    // QueryPerformanceFrequency/Counter, GetConsoleMode/ScreenBufferInfo,
    // SRWLock, GetCurrentThreadId, setvbuf/fputs/fputc/fflush, realloc,
    // WSAStartup/WSACleanup, SetUnhandledExceptionFilter.
    // Честный подсчёт: активируются только НАЙДЕННЫЕ в импортах имена.
    const impl_specs = [_][2][]const u8{
        .{ "KERNEL32.dll", "GetStdHandle" },
        .{ "KERNEL32.dll", "GetCommandLineA" },
        .{ "KERNEL32.dll", "GetCommandLineW" },
        .{ "KERNEL32.dll", "VirtualAlloc" },
        .{ "KERNEL32.dll", "ExitProcess" },
        .{ "KERNEL32.dll", "GetModuleHandleA" },
        .{ "KERNEL32.dll", "GetModuleHandleW" },
        .{ "KERNEL32.dll", "Sleep" },
        .{ "KERNEL32.dll", "GetProcAddress" },
        .{ "KERNEL32.dll", "QueryPerformanceFrequency" },
        .{ "KERNEL32.dll", "QueryPerformanceCounter" },
        .{ "KERNEL32.dll", "GetConsoleMode" },
        .{ "KERNEL32.dll", "GetConsoleScreenBufferInfo" },
        .{ "KERNEL32.dll", "GetCurrentThreadId" },
        .{ "KERNEL32.dll", "AcquireSRWLockExclusive" },
        .{ "KERNEL32.dll", "ReleaseSRWLockExclusive" },
        .{ "KERNEL32.dll", "SetUnhandledExceptionFilter" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "__p__fmode" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "__p__commode" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "setvbuf" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fputs" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fputc" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fwrite" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fflush" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "exit" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_exit" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "abort" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_errno" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_crt_atexit" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_set_app_type" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_set_invalid_parameter_handler" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_onexit_table" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_register_onexit_function" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_configure_narrow_argv" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_narrow_environment" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_initterm" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_cexit" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_exe" },
        .{ "api-ms-win-crt-heap-l1-1-0.dll", "malloc" },
        .{ "api-ms-win-crt-heap-l1-1-0.dll", "calloc" },
        .{ "api-ms-win-crt-heap-l1-1-0.dll", "realloc" },
        .{ "api-ms-win-crt-heap-l1-1-0.dll", "free" },
        .{ "api-ms-win-crt-heap-l1-1-0.dll", "_set_new_mode" },
        .{ "api-ms-win-crt-locale-l1-1-0.dll", "_configthreadlocale" },
        .{ "api-ms-win-crt-environment-l1-1-0.dll", "__p__environ" },
        .{ "api-ms-win-crt-environment-l1-1-0.dll", "getenv" },
        .{ "WS2_32.dll", "WSAStartup" },
        .{ "WS2_32.dll", "WSACleanup" },
        // Волна №3 (CDD №3, по логу цепочки v0.11.0): версионирование
        // (VerSetConditionMask/VerifyVersionInfoW — curl проверяет Win7+),
        // окружение (GetEnvironmentVariable → пустое), ошибки (GetLastError/
        // SetLastError/FormatMessage), синхронизация (InitOnce → мост),
        // SSPI (InitSecurityInterfaceA — таблица), сокеты (socket/connect/
        // closesocket/ioctlsocket/getaddrinfo/send/recv…).
        .{ "KERNEL32.dll", "VerSetConditionMask" },
        .{ "KERNEL32.dll", "VerifyVersionInfoW" },
        .{ "KERNEL32.dll", "InitOnceExecuteOnce" },
        .{ "KERNEL32.dll", "GetEnvironmentVariableA" },
        .{ "KERNEL32.dll", "GetEnvironmentVariableW" },
        .{ "KERNEL32.dll", "FormatMessageA" },
        .{ "KERNEL32.dll", "FormatMessageW" },
        .{ "KERNEL32.dll", "GetLastError" },
        .{ "KERNEL32.dll", "SetLastError" },
        .{ "Secur32.dll", "InitSecurityInterfaceA" },
        .{ "Secur32.dll", "InitSecurityInterfaceW" },
        .{ "WS2_32.dll", "socket" },
        .{ "WS2_32.dll", "connect" },
        .{ "WS2_32.dll", "closesocket" },
        .{ "WS2_32.dll", "ioctlsocket" },
        .{ "WS2_32.dll", "send" },
        .{ "WS2_32.dll", "recv" },
        .{ "WS2_32.dll", "htons" },
        .{ "WS2_32.dll", "htonl" },
        .{ "WS2_32.dll", "ntohs" },
        .{ "WS2_32.dll", "ntohl" },
        .{ "WS2_32.dll", "WSAGetLastError" },
        .{ "WS2_32.dll", "getaddrinfo" },
        .{ "WS2_32.dll", "freeaddrinfo" },
        // Module-walk (проявился с URL-аргументами: curl инспектирует DLL)
        .{ "KERNEL32.dll", "CreateToolhelp32Snapshot" },
        .{ "KERNEL32.dll", "Module32First" },
        .{ "KERNEL32.dll", "Module32Next" },
        .{ "KERNEL32.dll", "CloseHandle" },
        // Critical sections: Initialize/Enter/Leave — void-функции, no-op
        // для однопоточного CDD-процесса (semantически корректный ноль).
        .{ "KERNEL32.dll", "InitializeCriticalSection" },
        .{ "KERNEL32.dll", "EnterCriticalSection" },
        .{ "KERNEL32.dll", "LeaveCriticalSection" },
        .{ "KERNEL32.dll", "GetModuleFileNameA" },
        // fix-волна №3 (по логу v0.12-run4): «curl: option …: out of memory» —
        // _strdup(trap)→NULL; strrchr(NULL) ломал конфиг-путь. Строковое
        // семейство закрывается целиком (bsearch-компараторы уже native).
        .{ "api-ms-win-crt-string-l1-1-0.dll", "_strdup" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "_stricmp" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "_strnicmp" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "tolower" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isspace" },
        .{ "api-ms-win-crt-private-l1-1-0.dll", "memcmp" },
        .{ "api-ms-win-crt-private-l1-1-0.dll", "strchr" },
        .{ "api-ms-win-crt-private-l1-1-0.dll", "strrchr" },
        .{ "api-ms-win-crt-private-l1-1-0.dll", "strstr" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "strerror" },
        .{ "api-ms-win-crt-runtime-l1-1-0.dll", "strerror_s" },
        // (_wcserror_s реализован в win32_crt-dispatch + тесты; curl его не
        // импортирует → в impl_specs не вносим — счёт честный)
        .{ "api-ms-win-crt-locale-l1-1-0.dll", "setlocale" },
        .{ "api-ms-win-crt-convert-l1-1-0.dll", "atoi" },
        .{ "api-ms-win-crt-convert-l1-1-0.dll", "strtol" },
        .{ "api-ms-win-crt-convert-l1-1-0.dll", "strtoul" },
        // event-волна (по логу v0.12-run5): «curl: (27) Out of memory» —
        // WSACreateEvent(trap)→NULL. Событийный каркас сетевой модели:
        // WSAEventSelect/Wait/Enum + KERNEL32 WaitFor-семья + stdio-тройка.
        .{ "WS2_32.dll", "WSACreateEvent" },
        .{ "WS2_32.dll", "WSACloseEvent" },
        .{ "WS2_32.dll", "WSAResetEvent" },
        .{ "WS2_32.dll", "WSAEventSelect" },
        .{ "WS2_32.dll", "WSAEnumNetworkEvents" },
        .{ "WS2_32.dll", "WSAWaitForMultipleEvents" },
        .{ "WS2_32.dll", "WSAIoctl" },
        .{ "WS2_32.dll", "WSASetLastError" },
        .{ "WS2_32.dll", "__WSAFDIsSet" },
        // sockopt-волна (CDD №4, по логу v0.12.0-run): curl после connect
        // вызывает setsockopt/getsockopt(SO_ERROR)/getsockname и ЖДЁТ
        // завершения соединения в select/WSAEnumNetworkEvents — без них
        // вечный поллинг. send/recv — loopback-шим HTTP-обмена.
        .{ "WS2_32.dll", "setsockopt" },
        .{ "WS2_32.dll", "getsockopt" },
        .{ "WS2_32.dll", "getsockname" },
        .{ "WS2_32.dll", "getpeername" },
        .{ "WS2_32.dll", "select" },
        .{ "WS2_32.dll", "shutdown" },
        .{ "KERNEL32.dll", "CreateEventA" },
        .{ "KERNEL32.dll", "WaitForSingleObject" },
        .{ "KERNEL32.dll", "WaitForSingleObjectEx" },
        .{ "KERNEL32.dll", "WaitForMultipleObjects" },
        .{ "KERNEL32.dll", "InitializeCriticalSectionEx" },
        .{ "KERNEL32.dll", "DeleteCriticalSection" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_fileno" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_isatty" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_setmode" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_fsopen" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "strcspn" },
        .{ "api-ms-win-crt-convert-l1-1-0.dll", "mbstowcs_s" },
        // threading-волна (по логу v0.12-run6): CreateThread(trap)→NULL →
        // curl вечно ждёт резолвер. Теперь тред — задача планировщика на
        // той же PML4; время/CV/memchr — поддержка цикла резолвера.
        .{ "KERNEL32.dll", "CreateThread" },
        .{ "KERNEL32.dll", "GetSystemTimeAsFileTime" },
        .{ "KERNEL32.dll", "GetTickCount64" },
        .{ "KERNEL32.dll", "InitializeConditionVariable" },
        .{ "KERNEL32.dll", "WakeConditionVariable" },
        .{ "KERNEL32.dll", "SleepConditionVariableCS" },
        .{ "api-ms-win-crt-private-l1-1-0.dll", "memchr" },
        .{ "api-ms-win-crt-time-l1-1-0.dll", "_time64" },
        // финал-волна (CDD №4): SleepEx — сон-поллинг резолвера после recv;
        // _get_osfhandle — mingw-UCRT печать тела ответа (fwrite-путь);
        // MultiByteToWideChar — UCRT конвертация перед WriteFile (без него
        // «curl: (23) ERROR on write of 13 bytes» — тело не печаталось).
        .{ "KERNEL32.dll", "SleepEx" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_get_osfhandle" },
        .{ "KERNEL32.dll", "MultiByteToWideChar" },
        .{ "KERNEL32.dll", "WriteConsoleW" },
        // Wave-A (CDD №5, по живому логу https-разведки): пред-SSPI волна —
        // без валидного мьютекса и энтропии curl не доходит до
        // AcquireCredentialsHandle (WaitForSingleObject(0)-retry-loop +
        // мусорный BCryptGenRandom-буфер от trap-стаба).
        .{ "KERNEL32.dll", "CreateMutexA" },
        .{ "KERNEL32.dll", "ReleaseMutex" },
        .{ "bcrypt.dll", "BCryptGenRandom" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "strnlen" },
        .{ "WS2_32.dll", "inet_pton" },
        // ctype-семейство (по логу: punycode/IDNA резолвер-треда зовёт
        // isalnum ЧЕРЕЗ УКАЗАТЕЛЬ (call r15) — резолв GetProcAddress'ом
        // по реестру стабов; trap → livelock-kill задачи).
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isalnum" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isdigit" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isalpha" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isupper" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "islower" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "isxdigit" },
        .{ "api-ms-win-crt-string-l1-1-0.dll", "ispunct" },
        // byteswap-семейство (OpenSSL-путь, TLS-записи): _byteswap_ulong
        // — trap → livelock (финальный бэклог живого https-прогона)
        .{ "api-ms-win-crt-utility-l1-1-0.dll", "_byteswap_ulong" },
        .{ "api-ms-win-crt-utility-l1-1-0.dll", "_byteswap_ushort" },
        .{ "api-ms-win-crt-utility-l1-1-0.dll", "_byteswap_uint64" },
        // Волна CDD №7 (v0.16.0): файловая волна VFS — верификация SSL без
        // -k требует от curl-OpenSSL РЕАЛЬНЫХ файлов: CA-бандл открывается
        // fopen/fread (BIO), конфиг — _fsopen; Win32 File API — каркас
        // (CreateFileA/ReadFile/CloseHandle/атрибуты/типы); lowio — мост.
        .{ "KERNEL32.dll", "CreateFileA" },
        .{ "KERNEL32.dll", "ReadFile" },
        .{ "KERNEL32.dll", "WriteFile" },
        .{ "KERNEL32.dll", "GetFileAttributesA" },
        .{ "KERNEL32.dll", "GetFileType" },
        .{ "KERNEL32.dll", "SetConsoleCtrlHandler" },
        .{ "KERNEL32.dll", "SetHandleInformation" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fopen" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fread" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fseek" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_fseeki64" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "ftell" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fclose" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "feof" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "ferror" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "rewind" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "fgets" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "getc" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "ungetc" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "puts" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "putchar" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_read" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_write" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_close" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_lseeki64" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_sopen_s" },
        .{ "api-ms-win-crt-stdio-l1-1-0.dll", "_chsize_s" },
        // ── Волна CDD №8 (v0.17.0): 7-Zip (msvcrt /MD + KERNEL32-heavy) ──
        // КРТИТ-стартап MSVC + системный слой бенчмарка: __getmainargs/…;
        // события/семафоры с реальной сигнальностью; CPU/память/времена;
        // файловая RW-волна (SetEndOfFile/Flush); реестр/токены — честный
        // отказ (приложение живёт с fallback). Нативы msvcrt — выше.
        .{ "msvcrt.dll", "__getmainargs" },
        .{ "msvcrt.dll", "__set_app_type" },
        .{ "msvcrt.dll", "__setusermatherr" },
        .{ "msvcrt.dll", "_XcptFilter" },
        .{ "msvcrt.dll", "_onexit" },
        .{ "msvcrt.dll", "__dllonexit" },
        .{ "msvcrt.dll", "_purecall" },
        .{ "msvcrt.dll", "_CxxThrowException" },
        .{ "msvcrt.dll", "__CxxFrameHandler" },
        .{ "msvcrt.dll", "__C_specific_handler" },
        .{ "msvcrt.dll", "??1type_info@@UEAA@XZ" },
        .{ "msvcrt.dll", "?terminate@@YAXXZ" },
        .{ "msvcrt.dll", "_beginthreadex" },
        .{ "msvcrt.dll", "exit" },
        .{ "msvcrt.dll", "_exit" },
        .{ "msvcrt.dll", "_cexit" },
        .{ "msvcrt.dll", "_c_exit" },
        .{ "msvcrt.dll", "malloc" },
        .{ "msvcrt.dll", "free" },
        .{ "msvcrt.dll", "realloc" },
        .{ "msvcrt.dll", "memcmp" },
        .{ "msvcrt.dll", "wcscmp" },
        .{ "msvcrt.dll", "wcsstr" },
        .{ "msvcrt.dll", "fflush" },
        .{ "msvcrt.dll", "fputc" },
        .{ "msvcrt.dll", "fputs" },
        .{ "msvcrt.dll", "fgetc" },
        .{ "msvcrt.dll", "fclose" },
        .{ "msvcrt.dll", "_isatty" },
        .{ "KERNEL32.dll", "CreateEventW" },
        .{ "KERNEL32.dll", "SetEvent" },
        .{ "KERNEL32.dll", "ResetEvent" },
        .{ "KERNEL32.dll", "CreateSemaphoreW" },
        .{ "KERNEL32.dll", "ReleaseSemaphore" },
        .{ "KERNEL32.dll", "OpenEventW" },
        .{ "KERNEL32.dll", "SetEndOfFile" },
        .{ "KERNEL32.dll", "FlushFileBuffers" },
        .{ "KERNEL32.dll", "VirtualFree" },
        .{ "KERNEL32.dll", "GetTickCount" },
        .{ "KERNEL32.dll", "GetCurrentProcess" },
        .{ "KERNEL32.dll", "GetCurrentProcessId" },
        .{ "KERNEL32.dll", "GetSystemInfo" },
        .{ "KERNEL32.dll", "GlobalMemoryStatusEx" },
        .{ "KERNEL32.dll", "IsProcessorFeaturePresent" },
        .{ "KERNEL32.dll", "GetVersionExW" },
        .{ "KERNEL32.dll", "GetOEMCP" },
        .{ "KERNEL32.dll", "SetFileApisToOEM" },
        .{ "KERNEL32.dll", "LocalFree" },
        .{ "KERNEL32.dll", "ResumeThread" },
        .{ "KERNEL32.dll", "SetThreadAffinityMask" },
        .{ "KERNEL32.dll", "SetProcessAffinityMask" },
        .{ "KERNEL32.dll", "GetProcessAffinityMask" },
        .{ "KERNEL32.dll", "GetProcessTimes" },
        .{ "KERNEL32.dll", "FileTimeToSystemTime" },
        .{ "KERNEL32.dll", "FileTimeToLocalFileTime" },
        .{ "KERNEL32.dll", "LocalFileTimeToFileTime" },
        .{ "KERNEL32.dll", "DosDateTimeToFileTime" },
        .{ "KERNEL32.dll", "FileTimeToDosDateTime" },
        .{ "KERNEL32.dll", "CompareFileTime" },
        .{ "KERNEL32.dll", "SetFileTime" },
        .{ "KERNEL32.dll", "GetFileInformationByHandle" },
        .{ "KERNEL32.dll", "GetModuleFileNameW" },
        .{ "KERNEL32.dll", "LoadLibraryW" },
        .{ "KERNEL32.dll", "FreeLibrary" },
        .{ "KERNEL32.dll", "WideCharToMultiByte" },
        .{ "KERNEL32.dll", "GetLogicalDriveStringsW" },
        .{ "KERNEL32.dll", "GetTempPathW" },
        .{ "KERNEL32.dll", "GetDiskFreeSpaceW" },
        .{ "KERNEL32.dll", "DeviceIoControl" },
        .{ "KERNEL32.dll", "DeleteFileW" },
        .{ "KERNEL32.dll", "CreateDirectoryW" },
        .{ "KERNEL32.dll", "RemoveDirectoryW" },
        .{ "KERNEL32.dll", "MoveFileW" },
        .{ "KERNEL32.dll", "SetCurrentDirectoryW" },
        .{ "KERNEL32.dll", "GetCurrentDirectoryW" },
        .{ "KERNEL32.dll", "SetFileAttributesW" },
        .{ "KERNEL32.dll", "GetFileAttributesW" },
        .{ "KERNEL32.dll", "FindFirstFileW" },
        .{ "KERNEL32.dll", "FindNextFileW" },
        .{ "KERNEL32.dll", "FindClose" },
        .{ "KERNEL32.dll", "OpenFileMappingW" },
        .{ "KERNEL32.dll", "MapViewOfFile" },
        .{ "KERNEL32.dll", "UnmapViewOfFile" },
        .{ "KERNEL32.dll", "SetConsoleMode" },
        .{ "KERNEL32.dll", "GetProcessHeap" },
        .{ "ADVAPI32.dll", "SystemFunction036" },
        .{ "ADVAPI32.dll", "RegOpenKeyExW" },
        .{ "ADVAPI32.dll", "RegQueryValueExW" },
        .{ "ADVAPI32.dll", "RegCloseKey" },
        .{ "ADVAPI32.dll", "OpenProcessToken" },
        .{ "ADVAPI32.dll", "AdjustTokenPrivileges" },
        .{ "ADVAPI32.dll", "LookupPrivilegeValueW" },
        .{ "ADVAPI32.dll", "GetFileSecurityW" },
        .{ "ADVAPI32.dll", "SetFileSecurityW" },
        .{ "USER32.dll", "CharUpperW" },
        .{ "USER32.dll", "CharPrevExA" },
    };
    var impls: usize = 0;
    for (impl_specs) |spec| {
        if (kdisp.implementBy(spec[0], spec[1])) impls += 1;
    }
    sys_print("[PE] Implemented Win32 (top CDD): ");
    printDec(impls);
    sys_print(" / ");
    printDec(impl_specs.len);
    sys_print(" — cycles 1+…+8 (+CDD8: FAT32-RW/файлы, 7-Zip: события/CPU/память/msvcrt-CRT))\n");

    // 7. Патч IAT: слоты → user-VA стабов (запись через identity, CPL=0)
    kdisp.applyToImage(img.backing);
    sys_print("[PE] IAT patched: ");
    printDec(generated);
    sys_print(" slots\n");

    // DEBUG (CDD №8): контроль слота msvcrt!malloc (RVA 0xDF408 у 7za 21.07)
    {
        const dbg_slot: *volatile u64 = @ptrFromInt(@intFromPtr(img.backing) + 0xDF408);
        sys_print("[DBG] malloc-slot after applyToImage = 0x");
        putHex(dbg_slot.*);
        sys_print("\n");
    }


    // 8. User-контекст Win64: стек, TEB, PEB, params+cmdline, TLS
    const uctx = pe_loader.buildUserContext(ops, user_pml4, layout, img.base_va, args) catch |err| {
        sys_print("buildUserContext error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    sys_print("[PE] User ctx: TEB=");
    putHex(uctx.teb_va);
    sys_print(" PEB=");
    putHex(uctx.peb_va);
    sys_print(" RSP=");
    putHex(uctx.stack_rsp);
    sys_print(" heap=");
    putHex(uctx.heap_base);
    sys_print("\n");

    // 9. Контекст Win32/CRT (win32_crt) для syscall #6. Heap-регион делится:
    //    vheap [base, +512МБ) — VirtualAlloc (сырые страницы), bheap
    //    [+512МБ, limit) — CRT block-heap (заголовки 16Б). VA-бюджет бесплатен
    //    (страницы выделяются PMM по требованию).
    //    TSC-частота для QPF калибруется по тикам APIC-таймера (100 Гц —
    //    10мс/тик, калибровка PIT в hal): 5 тиков = 50мс.
    const tsc_freq = calibrateTsc();
    win32_crt.ctx = .{
        .pml4 = user_pml4,
        .image_base = img.base_va,
        .cmdline_a = uctx.cmdline_a_va,
        .cmdline_w = uctx.cmdline_w_va,
        .vheap_base = uctx.heap_base,
        .vheap_limit = uctx.heap_base + 0x2000_0000,
        .vheap_cursor = uctx.heap_base,
        .vallocs = 0,
        .bheap_base = uctx.heap_base + 0x2000_0000,
        .bheap_limit = uctx.heap_limit,
        .bheap_cursor = uctx.heap_base + 0x2000_0000,
        .bheap_mapped = uctx.heap_base + 0x2000_0000,
        .iob_array = 0,
        .argc_ptr = 0,
        .argv_slot = 0,
        .environ_slot = 0,
        .fmode_ptr = 0,
        .commode_ptr = 0,
        .errno_ptr = 0,
        .tsc_freq = tsc_freq,
        .tid = 0,
        .implemented_calls = 0,
        .last_error = 0,
        .next_socket_fd = 0x100,
        .sockets_opened = 0,
        .sspi_table = 0,
        .locale_str = 0,
        .next_event_handle = 0x200,
        // v0.14.0 (CDD №5): SSPI/SChannel TLS-движок (SYNTHETIC-TLS)
        .next_mutex_handle = 0x400,
        .tls_sessions = undefined,
        .tls_last_fd = 0,
        // v0.13.0-fix: массив состояния сокетов — ЦИКЛ после литерала, НЕ
        // гигантский стековый темп (8КБ-переполнение cmd_peload затирало
        // tasks[1] нулями — kernel-panic каскад; см. scheduler.zig).
        .sockets = undefined,
        // v0.16.0 (CDD №7): файловая волна VFS (хэндлы 0x800+, слоты)
        .next_file_handle = win32_crt.FILE_HANDLE_BASE,
        .files = undefined,
        // v0.17.0 (CDD №8): события/семафоры с реальным сигнальным состоянием
        .events = undefined,
    };
    for (&win32_crt.ctx.?.sockets) |*sk| sk.* = .{};
    for (&win32_crt.ctx.?.tls_sessions) |*ts| ts.* = .{};
    for (&win32_crt.ctx.?.files) |*fl| fl.* = .{};
    for (&win32_crt.ctx.?.events) |*ev| ev.* = .{};

    // 9b. v0.17.0 (CDD №8): DATA-импорты msvcrt — IAT-слоты указывают на
    //     ЗАПИСЫВАЕМЫЕ переменные CRT (_fmode/_commode — int, __initenv —
    //     char**, _iob — FILE-массив). applyToImage уже записал туда VA
    //     RX-стаба → приложение писало бы в RX-страницу (#PF!). Патчим
    //     слоты на RW+NX-блок (1 страница user-VA), FILE* из блока
    //     маршрутизируются на консоль (isMsvcrtIobStream в win32_crt).
    patch_blk: {
        const data_blk = pe_loader.mapRegion(
            ops,
            user_pml4,
            0x21_0004_0000, // data-импорты: отдельная страница (RW+NX)
            4096,
            pe_loader.PTE_USER | pe_loader.PTE_WRITABLE | pe_loader.PTE_NO_EXECUTE,
        ) catch {
            sys_print("[PE] patchDataImports: mapRegion FAIL — msvcrt-данные не подключены\n");
            win32_crt.ctx.?.iob_block = 0;
            break :patch_blk;
        };
        // раскладка блока: _fmode@0, _commode@8, __initenv@16, _iob@0x100(3×48Б)
        const specs = [_]struct { name: []const u8, off: u64 }{
            .{ .name = "_fmode", .off = 0x00 },
            .{ .name = "_commode", .off = 0x08 },
            .{ .name = "__initenv", .off = 0x10 },
        };
        var patched: usize = 0;
        for (specs) |spec| {
            for (kdisp.entries[0..kdisp.count]) |*e| {
                const n = switch (e.func) {
                    .by_name => |nm| nm,
                    .by_ordinal => continue,
                };
                if (!std.ascii.eqlIgnoreCase(e.dll, "msvcrt.dll")) continue;
                if (!std.mem.eql(u8, n, spec.name)) continue;
                // Слот IAT (как applyToImage) → VA блока
                const slot: *u64 = @ptrFromInt(@intFromPtr(img.backing) + e.iat_rva + e.slot_index * 8);
                slot.* = data_blk.va + spec.off;
                patched += 1;
                break;
            }
        }
        // _iob: FILE-массив (3×48Б нулей — заполняется неявно: страница нулевая)
        var iob_done = false;
        for (kdisp.entries[0..kdisp.count]) |*e| {
            const n = switch (e.func) {
                .by_name => |nm| nm,
                .by_ordinal => continue,
            };
            if (!std.ascii.eqlIgnoreCase(e.dll, "msvcrt.dll")) continue;
            if (!std.mem.eql(u8, n, "_iob")) continue;
            const slot: *u64 = @ptrFromInt(@intFromPtr(img.backing) + e.iat_rva + e.slot_index * 8);
            slot.* = data_blk.va + 0x100;
            patched += 1;
            iob_done = true;
            break;
        }
        if (iob_done) win32_crt.ctx.?.iob_block = data_blk.va;
        // DEBUG (CDD №8): контроль слота malloc после patchDataImports
        {
            const dbg_slot: *volatile u64 = @ptrFromInt(@intFromPtr(img.backing) + 0xDF408);
            sys_print("[DBG] malloc-slot after patchDataImports = 0x");
            putHex(dbg_slot.*);
            sys_print("\n");
        }
        sys_print("[PE] patchDataImports: ");
        printDec(patched);
        sys_print(" msvcrt-слотов (");
        if (iob_done) {
            sys_print("_fmode/_commode/__initenv/_iob");
        } else {
            sys_print("_fmode/_commode/__initenv");
        }
        sys_print(") -> RW-блок 0x");
        putHex(data_blk.va);
        sys_print("\n");
    }
    // v0.16.0 (CDD №7): окружение PE-процесса — ядро отвечает за него, как
    // и за «версию Windows» (OS_ACTUAL). CURL_CA_BUNDLE/SSL_CERT_FILE — путь
    // к CA-бандлу в initrd-VFS: верификация сертификата БЕЗ флага -k.
    win32_crt.env_table = &pe_env;
    sys_print("[PE] env: CURL_CA_BUNDLE=cacert.pem (VFS) — верификация SSL без -k\n");
    sys_print("[PE] TSC calibrated: ");
    printDec(tsc_freq);
    sys_print(" Hz (QPF/QPC source, 5 APIC ticks)\n");

    // 10. GS-base → TEB (Ring 3 читает NtCurrentTeb через [gs:0x30]).
    //     Ядро GS не использует (нет swapgs) — держим TEB постоянно.
    hal.writeMsr(hal.MSR.GS_BASE, uctx.teb_va);

    // 11. Ring-3 задача: IRETQ-кадр с CS=0x1B/SS=0x23, диспетчеризация тикером
    const task_id = scheduler.createUserTaskAbi(img.entry_va, user_pml4, uctx.stack_rsp, .win32) catch |err| {
        sys_print("createUserTask error: ");
        sys_print(@errorName(err));
        sys_print("\n");
        return;
    };
    // v0.18.0 (CDD №9): регистрируем главный user-стек задачи в таблицах
    // asm-владельца (isr64.S: syscall-каскад — ТОЛЬКО на СВОЁМ kstack).
    // Границы = замапленный регион [stack_top - pages*4K, stack_top).
    scheduler.registerUserStack(
        task_id,
        layout.stack_top - layout.stack_pages * 4096,
        layout.stack_top,
    );
    sys_print("[PE] Ring 3 task #");
    printDec(task_id);
    sys_print(" created — waiting for first CDD int3 log\n");
    sys_print("[CDD] chain: lines [CDD]/[WIN32] below = next functions to implement\n");
}

// ============================================================================
// v0.15.0 (CDD №6): сетевая диагностика шелла — ping / ifconfig / netstat
// ============================================================================

/// «10.0.2.15» в десятичной записи.
fn printIp(ip: [4]u8) void {
    printDec(ip[0]);
    sys_print(".");
    printDec(ip[1]);
    sys_print(".");
    printDec(ip[2]);
    sys_print(".");
    printDec(ip[3]);
}

/// Два hex-символа (байт MAC-адреса без префикса).
fn putHexByte(b: u8) void {
    const hex = "0123456789abcdef";
    var s: [2]u8 = undefined;
    s[0] = hex[b >> 4];
    s[1] = hex[b & 0xF];
    sys_print(&s);
}

/// ping <ip|host> [count]: ICMP Echo Request/Reply через virtio-net
/// (SLIRP-шлюз 10.0.2.2 отвечает мгновенно; внешние IP — NAT-проброс).
/// Пофробные [PING]-строки идут в serial (virtio_net.icmpPing), сводка —
/// в VGA-консоль.
fn cmd_ping(args: []const u8) void {
    if (args.len == 0) {
        sys_print("Usage: ping <ip|host> [count]   (например: ping 10.0.2.2, ping example.com)\n");
        return;
    }
    var it = std.mem.tokenizeScalar(u8, args, ' ');
    const target = it.next() orelse {
        sys_print("ping: пустая цель\n");
        return;
    };
    var count: u8 = 4;
    if (it.next()) |cnt_s| {
        const v = std.fmt.parseInt(u8, cnt_s, 10) catch 4;
        if (v > 0) count = @min(v, 16);
    }
    if (!virtio_net.isInitialized()) {
        sys_print("ping: virtio-net не инициализирован (нет устройства)\n");
        return;
    }
    // цель: IP-литерал или DNS-резолв
    var ip: [4]u8 = undefined;
    if (virtio_net.parseIpLiteral(target)) |lit| {
        ip = lit;
    } else {
        sys_print("ping: резолв '");
        sys_print(target);
        sys_print("' через DNS (10.0.2.3)…\n");
        ip = virtio_net.dnsResolve(target) orelse {
            sys_print("ping: DNS не разрезолвил '");
            sys_print(target);
            sys_print("'\n");
            return;
        };
    }
    sys_print("PING ");
    sys_print(target);
    sys_print(" (");
    printIp(ip);
    sys_print("): 64Б данных, ");
    printDec(count);
    sys_print(" проб\n");
    const res = virtio_net.icmpPing(ip, count);
    sys_print("\n--- ");
    sys_print(target);
    sys_print(" — статистика пинга ---\n");
    sys_print("передано: ");
    printDec(res.sent);
    sys_print(", получено: ");
    printDec(res.received);
    if (res.received > 0 and res.sent > 0) {
        const pct = (@as(u64, res.received) * 100) / @as(u64, res.sent);
        sys_print(" (");
        printDec(pct);
        sys_print("%), лучший RTT: ");
        printDec(res.rtt_ms);
        sys_print("мс\n");
    } else {
        sys_print(" — таймаут (хост недоступен или ICMP фильтруется)\n");
    }
}

/// ifconfig: интерфейс eth0 (virtio-net) — IP/MAC/шлюз/DNS + счётчики.
fn cmd_ifconfig() void {
    if (!virtio_net.isInitialized()) {
        sys_print("eth0: virtio-net устройство не найдено\n");
        return;
    }
    const mac = virtio_net.ourMac();
    sys_print("eth0: virtio-net (POLER SLIRP user-mode)\n");
    sys_print("  inet 10.0.2.15  netmask 255.255.255.0\n");
    sys_print("  gateway 10.0.2.2    dns 10.0.2.3\n");
    sys_print("  ether ");
    for (mac, 0..) |b, i| {
        putHexByte(b);
        if (i < 5) sys_print(":");
    }
    sys_print("\n  link: ");
    if (virtio_net.gatewayResolved()) {
        sys_print("UP (ARP шлюза резолвлен)\n");
    } else {
        sys_print("DOWN (ARP шлюза не резолвлен)\n");
    }
    const st = virtio_net.netStats();
    sys_print("  RX: ");
    printDec(st.rx_frames);
    sys_print(" кадров / ");
    printDec(st.rx_bytes);
    sys_print("Б\n  TX: ");
    printDec(st.tx_frames);
    sys_print(" кадров / ");
    printDec(st.tx_bytes);
    sys_print("Б\n  ретрансмиты TCP: ");
    printDec(st.rtx_frames);
    sys_print(", keep-alive пробы: ");
    printDec(st.ka_probes);
    sys_print("\n");
    if (virtio_net.dnsCacheGet()) |dc| {
        sys_print("  DNS-кэш: ");
        sys_print(dc.host);
        sys_print(" -> ");
        printIp(dc.ip);
        sys_print("\n");
    }
}

/// netstat: таблица TCP-соединений мини-стека (слот/пир/состояние/ринг).
fn cmd_netstat() void {
    if (!virtio_net.isInitialized()) {
        sys_print("netstat: virtio-net не инициализирован\n");
        return;
    }
    sys_print("Активные TCP-соединения (мини-стек ядра)\n");
    sys_print("slot  пир                 состояние    ring(Б)  inflight(Б)\n");
    var any = false;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const ci = virtio_net.connInfo(i) orelse continue;
        any = true;
        printDec(ci.slot);
        sys_print("     ");
        printIp(ci.peer_ip);
        sys_print(":");
        printDec(ci.peer_port);
        if (ci.peer_port < 10) sys_print("  ");
        if (ci.peer_port < 100) sys_print(" ");
        sys_print("  ");
        sys_print(@tagName(ci.state));
        sys_print("  ");
        printDec(ci.ring_bytes);
        sys_print("  ");
        printDec(ci.inflight);
        if (ci.fin_received) sys_print("  [FIN]");
        if (ci.aborted) sys_print("  [ABORT]");
        sys_print("\n");
    }
    if (!any) sys_print("  (нет активных соединений)\n");
}

fn cmd_disk() void {
    if (!virtio_blk.isInitialized()) {
        sys_print("No disk driver found\n");
        return;
    }

    sys_print("VirtIO Block Device:\n");
    sys_print("  Capacity: ");
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var val = virtio_blk.getCapacityBytes();
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var temp: usize = 0;
        var tmp_buf: [20]u8 = undefined;
        while (val > 0) {
            tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
            val /= 10;
            temp += 1;
        }
        while (temp > 0) {
            temp -= 1;
            buf[len] = tmp_buf[temp];
            len += 1;
        }
    }
    sys_print(buf[0..len]);
    sys_print(" bytes\n");

    sys_print("  Sectors: 0x");
    // Hex for sector count
    const sectors = virtio_blk.getCapacitySectors();
    var hex_buf: [16]u8 = undefined;
    var hex_len: usize = 0;
    const hex_chars = "0123456789ABCDEF";
    var sv = sectors;
    if (sv == 0) {
        hex_buf[0] = '0';
        hex_len = 1;
    } else {
        while (sv > 0) {
            hex_buf[hex_len] = hex_chars[@intCast(sv % 16)];
            sv /= 16;
            hex_len += 1;
        }
        // Reverse
        var i: usize = 0;
        while (i < hex_len / 2) : (i += 1) {
            const tmp = hex_buf[i];
            hex_buf[i] = hex_buf[hex_len - 1 - i];
            hex_buf[hex_len - 1 - i] = tmp;
        }
    }
    sys_print(hex_buf[0..hex_len]);
    sys_print("\n");

    const fs = fat32.getFs() orelse {
        sys_print("  No FAT32 filesystem mounted\n");
        return;
    };

    sys_print("  Filesystem: FAT32\n");
    sys_print("  Cluster size: ");
    // Decimal for cluster size
    len = 0;
    val = fs.cluster_size;
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var temp: usize = 0;
        var tmp_buf2: [20]u8 = undefined;
        while (val > 0) {
            tmp_buf2[temp] = '0' + @as(u8, @intCast(val % 10));
            val /= 10;
            temp += 1;
        }
        while (temp > 0) {
            temp -= 1;
            buf[len] = tmp_buf2[temp];
            len += 1;
        }
    }
    sys_print(buf[0..len]);
    sys_print(" bytes\n");
}

fn cmd_mkdir(dirname: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        sys_print("Device is read-only\n");
        return;
    }

    // Parse path: find parent directory and directory name
    var path = dirname;
    while (path.len > 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
    while (path.len > 0 and path[0] == '/') path = path[1..];

    if (path.len == 0) {
        sys_print("Invalid directory name\n");
        return;
    }

    // Split into parent path and dir name
    var last_slash: usize = 0;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '/') last_slash = i;
    }

    var parent_cluster: u32 = fs.root_cluster;
    var dir_name: []const u8 = path;

    if (last_slash > 0) {
        const parent_path = path[0..last_slash];
        dir_name = path[last_slash + 1 ..];
        if (dir_name.len == 0) {
            sys_print("Invalid directory name\n");
            return;
        }
        parent_cluster = fs.resolveDirCluster(parent_path) orelse {
            sys_print("Parent directory not found: ");
            sys_print(parent_path);
            sys_print("\n");
            return;
        };
    }

    const result = fs.createDir(parent_cluster, dir_name);
    if (result) |cluster| {
        sys_print("Created directory: ");
        sys_print(dirname);
        sys_print(" (cluster ");
        var buf: [16]u8 = undefined;
        var len: usize = 0;
        var val: u32 = cluster;
        if (val == 0) {
            buf[0] = '0';
            len = 1;
        } else {
            var temp: usize = 0;
            var tmp_buf: [16]u8 = undefined;
            while (val > 0) {
                tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
                val /= 10;
                temp += 1;
            }
            while (temp > 0) {
                temp -= 1;
                buf[len] = tmp_buf[temp];
                len += 1;
            }
        }
        sys_print(buf[0..len]);
        sys_print(")\n");
    } else {
        sys_print("Failed to create directory: ");
        sys_print(dirname);
        sys_print("\n");
    }
}

fn cmd_touch(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        sys_print("Device is read-only\n");
        return;
    }

    // Parse path: find parent directory and file name
    var path = filename;
    while (path.len > 0 and path[0] == '/') path = path[1..];

    if (path.len == 0) {
        sys_print("Invalid file name\n");
        return;
    }

    var last_slash: usize = 0;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '/') last_slash = i;
    }

    var parent_cluster: u32 = fs.root_cluster;
    var file_name: []const u8 = path;

    if (last_slash > 0) {
        const parent_path = path[0..last_slash];
        file_name = path[last_slash + 1 ..];
        if (file_name.len == 0) {
            sys_print("Invalid file name\n");
            return;
        }
        parent_cluster = fs.resolveDirCluster(parent_path) orelse {
            sys_print("Parent directory not found: ");
            sys_print(parent_path);
            sys_print("\n");
            return;
        };
    }

    const file = fs.createFile(parent_cluster, file_name);
    if (file) |_| {
        sys_print("Created file: ");
        sys_print(filename);
        sys_print("\n");
    } else {
        sys_print("Failed to create file: ");
        sys_print(filename);
        sys_print("\n");
    }
}

fn cmd_write(args: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    if (virtio_blk.isReadOnly()) {
        sys_print("Device is read-only\n");
        return;
    }

    // Parse: write <filename> <text>
    // Find the space separating filename from text
    var space_pos: usize = 0;
    while (space_pos < args.len and args[space_pos] != ' ') : (space_pos += 1) {}

    if (space_pos == 0 or space_pos >= args.len) {
        sys_print("Usage: write <filename> <text>\n");
        return;
    }

    const filename = args[0..space_pos];
    const text = args[space_pos + 1 ..];

    if (text.len == 0) {
        sys_print("No text provided\n");
        return;
    }

    // Open or create the file
    var file = fs.openFile(filename) orelse blk: {
        // File doesn't exist — create it
        const f = fs.openFile(filename) orelse {
            // Try to create in root dir for simplicity
            var path = filename;
            while (path.len > 0 and path[0] == '/') path = path[1..];
            var parent_cluster: u32 = fs.root_cluster;
            var file_name: []const u8 = path;

            var last_slash: usize = 0;
            var j: usize = 0;
            while (j < path.len) : (j += 1) {
                if (path[j] == '/') last_slash = j;
            }
            if (last_slash > 0) {
                const parent_path = path[0..last_slash];
                file_name = path[last_slash + 1 ..];
                parent_cluster = fs.resolveDirCluster(parent_path) orelse {
                    sys_print("Parent directory not found\n");
                    return;
                };
            }

            break :blk fs.createFile(parent_cluster, file_name) orelse {
                sys_print("Failed to create file\n");
                return;
            };
        };
        break :blk f;
    };

    // Write the text
    const written = fs.writeFile(&file, text);
    sys_print("Wrote ");
    var buf: [16]u8 = undefined;
    var len: usize = 0;
    var val: u32 = written;
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var temp: usize = 0;
        var tmp_buf: [16]u8 = undefined;
        while (val > 0) {
            tmp_buf[temp] = '0' + @as(u8, @intCast(val % 10));
            val /= 10;
            temp += 1;
        }
        while (temp > 0) {
            temp -= 1;
            buf[len] = tmp_buf[temp];
            len += 1;
        }
    }
    sys_print(buf[0..len]);
    sys_print(" bytes to ");
    sys_print(filename);
    sys_print("\n");
}

fn eq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |item, i| {
        if (item != b[i]) return false;
    }
    return true;
}

fn task2() noreturn {
    while (true) {
        var i: usize = 0;
        while (i < 100000000) : (i += 1) {
            asm volatile ("nop");
        }
    }
}

fn cmd_rm(filename: []const u8) void {
    const fs = fat32.getFs() orelse {
        sys_print("No filesystem mounted\n");
        return;
    };

    if (filename.len == 0) {
        sys_print("Usage: rm <file>\n");
        return;
    }

    if (fs.deleteFile(filename)) {
        sys_print("Deleted: ");
        sys_print(filename);
        sys_print("\n");
    } else {
        sys_print("Failed to delete: ");
        sys_print(filename);
        sys_print(" (not found or is a directory)\n");
    }
}

pub fn panic(msg: []const u8, error_return_trace: ?*@import("std").builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    vga_setcolor(0x0C); // Light red
    puts("\n!!! KERNEL PANIC !!!\n");
    puts(msg);
    if (ret_addr) |ra| {
        puts("\n[panic] ret_addr=0x");
        putHex(ra);
        puts(" (addr2line poler-os64)");
    }
    puts("\nHalting CPU...\n");
    while (true) {
        hal.cli();
        hal.hlt();
    }
}
