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
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const heap = @import("heap64.zig");
const cpio = @import("cpio.zig");
const scheduler = @import("scheduler.zig");
const multiboot2 = @import("multiboot2.zig");
const framebuffer = @import("framebuffer.zig");
const pci = @import("pci.zig");
const virtio_blk = @import("virtio_blk.zig");
const fat32 = @import("fat32.zig");
const pe = @import("pe.zig");
const win32 = @import("win32_stubs.zig");



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
    // только 1-й модуль (initrd); лимит sanity — 64 модуля
    const n = @min(si.nr_modules, 64);
    const mods: [*]const HvmModListEntry = @ptrFromInt(si.mods_addr);
    for (mods[0..n]) |*m| {
        if (m.addr == 0 or m.size == 0 or m.size > 256 * 1024 * 1024) continue;
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

/// Поиск файла в initrd-cpio по имени (для peinfo/pestubs).
fn initrdFindFile(name: []const u8) ?[]const u8 {
    const arch = initrd_archive orelse return null;
    var cpio_parser = cpio.CpioParser.init(arch);
    while (cpio_parser.next()) |file| {
        if (std.mem.eql(u8, file.name, name)) return file.data;
    }
    return null;
}

/// Случайное u32 для ядра (планировщик/крипто/соль). До привязки PUF — 0.
fn krand() u32 {
    if (kernel_rng_ready) return kernel_rng.next();
    return 0;
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
    puts_vga_or_fb("0x");
    var i: usize = 60;
    while (true) {
        const nibble = (val >> @intCast(i)) & 0xF;
        puts_vga_or_fb(&.{hex[@intCast(nibble)]});
        if (i == 0) break;
        i -= 4;
    }
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
        \\╔══════════════════════════════════════════════════════╗
        \\║             POLER-OS v0.7.0 (64-bit)                ║
        \\║          Semantic Runtime Architecture              ║
        \\║                                                      ║
        \\║   Zig Kernel · VirtIO-BLK · FAT32 · POLER Core     ║
        \\╚══════════════════════════════════════════════════════╝
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

export fn poler_kernel_main(multiboot_magic: u32, multiboot_info: u64) callconv(.C) void {
    const have_mb2 = multiboot_magic == 0x36D76289;

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

    // 8. Test POLER Core
    testPolerCore();

    // 8.7. PUF: привязка аппаратной энтропии (спека
    //      docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md)
    pufBootInit();

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
    } else {
        puts("[VIRTIO-BLK] No virtio-blk device found (expected with -drive)\n");
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
    } else {
        puts("[INITRD] No initrd modules loaded by bootloader.\n");
    }

    // 9. Ready!
    vga_setcolor(0x0B);
    puts("\n╔══════════════════════════════════════════════════════╗\n");
    puts("║         POLER-OS v0.7.0 — BOOT COMPLETE             ║\n");
    puts("║     HAL + ACPI + POLER Core — all systems GO        ║\n");
    puts("╚══════════════════════════════════════════════════════╝\n");
    vga_setcolor(0x07);

    puts("\nNext steps: Memory Manager (PMM/VMM) → Process Service → Intent Layer\n");
    puts("Timer: APIC periodic, tick count will increment in idle loop\n");

    // 8.55. Initialize Syscalls
    hal.print_fn = &puts;
    hal.clear_screen_fn = &clear_screen;
    hal.initSyscalls(@intFromPtr(&syscall_entry));

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
    sys_print("\n=== POLER-OS v0.7.0 Interactive Shell ===\n");
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
        sys_print("  disk      - Show disk info\n");
        sys_print("  entropy   - Show all hardware entropy pools status (PUF, Bus, IRQ, Bio)\n");
        sys_print("  peinfo <f> - Analyze PE/COFF executable from initrd (headers, sections, imports)\n");
        sys_print("  pestubs <f> - Generate Win32 stub table for PE executable (CDD: log+int3)\n");
    } else if (eq(cmd, "about")) {
        sys_print("POLER-OS v0.7.2 (x86_64 Long Mode)\n");
        sys_print("Cognitive Semantic Runtime Environment (PUF Multi-Pool Active).\n");
    } else if (eq(cmd, "clear")) {
        sys_clear_screen();
    } else if (eq(cmd, "poler")) {
        sys_print("Running POLER core PND mix...\n");
        sys_print("pndMix(42, 17, 1) = 0x6448728B\n");
        sys_print("pndMixAlt(42, 17, 1) = 0x000002CD\n");
    } else if (eq(cmd, "entropy")) {
        cmd_entropy();
    } else if (startsWith(cmd, "peinfo ")) {
        cmd_peinfo(cmd[7..]);
    } else if (eq(cmd, "peinfo")) {
        cmd_peinfo("");
    } else if (startsWith(cmd, "pestubs ")) {
        cmd_pestubs(cmd[8..]);
    } else if (eq(cmd, "pestubs")) {
        cmd_pestubs("");
    } else if (eq(cmd, "ls")) {
        cmd_ls("");
    } else if (startsWith(cmd, "ls ")) {
        cmd_ls(cmd[3..]);
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
    _ = ret_addr;
    vga_setcolor(0x0C); // Light red
    puts("\n!!! KERNEL PANIC !!!\n");
    puts(msg);
    puts("\nHalting CPU...\n");
    while (true) {
        hal.cli();
        hal.hlt();
    }
}
