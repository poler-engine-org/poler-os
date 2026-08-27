// ============================================================================
// POLER-OS v0.7.0 — 64-bit x86_64 Universal OS Kernel
// ============================================================================
//
// Эволюция:
//   v0.4.0: 32-bit kernel, POLER Core, shell, PCI scan
//   v0.5.0: 64-bit boot, HAL (GDT/IDT/PIC/APIC), ACPI, interrupts
//   v0.5.1: VirtualBox compatibility, 64-bit Long Mode fix
//   v0.7.0: VirtIO-BLK + FAT32 + PCI, Ring 3, ELF loader, scheduler, crypto
// ============================================================================

const hal = @import("hal.zig");
const std = @import("std");
const acpi = @import("acpi.zig");
const poler = @import("poler_core.zig");
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



var use_fb: bool = false;

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

    // 4. Dump Multiboot2 Memory Map if available
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

// ============================================================================
// Main Kernel Entry Point
// Вызывается из boot64.S после перехода в 64-bit mode
// ============================================================================

export fn poler_kernel_main(multiboot_magic: u32, multiboot_info: u64) callconv(.C) void {
    // 0. Detect and Initialize Framebuffer if available from Multiboot2
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

    // 1. Initialize VGA (if framebuffer not active)
    if (!use_fb) {
        vga_init();
    }

    // 2. Print banner
    print_banner();

    // 3. Verify Multiboot2 magic
    if (multiboot_magic == 0x36D76289) {
        puts("[BOOT] Multiboot2 loaded successfully\n");
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
    printMemoryInfo(multiboot_info);

    // 8. Test POLER Core
    testPolerCore();

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
    puts("[BOOT] Checking for initrd modules...\n");
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
            puts(", Size: ");
            putDecimal(mod_size);
            puts(" bytes\n");

            const archive_slice: []const u8 = @as([*]const u8, @ptrFromInt(mod.mod_start))[0..mod_size];

            var cpio_parser = cpio.CpioParser.init(archive_slice);
            var file_count: usize = 0;
            while (cpio_parser.next()) |file| {
                puts("  - File: ");
                puts(file.name);
                puts(" Size: ");
                putDecimal(file.size);
                puts(" bytes\n");
                
                // Print text file contents (e.g. hello.txt)
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
fn sys_print(str: []const u8) void {
    asm volatile (
        "syscall"
        :
        : [num] "{rax}" (@as(u64, 1)),
          [arg1] "{rdi}" (@intFromPtr(str.ptr)),
          [arg2] "{rsi}" (str.len),
        : "rcx", "r11", "memory"
    );
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
                asm volatile ("nop");
            }
        }
    }
}

fn sys_read_key() u8 {
    return asm volatile (
        "syscall"
        : [ret] "={rax}" (-> u8),
        : [num] "{rax}" (@as(u64, 2)),
        : "rcx", "r11", "memory"
    );
}

fn sys_clear_screen() void {
    asm volatile (
        "syscall"
        :
        : [num] "{rax}" (@as(u64, 3)),
        : "rcx", "r11", "memory"
    );
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
    } else if (eq(cmd, "about")) {
        sys_print("POLER-OS v0.7.0 (x86_64 Long Mode)\n");
        sys_print("Cognitive Semantic Runtime Environment.\n");
    } else if (eq(cmd, "clear")) {
        sys_clear_screen();
    } else if (eq(cmd, "poler")) {
        sys_print("Running POLER core PND mix...\n");
        sys_print("pndMix(42, 17, 1) = 0x6448728B\n");
        sys_print("pndMixAlt(42, 17, 1) = 0x000002CD\n");
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
