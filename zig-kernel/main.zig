// POLER-OS Kernel Main — Zig 0.13 x86_64 freestanding
// This is the entry point after boot.zig transitions to long mode
// Kernel loaded at 0x100000 (1MB mark)

const std = @import("std");
const vga = @import("drivers/vga.zig");
const idt = @import("arch/x86_64/idt.zig");
const mm = @import("mm/pmm.zig");

// Kernel entry point — called from boot.zig in 64-bit long mode
pub export fn kernel_main() callconv(.c) noreturn {
    // 1. Initialize VGA text buffer (0xB8000)
    vga.init();
    vga.setColor(vga.Color.White, vga.Color.Black);
    vga.clear();
    
    // 2. Print POLER-OS banner
    vga.print("╔══════════════════════════════════════╗\n");
    vga.print("║         POLER-OS v0.1.0              ║\n");
    vga.print("║    Zig Kernel + Rust Safety Core     ║\n");
    vga.print("║    LLM Operating System              ║\n");
    vga.print("╚══════════════════════════════════════╝\n\n");
    
    vga.print("[BOOT] Entered long mode at 0x100000\n");
    vga.print("[BOOT] Initializing IDT...\n");
    
    // 3. Set up Interrupt Descriptor Table
    idt.init();
    vga.print("[BOOT] IDT loaded\n");
    
    // 4. Initialize Physical Memory Manager
    vga.print("[BOOT] Scanning memory map...\n");
    mm.init();
    vga.print("[BOOT] PMM initialized\n");
    
    // 5. Hand off to Rust safety core
    vga.print("[BOOT] Loading Rust safety core...\n");
    // rust_core_entry() is defined in Rust and linked via Zig
    // const rust_entry = @extern(*const fn() callconv(.c) void, .{ .name = "rust_core_entry" });
    // rust_entry();
    
    vga.print("[BOOT] POLER-OS kernel idle\n");
    
    // Halt loop
    while (true) {
        asm volatile ("hlt");
    }
}

// Panic handler — required for freestanding
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    vga.setColor(vga.Color.Red, vga.Color.Black);
    vga.print("KERNEL PANIC: ");
    vga.print(msg);
    vga.print("\nSystem halted.\n");
    while (true) {
        asm volatile ("hlt");
    }
}
