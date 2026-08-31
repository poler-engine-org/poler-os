// ============================================================================
// POLER-OS HAL (Hardware Abstraction Layer) — x86_64
// ============================================================================
// ISR stubs: isr64.S (assembly) → isr_common_handler() (this file)

// Timer tick callback — registered by scheduler at init
// Breaks circular dependency: hal.zig ↔ scheduler.zig
pub var timerTickCallback: ?*const fn (u64) callconv(.C) u64 = null;

// Multi-pool hardware entropy callbacks (Spec §1-2)
pub var irq_entropy_sink: ?*const fn (u64) void = null; // IRQ pool (APIC timer / hardware interrupt intervals)
pub var bio_entropy_sink: ?*const fn (u64) void = null; // Bio pool (keystroke interval bio-dynamics)

// Simple spinlock for protecting shared resources (e.g. serial output)
pub var serial_lock: u32 = 0;

pub fn spinLock(lock: *u32) void {
    while (@atomicRmw(u32, lock, .Xchg, 1, .acquire) != 0) {
        asm volatile ("pause");
    }
}

pub fn spinUnlock(lock: *u32) void {
    _ = @atomicRmw(u32, lock, .Xchg, 0, .release);
}
// ============================================================================

// No std import — freestanding kernel

// ============================================================================
// CPU INSTRUCTIONS
// ============================================================================

pub fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outw(port: u16, val: u16) void {
    asm volatile ("outw %[val], %[port]"
        :
        : [val] "{ax}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "{dx}" (port),
    );
}

pub fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

pub fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

pub fn cli() void {
    asm volatile ("cli");
}

pub fn sti() void {
    asm volatile ("sti");
}

pub fn hlt() void {
    asm volatile ("hlt");
}

pub fn ltr(selector: u16) void {
    asm volatile ("ltr %[sel]"
        :
        : [sel] "{ax}" (selector),
    );
}

pub fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn writeCr3(val: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (val),
        : "memory"
    );
}

pub fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub fn writeMsr(msr: u32, val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(val))),
          [high] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

// ============================================================================
// MSR Constants
// ============================================================================

pub const MSR = struct {
    pub const EFER = 0xC0000080;
    pub const STAR = 0xC0000081;
    pub const LSTAR = 0xC0000082;
    pub const CSTAR = 0xC0000083;
    pub const SFMASK = 0xC0000084;
    pub const FS_BASE = 0xC0000100;
    pub const GS_BASE = 0xC0000101;
    pub const KERNEL_GS_BASE = 0xC0000102;
};

pub const EFER = struct {
    pub const SCE = 1 << 0;  // System Call Extensions
    pub const LME = 1 << 8;  // Long Mode Enable
    pub const LMA = 1 << 10; // Long Mode Active
    pub const NXE = 1 << 11; // No-Execute Enable
};

// ============================================================================
// GDT (Global Descriptor Table)
// ============================================================================

pub const GDT = struct {
    pub const Entry = packed struct {
        limit_low: u16,
        base_low: u24,
        type: u4,
        s: u1,
        dpl: u2,
        p: u1,
        limit_high: u4,
        avl: u1,
        l: u1,
        d: u1,
        g: u1,
        base_high: u8,
    };

    pub const Ptr = packed struct {
        limit: u16,
        base: u64,
    };

    pub const TSSDesc = packed struct {
        low: u64,
        high: u64,
    };

    pub const NUM_ENTRIES = 7; // null + kcode + kdata + ucode + udata + tss_low + tss_high

    var entries: [NUM_ENTRIES]u64 = undefined;
    var ptr: Ptr = undefined;

    pub fn init() void {
        Serial.puts("[GDT] entries address: ");
        Serial.putHex(@intFromPtr(&entries));
        Serial.puts("\n");

        // Entry 0: Null
        entries[0] = 0;

        // Entry 1: 64-bit Kernel Code (ring 0) — matches GRUB's CS=0x08
        entries[1] = 0x00209A0000000000;

        // Entry 2: 64-bit Kernel Data (ring 0) — matches GRUB's DS=0x10
        // sysretq bypasses DPL checks, so SS=0x13 (0x10|RPL3) works even with DPL=0.
        entries[2] = 0x0000920000000000;

        // Entry 3: 64-bit User Code (ring 3)
        // sysretq CS = STAR[32:47]+16 | RPL3 = 0x18 | 3 = 0x1B
        // CRITICAL: Entry 3 MUST be User Code (not User Data) because
        // sysretq computes CS.selector = STAR[32:47]+16, which points here.
        entries[3] = 0x0020FA0000000000;

        // Entry 4: 64-bit User Data (ring 3)
        // Used by IRETQ for SS = 0x20 | 3 = 0x23
        entries[4] = 0x0000F20000000000;

        // Entries 5-6: TSS (filled by setTSS)
        entries[5] = 0;
        entries[6] = 0;

        // Load our GDT — GRUB's selectors (0x08, 0x10) are compatible
        var gdt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u64) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        gdt_ptr[0] = @truncate(limit);
        gdt_ptr[1] = @truncate(limit >> 8);
        gdt_ptr[2] = @truncate(base);
        gdt_ptr[3] = @truncate(base >> 8);
        gdt_ptr[4] = @truncate(base >> 16);
        gdt_ptr[5] = @truncate(base >> 24);
        gdt_ptr[6] = @truncate(base >> 32);
        gdt_ptr[7] = @truncate(base >> 40);
        gdt_ptr[8] = @truncate(base >> 48);
        gdt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lgdt (%[p])"
            :
            : [p] "r" (@intFromPtr(&gdt_ptr)),
        );

        // DON'T reload segment registers — GRUB already set them correctly
        // and our GDT layout matches GRUB's (0x08=code, 0x10=data).
        // Reloading DS/SS with 0x10 is safe but unnecessary.
    }

    pub fn setTSS(cpu: u32, base: u64, limit: u64) void {
        _ = cpu;
        const entry_idx: usize = 5; // TSS starts at entry 5

        const base_low = base & 0xFFFFFF;
        const base_mid = (base >> 24) & 0xFF;
        const base_high = (base >> 32) & 0xFFFFFFFF;

        // TSS low 8 bytes
        entries[entry_idx] = (limit & 0xFFFF) |
            ((base_low & 0xFFFFFF) << 16) |
            (0x89 << 40) | // Present, TSS type
            ((limit >> 16) << 48) |
            (@as(u64, base_mid) << 56);

        // TSS high 8 bytes
        entries[entry_idx + 1] = base_high;
    }
};

// ============================================================================
// IDT (Interrupt Descriptor Table)
// ============================================================================

pub const InterruptFrame = packed struct {
    r15: u64, r14: u64, r13: u64, r12: u64,
    r11: u64, r10: u64, r9: u64, r8: u64,
    rdi: u64, rsi: u64, rbp: u64,
    rdx: u64, rcx: u64, rbx: u64, rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64, cs: u64, rflags: u64, rsp: u64, ss: u64,
};

const GateType = enum(u4) {
    interrupt = 0xE,
    trap = 0xF,
};

pub const IDT = struct {
    pub const NUM_ENTRIES = 256;

    pub var entries: [NUM_ENTRIES]u128 = undefined;
    var ptr: packed struct { limit: u16, base: u64 } = undefined;

    // ISR stub table — linker-provided bounds of .rodata.isr_table section
    // LLD may resolve isr_stub_table to the wrong address, so we use
    // linker symbols __isr_table_start / __isr_table_end instead.
    pub extern const __isr_table_start: u8;
    pub extern const __isr_table_end: u8;

    pub fn init() void {
        // Read the ISR table from the linker-defined section bounds
        const table_start: u64 = @intFromPtr(&__isr_table_start);
        const table_end: u64 = @intFromPtr(&__isr_table_end);
        const num_entries = (table_end - table_start) / 8;

        for (0..num_entries) |i| {
            const ptr_arr: [*]const u64 = @ptrFromInt(table_start);
            const handler: u64 = ptr_arr[i];
            if (handler > 0x100000 and i < 49) {
                const dpl: u8 = if (i == 3) 3 else 0;
                // v0.7.0: Use IST1 for Double Fault (vector 8)
                const ist: u3 = if (i == 8) 1 else 0;
                setGate(@intCast(i), .interrupt, handler, 0x08, dpl, ist);
            }
        }

        // Load IDT using raw 10-byte descriptor (2 bytes limit + 8 bytes base)
        var idt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u128) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        // Little-endian: limit (2 bytes) then base (8 bytes)
        idt_ptr[0] = @truncate(limit);
        idt_ptr[1] = @truncate(limit >> 8);
        idt_ptr[2] = @truncate(base);
        idt_ptr[3] = @truncate(base >> 8);
        idt_ptr[4] = @truncate(base >> 16);
        idt_ptr[5] = @truncate(base >> 24);
        idt_ptr[6] = @truncate(base >> 32);
        idt_ptr[7] = @truncate(base >> 40);
        idt_ptr[8] = @truncate(base >> 48);
        idt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lidt (%[p])"
            :
            : [p] "r" (@intFromPtr(&idt_ptr)),
        );
    }

    fn setGate(vector: u8, gate_type: GateType, handler: u64, selector: u16, dpl: u8, ist: u3) void {
        const low: u64 =
            (handler & 0x0000FFFF) | // Offset low
            (@as(u64, selector) << 16) | // Selector
            (@as(u64, ist) << 32) | // IST (v0.7.0: IST1 for #DF)
            (@as(u64, @intFromEnum(gate_type)) << 40) | // Type
            (@as(u64, dpl) << 45) | // DPL
            (@as(u64, 1) << 47) | // Present
            ((handler >> 16) & 0xFFFF) << 48; // Offset mid

        const high: u64 = handler >> 32; // Offset high

        entries[vector] = (@as(u128, high) << 64) | @as(u128, low);
    }
};

/// Idle loop for after a user-mode fault.
/// When a user process causes a CPU exception (e.g., page fault, GP fault),
/// the exception handler kills the task and redirects IRETQ here.
/// This function simply halts the CPU and waits for the next interrupt
/// (APIC timer tick), which will trigger the scheduler to pick a Ready task.
pub fn idle_after_fault() callconv(.C) noreturn {
    while (true) {
        hlt();
    }
}

// ============================================================================
// ISR Common Handler — called from isr64.S isr_common
// ============================================================================

pub export fn isr_common_handler(frame: *InterruptFrame) callconv(.C) *InterruptFrame {
    if (frame.vector < 32) {
        handleException(frame);
        return frame;
    } else {
        return handleIRQ(frame);
    }
}

pub var tick_count: u64 = 0;

fn handleIRQ(frame: *InterruptFrame) *InterruptFrame {
    var next_frame = frame;

    // CRITICAL: Send APIC EOI BEFORE scheduler callback.
    // If we don't, the APIC won't deliver the next timer interrupt,
    // and the system hangs after the first context switch.
    if (frame.vector >= 48 and APIC.base_addr != 0) {
        APIC.sendEOI();
    }

    // Also send APIC EOI for PIC vectors if APIC is active
    if (APIC.base_addr != 0 and frame.vector >= 32 and frame.vector < 48) {
        APIC.sendEOI();
    }

    // Send PIC EOI for hardware interrupts (IRQ0-15 = vectors 32-47)
    if (frame.vector >= 32 and frame.vector < 48) {
        PIC.sendEOI(@intCast(frame.vector - 32));
    }

    const irq_tsc = readMsr(0x10);
    if (irq_entropy_sink) |sink| {
        sink(irq_tsc ^ (@as(u64, frame.vector) << 32));
    }

    switch (frame.vector) {
        48 => {
            // APIC Timer tick — scheduler preemption
            tick_count += 1;
            // DEBUG: first tick confirmation
            if (tick_count == 1) {
                Serial.puts("[HAL] First APIC timer tick received!\n");
            }
            if (timerTickCallback) |cb| {
                next_frame = @ptrFromInt(cb(@intFromPtr(frame)));
            }
        },
        33 => {
            if (bio_entropy_sink) |bio_sink| {
                const kbd_tsc = readMsr(0x10);
                bio_sink(kbd_tsc ^ (@as(u64, inb(0x60)) << 48));
            }
            handleKeyboard(frame);
        },
        36 => handleSerial(frame),
        else => {}, // Unknown interrupt — ignore for now
    }
    
    return next_frame;
}

fn handleException(frame: *InterruptFrame) void {
    // v0.7.0: Differentiate user-mode vs kernel-mode exceptions
    const from_user = (frame.cs & 0x3) != 0;

    Serial.puts("\n!!! CPU EXCEPTION !!!\n");
    Serial.puts("Vector: ");
    Serial.putHex(frame.vector);
    Serial.puts("\nError Code: ");
    Serial.putHex(frame.error_code);
    Serial.puts("\nRIP: ");
    Serial.putHex(frame.rip);
    Serial.puts("\nCS: ");
    Serial.putHex(frame.cs);
    Serial.puts("\nRFLAGS: ");
    Serial.putHex(frame.rflags);
    Serial.puts("\nRSP: ");
    Serial.putHex(frame.rsp);
    Serial.puts("\nSS: ");
    Serial.putHex(frame.ss);

    if (from_user) {
        // User-mode exception — kill the offending process instead of kernel panic
        Serial.puts("\n[EXCEPTION] Ring 3 fault! Killing user process.\n");
        // Kill the current task via the exit callback (same mechanism as syscall exit)
        if (exitCallback) |cb| {
            cb();
        }
        // After killing, we can't return to the faulting user code.
        // Modify the interrupt frame to point to a safe idle loop in Ring 0
        // so IRETQ returns to kernel idle code instead of the dead user task.
        // The scheduler will pick a Ready task on the next tick.
        frame.rip = @intFromPtr(&idle_after_fault);
        frame.cs = 0x08; // Kernel code segment
        frame.ss = 0x10; // Kernel data segment
        frame.rflags = 0x202; // IF set
        // Use the idle task's kernel stack for safety
        frame.rsp = 0x10b000; // Boot stack top
        Serial.puts("[EXCEPTION] User process killed. Returning to idle.\n");
    } else {
        // Kernel-mode exception — fatal, halt
        Serial.puts("\n[EXCEPTION] Kernel fault! Halting CPU...\n");
        while (true) {
            cli();
            hlt();
        }
    }
}

fn handleTimer(frame: *InterruptFrame) void {
    _ = frame;
    tick_count += 1;
}

fn handleKeyboard(frame: *InterruptFrame) void {
    _ = frame;
    const scan = inb(0x60);

    // Debug: show raw scancode on serial (helps diagnose translation issues)
    Serial.puts("[KBD] scan=0x");
    Serial.putHex(scan);
    Serial.puts("\n");

    // Extended key prefix
    if (scan == 0xE0) {
        kbd_extended = true;
        return;
    }

    // Key release (bit 7 set)
    if (scan & 0x80 != 0) {
        const released = scan & 0x7F;
        if (released == 0x2A or released == 0x36) kbd_shift = false;
        if (released == 0x1D) kbd_ctrl = false;
        if (released == 0x38) kbd_alt = false;
        kbd_extended = false;
        return;
    }

    // Extended key handling
    if (kbd_extended) {
        kbd_extended = false;
        // Arrow keys
        if (scan == 0x48) kbd_push(0x11); // Up
        if (scan == 0x50) kbd_push(0x12); // Down
        if (scan == 0x4B) kbd_push(0x13); // Left
        if (scan == 0x4D) kbd_push(0x14); // Right
        return;
    }

    // Modifier keys
    if (scan == 0x2A or scan == 0x36) { kbd_shift = true; return; }
    if (scan == 0x1D) { kbd_ctrl = true; return; }
    if (scan == 0x38) { kbd_alt = true; return; }

    // Convert scan code to ASCII
    if (scan < 128) {
        if (kbd_ctrl and scan == 0x2E) { kbd_push(0x03); return; } // Ctrl-C
        if (kbd_ctrl and scan == 0x15) { kbd_push(0x18); return; } // Ctrl-X
        if (kbd_ctrl and scan == 0x31) { kbd_push(0x1A); return; } // Ctrl-Z
        const ch = if (kbd_shift) scan_to_ascii_shift[scan] else scan_to_ascii[scan];
        if (ch != 0) {
            kbd_push(ch);
        }
    }
}

fn handleSerial(frame: *InterruptFrame) void {
    _ = frame;
    // TODO: Serial port interrupt handler
}

// ============================================================================
// PIC (8259 Programmable Interrupt Controller)
// ============================================================================

pub const PIC = struct {
    const PIC1_CMD: u16 = 0x20;
    const PIC1_DATA: u16 = 0x21;
    const PIC2_CMD: u16 = 0xA0;
    const PIC2_DATA: u16 = 0xA1;

    const ICW1_ICW4: u8 = 0x01;
    const ICW1_INIT: u8 = 0x10;
    const ICW4_8086: u8 = 0x01;

    pub fn init() void {
        // Remap PIC: IRQ 0-15 → INT 32-47

        // ICW1: Init + ICW4 needed
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);

        // ICW2: Vector offsets
        outb(PIC1_DATA, 32); // Master: IRQ 0-7 → INT 32-39
        outb(PIC2_DATA, 40); // Slave:  IRQ 8-15 → INT 40-47

        // ICW3: Wiring
        outb(PIC1_DATA, 0x04); // Master: slave on IRQ2
        outb(PIC2_DATA, 0x02); // Slave: identity

        // ICW4: 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        outb(PIC2_DATA, ICW4_8086);

        // Mask all PIC interrupts — we use APIC timer (vector 32)
        // and IO-APIC for keyboard. Only unmask IRQ1 (keyboard) as fallback.
        // IRQ0 (PIT) is masked because APIC timer replaces it.
        outb(PIC1_DATA, 0xFD); // Mask all except IRQ1 (keyboard)
        outb(PIC2_DATA, 0xFF); // Mask all slave
    }

    pub fn sendEOI(irq: u8) void {
        if (irq >= 8) {
            outb(PIC2_CMD, 0x20); // EOI to slave
        }
        outb(PIC1_CMD, 0x20); // EOI to master
    }
};

// ============================================================================
// Programmable Interval Timer (PIT) — Calibration helper
// ============================================================================
pub const PIT = struct {
    const CH2_DATA: u16 = 0x42;
    const CMD: u16 = 0x43;
    const GATE: u16 = 0x61;

    /// Калибровка через PIT channel 2 (метод из OSDev, без побочных IRQ).
    /// Возвращает число APIC-тиков за calibration_ms миллисекунд.
    pub fn calibrateApicTicks(comptime calibration_ms: u32) u32 {
        // PIT работает на 1.193182 MHz
        const pit_freq: u32 = 1193182;
        const pit_count: u32 = pit_freq / (1000 / calibration_ms);

        // Включаем gate PIT ch2, отключаем спикер-выход
        const gate_val = inb(GATE);
        outb(GATE, (gate_val & 0xFC) | 0x01);

        // Mode 0 (one-shot), channel 2, lobyte/hibyte
        outb(CMD, 0b10110000);
        outb(CH2_DATA, @truncate(pit_count));
        outb(CH2_DATA, @truncate(pit_count >> 8));

        // Взводим APIC-таймер на максимум и засекаем сколько он "проедет"
        APIC.writeReg(APIC.REG_TIMER_DIV, APIC.DIV_BY_16);
        APIC.writeReg(APIC.REG_TIMER_INIT, 0xFFFFFFFF);

        // Ждём пока PIT ch2 (OUT, бит 5 порта 0x61) досчитает до 0
        while ((inb(GATE) & 0x20) == 0) {}

        const remaining = APIC.readReg(APIC.REG_TIMER_CURRENT);
        return 0xFFFFFFFF - remaining; // тиков APIC за calibration_ms
    }
};

// ============================================================================
// Local APIC
// Local APIC
// ============================================================================

pub const APIC = struct {
    pub const BASE_MSR = 0x0000001B;
    pub const DEFAULT_PHYS_BASE: u64 = 0xFEE00000;

    pub const REG_ID = 0x020;
    pub const REG_VERSION = 0x030;
    pub const REG_TPR = 0x080;
    pub const REG_EOI = 0x0B0;
    pub const REG_SVR = 0x0F0;
    pub const REG_ICR_LOW = 0x300;
    pub const REG_ICR_HIGH = 0x310;
    pub const REG_LVT_TIMER = 0x320;
    pub const REG_LVT_ERROR = 0x370;
    pub const REG_TIMER_INIT = 0x380;
    pub const REG_TIMER_CURRENT = 0x390;
    pub const REG_TIMER_DIV = 0x3E0;

    pub const SVR_APIC_ENABLE: u32 = 1 << 8;
    pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
    pub const LVT_MASKED: u32 = 1 << 16;
    pub const DIV_BY_16: u32 = 0x03;

    var base_addr: u64 = 0;

    pub fn init() void {
        Serial.puts("[APIC] Reading MSR 0x1B...\n");
        const msr_val = readMsr(BASE_MSR);
        Serial.puts("[APIC] MSR value: ");
        Serial.putHex(msr_val);
        Serial.puts("\n");

        base_addr = msr_val & 0xFFFFFF000;
        Serial.puts("[APIC] Base addr: ");
        Serial.putHex(base_addr);
        Serial.puts("\n");

        // Если APIC глобально выключен — включаем
        if ((msr_val & (1 << 11)) == 0) {
            Serial.puts("[APIC] Enabling APIC...\n");
            writeMsr(BASE_MSR, msr_val | (1 << 11));
        } else {
            Serial.puts("[APIC] APIC already enabled\n");
        }

        // Set Spurious Interrupt Vector Register
        Serial.puts("[APIC] Setting SVR...\n");
        writeReg(REG_SVR, SVR_APIC_ENABLE | 0xFF);

        // Set up timer
        Serial.puts("[APIC] Setting timer...\n");
        writeReg(REG_LVT_TIMER, 48 | LVT_TIMER_PERIODIC); // Vector 48 — avoids PIC IRQ0-15 conflict
        writeReg(REG_TIMER_DIV, DIV_BY_16);

        // Калибровка: считаем сколько APIC-тиков в 10мс, целимся в 100 Гц context-switch
        const ticks_per_10ms = PIT.calibrateApicTicks(10);
        writeReg(REG_TIMER_INIT, ticks_per_10ms);

        // Mask error LVT
        writeReg(REG_LVT_ERROR, LVT_MASKED);
        Serial.puts("[APIC] Timer configured via PIT calibration\n");
    }

    pub fn writeReg(offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        ptr.* = val;
    }

    pub fn readReg(offset: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        return ptr.*;
    }

    pub fn sendEOI() void {
        writeReg(REG_EOI, 0);
    }

    pub fn getId() u32 {
        return readReg(REG_ID) >> 24;
    }
};

// ============================================================================
// IO-APIC (I/O Advanced Programmable Interrupt Controller)
// ============================================================================
pub const IOAPIC = struct {
    const BASE_ADDR: u64 = 0xFEC00000;
    const REG_SEL: *volatile u32 = @ptrFromInt(BASE_ADDR);
    const REG_WIN: *volatile u32 = @ptrFromInt(BASE_ADDR + 0x10);

    pub fn write(reg: u32, val: u32) void {
        REG_SEL.* = reg;
        REG_WIN.* = val;
    }

    pub fn read(reg: u32) u32 {
        REG_SEL.* = reg;
        return REG_WIN.*;
    }

    pub fn init() void {
        // Redirection table entry for Keyboard (IRQ 1) -> Vector 33
        // 0x12: redirection register for IRQ1 low 32 bits (vector 33, active high, edge triggered)
        // 0x13: redirection register for IRQ1 high 32 bits (destination APIC ID 0)
        write(0x12, 33);
        write(0x13, 0);
        Serial.puts("[IOAPIC] Keyboard redirection configured (IRQ1 -> Vector 33)\n");
    }
};

// ============================================================================
// PS/2 Keyboard Driver & Buffer
// ============================================================================
var kbd_shift: bool = false;
var kbd_ctrl: bool = false;
var kbd_alt: bool = false;
var kbd_extended: bool = false;

const scan_to_ascii = [128]u8{
    0, 0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', 0,
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 0,
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 0,
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const scan_to_ascii_shift = [128]u8{
    0, 0x1B, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', 0,
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 0,
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 0,
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

var kbd_buffer: [256]u8 = undefined;
var kbd_head: usize = 0;
var kbd_tail: usize = 0;

pub fn kbd_push(ch: u8) void {
    const next = (kbd_head + 1) % kbd_buffer.len;
    if (next != kbd_tail) {
        kbd_buffer[kbd_head] = ch;
        kbd_head = next;
    }
}

pub fn kbd_pop() u8 {
    if (kbd_head == kbd_tail) return 0;
    const ch = kbd_buffer[kbd_tail];
    kbd_tail = (kbd_tail + 1) % kbd_buffer.len;
    return ch;
}

fn kbd_init() void {
    // Flush pending data from keyboard controller
    while ((inb(0x64) & 0x01) != 0) {
        _ = inb(0x60);
    }

    // Disable keyboard port temporarily during reconfiguration
    outb(0x64, 0xAD);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Read current controller command byte
    outb(0x64, 0x20);
    while ((inb(0x64) & 0x01) == 0) {} // Wait for output buffer full
    var config = inb(0x60);

    // Print initial config for debugging
    Serial.puts("[KBD] Initial controller config: 0x");
    Serial.putHex(config);
    Serial.puts("\n");

    // Set config: enable IRQ1 (bit 0), enable keyboard port (clear bit 4)
    // EXPLICITLY enable translation mode (bit 6 = 0x40)
    // When translation is ON, the PS/2 controller converts
    // Set 2 scancodes from the keyboard into Set 1 before
    // delivering them to us. Our scan_to_ascii table uses Set 1.
    //
    // CRITICAL: Do NOT send 0xF0 0x01 to set scancode set 1 on the keyboard!
    // If translation is ON (bit 6) AND keyboard is in Set 1,
    // the controller's translate_table will mangle the Set 1 codes
    // (double translation). Leave keyboard in default Set 2 and
    // let the controller translate Set 2 → Set 1 for us.
    config |= 0x01;              // Enable IRQ1
    config &= ~@as(u8, 0x10);    // Enable keyboard port (bit 4 clear = enabled)
    config |= 0x40;              // EXPLICITLY enable translation (bit 6)
    // This converts Set 2 scancodes → Set 1 before delivering to port 0x60.
    // QEMU does NOT always have bit 6 set by default — if we don't set it,
    // we get raw Set 2 codes but our scan_to_ascii table is Set 1 = wrong chars!

    // Write command byte back
    outb(0x64, 0x60);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty
    outb(0x60, config);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Re-enable keyboard port
    outb(0x64, 0xAE);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Reset keyboard (0xFF) — this resets to default Set 2 mode
    outb(0x60, 0xFF);
    // Wait for BAT completion (ACK 0xFA + BAT OK 0xAA)
    var timeout: u32 = 0;
    var got_bat: bool = false;
    while (timeout < 100000) : (timeout += 1) {
        if ((inb(0x64) & 0x01) != 0) {
            const resp = inb(0x60);
            if (resp == 0xAA) {
                got_bat = true;
                break;
            }
            // Consume ACK (0xFA) and keep waiting for BAT (0xAA)
        }
    }
    if (!got_bat) {
        Serial.puts("[KBD] WARNING: Keyboard BAT not received\n");
    }

    // Drain any remaining bytes after reset
    while ((inb(0x64) & 0x01) != 0) {
        _ = inb(0x60);
    }

    // DO NOT send 0xF0 0x01 to set scancode set 1!
    // The PS/2 controller's translation mode (bit 6) already converts
    // Set 2 → Set 1 for us. Setting Set 1 on the keyboard while
    // translation is ON causes double translation = wrong characters.
    // Just leave the keyboard in its default Set 2 mode and let
    // the controller handle the translation.

    kbd_head = 0;
    kbd_tail = 0;
    // Print the final config byte for debugging
    Serial.puts("[KBD] Controller config byte: 0x");
    Serial.putHex(config);
    Serial.puts(" (bit6=translate should be 1)\n");
    Serial.puts("[KBD] Keyboard initialized (Set 2 → Set 1 translation via controller)\n");
}

// Global print and clear screen functions (registered by main kernel)
pub var print_fn: ?*const fn ([]const u8) void = null;
pub var clear_screen_fn: ?*const fn () void = null;

// ============================================================================
// Page Table Flags
// Page table flags
// ============================================================================

pub const PAGE = struct {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NX: u64 = 1 << 63;

    pub const KERNEL_RW: u64 = PRESENT | WRITABLE;
    pub const KERNEL_RX: u64 = PRESENT;
    pub const USER_RW: u64 = PRESENT | WRITABLE | USER;
    pub const USER_RX: u64 = PRESENT | USER;
};

// ============================================================================
// TSS (Task State Segment)
// Task State Segment
// ============================================================================

pub const TSS = packed struct {
    _reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
};

// IST1 stack for Double Fault (#DF, vector 8)
var ist1_stack: [4096]u8 align(16) = undefined;

var tss: TSS = .{
    ._reserved0 = 0,
    .rsp0 = 0,
    .rsp1 = 0,
    .rsp2 = 0,
    ._reserved1 = 0,
    .ist1 = 0,
    .ist2 = 0,
    .ist3 = 0,
    .ist4 = 0,
    .ist5 = 0,
    .ist6 = 0,
    .ist7 = 0,
    ._reserved2 = 0,
    ._reserved3 = 0,
    .iomap_base = 104,
};

pub fn setKernelStack(stack: u64) void {
    tss.rsp0 = stack;
}

// ============================================================================
// Serial Port (для early debug)
// ============================================================================

pub const Serial = struct {
    const COM1: u16 = 0x3F8;

    pub fn init() void {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB
        outb(COM1 + 0, 0x01); // Baud divisor low = 1 → 115200
        outb(COM1 + 1, 0x00); // Baud divisor high = 0
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // Enable RTS/DSR/DTR
    }

    pub fn puts(str: []const u8) void {
        for (str) |ch| {
            if (ch == '\n') {
                while ((inb(COM1 + 5) & 0x20) == 0) {}
                outb(COM1, '\r');
            }
            while ((inb(COM1 + 5) & 0x20) == 0) {}
            outb(COM1, ch);
        }
    }

    pub fn putHex(val: u64) void {
        const hex = "0123456789ABCDEF";
        puts("0x");
        var i: usize = 60;
        while (true) {
            puts(&.{hex[@intCast((val >> @intCast(i)) & 0xF)]});
            if (i == 0) break;
            i -= 4;
        }
    }

    pub fn putDecimal(val: u64) void {
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
};

pub fn initSyscalls(handler_addr: u64) void {
    // 1. Enable System Call Extensions (SCE) in EFER MSR
    const efer = readMsr(MSR.EFER);
    writeMsr(MSR.EFER, efer | EFER.SCE);

    // 2. Set segment selectors in STAR MSR (0xC0000081)
    const star: u64 = (@as(u64, 0x10) << 48) | (@as(u64, 0x08) << 32);
    writeMsr(MSR.STAR, star);

    // 3. Set entry point in LSTAR MSR (0xC0000082)
    writeMsr(MSR.LSTAR, handler_addr);

    // 4. Set RFLAGS mask in SFMASK MSR (0xC0000084)
    const sfmask: u64 = (1 << 9) | (1 << 10);
    writeMsr(MSR.SFMASK, sfmask);

    Serial.puts("[HAL] Syscall mechanism initialized\n");
}

pub export fn zig_syscall_handler(arg1: u64, arg2: u64, arg3: u64, arg4: u64, syscall_num: u64) callconv(.C) u64 {
    _ = arg3;
    _ = arg4;

    // Re-enable interrupts — syscall clears IF via SFMASK, but we need
    // timer interrupts to fire for preemptive scheduling. IF will be
    // restored from R11 on sysretq anyway.
    sti();

    switch (syscall_num) {
        1 => {
            // Syscall 1: Print string
            // arg1 = pointer to string, arg2 = length
            const ptr: [*]const u8 = @ptrFromInt(arg1);
            const len: usize = @intCast(arg2);
            const slice = ptr[0..len];
            if (print_fn) |f| {
                f(slice);
            } else {
                Serial.puts(slice);
            }
            return 0;
        },
        2 => {
            // Syscall 2: Read key (non-blocking)
            return kbd_pop();
        },
        3 => {
            // Syscall 3: Clear screen
            if (clear_screen_fn) |f| {
                f();
            }
            return 0;
        },
        4 => {
            // Syscall 4: Exit — terminate the calling user process
            // arg1 = exit code (unused for now)
            // This sets the current task to Killed state.
            // The scheduler will skip Killed tasks on next tick.
            Serial.puts("[SYSCALL] exit(");
            Serial.putDecimal(arg1);
            Serial.puts(") — killing user process\n");

            // Import scheduler to kill the current task.
            // We can't import scheduler directly (circular dep), so we use
            // a function pointer callback, similar to timerTickCallback.
            if (exitCallback) |cb| {
                cb();
            }
            // The task should never reach here — the scheduler will
            // have marked it as Killed and won't return to it.
            // But just in case, spin forever.
            while (true) {
                asm volatile ("pause");
            }
        },
        5 => {
            // Syscall 5: Yield — voluntarily give up CPU time
            // The scheduler will pick the next Ready task on the next tick.
            // For now, this is a no-op since the APIC timer preempts anyway.
            // In the future, this could trigger an immediate reschedule.
            return 0;
        },
        else => {
            Serial.puts("[SYSCALL] Unknown syscall: ");
            Serial.putDecimal(syscall_num);
            Serial.puts("\n");
            return @as(u64, @bitCast(@as(i64, -1)));
        }
    }
}

// Exit callback — registered by scheduler at init to break circular dependency
pub var exitCallback: ?*const fn () callconv(.C) void = null;

// ============================================================================
// HAL Initialization
// ============================================================================

pub fn init() void {
    // 1. Initialize serial port (early debug)
    Serial.init();
    Serial.puts("[HAL] Serial port initialized\n");

    // 2. GDT — Initialize and load our own 64-bit GDT
    GDT.init();
    Serial.puts("[HAL] GDT loaded\n");

    // 3. Initialize IDT (using ISR stubs from isr64.S)
    IDT.init();
    Serial.puts("[HAL] IDT loaded\n");

    // 4. Initialize PIC (remap IRQs)
    PIC.init();
    Serial.puts("[HAL] PIC remapped\n");

    // 5. TSS — Initialize Task State Segment + IST1 for Double Fault
    tss.ist1 = @intFromPtr(&ist1_stack) + ist1_stack.len;
    GDT.setTSS(0, @intFromPtr(&tss), @sizeOf(TSS) - 1);
    ltr(0x28);
    Serial.puts("[HAL] TSS loaded (IST1 for #DF at ");
    Serial.putHex(tss.ist1);
    Serial.puts(")\n");

    // 6. Initialize Local APIC
    APIC.init();
    Serial.puts("[HAL] Local APIC initialized\n");

    // 6.5. Initialize IO-APIC & Keyboard
    IOAPIC.init();
    kbd_init();

    // 7. Enable interrupts!
    sti();
    Serial.puts("[HAL] Interrupts enabled\n");
}

// ============================================================================
// VGA Text Mode Initialization — Program VGA registers for 80x25 text mode
// ============================================================================
//
// Switches VGA from any mode (including VBE graphical) to standard
// 80x25 text mode at 0xB8000. Works from 64-bit long mode without BIOS.
// Based on Linux vgacon, IBM VGA spec, and Rust vga crate.
//
// This is needed because GRUB may leave the VGA controller in graphical
// (VBE) mode. In that state, writing to 0xB8000 has no visible effect —
// the CRTC scans the linear framebuffer, not the text plane.
//
// After calling this, the VGA text buffer at 0xB8000 is active and
// characters written there appear on screen immediately.

pub fn vgaSetTextMode() void {
    // Step 1: Assert synchronous reset on sequencer (disables display)
    vgaWriteIndexed(0x3C4, 0x3C5, 0x00, 0x01);

    // Step 2: Set Miscellaneous Output Register
    // 0x67 = Color I/O, CPU access, 25MHz clock, 400 scan lines
    outb(0x3C2, 0x67);

    // Step 3: Program Sequencer registers
    vgaWriteIndexed(0x3C4, 0x3C5, 0x01, 0x00); // Clocking: 9-dot, screen on
    vgaWriteIndexed(0x3C4, 0x3C5, 0x02, 0x03); // Plane mask: enable planes 0,1
    vgaWriteIndexed(0x3C4, 0x3C5, 0x03, 0x00); // Font: map 0
    vgaWriteIndexed(0x3C4, 0x3C5, 0x04, 0x02); // Memory: odd/even, >64KB

    // De-assert sequencer reset
    vgaWriteIndexed(0x3C4, 0x3C5, 0x00, 0x03);

    // Step 4: Unlock CRTC registers (clear protect bit)
    vgaWriteIndexed(0x3D4, 0x3D5, 0x11, 0x00);

    // Step 5: Program CRTC registers for 80x25 text (720x400, 70Hz)
    const crtc = [_][2]u8{
        .{ 0x00, 0x5F }, // Horizontal Total
        .{ 0x01, 0x4F }, // Horizontal Display End (80 chars)
        .{ 0x02, 0x50 }, // Horizontal Blanking Start
        .{ 0x03, 0x82 }, // Horizontal Blanking End
        .{ 0x04, 0x55 }, // Horizontal Sync Start
        .{ 0x05, 0x81 }, // Horizontal Sync End
        .{ 0x06, 0xBF }, // Vertical Total
        .{ 0x07, 0x1F }, // Overflow
        .{ 0x08, 0x00 }, // Preset Row Scan
        .{ 0x09, 0x4F }, // Maximum Scan Line (16 scanlines/char)
        .{ 0x0A, 0x0D }, // Text Cursor Start
        .{ 0x0B, 0x0E }, // Text Cursor End
        .{ 0x0C, 0x00 }, // Start Address High
        .{ 0x0D, 0x00 }, // Start Address Low
        .{ 0x0E, 0x00 }, // Cursor Location High
        .{ 0x0F, 0x50 }, // Cursor Location Low
        .{ 0x10, 0x9C }, // Vertical Sync Start
        .{ 0x11, 0x8E }, // Vertical Sync End (bit 7=1 re-protects)
        .{ 0x12, 0x8F }, // Vertical Display End (399 = 25*16-1)
        .{ 0x13, 0x28 }, // Offset (40 = 80/2 word mode)
        .{ 0x14, 0x1F }, // Underline Location
        .{ 0x15, 0x96 }, // Vertical Blanking Start
        .{ 0x16, 0xB9 }, // Vertical Blanking End
        .{ 0x17, 0xA3 }, // Mode Control (word mode, sync enabled)
        .{ 0x18, 0xFF }, // Line Compare
    };
    for (&crtc) |reg| {
        vgaWriteIndexed(0x3D4, 0x3D5, reg[0], reg[1]);
    }

    // Step 6: Program Graphics Controller registers
    const gc = [_][2]u8{
        .{ 0x00, 0x00 }, // Set/Reset
        .{ 0x01, 0x00 }, // Enable Set/Reset
        .{ 0x02, 0x00 }, // Color Compare
        .{ 0x03, 0x00 }, // Data Rotate
        .{ 0x04, 0x00 }, // Read Plane Select
        .{ 0x05, 0x10 }, // Graphics Mode: odd/even (text mode)
        .{ 0x06, 0x0E }, // Miscellaneous: TEXT MODE, B8000 mapping
        .{ 0x07, 0x00 }, // Color Don't Care
        .{ 0x08, 0xFF }, // Bit Mask
    };
    for (&gc) |reg| {
        vgaWriteIndexed(0x3CE, 0x3CF, reg[0], reg[1]);
    }

    // Step 7: Blank screen to unlock attribute palette
    _ = inb(0x3DA); // Reset attribute controller flip-flop
    outb(0x3C0, 0x00); // Index 0, blanked (bit 5=0)

    // Step 8: Program Attribute Controller registers
    const ac_palette = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    for (&ac_palette, 0..) |val, idx| {
        outb(0x3C0, @intCast(idx)); // Write index
        outb(0x3C0, val); // Write data
    }
    outb(0x3C0, 0x10); outb(0x3C0, 0x0C); // Mode: text, 9-dot, blink
    outb(0x3C0, 0x11); outb(0x3C0, 0x00); // Overscan: black
    outb(0x3C0, 0x12); outb(0x3C0, 0x0F); // Plane enable: all
    outb(0x3C0, 0x13); outb(0x3C0, 0x08); // Horizontal panning
    outb(0x3C0, 0x14); outb(0x3C0, 0x00); // Color select

    // Step 9: Unblank screen (enable display)
    _ = inb(0x3DA); // Reset flip-flop
    outb(0x3C0, 0x20); // Set bit 5 = enable display

    // Step 10: Initialize DAC palette (16 standard VGA colors)
    outb(0x3C8, 0x00); // DAC write index = 0
    // Standard 16 VGA colors (6-bit RGB: 0x00=0, 0x2A=42, 0x15=21, 0x3F=63)
    const palette = [_][3]u8{
        .{ 0x00, 0x00, 0x00 }, // 0: Black
        .{ 0x00, 0x00, 0x2A }, // 1: Blue
        .{ 0x00, 0x2A, 0x00 }, // 2: Green
        .{ 0x00, 0x2A, 0x2A }, // 3: Cyan
        .{ 0x2A, 0x00, 0x00 }, // 4: Red
        .{ 0x2A, 0x00, 0x2A }, // 5: Magenta
        .{ 0x2A, 0x15, 0x00 }, // 6: Brown
        .{ 0x2A, 0x2A, 0x2A }, // 7: Light Gray
        .{ 0x15, 0x15, 0x15 }, // 8: Dark Gray
        .{ 0x15, 0x15, 0x3F }, // 9: Light Blue
        .{ 0x15, 0x3F, 0x15 }, // 10: Light Green
        .{ 0x15, 0x3F, 0x3F }, // 11: Light Cyan
        .{ 0x3F, 0x15, 0x15 }, // 12: Light Red
        .{ 0x3F, 0x15, 0x3F }, // 13: Light Magenta
        .{ 0x3F, 0x3F, 0x15 }, // 14: Yellow
        .{ 0x3F, 0x3F, 0x3F }, // 15: White
    };
    for (&palette) |color| {
        outb(0x3C9, color[0]); // Red
        outb(0x3C9, color[1]); // Green
        outb(0x3C9, color[2]); // Blue
    }
    outb(0x3C6, 0xFF); // PEL mask

    // Step 11: Clear text buffer at 0xB8000
    const vram: [*]volatile u16 = @ptrFromInt(0xB8000);
    var i: usize = 0;
    while (i < 80 * 25) : (i += 1) {
        vram[i] = 0x0720; // Space (0x20) with light gray on black (0x07)
    }

    // Set cursor to top-left
    vgaWriteIndexed(0x3D4, 0x3D5, 0x0E, 0x00);
    vgaWriteIndexed(0x3D4, 0x3D5, 0x0F, 0x00);

    Serial.puts("[HAL] VGA text mode (80x25) initialized via register programming\n");
}

/// Helper: Write to an indexed VGA register pair
fn vgaWriteIndexed(index_port: u16, data_port: u16, index: u8, value: u8) void {
    outb(index_port, index);
    outb(data_port, value);
}
