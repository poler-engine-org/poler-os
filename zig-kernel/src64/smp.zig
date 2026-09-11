// ============================================================================
// POLER-OS SMP (Symmetric Multi-Processing) — x86_64
// ============================================================================
//
// Manages multi-core initialization and per-CPU state.
//
// Boot sequence:
//   1. BSP (Bootstrap Processor) boots via Multiboot2 → main64.zig
//   2. BSP initializes HAL, ACPI, memory, scheduler
//   3. BSP calls smp.init() which:
//      a. Reads BSP's Local APIC ID
//      b. Parses MADT to find all CPUs (already done by acpi.init)
//      c. Marks BSP in cpu_list
//      d. Copies AP trampoline code to 0x8000 (low memory)
//      e. Sends INIT IPI → SIPI to each AP
//      f. Waits for each AP to signal ready
//   4. Each AP:
//      a. Starts in 16-bit real mode at 0x8000 (trampoline)
//      b. Switches to 64-bit long mode
//      c. Loads GDT, IDT, page tables from BSP
//      d. Sets up per-CPU GSBASE
//      e. Initializes Local APIC
//      f. Signals ready
//      g. Enters scheduler loop
//
// ============================================================================

const hal = @import("hal.zig");
const acpi = @import("acpi.zig");
const spinlock = @import("spinlock.zig");

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of CPUs supported
pub const MAX_CPUS = acpi.MAX_CPUS;

/// AP trampoline is placed at physical address 0x8000 (page 8).
/// This must be below 640KB for SIPI to work (SIPI vector = page number).
pub const AP_TRAMPOLINE_ADDR: u64 = 0x8000;
pub const AP_TRAMPOLINE_PAGE: u32 = 8; // 0x8000 / 4096

/// Stack size for each AP (16KB)
pub const AP_STACK_SIZE: usize = 16384;

// ============================================================================
// Per-CPU State
// ============================================================================

pub const CpuState = enum(u8) {
    Offline = 0,
    Initializing = 1,
    Ready = 2,
    Running = 3,
    Halted = 4,
};

pub const PerCpu = struct {
    cpu_id: u32, // Logical CPU index (0 = BSP)
    lapic_id: u32, // Local APIC ID
    state: CpuState,
    stack_top: u64, // Top of this CPU's kernel stack
    current_task_id: usize, // Currently running task (-1 = idle)
    scheduler_ticks: u64, // Per-CPU scheduler tick counter
    irq_count: u64, // Interrupt count
    syscall_count: u64, // Syscall count
};

/// Global array of per-CPU data, aligned to cache line to avoid false sharing
pub var cpu_data: [MAX_CPUS]PerCpu align(64) = undefined;

/// Number of CPUs that are online (initialized + ready)
pub var online_cpus: u32 = 0;

/// Spinlock protecting SMP initialization
var smp_lock: spinlock.Spinlock = .{};

/// AP stack memory — each AP gets its own stack
var ap_stacks: [MAX_CPUS - 1][AP_STACK_SIZE]u8 align(16) = undefined;

// ============================================================================
// AP trampoline code — 16-bit real mode startup
// ============================================================================
// This code is copied to physical address 0x8000 at boot.
// APs start here in 16-bit real mode after SIPI.
// The trampoline switches to 64-bit long mode and jumps to ap_entry_zig().
// ============================================================================

/// Shared data between BSP and AP (placed at known offsets from 0x8000)
pub const ApTrampolineData = extern struct {
    /// GDT64 pointer (10 bytes: 2-byte limit + 8-byte base)
    gdt_ptr: [10]u8 align(1),
    /// IDT pointer (10 bytes: 2-byte limit + 8-byte base)
    idt_ptr: [10]u8 align(1),
    /// PML4 physical address for CR3
    cr3: u64,
    /// Address of ap_entry_zig() function (64-bit)
    entry64: u64,
    /// Address of this CPU's PerCpu structure (for GSBASE)
    per_cpu_addr: u64,
    /// CPU index for this AP
    cpu_id: u32,
    /// Stack top for this AP
    stack_top: u64,
};

/// The trampoline data lives at AP_TRAMPOLINE_ADDR + 0x100 (offset from code)
pub const AP_DATA_OFFSET: u64 = 0x100;

// ============================================================================
// SMP Initialization (called by BSP)
// ============================================================================

pub fn init() void {
    hal.Serial.puts("[SMP] Initializing SMP subsystem...\n");

    // Step 1: Read BSP's Local APIC ID
    const bsp_lapic_id = hal.APIC.getId();
    acpi.bsp_apic_id = bsp_lapic_id;
    hal.Serial.puts("[SMP] BSP Local APIC ID: ");
    hal.Serial.putHex(@as(u64, bsp_lapic_id));
    hal.Serial.puts("\n");

    // Step 2: Mark BSP in cpu_list
    for (0..acpi.cpu_count) |i| {
        if (acpi.cpu_list[i].apic_id == bsp_lapic_id) {
            acpi.cpu_list[i].is_bsp = true;
            break;
        }
    }

    // Step 3: Initialize PerCpu for BSP (CPU 0)
    cpu_data[0] = PerCpu{
        .cpu_id = 0,
        .lapic_id = bsp_lapic_id,
        .state = .Running,
        .stack_top = 0x10b000, // Boot stack top (from linker64.ld)
        .current_task_id = 0,
        .scheduler_ticks = 0,
        .irq_count = 0,
        .syscall_count = 0,
    };
    online_cpus = 1;

    // Set GSBASE for BSP — points to its PerCpu structure
    hal.writeGsBase(@intFromPtr(&cpu_data[0]));
    hal.writeKernelGsBase(@intFromPtr(&cpu_data[0]));
    hal.Serial.puts("[SMP] BSP GSBASE set to ");
    hal.Serial.putHex(@intFromPtr(&cpu_data[0]));
    hal.Serial.puts("\n");

    // Step 4: If only 1 CPU, skip AP startup
    if (acpi.cpu_count <= 1) {
        hal.Serial.puts("[SMP] Single CPU system, no APs to start\n");
        return;
    }

    // Step 5: Copy AP trampoline code to 0x8000
    setupTrampoline();

    // Step 6: Start each AP
    startApplicationProcessors();

    hal.Serial.puts("[SMP] All CPUs online: ");
    hal.Serial.putDecimal(online_cpus);
    hal.Serial.puts("\n");
}

/// Get the current CPU's PerCpu structure via GSBASE
pub fn currentCpu() *PerCpu {
    const gsbase = hal.readGsBase();
    return @ptrFromInt(gsbase);
}

/// Get the current CPU's logical index
pub fn currentCpuId() u32 {
    return currentCpu().cpu_id;
}

// ============================================================================
// AP Trampoline Setup
// ============================================================================

fn setupTrampoline() void {
    hal.Serial.puts("[SMP] Setting up AP trampoline at 0x8000...\n");

    // The trampoline consists of:
    // 1. 16-bit real mode code that switches to 64-bit long mode
    // 2. Data area with GDT/IDT/CR3/entry pointers

    // We write the trampoline in assembly (boot_smp.S) and copy it at runtime.
    // For now, we'll use the symbols from boot_smp.S:
    //   ap_trampoline_start, ap_trampoline_end

    // Copy trampoline binary to 0x8000
    const src: [*]const u8 = @ptrCast(&ap_trampoline_start);
    const len: usize = @intFromPtr(&ap_trampoline_end) - @intFromPtr(&ap_trampoline_start);
    const dst: [*]volatile u8 = @ptrFromInt(AP_TRAMPOLINE_ADDR);

    for (0..len) |i| {
        dst[i] = src[i];
    }

    // Fill in the trampoline data area
    const data: *volatile ApTrampolineData = @ptrFromInt(AP_TRAMPOLINE_ADDR + AP_DATA_OFFSET);

    // Read current GDT and IDT pointers
    var gdt_ptr: [10]u8 = undefined;
    asm volatile ("sgdt %[p]"
        : [p] "=m" (gdt_ptr),
    );
    var idt_ptr: [10]u8 = undefined;
    asm volatile ("sidt %[p]"
        : [p] "=m" (idt_ptr),
    );

    data.gdt_ptr = gdt_ptr;
    data.idt_ptr = idt_ptr;
    data.cr3 = hal.readCr3() & 0x000FFFFFFFFFF000; // PML4 physical address
    data.entry64 = @intFromPtr(&ap_entry_zig);
    data.cpu_id = 0; // Will be set per-AP before SIPI
    data.per_cpu_addr = 0; // Will be set per-AP before SIPI

    hal.Serial.puts("[SMP] Trampoline data: CR3=");
    hal.Serial.putHex(data.cr3);
    hal.Serial.puts(" entry=");
    hal.Serial.putHex(data.entry64);
    hal.Serial.puts("\n");
}

// ============================================================================
// Start Application Processors
// ============================================================================

fn startApplicationProcessors() void {
    var ap_index: u32 = 0; // Logical AP index (0 = first AP)

    for (0..acpi.cpu_count) |i| {
        const cpu = &acpi.cpu_list[i];
        if (cpu.is_bsp) continue; // Skip BSP
        if (!cpu.enabled) continue; // Skip disabled CPUs

        if (ap_index >= MAX_CPUS - 1) {
            hal.Serial.puts("[SMP] WARNING: Too many APs, max ");
            hal.Serial.putDecimal(MAX_CPUS - 1);
            hal.Serial.puts(" supported\n");
            break;
        }

        const logical_id: u32 = ap_index + 1; // CPU 0 = BSP

        hal.Serial.puts("[SMP] Starting AP ");
        hal.Serial.putDecimal(logical_id);
        hal.Serial.puts(" (APIC_ID=");
        hal.Serial.putHex(@as(u64, cpu.apic_id));
        hal.Serial.puts(")\n");

        // Set up PerCpu structure for this AP
        const stack_top: u64 = @intFromPtr(&ap_stacks[ap_index]) + AP_STACK_SIZE;
        cpu_data[logical_id] = PerCpu{
            .cpu_id = logical_id,
            .lapic_id = cpu.apic_id,
            .state = .Initializing,
            .stack_top = stack_top,
            .current_task_id = 0,
            .scheduler_ticks = 0,
            .irq_count = 0,
            .syscall_count = 0,
        };

        // Update trampoline data for this specific AP
        const data: *volatile ApTrampolineData = @ptrFromInt(AP_TRAMPOLINE_ADDR + AP_DATA_OFFSET);
        data.cpu_id = logical_id;
        data.per_cpu_addr = @intFromPtr(&cpu_data[logical_id]);
        data.stack_top = stack_top;

        // Intel SDM says: INIT IPI → 10ms delay → SIPI → 200us delay → SIPI (retry)
        hal.APIC.sendInitIpi(cpu.apic_id);
        microDelay(10000); // 10ms

        hal.APIC.sendStartupIpi(cpu.apic_id, AP_TRAMPOLINE_PAGE);
        microDelay(200); // 200us

        // Retry SIPI if AP is not ready (Intel SDM recommends sending SIPI twice)
        if (cpu_data[logical_id].state != .Ready) {
            hal.APIC.sendStartupIpi(cpu.apic_id, AP_TRAMPOLINE_PAGE);
            microDelay(200);
        }

        // Wait for AP to signal ready (with timeout)
        // AP needs time to: switch modes → load GDT/IDT → init APIC → set Ready
        // Use atomic load with acquire semantics to ensure we see the AP's store
        var timeout: u32 = 0;
        const state_ptr: *const u8 = @ptrCast(&cpu_data[logical_id].state);
        while (@atomicLoad(u8, state_ptr, .acquire) != @intFromEnum(CpuState.Ready) and timeout < 50000000) : (timeout += 1) {
            asm volatile ("pause");
        }

        if (@atomicLoad(u8, state_ptr, .acquire) == @intFromEnum(CpuState.Ready)) {
            online_cpus += 1;
            hal.Serial.puts("[SMP] AP ");
            hal.Serial.putDecimal(logical_id);
            hal.Serial.puts(" is ready\n");
        } else {
            hal.Serial.puts("[SMP] WARNING: AP ");
            hal.Serial.putDecimal(logical_id);
            hal.Serial.puts(" failed to start (timeout)\n");
            cpu_data[logical_id].state = .Offline;
        }

        ap_index += 1;
    }
}

/// Crude micro-delay using a busy loop. Not precise, but good enough for
/// IPI timing where we just need "at least N microseconds".
///
/// TODO(v2.0): Replace with PIT-driven or HPET-driven precise delay.
/// Current calibration assumes ~2GHz CPU and is wildly inaccurate on
/// faster/slower CPUs or under virtualization. For IPI, Intel SDM mandates
/// 10ms INIT delay and 200us SIPI delay — we overshoot significantly,
/// which is safe but wastes boot time.
fn microDelay(us: u32) void {
    // Rough calibration: ~1 billion iterations per second on a 2GHz CPU
    // This is very imprecise but sufficient for IPI delays.
    const iterations = us * 1000;
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("nop");
    }
}

// ============================================================================
// AP Entry Point (called from trampoline assembly in 64-bit long mode)
// ============================================================================

/// This function is called by each AP after the trampoline switches to
/// 64-bit long mode. It runs on the AP's own stack.
pub export fn ap_entry_zig() callconv(.c) void {
    // Read our CPU ID from the trampoline data
    const data: *volatile ApTrampolineData = @ptrFromInt(AP_TRAMPOLINE_ADDR + AP_DATA_OFFSET);
    const cpu_id = data.cpu_id;
    const per_cpu_addr = data.per_cpu_addr;

    const cpu = &cpu_data[cpu_id];

    hal.spinLock(&hal.serial_lock);
    hal.Serial.puts("[SMP] AP ");
    hal.Serial.putDecimal(cpu_id);
    hal.Serial.puts(" entering ap_entry_zig()\n");
    hal.spinUnlock(&hal.serial_lock);

    // Set GSBASE for per-CPU data
    hal.writeGsBase(per_cpu_addr);
    hal.writeKernelGsBase(per_cpu_addr);

    // Initialize Local APIC on this CPU
    // The APIC base address is the same for all CPUs (MMIO),
    // but each CPU has its own set of APIC registers.
    hal.APIC.init();

    // Enable interrupts
    hal.sti();

    // Signal that we're ready (atomic store with release semantics so BSP sees it)
    const state_ptr_ap: *u8 = @ptrCast(&cpu.state);
    @atomicStore(u8, state_ptr_ap, @intFromEnum(CpuState.Ready), .release);

    hal.spinLock(&hal.serial_lock);
    hal.Serial.puts("[SMP] AP ");
    hal.Serial.putDecimal(cpu_id);
    hal.Serial.puts(" ready (APIC_ID=");
    hal.Serial.putHex(@as(u64, cpu.lapic_id));
    hal.Serial.puts(")\n");
    hal.spinUnlock(&hal.serial_lock);

    // Enter scheduler idle loop — HLT until an interrupt (IPI/timer)
    // wakes us up, then check the per-CPU run queue for tasks.
    // This is the standard pattern: HLT + APIC timer for scheduler ticks.
    const scheduler = @import("scheduler.zig");
    const state_ptr_idle: *u8 = @ptrCast(&cpu.state);
    while (true) {
        // Check if there are tasks in our run queue
        if (scheduler.cpu_run_queues[cpu_id].count > 0) {
            // Tasks available — let the next timer tick schedule them
            // (schedule() is called from the APIC timer ISR)
        }
        // HLT: CPU enters low-power state until next interrupt.
        // APIC timer, IPI, or device interrupt will wake this CPU.
        // When woken, the timer ISR calls schedule() which picks
        // the next task from this CPU's run queue.
        //
        // IMPORTANT: Use atomic stores for cpu.state so that BSP
        // can safely read it when deciding whether to send RESCHEDULE IPI.
        // Plain stores here would be a data race (BSP uses atomicLoad).
        @atomicStore(u8, state_ptr_idle, @intFromEnum(CpuState.Halted), .release);
        hal.hlt();
        @atomicStore(u8, state_ptr_idle, @intFromEnum(CpuState.Running), .release);
    }
}

// ============================================================================
// Trampoline symbols (defined in boot_smp.S)
// ============================================================================

extern const ap_trampoline_start: u8;
extern const ap_trampoline_end: u8;
