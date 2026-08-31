// ============================================================================
// POLER-OS Task Scheduler — x86_64
// ============================================================================
//
// v0.7.0: Ring 3 (user mode) support
//   - Per-process CR3 (page tables)
//   - User code/data segments (CS=0x23, SS=0x1B — v0.10.0 SYSRET-совместимо)
//   - TSS IST1 for double-fault handling
//   - IRETQ privilege switch
//   - CR3 switching on context switch
//   - sysretq convention: CS = STAR[63:48]+16|RPL3 = 0x23, SS = STAR[63:48]+8|RPL3 = 0x1B
//
// v0.6.1-fix: Tasks run in Ring 0 (kernel mode) for stability.
// Ring 3 user-mode tasks will be added in v0.7.0 with proper:
//   - Per-process CR3 (page tables)
//   - User code/data segments (0x1B/0x23)
//   - TSS IST for double-fault handling
//   - IRETQ privilege switch
// ============================================================================

const hal = @import("hal.zig");

pub const MAX_TASKS = 8;

pub const TaskState = enum {
    Ready,
    Running,
    Killed,
};

pub const TaskPrivilege = enum(u2) {
    Kernel = 0,
    User = 3,
};

pub const Task = struct {
    id: usize,
    state: TaskState,
    privilege: TaskPrivilege,
    rsp: u64, // Saved stack pointer (points to saved InterruptFrame in kernel_stack)
    kernel_stack: [8192]u8 align(16), // Ring 0 stack (8KB — larger for safety)
    cr3: u64, // Per-process PML4 physical address (0 = use kernel CR3)
    user_stack_top: u64, // Top of user stack (virtual address, for reference/cleanup)
};

pub var tasks: [MAX_TASKS]Task = undefined;
pub var current_task_id: usize = 0;
pub var task_count: usize = 0;
pub var scheduler_ticks: u64 = 0;

// Exported variables for assembly syscall_entry
pub export var user_rsp: u64 = 0;
pub export var current_kernel_stack: u64 = 0;

// v0.7.0: CR3 tracking for per-process address spaces
var kernel_cr3: u64 = 0; // Boot/kernel PML4 physical address
var current_cr3: u64 = 0; // Currently loaded CR3

pub fn init() void {
    task_count = 0;
    current_task_id = 0;
    scheduler_ticks = 0;

    // Save the kernel's CR3 (boot PML4) — used to restore when switching back
    kernel_cr3 = hal.readCr3() & 0x000FFFFFFFFFF000;
    current_cr3 = kernel_cr3;

    // Create idle task (Task 0) — maps to the main kernel thread
    tasks[0] = Task{
        .id = 0,
        .state = .Running,
        .privilege = .Kernel,
        .rsp = 0,
        .kernel_stack = undefined,
        .cr3 = 0, // 0 = use kernel CR3
        .user_stack_top = 0,
    };
    task_count = 1;

    // Set initial kernel stack top (corresponds to stack_top in linker64.ld)
    current_kernel_stack = 0x10b000;

    // Register exit callback — HAL calls this on syscall exit(4)
    // Breaks circular dependency hal.zig ↔ scheduler.zig via function pointer.
    hal.exitCallback = exitCurrentTask;

    // v0.7.3: Register timer tick callback — APIC timer (vector 48) calls
    // schedule() on every tick. This is the heart of preemptive multitasking:
    // without this wiring, kernel tasks are created but NEVER scheduled and
    // the interactive shell never starts (regression since the v0.7.0 rewrite;
    // the fix existed in the orphaned July v1.2.0 chain, commit 228f9fdc).
    hal.timerTickCallback = schedule;

    hal.Serial.puts("[SCHED] Scheduler initialized (v0.7.0 Ring 3 + exit syscall)\n");
}

/// Called by HAL when a user process invokes syscall 4 (exit).
/// Kills the current task. The scheduler will skip it on the next tick.
pub fn exitCurrentTask() callconv(.C) void {
    if (current_task_id == 0) {
        hal.Serial.puts("[SCHED] ERROR: Cannot kill idle task!\n");
        return;
    }
    hal.Serial.puts("[SCHED] Exiting task ");
    hal.Serial.putHex(current_task_id);
    hal.Serial.puts("\n");
    tasks[current_task_id].state = .Killed;
}

/// Mark a task as Killed. The idle task (id 0) CANNOT be killed —
/// it is the scheduler's safety net and must always remain schedulable.
pub fn killTask(id: usize) !void {
    if (id == 0) return error.InvalidTask;
    if (id >= task_count) return error.InvalidTask;
    tasks[id].state = .Killed;
    hal.Serial.puts("[SCHED] Killed task ");
    hal.Serial.putHex(id);
    hal.Serial.puts("\n");
}

/// Create a kernel-mode (Ring 0) task.
/// CS=0x08, SS=0x10, runs in kernel space.
pub fn createTask(entry_point: u64) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.state = .Ready;
    task.privilege = .Kernel;
    task.cr3 = 0; // Use kernel CR3
    task.user_stack_top = 0;

    // Set up the initial stack frame in the kernel stack.
    // InterruptFrame layout (176 bytes):
    //   [0..120]   = r15..rax (15 GP registers, pushed by isr_common)
    //   [120..128] = vector
    //   [128..136] = error_code
    //   [136..176] = rip, cs, rflags, rsp, ss (CPU-pushed on interrupt)
    const kstack_top = @intFromPtr(&task.kernel_stack) + task.kernel_stack.len;

    // Place InterruptFrame at the top of kernel stack
    const frame_ptr: *hal.InterruptFrame = @ptrFromInt(kstack_top - 176);

    // Clear the stack frame initial contents
    @memset(@as([*]volatile u8, @ptrCast(frame_ptr))[0..176], 0);

    // Set up segment registers and execution context
    // Ring 0 task: CS=0x08, SS=0x10 (kernel mode)
    frame_ptr.rip = entry_point;
    frame_ptr.cs = 0x08; // Kernel code segment selector (Ring 0)
    frame_ptr.rflags = 0x202; // IF (Interrupt Enable Flag) set
    // v0.7.3: Stack alignment — System V AMD64 ABI requires RSP 16-byte
    // aligned after the function prologue (push rbp = -8). kstack_top is
    // 16-aligned and 176 % 16 == 0, so (kstack_top - 176) is 16-aligned;
    // subtracting 8 makes RSP properly aligned AFTER push rbp, keeping
    // movaps from faulting (from the orphaned v1.2.0 chain, 228f9fdc).
    frame_ptr.rsp = kstack_top - 176 - 8;
    frame_ptr.ss = 0x10; // Kernel data segment selector (Ring 0)
    frame_ptr.vector = 48; // APIC timer vector (matches actual interrupt source)
    frame_ptr.error_code = 0;

    // Initialize RDI, RSI, RDX etc. to 0 (already zeroed by memset above)

    // Save stack pointer to task control block
    task.rsp = @intFromPtr(frame_ptr);

    hal.Serial.puts("[SCHED] Created kernel task ");
    hal.Serial.putHex(id);
    hal.Serial.puts(" at entry ");
    hal.Serial.putHex(entry_point);
    hal.Serial.puts(" RSP=");
    hal.Serial.putHex(task.rsp);
    hal.Serial.puts("\n");

    return id;
}

/// Create a user-mode (Ring 3) task — v0.7.0
///
/// Parameters:
///   entry_point:  Virtual address of the user program's _start
///   user_cr3:     Physical address of the user's PML4 (from vmm.createUserPML4)
///   user_stack:   Virtual address of the top of user stack (e.g., 0x100081000)
///
/// v0.10.0 FIX — селекторы под новую GDT-раскладку (SYSRET-совместимую):
///   CS = 0x23 (User Code: GDT entry 4 = 0x20 | RPL3)
///   SS = 0x1B (User Data: GDT entry 3 = 0x18 | RPL3)
/// SYSRET возвращает ровно эти значения (CS = STAR[63:48]+16, SS = +8) —
/// теперь syscall-трамплины и IRETQ-кадры живут в ОДНОЙ конвенции.
///
/// When an interrupt fires in Ring 3, the CPU automatically:
///   1. Switches to TSS.rsp0 (kernel stack)
///   2. Pushes user SS, RSP, RFLAGS, CS, RIP
///   3. Enters the ISR in Ring 0
///
/// IRETQ restores CS with RPL=3 → switches back to Ring 3.
/// sysretq returns with CS = STAR[63:48]+16 | RPL3 = 0x23, SS = STAR[63:48]+8 | RPL3 = 0x1B.
pub fn createUserTask(entry_point: u64, user_cr3: u64, user_stack: u64) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.state = .Ready;
    task.privilege = .User;
    task.cr3 = user_cr3; // Per-process page tables!
    task.user_stack_top = user_stack;

    // Set up the initial stack frame in the kernel stack.
    // When IRETQ pops this frame and sees CS=0x23 (RPL=3),
    // it performs a privilege switch to Ring 3.
    const kstack_top = @intFromPtr(&task.kernel_stack) + task.kernel_stack.len;

    // Place InterruptFrame at the top of kernel stack
    const frame_ptr: *hal.InterruptFrame = @ptrFromInt(kstack_top - 176);

    // Clear the stack frame initial contents
    @memset(@as([*]volatile u8, @ptrCast(frame_ptr))[0..176], 0);

    // Set up segment registers and execution context for Ring 3
    // GDT layout (v0.10.0, SYSRET-совместимая — см. hal.zig):
    //   Entry 1 (0x08): Kernel Code — syscall CS
    //   Entry 2 (0x10): Kernel Data — syscall SS
    //   Entry 3 (0x18): User Data  — sysretq SS / IRETQ SS = 0x1B
    //   Entry 4 (0x20): User Code  — sysretq CS / IRETQ CS = 0x23
    frame_ptr.rip = entry_point;
    frame_ptr.cs = 0x23; // User code segment (0x20 | RPL3) — entry 4 = User Code
    frame_ptr.rflags = 0x202; // IF set, IOPL=0 (no I/O port access from Ring 3)
    frame_ptr.rsp = user_stack; // User stack top (grows downward)
    frame_ptr.ss = 0x1B; // User data segment (0x18 | RPL3) — entry 3 = User Data
    frame_ptr.vector = 48; // APIC timer vector
    frame_ptr.error_code = 0;

    // Save stack pointer to task control block
    task.rsp = @intFromPtr(frame_ptr);

    hal.Serial.puts("[SCHED] Created user task ");
    hal.Serial.putHex(id);
    hal.Serial.puts(" at entry ");
    hal.Serial.putHex(entry_point);
    hal.Serial.puts(" CR3=");
    hal.Serial.putHex(user_cr3);
    hal.Serial.puts(" USP=");
    hal.Serial.putHex(user_stack);
    hal.Serial.puts("\n");

    return id;
}

pub fn schedule(current_rsp: u64) callconv(.C) u64 {
    if (task_count <= 1) return current_rsp; // Only idle/kernel task exists

    scheduler_ticks += 1;

    // DEBUG: periodic log to confirm schedule is running
    if (scheduler_ticks % 100 == 1) {
        hal.Serial.puts("[SCHED] tick ");
        hal.Serial.putDecimal(scheduler_ticks);
        hal.Serial.puts(" current=");
        hal.Serial.putDecimal(current_task_id);
        hal.Serial.puts(" tasks=");
        hal.Serial.putDecimal(task_count);
        hal.Serial.puts("\n");
    }

    // Save RSP of the current task
    tasks[current_task_id].rsp = current_rsp;
    if (tasks[current_task_id].state == .Running) {
        tasks[current_task_id].state = .Ready;
    }

    // Select the next task using Round-Robin
    var next_id = (current_task_id + 1) % task_count;
    var checked: usize = 0;
    while (checked < task_count) : ({
        next_id = (next_id + 1) % task_count;
        checked += 1;
    }) {
        if (tasks[next_id].state == .Ready or tasks[next_id].state == .Running) {
            break;
        }
    }

    // Safety: if no Ready/Running task found, stay on current if it's not Killed
    if (tasks[next_id].state == .Killed) {
        // All tasks are killed — spin on idle (task 0)
        next_id = 0;
        if (tasks[0].state == .Killed) {
            // Even idle is killed — shouldn't happen, but prevent resurrection
            tasks[0].state = .Running;
        }
    }

    current_task_id = next_id;
    tasks[current_task_id].state = .Running;

    // DEBUG: Log when switching to a user task
    if (tasks[current_task_id].privilege == .User) {
        hal.Serial.puts("[SCHED] Switching to user task ");
        hal.Serial.putHex(current_task_id);
        hal.Serial.puts(" RIP=");
        // Peek at the InterruptFrame to see what IRETQ will restore
        const frame: *hal.InterruptFrame = @ptrFromInt(tasks[current_task_id].rsp);
        hal.Serial.putHex(frame.rip);
        hal.Serial.puts(" CS=");
        hal.Serial.putHex(frame.cs);
        hal.Serial.puts(" RSP=");
        hal.Serial.putHex(frame.rsp);
        hal.Serial.puts(" SS=");
        hal.Serial.putHex(frame.ss);
        hal.Serial.puts("\n");
    }

    // Update TSS.rsp0 and current_kernel_stack
    // For user tasks: TSS.rsp0 must point to the kernel stack top,
    // so that interrupts from Ring 3 switch to the correct kernel stack.
    const next_task = &tasks[current_task_id];
    if (next_task.id != 0) {
        const kstack_top = @intFromPtr(&next_task.kernel_stack) + next_task.kernel_stack.len;
        hal.setKernelStack(kstack_top);
        current_kernel_stack = kstack_top;
    } else {
        // Idle/Kernel task uses the main boot stack
        hal.setKernelStack(0x10b000);
        current_kernel_stack = 0x10b000;
    }

    // v0.7.0: Switch CR3 if the new task has different page tables
    // This implements per-process address space isolation.
    // When switching to a user task: load its CR3
    // When switching to a kernel task: load kernel CR3
    // CR3 write flushes the entire TLB — acceptable for v0.7.0.
    const next_cr3 = if (next_task.cr3 != 0) next_task.cr3 else kernel_cr3;
    if (next_cr3 != current_cr3) {
        hal.writeCr3(next_cr3);
        current_cr3 = next_cr3;
    }

    return next_task.rsp;
}
