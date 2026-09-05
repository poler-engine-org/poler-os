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
const sres = @import("sched_resume.zig"); // v0.18.1: пер-таск резюм-кадры (.bss)

pub const MAX_TASKS = 8;

/// v0.13.0-fix: канарейка переполнения kstack (низ 256Б каждого стека
/// заполняется паттерном при создании; schedule проверяет — smash = overflow).
const KSTACK_CANARY: u64 = 0xC0FFEE_BEEF_1234;
const CANARY_BYTES: usize = 256;

pub const TaskState = enum {
    Ready,
    Running,
    Killed,
};

pub const TaskPrivilege = enum(u2) {
    Kernel = 0,
    User = 3,
};

/// v0.18.0 (CDD №9): ABI пользовательского бинарника задачи. Win32 (PE)
/// задачи ходят через фиксированные syscall-вектора #6/#7 (вход — трамплин
/// win32_stubs); Linux (ELF) задачи — через стандартный Linux x86_64 RAX-ABI
/// (номер в RAX, аргументы RDI/RSI/RDX/R10/R8/R9 — маршрутизация в hal).
pub const TaskAbi = enum {
    win32,
    linux,
};

pub const Task = struct {
    id: usize,
    state: TaskState,
    privilege: TaskPrivilege,
    rsp: u64, // Saved stack pointer (points to saved InterruptFrame in kernel_stack)
    // v0.13.0-fix: 8КБ МАЛО — cmd_peload (PE-загрузка: Zig-Debug каскад
    // pe→win32→стабы + литерал ctx) упирался в дно kstack[1] и ЗАТИРАЛ
    // НУЛЯМИ header НИЖЕЛЕЖАЩЕЙ tasks[1] (id/rsp → 0) → каскад
    // task-state-расхождений и kernel-panic @ptrFromInt (E2E-цикл №4).
    // v0.18.1: 128КБ × 8 = 1МБ .bss (identity 4ГБ + user-PML4-копия — покрыто).
    kernel_stack: [131072]u8 align(16), // Ring 0 stack (128КБ — v0.18.1: DEBUG-кадр win32_crt.dispatch ≈ 57КБ — все локали гигантского if-else живут в одном кадре; 32КБ переполнялся на 25КБ в kstack СОСЕДА — ЭТО был исходный корень cks-гонки v0.17-v0.18.0)
    cr3: u64, // Per-process PML4 physical address (0 = use kernel CR3)
    user_stack_top: u64, // Top of user stack (virtual address, for reference/cleanup)
    // v0.15.0 (CDD №6): сон задачи — планировщик пропускает до wake_tick
    // (hal.tick_count, 10мс-джиффи). 0 = не спит. ПОЧЕМУ ТАК: CV-треды curl
    // (SleepConditionVariableCS 10мс с мгновенным возвратом) жгли CPU
    // сисколами — TLS-крипто главного треда получал ~1/6 слайсов → Finished
    // опаздывал за серверный TLS-таймаут (~10с) → FIN → bad decrypt-подобные
    // провалы. Парковка: сискол мгновенно возвращается, wake откладывается.
    wake_tick: u64 = 0,
    /// v0.18.0 (CDD №9): syscall-ABI задачи (маршрутизация в hal.zig).
    abi: TaskAbi = .win32,
};

pub var tasks: [MAX_TASKS]Task = undefined;
pub var current_task_id: usize = 0;
pub var task_count: usize = 0;
pub var scheduler_ticks: u64 = 0;
// v0.16.0-fix (CDD №7): дедупликация WARN «вне собственного стека» (раз на задачу)
var warned_tasks: [MAX_TASKS]usize = .{0} ** MAX_TASKS;
var warned_n: usize = 0;
// v0.16.0-fix (CDD №7, SELF-HEAL): теневые валидные rsp (см. schedule)
pub var shadow_rsp: [MAX_TASKS]u64 = .{0} ** MAX_TASKS;
// v0.18.0 (CDD №9): счётчики подряд-мусорных кадров (FRAME-GUARD-паллиатив)
var bad_frame_drops: [MAX_TASKS]u32 = .{0} ** MAX_TASKS;
// v0.17.0-fix (CDD №8 p7): дедуп SAVE-REROUTE-печати (анти-спам 100Гц)
var last_reroute_key: u64 = 0;

// Exported variables for assembly syscall_entry
pub export var user_rsp: u64 = 0;
pub export var current_kernel_stack: u64 = 0;

/// v0.18.0 (CDD №9): 5/6-й аргументы Linux-syscall (user R8/R9). isr64.S
/// сохраняет их в САМОМ начале syscall_entry — ДО затирания R8 номером
/// (Win32-путь эти значения не читает — аддитивная запись, IF=0 от
/// SYSCALL — атомарно). Читает hal.zig для Linux-маршрутизации.
pub export var linux_arg5: u64 = 0;
pub export var linux_arg6: u64 = 0;

/// v0.20.0 (CDD №11, glibc-волна): FS-base per-task (Linux TLS —
/// arch_prctl(ARCH_SET_FS)). Диспетчер восстанавливает после свитча:
/// MSR FS живёт на CPU, а не в CR3. Win32-задачи GS-base (TEB) не трогаем.
pub var fs_base_tab: [MAX_TASKS]u64 = [_]u64{0} ** MAX_TASKS;

/// v0.18.0 (CDD №9, бисект-инструментация): трассировка тика/диспетчера/
/// syscall-входа — ловим ПЕРВЫЙ десинк cks/TSS/owner вживую.
pub var dbg_sched_trace: bool = false;

/// v0.18.1 (бисект): [E]-трейс входа syscall (ОТДЕЛЬНЫЙ от dbg1 — спами-
/// тообразный; включается командой dbg2).
pub var dbg_entry_trace: bool = false;

/// v0.18.0 (CDD №9, бисект): kstack-топ задачи (для сверки cks в syscall-входе).
pub fn taskKstackTop(id: usize) u64 {
    if (id >= task_count) return 0;
    return @intFromPtr(&tasks[id].kernel_stack) + tasks[id].kernel_stack.len;
}

/// v0.18.0 (CDD №9): физический ВЛАДЕЛЕЦ стека по RSP — задача, чей kstack
/// (или бут-стек для task 0) накрывает адрес. Это АВТОРИТЕТНЫЙ признак
/// «кто исполняется» — не зависит от current_task_id (который рассин-
/// хронизируется в окнах паркинга). Возврат 255 = вне всех стеков.
pub fn stackOwner(rsp: u64) usize {
    // idle/boot-стек линкера [0x108000, 0x10C000)
    if (rsp >= 0x108000 and rsp < 0x10C000) return 0;
    var i: usize = 1;
    while (i < task_count) : (i += 1) {
        const base: u64 = @intFromPtr(&tasks[i].kernel_stack);
        if (rsp >= base and rsp < base + tasks[i].kernel_stack.len) return i;
    }
    return 255;
}

// ─── v0.18.0 (CDD №9): PER-TASK SYSCALL STATE — таблицы владельца ──────────
//
// КОРЕНЬ cks-гонки (эмпирика [T]/[S]-трейса, QEMU 11): в окнах паркинга
// (kSleepTask hlt) current_task_id/cks РАССИНХРОНИЗИРОВАНЫ с задачей, чей
// syscall активен: следующий syscall входил по cks на ЧУЖОЙ kstack, и
// Zig-каскад (DNS-буферы, строки) ЗАТИРАЛ замороженные кадры владельца
// стека (FRAME-GUARD «кадр мусорен: ASCII/heap-указатели» — это содержимое
// ЧУЖОГО каскада). АРХИТЕКТУРНОЕ ЗАКРЫТИЕ: syscall-вход выбирает kstack ПО
// ВЛАДЕЛЬЦУ user-RSP (стеки тредов/задач УНИКАЛЬНЫ), а не по глобальному
// cks. isr64.S.scan-цикл читает эти таблицы (IF=0 от SYSCALL — атомарно):
//   1) kernel-задача: RSP уже внутри её kstack (syscall из Ring 0);
//   2) user-задача: RSP внутри ЕЁ пользовательского стека (уникален на
//      задачу/тред: главный 0x22_0000_0000±, треды из VHEAP-региона).
// Заполняются при создании задач (createTask/createUserTask/
// createUserThreadTask) и при выделении тредового стека (win32_api).

/// Низ kstack задачи (границы для asm-скана владельца).
pub export var kstack_lo_tab: [MAX_TASKS]u64 = .{0} ** MAX_TASKS;
/// Верх kstack задачи (asm: movq kstack_hi_tab(,%rax,8), %rsp).
pub export var kstack_hi_tab: [MAX_TASKS]u64 = .{0} ** MAX_TASKS;
/// Верх USER-стека задачи (0 = нет: kernel-задача/вакантный слот).
pub export var ustack_hi_tab: [MAX_TASKS]u64 = .{0} ** MAX_TASKS;
/// Низ USER-стека задачи (стек растёт вниз: lo ≤ user_rsp < hi).
pub export var ustack_lo_tab: [MAX_TASKS]u64 = .{0} ** MAX_TASKS;

/// Регистрация kstack-границ задачи в asm-таблицах (вызывается при создании).
fn registerKstack(id: usize) void {
    if (id >= MAX_TASKS) return;
    const base: u64 = @intFromPtr(&tasks[id].kernel_stack);
    kstack_lo_tab[id] = base;
    kstack_hi_tab[id] = base + tasks[id].kernel_stack.len;
}

/// Регистрация user-стека задачи (главный стек при createUserTask;
/// тредовый — при createUserThreadTask: win32_api допишет точные границы).
pub fn registerUserStack(id: usize, lo: u64, hi: u64) void {
    if (id >= MAX_TASKS) return;
    ustack_lo_tab[id] = lo;
    ustack_hi_tab[id] = hi;
}

/// v0.18.0 (CDD №9): владелец syscall-транзакции ПО USER-RSP — ЗЕРКАЛО
/// asm-скана isr64.S В ZIG. user_rsp-глобал записан ВХОДОМ ЭТОЙ ЖЕ
/// транзакции при IF=0 (атомарно, до переключения стека) — НЕ МОЖЕТ
/// ВРАТЬ (в отличие от SP внутри каскада: эмпирика InitOnce-бисекта —
/// kLaunchCallback, позванный из каскада, видел SP на ЧУЖОМ kstack).
/// Возврат 255 = вне всех диапазонов (мусорный ur / CB-стек до моста).
pub fn syscallStackOwner(ur: u64) usize {
    var i: usize = 0;
    while (i < MAX_TASKS) : (i += 1) {
        // kernel-задача: syscall из Ring 0 — ur внутри её kstack
        if (ur >= kstack_lo_tab[i] and ur < kstack_hi_tab[i] and kstack_hi_tab[i] != 0) return i;
        // user-задача/тред/колбэк-транзакция: ur внутри зарегистрированного региона
        if (ustack_hi_tab[i] != 0 and ur >= ustack_lo_tab[i] and ur < ustack_hi_tab[i]) return i;
    }
    // idle/boot-стек (kernelMain сисколы шелла ДО создания задач)
    if (ur >= 0x108000 and ur < 0x10C000) return 0;
    return 255;
}

/// v0.18.0 (CDD №9): времяянки asm-скана владельца (isr64.S): user RAX/RBX
/// сохраняются ДО цикла и восстанавливаются после выбора стека (IF=0).
pub export var syscall_num_tmp: u64 = 0;

/// v0.20.0 (CDD №11, glibc-волна): результат Zig-обработчика syscall.
/// asm сохраняет сюда RAX до восстановления аргументных регистров
/// (Linux-ABI: RDI/RSI/RDX/R10/R8/R9 прозаика syscall'а — неизменны).
pub export var syscall_ret_tmp: u64 = 0;
pub export var rbx_tmp: u64 = 0;

/// v0.18.0 (CDD №9): ABI текущей Ring-3 задачи — для syscall-маршрутизации
/// (hal.zig): linux → linux_syscalls.dispatch (RAX-ABI), иначе Win32 #6/#7.
/// Read-only эвристика: рассинк current_task_id не паникует — худший случай
/// неверный маршрутиз (=-ENOSYS), а не kernel-halt (инвариант CDD №9).
pub fn ownerAbiIsLinux() callconv(.C) bool {
    if (current_task_id >= MAX_TASKS) return false;
    return tasks[current_task_id].abi == .linux;
}


/// v0.12.0 (CDD №3): снапшот syscall-кадра активной задачи. isr64.S (путь
/// syscall_entry) копирует сюда 8 слов СПУЩЕННОГО кадра при IF=0 — ДО sti()
/// обработчика: прерывания не могут затереть данные в .bss, в отличие от
/// стека ядра. Читает win32_api.kLaunchCallback (мост InitOnce-колбэка).
/// Раскладка (порядок push'ей): [0]=r15 [1]=r14 [2]=r13 [3]=r12
/// [4]=rbp [5]=rbx [6]=r11(user RFLAGS) [7]=rcx(user RIP после syscall).
pub export var syscall_frame: [8]u64 = .{0} ** 8;

/// v0.13.0-fix (КРИТИЧНО, CDD №4): транзакция syscall Ring-3 активна.
/// isr64.S ставит 1 на входе syscall_entry и 0 перед sysretq (IF=0 —
/// атомарно). Пока флаг поднят, schedule НЕ ПЕРЕКЛЮЧАЕТ задачу: тик,
/// прервавший syscall-обработчик, и свитч на ДРУГОЙ Ring-3 контекст
/// (треды!) приводили к перезаписи глобального user_rsp чужим стеком —
/// sysretq выбрасывал задачу на ЧУЖОЙ стек (латентная гонка v0.12,
/// взорвавшаяся на 3 Ring-3 задачах: main + 2 resolver-треда).
pub export var in_win32_syscall: u64 = 0;


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

    // v0.18.0 (CDD №9): таблицы владельца для asm syscall-входа: idle
    // (task 0) живёт на бут-стеке линкера [0x108000, 0x10C000).
    kstack_lo_tab[0] = 0x108000;
    kstack_hi_tab[0] = 0x10C000;

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
    // v0.13.0-fix: путь завершения уходит в hlt-цикл ИЗНУТРИ syscall-
    // транзакции — сбросить флаг, иначе таймер не сможет вытеснить задачу
    // (schedule видит in_win32_syscall=1 и не переключает — deadlock).
    in_win32_syscall = 0;
    // v0.18.0 (CDD №9): kill ИСПОЛНИТЕЛЯ = владельца транзакции по
    // user_rsp (записан атомарным входом ЭТОГО syscall'а — не врёт).
    // Убийство «по cur» при рассинкронизированном current_task_id
    // убивало ЖИВУЮ задачу и оставляло зомби-исполнителя.
    const owner = syscallStackOwner(user_rsp);
    const victim = if (owner != 255) owner else current_task_id;
    if (victim == 0) {
        hal.Serial.puts("[SCHED] ERROR: Cannot kill idle task!\n");
        return;
    }
    hal.Serial.puts("[SCHED] Exiting task ");
    hal.Serial.putHex(victim);
    hal.Serial.puts("\n");
    tasks[victim].state = .Killed;
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
    task.wake_tick = 0; // v0.15.0: не спит при рождении

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
    fillCanary(task);
    registerKstack(id);

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
/// v0.20.0 (CDD №12 p3 — КРИТИЧЕСКИЙ ФИКС ГОНКИ): abi задаётся ПАРАМЕТРОМ
/// и пишется ДО state=.Ready. ЭМПИРИКА drm-gamescope-run7: createUserTask
/// возвращал задачу с abi=.win32 (default), вызывающий ставил .linux ПОСЛЕ
/// возврата — тик-прерывание в ЭТОМ окне переключался на задачу, ld.so
/// шлёт syscall №262 → hal-маршрутизация ownerAbiIsLinux() = FALSE →
/// легаси-свитч «[SYSCALL] Unknown syscall: 262» → все вызовы -1 → #GP
/// (вектор 0xD, ld.so+0xF52F). КЛАССИЧЕСКАЯ гонка создания.
pub fn createUserTaskAbi(entry_point: u64, user_cr3: u64, user_stack: u64, abi: TaskAbi) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.abi = abi; // АБИ ДО ДОСТУПНОСТИ планировщику (state ниже!)
    task.state = .Ready;
    task.privilege = .User;
    task.cr3 = user_cr3; // Per-process page tables!
    task.user_stack_top = user_stack;
    task.wake_tick = 0; // v0.15.0: не спит при рождении

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
    fillCanary(task);
    registerKstack(id);

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

/// v0.12.0 (CDD №3, event-волна): НАСТОЯЩИЙ Win64-тред приложения.
/// CreateThread(curl): планировщик уже мульти-задачный и PML4 у процесса
/// свой — тред = ещё одна задача на ТОМ ЖЕ CR3 (общее адресное пространство,
/// как в Windows: один процесс, несколько потоков). Отличия от createUserTask:
///   • RCX = param (Win64: ThreadProc(LPVOID) — единственный аргумент)
///   • RSP указывает на фейковый return-адрес (exit-трамплин ExitThread):
///     возврат из ThreadProc = штатное завершение потока (как CRT-тханк).
/// Вызывается ИЗ syscall-контекста процесса (CR3 = process PML4) — запись
/// exit-адреса в user-стек выполняет вызывающий (win32_api), здесь только
/// кадр задачи.
pub fn createUserThreadTask(entry_point: u64, user_cr3: u64, thread_rsp: u64, param_rcx: u64) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.state = .Ready;
    task.privilege = .User;
    task.cr3 = user_cr3;
    task.user_stack_top = thread_rsp;

    const kstack_top = @intFromPtr(&task.kernel_stack) + task.kernel_stack.len;
    const frame_ptr: *hal.InterruptFrame = @ptrFromInt(kstack_top - 176);
    @memset(@as([*]volatile u8, @ptrCast(frame_ptr))[0..176], 0);

    frame_ptr.rip = entry_point;
    frame_ptr.cs = 0x23;
    frame_ptr.rflags = 0x202; // IF=1: треду доступны прерывания/вытеснение
    frame_ptr.rsp = thread_rsp;
    frame_ptr.ss = 0x1B;
    frame_ptr.vector = 48;
    frame_ptr.error_code = 0;
    frame_ptr.rcx = param_rcx; // ThreadProc(LPVOID) — Win64 RCX

    task.rsp = @intFromPtr(frame_ptr);
    fillCanary(task);
    registerKstack(id);

    hal.Serial.puts("[SCHED] Created user THREAD ");
    hal.Serial.putDecimal(id);
    hal.Serial.puts(" at entry ");
    hal.Serial.putHex(entry_point);
    hal.Serial.puts(" param=");
    hal.Serial.putHex(param_rcx);
    hal.Serial.puts(" (shared CR3 with process)\n");

    return id;
}

/// v0.20.0 (CDD №11, p1): Linux-тред — clone(CLONE_VM|CLONE_SIGHAND…).
/// Задача с ГОТОВЫМ кадром «возврата из clone-syscall»:
///   • RAX = 0 (ребёнок: clone() возвращает 0);
///   • RSP = новый стек (аргумент clone — пишет вызывающий в frame_src);
///   • RIP = инструкция ПОСЛЕ syscall (frame_src.rip);
///   • callee-saved (rbx/rbp/r12-r15) наследуются от родителя;
///   • CR3 = родительский (CLONE_VM — общее адресное пространство);
///   • ABI = linux (RAX-маршрутизация в hal.zig).
/// Кадр-источник строит main64.linuxDoClone из syscall_frame-снапшота
/// (IF=0 от SYSCALL — снапшот атомарен, это ЭТА транзакция).
pub fn createLinuxCloneTask(user_cr3: u64, frame_src: *const hal.InterruptFrame) !usize {
    if (task_count >= MAX_TASKS) return error.OutOfTasks;

    const id = task_count;
    task_count += 1;

    const task = &tasks[id];
    task.id = id;
    task.state = .Ready;
    task.privilege = .User;
    task.cr3 = user_cr3; // CLONE_VM: общий PML4 с родителем
    task.user_stack_top = frame_src.rsp;
    task.wake_tick = 0; // не спит при рождении
    task.abi = .linux; // RAX-ABI Linux

    const kstack_top = @intFromPtr(&task.kernel_stack) + task.kernel_stack.len;
    const frame_ptr: *hal.InterruptFrame = @ptrFromInt(kstack_top - 176);
    // Полная копия кадра-источника (GPR-наследие + сегменты + IF=1)
    frame_ptr.* = frame_src.*;
    frame_ptr.rflags |= 0x200; // IF=1: прерывания/вытеснение доступны
    frame_ptr.vector = 48;
    frame_ptr.error_code = 0;

    task.rsp = @intFromPtr(frame_ptr);
    fillCanary(task);
    registerKstack(id);

    hal.Serial.puts("[SCHED] Created Linux CLONE thread ");
    hal.Serial.putDecimal(id);
    hal.Serial.puts(" RIP=");
    hal.Serial.putHex(frame_ptr.rip);
    hal.Serial.puts(" RSP=");
    hal.Serial.putHex(frame_ptr.rsp);
    hal.Serial.puts(" RAX=");
    hal.Serial.putHex(frame_ptr.rax);
    hal.Serial.puts(" (shared CR3)\n");

    return id;
}

/// v0.12.0: тред по хэндлу мёртв? (WaitForSingleObject на thread-handle).
/// Хэндл = THREAD_HANDLE_BASE + task_id (см. win32_api.kCreateThreadOp).
/// База 0x1000 — выше пулов сокетов (0x100+) и WSA-событий (0x200+),
/// чтобы threadHandleDead не принял событие за тред.
pub const THREAD_HANDLE_BASE: u64 = 0x1000;

pub fn threadHandleDead(handle: u64) bool {
    if (handle < THREAD_HANDLE_BASE) return false;
    const id = handle - THREAD_HANDLE_BASE;
    if (id == 0 or id >= task_count) return true; // вне диапазона = мёртв
    return tasks[id].state == .Killed;
}

/// v0.13.0-fix: структурная валидность кадра задачи — rsp обязан указывать
/// в ЕЁ СОбственный kernel_stack (idle — бут-стек [stack_bottom, stack_top)
/// = [0x108000, 0x10C000), см. linker64.ld).
/// v0.18.1-fix (CDD №9 residual): .bss-слот резюм-кадра задачи
/// (sched_resume.syscall_frame_tab[id]) — ВАЛИДНЫЙ адрес кадра: кадр в .bss
/// иммунен к затиранию каскадами на kstack (residual v0.18.0-RC: указатель
/// после kSleepTask-эпилога висел вглуби каскада → мусор по слотам →
/// FRAME-GUARD убивал живые треды резолвера curl после 50 пропусков).
fn taskRspValid(id: usize, rsp: u64) bool {
    if (rsp == 0 or rsp & 7 != 0) return false;
    // v0.18.1: пер-таск резюм-кадр в .bss — whitelist для диспетчеризации
    if (id != 0 and id < MAX_TASKS and rsp == sres.frameSlot(id)) return true;
    if (id == 0) {
        // idle/boot: кадры на главном бут-стеке линкера
        return rsp >= 0x108000 and rsp < 0x10C000;
    }
    if (id >= task_count) return false;
    const base: u64 = @intFromPtr(&tasks[id].kernel_stack);
    return rsp >= base and rsp < base + tasks[id].kernel_stack.len;
}

/// v0.17.0 (CDD №8): валидность СОДЕРЖИМОГО кадра (InterruptFrame).
/// v0.18.1: ПЕРЕНЕСЕНО в чистый модуль sched_resume.zig (нативные тесты);
/// alias сохраняет все точки вызова в scheduler.zig без правок.
const frameContentValid = sres.frameContentValid;

/// v0.18.1 (CDD №9, residual-fix): снапшот резюм-кадра задачи из ЖИВОГО
/// syscall-каскада (вызывается kSleepTask ДО парковки — каскад ещё на
/// kstack-топе владельца). Слот .bss переживает любые каскады: указатель
/// tasks[owner].rsp остаётся валидным ВСЕГДА (см. sched_resume.zig).
pub fn snapshotResumeFrame(owner: usize, ur: u64) void {
    if (owner == 0 or owner >= MAX_TASKS) return;
    sres.snapshotSyscallFrame(owner, taskKstackTop(owner), ur);
}

/// v0.18.1 (CDD №9, residual-fix): направить резюм-указатель задачи на
/// .bss-слот (эпилог kSleepTask, ПОСЛЕ снятия будильника). Кадр — точка
/// «после syscall» (сон завершён): диспетчеризация из него корректна;
/// невалидные окна «sysretq → первый тик» закрыты. Попутно реанимируем
/// теневую копию (FRAME-HEAL) и ОБНУЛЯЕМ счётчик пропусков FRAME-GUARD —
/// тред резолвера больше не отсекается по накопленным пропускам (семан-
/// тика «50 подряд» вместо «50 суммарно» — счётчик живого кадра честно
/// сбрасывается).
pub fn installResumeFrame(owner: usize) void {
    if (owner == 0 or owner >= MAX_TASKS) return;
    const slot = sres.frameSlot(owner);
    if (slot == 0) return;
    tasks[owner].rsp = slot;
    shadow_rsp[owner] = slot;
    bad_frame_drops[owner] = 0; // живой кадр — пропуск-таймаут не копится
}



/// v0.13.0-fix: заполнить низ kstack задачи паттерном (детектор overflow).
fn fillCanary(task: *Task) void {
    const base: usize = @intFromPtr(&task.kernel_stack);
    var i: usize = 0;
    while (i < CANARY_BYTES) : (i += 8) {
        @as(*volatile u64, @ptrFromInt(base + i)).* = KSTACK_CANARY ^ @as(u64, task.id << 32) ^ i;
    }
}

/// Проверить канарейку задачи (true = цела).
fn canaryOk(id: usize) bool {
    if (id == 0 or id >= task_count) return true; // idle — бут-стек, без канарейки
    const base: usize = @intFromPtr(&tasks[id].kernel_stack);
    var i: usize = 0;
    while (i < CANARY_BYTES) : (i += 8) {
        const v = @as(*volatile u64, @ptrFromInt(base + i)).*;
        if (v != (KSTACK_CANARY ^ @as(u64, @as(u64, id) << 32) ^ i)) return false;
    }
    return true;
}

pub fn schedule(current_rsp: u64) callconv(.C) u64 {
    if (task_count <= 1) return current_rsp; // Only idle/kernel task exists
    // v0.13.0-fix: syscall-транзакция активна — НЕ трогаем контекст задачи
    // (user_rsp/current_kernel_stack глобальны — свитч между Ring-3
    // задачами внутри syscall = порча; ждем sysretq, потом свободный тик).
    // v0.17.0-fix (CDD №8 p5-lite): РЕ-СИНК cks из flag-guard УДАЛЁН — при
    // рассинхронизированном current_task_id (окна паркинга: эмпирика
    // QEMU -d int — hlt-парк задачи X прерывался тиком при current==X+1)
    // ресинк ИНЖЕКТИРОВАЛ чужой kstack-топ → следующий syscall задачи
    // входил на ЧУЖОЙ стек (каскад WARN/FRAME-GUARD). Единственный писец
    // cks теперь — диспетчеризация ниже (iretq-авторитет: куда ушли —
    // тот стек и актуален).
    if (in_win32_syscall != 0) {
        return current_rsp;
    }
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
    if (current_rsp == 0) {
        // v0.13.0-fix (диагностика): ЗАПИСЬ НУЛЯ в tasks[].rsp — источник
        // kernel-panic @ptrFromInt(0). Кто передал current_rsp=0?
        hal.Serial.puts("[SCHED] !!! WRITE-0: current_task=");
        hal.Serial.putDecimal(current_task_id);
        hal.Serial.puts(" tick=");
        hal.Serial.putDecimal(scheduler_ticks);
        hal.Serial.puts(" tasks=");
        hal.Serial.putDecimal(task_count);
        hal.Serial.puts("\n");
    }
    // v0.17.0-fix (CDD №8 p7): SCAN-SAVE — адресат = ВЛАДЕЛЕЦ стека кадра.
    // Эмпирика QEMU -d int: current_task_id рассинхронизируется в окнах
    // паркинга (hlt-парк задачи X прерывается тиком при current==X+1),
    // при этом сам кадр (с p6/TSS-входом) лежит НА СВОЁМ kstack. Отказ
    // от сохранения валидного кадра оставлял tasks[X].rsp на стале
    // (инициальный кадр, затёртый syscall-слотами) → FRAME-GUARD ложно
    // убивал ЖИВЫЕ треды резолвера curl. Лечение: кадр сохраняется задаче,
    // НА ЧЬЁМ kstack он физически лежит (≤8 слотов; task 0 — бут-стек);
    // вне всех стеков — отказ (SAVE-GUARD, раз на задачу — анти-спам).
    var save_id: usize = current_task_id;
    if (!taskRspValid(save_id, current_rsp)) {
        var owner_found = false;
        var oid: usize = 0;
        while (oid < task_count) : (oid += 1) {
            if (taskRspValid(oid, current_rsp)) {
                save_id = oid;
                owner_found = true;
                break;
            }
        }
        if (owner_found and save_id != current_task_id) {
            // Печать — ТОЛЬКО при смене пары (cur,owner): анти-спам (эмпирика:
            // рассинхрон висел долго → сотни одинаковых строк на 100Гц).
            const key: u64 = @as(u64, @intCast(current_task_id)) * 16 + @as(u64, @intCast(save_id));
            if (key != last_reroute_key) {
                last_reroute_key = key;
                hal.Serial.puts("[SCHED] SAVE-REROUTE: кадр 0x");
                hal.Serial.putHex(current_rsp);
                hal.Serial.puts(" -> task ");
                hal.Serial.putDecimal(save_id);
                hal.Serial.puts(" (cur был ");
                hal.Serial.putDecimal(current_task_id);
                hal.Serial.puts(")\n");
            }
        }
        if (!owner_found) {
            var sg_warn = true;
            for (warned_tasks) |w| {
                if (w == current_task_id) sg_warn = false;
            }
            if (sg_warn and warned_n < warned_tasks.len) {
                warned_tasks[warned_n] = current_task_id;
                warned_n += 1;
                hal.Serial.puts("[SCHED] SAVE-GUARD: кадр rsp=0x");
                hal.Serial.putHex(current_rsp);
                hal.Serial.puts(" вне всех kstack (cur=");
                hal.Serial.putDecimal(current_task_id);
                hal.Serial.puts(") — НЕ сохранён\n");
            }
            save_id = 0; // отказ: ниже валидация отсечёт
        }
    }
    if (save_id != 0 and taskRspValid(save_id, current_rsp)) {
        // v0.18.0 (CDD №9): КОНТЕНТ-ВАЛИДАЦИЯ ПЕРЕД ЗАПИСЬЮ. Эмпирика
        // бисекта: точки-вглубь-Zig-каскада попадали в tasks[].rsp (кадр
        // «мусорен» по слотам CS/RIP → ложный FRAME-GUARD-kill живого
        // резолвера). Невалидный по содержимому кадр НЕ сохраняем —
        // остаётся прежний (замороженный, валидный) указатель задачи.
        if (frameContentValid(current_rsp)) {
            tasks[save_id].rsp = current_rsp;
            // v0.16.0-fix (CDD №7, SELF-HEAL): теневой слепок валидного rsp —
            // кадр на СОБСТВЕННОМ kstack (портился только УКАЗАТЕЛЬ — теневая
            // копия полностью реанимирует тред).
            if (save_id != 0) shadow_rsp[save_id] = current_rsp;
        } else if (shadow_rsp[save_id] == 0) {
            // тени нет и контент мусорен — деградация до v0.17-поведения
            // (сохраняем структурно-валидный указатель: лучше, чем потерять)
            tasks[save_id].rsp = current_rsp;
        }
    }
    if (tasks[current_task_id].state == .Running) {
        tasks[current_task_id].state = .Ready;
    }

    // Select the next task using Round-Robin. v0.13.0-fix: валидация
    // КАНДИДАТА до мутации состояния — СТРУКТУРНАЯ: кадр обязан лежать
    // В СОБСТВЕННОМ kstack задачи (idle — бут-стек). Мусорный rsp (порча/
    // переполнение/расхождение) → задача ПРОПУСКАЕТСЯ; живой fallback —
    // остаться в текущей (current_rsp валиден по построению).
    var next_id = (current_task_id + 1) % task_count;
    var checked: usize = 0;
    var found = false;
    var bad_rsp: u64 = 0;
    var bad_id: usize = 0;
    const now = hal.tick_count; // v0.15.0: сон-парковка задач
    while (checked < task_count) : ({
        next_id = (next_id + 1) % task_count;
        checked += 1;
    }) {
        if (tasks[next_id].wake_tick != 0 and tasks[next_id].wake_tick > now) {
            continue; // спит (Sleep/CV) — слайс не даём
        }
        if (tasks[next_id].state == .Ready or tasks[next_id].state == .Running) {
            if (taskRspValid(next_id, tasks[next_id].rsp)) {
                if (frameContentValid(tasks[next_id].rsp)) {
                    found = true;
                    // v0.18.1 (бисект): диспетчеризация из .bss-слота — редкое
                    // событие (парковка без сохранённого hlt-кадра); трассируем.
                    if (tasks[next_id].rsp == sres.frameSlot(next_id)) {
                        hal.Serial.puts("[SCHED] RESUME-SLOT: task ");
                        hal.Serial.putDecimal(next_id);
                        hal.Serial.puts("\n");
                    }
                    // v0.18.1-fix: живой кадр — счётчик пропусков FRAME-GUARD
                    // обнуляется. Прежде «50 суммарных» пропусков копились
                    // сквозь валидные окна (flapping) и убивали живой тред
                    // резолвера curl — теперь честные «50 ПОДРЯД».
                    bad_frame_drops[next_id] = 0;
                    break;
                }
                // v0.17.0-fix (CDD №8 p5+): СНАЧАЛА ТЕНЬ. Кадр-мусор = чаще
                // всего STALE-указатель (инициальный кадр, затёртый syscall-
                // слотами — эмпирика curl-тредов), а НЕ реальная порча:
                // теневая копия (последний валидный кадр парка) полностью
                // реанимирует тред. Килл — только если и тень мертва.
                if (shadow_rsp[next_id] != 0 and taskRspValid(next_id, shadow_rsp[next_id])
                    and frameContentValid(shadow_rsp[next_id]))
                {
                    tasks[next_id].rsp = shadow_rsp[next_id];
                    bad_frame_drops[next_id] = 0; // v0.18.1: тень жива — пропуски прощены
                    hal.Serial.puts("[SCHED] FRAME-HEAL: task ");
                    hal.Serial.putDecimal(next_id);
                    hal.Serial.puts(" кадр восстановлен из тени (0x");
                    hal.Serial.putHex(shadow_rsp[next_id]);
                    hal.Serial.puts(")\n");
                    found = true;
                    break;
                }
                // v0.17.0 (CDD №8): указатель корректен, СОДЕРЖИМОЕ кадра —
                // мусор. v0.18.0 (CDD №9): НЕ убиваем сразу — ПРОПУСК с
                // лимитом: старый hlt-ISR-кадр мог быть перезаписан СЛЕДУЮЩИМ
                // каскадом этой же задачи (эмпирика бисекта: tasks[].rsp
                // указывает вглубь собственного каскада задачи, пока она
                // паркуется/исполняется) — ближайший валидный SAVE
                // (kSleepTask-цикл) реанимирует указатель. 50 тиков
                // (0.5с) без валидного кадра → честный kill (анти-livelock).
                bad_frame_drops[next_id] += 1;
                if (bad_frame_drops[next_id] >= 50) {
                    tasks[next_id].state = .Killed;
                    bad_frame_drops[next_id] = 0;
                    hal.Serial.puts("[SCHED] FRAME-GUARD: task ");
                    hal.Serial.putDecimal(next_id);
                    hal.Serial.puts(" убита (кадр мусорен 50 тиков: CS=0x");
                    hal.Serial.putHex(@as(*volatile u64, @ptrFromInt(tasks[next_id].rsp + 144)).*);
                    hal.Serial.puts(" RIP=0x");
                    hal.Serial.putHex(@as(*volatile u64, @ptrFromInt(tasks[next_id].rsp + 136)).*);
                    hal.Serial.puts(" rsp_ptr=0x");
                    hal.Serial.putHex(tasks[next_id].rsp);
                    hal.Serial.puts(") — ядро живёт\n");
                }
                continue;
            }
            if (bad_rsp == 0) {
                bad_rsp = tasks[next_id].rsp;
                bad_id = next_id;
            }
        }
    }
    if (bad_rsp != 0) {
        // v0.16.0-fix (CDD №7, SELF-HEAL): гонка сохраняла кадр-на-чужом-
        // стеке как rsp задачи — тред застревал навечно. Валидный кадр на
        // СВОЁМ стеке цел (порча только указателя): восстанавливаем теневую
        // копию — тред реанимирован на следующем же тике.
        if (bad_id != 0 and shadow_rsp[bad_id] != 0 and taskRspValid(bad_id, shadow_rsp[bad_id])) {
            tasks[bad_id].rsp = shadow_rsp[bad_id];
            hal.Serial.puts("[SCHED] SELF-HEAL: task ");
            hal.Serial.putDecimal(bad_id);
            hal.Serial.puts(" rsp восстановлен из тени (0x");
            hal.Serial.putHex(shadow_rsp[bad_id]);
            hal.Serial.puts(")\n");
            bad_rsp = 0; // реанимирован — не считаем падением
        }
    }
    if (bad_rsp != 0) {
        // CDD-трейс: ПОРЧА кадров — не роняем ядро, пропускаем задачу.
        // v0.16.0-fix (CDD №7): печатаем ОДИН РАЗ на задачу — иначе 100Гц-тик
        // × серийный порт = тысячи строк/с (замедление тика и шум лога).
        var print_warn = true;
        for (warned_tasks) |w| {
            if (w == bad_id) print_warn = false;
        }
        if (print_warn and warned_n < warned_tasks.len) {
            warned_tasks[warned_n] = bad_id;
            warned_n += 1;
            hal.Serial.puts("[SCHED] WARN: task ");
            hal.Serial.putDecimal(bad_id);
            hal.Serial.puts(" rsp=0x");
            hal.Serial.putHex(bad_rsp);
            hal.Serial.puts(" вне [0x");
            const bbase: u64 = @intFromPtr(&tasks[bad_id].kernel_stack);
            hal.Serial.putHex(bbase);
            hal.Serial.puts(",0x");
            hal.Serial.putHex(bbase + tasks[bad_id].kernel_stack.len);
            hal.Serial.puts("] cks=0x");
            hal.Serial.putHex(current_kernel_stack);
            hal.Serial.puts(" cur=");
            hal.Serial.putDecimal(current_task_id);
            hal.Serial.puts(" state=");
            hal.Serial.putDecimal(@intFromEnum(tasks[bad_id].state));
            hal.Serial.puts(" wake=");
            hal.Serial.putDecimal(tasks[bad_id].wake_tick);
            hal.Serial.puts("\n");
        }
    }
    if (!found) {
        // Никто не готов С валидным кадром — не переключаемся вообще:
        // возвращаем ТЕКУЩИЙ кадр (никакой мутации current_task_id/TSS).
        return current_rsp;
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
    tasks[current_task_id].wake_tick = 0; // v0.15.0: проснулась по будильнику

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

    // v0.20.0 (CDD №11, glibc-волна): FS-base Linux-задачи (TLS).
    // Win32-задачам GS-base (TEB) — постоянный, FS не читают. Восстановление
    // идемпотентно: MSR-запись ~50 тактов, свитчи Linux-тредов редки.
    if (next_task.abi == .linux) {
        const fs = fs_base_tab[current_task_id];
        if (fs != 0) {
            hal.writeMsr(hal.MSR.FS_BASE, fs);
        }
    }

    return next_task.rsp;
}

// ============================================================================
// v0.15.0 (CDD №6): сон задач — парковка до wake_tick
// ============================================================================

/// Поставить будильник ТЕКУЩЕЙ задаче: ms миллисекунд (тик = 10мс,
/// калибровка APIC-таймера в hal). Сискол (Sleep/CV) мгновенно вернётся
/// в Ring 3, но планировщик НЕ даст задаче слайс до истечения — воркеры
/// паркуются, крипто-тред curl получает CPU. Гард: ms=0 — сброс (не спит),
/// потолок 60с (диагностический таймаут livelock-охоты).
pub fn setTaskSleep(ms: u64) void {
    if (current_task_id >= task_count) return;
    setTaskSleepFor(current_task_id, ms);
}

/// v0.18.0 (CDD №9): будильник КОНКРЕТНОЙ задаче — владелец физического
/// стека каскада (не current_task_id: в окнах паркинга он рассинхронизи-
/// рован — будильник «не той» задаче = потерянный wake + чужой слайс).
pub fn setTaskSleepFor(id: usize, ms: u64) void {
    if (id >= task_count) return;
    if (ms == 0) {
        tasks[id].wake_tick = 0;
        return;
    }
    const capped: u64 = @min(ms, 60_000);
    const ticks = (capped + 9) / 10; // округление вверх: Sleep(1) ≥ 1 тик
    tasks[id].wake_tick = hal.tick_count + ticks;
}
