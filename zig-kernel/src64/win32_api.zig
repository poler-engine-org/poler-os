// ============================================================================
// POLER-OS Win32 API — kernel-проводка (v0.12.0, CDD-цикл №3)
// ============================================================================
//
// ТОНКИЙ слой между hal (syscall #6/#7) и ЧИСТОЙ семантикой win32_crt.zig:
// устанавливает Ops-инъекцию (installOps) с НАСТОЯЩИМИ платформенными
// примитивами:
//   validate_read/write — walk таблиц PML4 процесса через identity
//                         (vmm.userLeafFlags): USER-бит обязателен (иначе
//                         Ring 3 не мог бы сам тронуть страницу — security),
//                         для записи ещё и WRITABLE. Мусорный указатель из
//                         приложения → отказ, а НЕ #PF-паника ядра.
//   map_user            — PMM-страницы + vmm.mapPageInPML4 (RW+USER+NX) в
//                         heap-регионы процесса (block-heap + VirtualAlloc).
//   read_tsc            — hal.readMsr(0x10) (IA32_TSC).
//   write_console       — hal.Serial (текст приложения попадает в консоль ОС).
//   log                 — hal.Serial ([WIN32]/[CDD]-трейс).
//   exit                — exitCallback (scheduler kill) + hlt.
//   launch_callback     — v0.12.0: мост Win64-колбэка (InitOnceExecuteOnce):
//                         сохранение syscall-кадра + mailbox + ucl_pending →
//                         isr64.S уводит sysretq в launcher (Ring 3),
//                         trampoline возвращает через syscall #7.
//   stack_arg           — v0.12.0: Win64-аргументы 5+ читаются из user-стека
//                         (scheduler.user_rsp + 0x18 + idx*8).
//
// Вся семантика (dispatch по именам, block-heap, GetProcAddress, ленивые
// CRT-структуры) живёт в win32_crt.zig и покрыта нативными тестами; здесь —
// только платформенные примитивы, покрытие через QEMU E2E.
//
// ⚠ Инвариант (см. шапку win32_crt.zig): прямой доступ к user-VA валиден в
// syscall-контексте (CR3 = PML4 процесса). Все вызовы идут через hal case 6.
// ============================================================================

const std = @import("std");
const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const win32 = @import("win32_stubs.zig");
const crt = @import("win32_crt.zig");
const scheduler = @import("scheduler.zig");
const virtio_net = @import("virtio_net.zig");

pub const PAGE_SIZE: u64 = 4096;

/// Длина одного validate-диапазона ограничена (мегабайтные memset из мусорных
/// аргументов не должны крутить walk миллионы итераций).
const MAX_VALIDATE_LEN: u64 = 64 * 1024 * 1024;

// ─── Установка Ops (kernelMain, после инициализации hal/vmm/pmm) ────────────

pub fn installOps() void {
    crt.ops = .{
        .validate_read = kValidateRead,
        .validate_write = kValidateWrite,
        .map_user = kMapUser,
        .read_tsc = kReadTsc,
        .write_console = kWriteConsole,
        .log = kLog,
        .exit = kExit,
        .launch_callback = kLaunchCallback,
        .stack_arg = kStackArg,
        .create_thread = kCreateThreadOp,
        .exit_task = kExitTask,
        .object_signaled = kObjectSignaled,
        .current_tid = kCurrentTid,
        // v0.14.0 (CDD №5): реальный сетевой обмен (virtio-net → SLIRP)
        .net_ready = kNetReady,
        .net_dns_resolve = kNetDnsResolve,
        .net_tcp_connect = kNetTcpConnect,
        .net_tcp_send = kNetTcpSend,
        .net_tcp_recv = kNetTcpRecv,
        .net_tcp_poll = kNetTcpPoll,
        .net_tcp_close = kNetTcpClose,
        .sleep_task = kSleepTask,
    };
}

// ─── v0.14.0 (CDD №5): virtio-net мост (syscall-контекст, CR3=user — CPL=0
//     читает USER-страницы и пишет supervisor identity-DMA: без SMAP ок) ────

fn kNetReady() bool {
    return virtio_net.isInitialized();
}

fn kNetDnsResolve(host: [*]const u8, host_len: usize) u64 {
    if (host_len == 0 or host_len > 127) return 0;
    const h = host[0..host_len];
    const ip = virtio_net.dnsResolve(h) orelse return 0;
    hal.Serial.puts("[VNET] DNS ");
    hal.Serial.puts(h);
    hal.Serial.puts(" -> ");
    hal.Serial.putDecimal(ip[0]);
    hal.Serial.puts(".");
    hal.Serial.putDecimal(ip[1]);
    hal.Serial.puts(".");
    hal.Serial.putDecimal(ip[2]);
    hal.Serial.puts(".");
    hal.Serial.putDecimal(ip[3]);
    hal.Serial.puts("\n");
    return (@as(u64, ip[0]) << 24) | (@as(u64, ip[1]) << 16) |
        (@as(u64, ip[2]) << 8) | ip[3];
}

fn kNetTcpConnect(be_ip: u64, port: u16) i64 {
    const ip = [4]u8{
        @truncate(be_ip >> 24),
        @truncate(be_ip >> 16),
        @truncate(be_ip >> 8),
        @truncate(be_ip),
    };
    const slot = virtio_net.tcpConnect(ip, port) catch |err| {
        hal.Serial.puts("[VNET] tcpConnect failed: ");
        hal.Serial.puts(@errorName(err));
        hal.Serial.puts("\n");
        return -1;
    };
    return @intCast(slot);
}

fn kNetTcpSend(slot: i64, data: [*]const u8, len: usize) i64 {
    if (len == 0) return 0;
    if (len > 64 * 1024 * 1024) return -1;
    const sent = virtio_net.tcpSend(@intCast(slot), data[0..len]) catch return -1;
    return @intCast(sent);
}

fn kNetTcpRecv(slot: i64, out: [*]u8, cap: usize) i64 {
    const n = virtio_net.tcpRecv(@intCast(slot), out[0..cap], false) catch |err| {
        if (err == error.ConnClosed) return -1;
        return 0;
    };
    return @intCast(n);
}

fn kNetTcpPoll(slot: i64) i64 {
    return virtio_net.tcpPoll(@intCast(slot));
}

fn kNetTcpClose(slot: i64) void {
    virtio_net.tcpClose(@intCast(slot));
}

/// v0.15.0 (CDD №6): НАСТОЯЩИЙ сон задачи — кооперативная парковка.
/// Проблема (диагноз https-разведки): CV-треды curl зовут
/// SleepConditionVariableCS(10мс) тысячами раз/с; с мгновенным возвратом
/// они жгут CPU, а in_win32_syscall≈всегда поднят → schedule() не тикает →
/// TLS-крипто главного треда получает крохи слайсов → Finished опаздывает
/// за серверный TLS-таймаут.
/// Решение: внутри syscall-транзакции АТОМАРНО (cli) опускаем флаг и
/// уходим в hlt-цикл до дедлайна — таймерные тики переключают задачи
/// (паркованная пропускается по wake_tick), CPU спит. Перед возвратом
/// восстанавливаем СВОЙ user_rsp (его мог затереть syscall чужой задачи)
/// и флаг транзакции — asm-exit сделает sysretq на НАШ стек.
fn kSleepTask(ms: u64) void {
    if (ms == 0) return;
    const capped: u64 = @min(ms, 60_000);
    const deadline = hal.tick_count + (capped + 9) / 10;

    // Наш user_rsp (записан НАШИМ syscall_entry; флаг с этого момента был
    // поднят — чужие syscall его затереть не могли)
    const my_rsp = scheduler.user_rsp;

    // Будильник планировщику: слайс паркованной не давать
    scheduler.setTaskSleep(capped);

    // Отпускаем транзакцию — атомарно под cli (тика между cli и sti нет)
    hal.cli();
    scheduler.in_win32_syscall = 0;
    hal.sti();

    // Спим: hlt до прерывания; тик может переключить нас (wake_tick гардит
    // повторную выдачу слайса до дедлайна). Возврат — когда дедлайн прошёл.
    var guard: u64 = 0;
    while (@as(i64, @bitCast(deadline -% hal.tick_count)) > 0) {
        asm volatile ("hlt" ::: "memory");
        guard += 1;
        if (guard > 60_000) break; // 600с страховка от зависшего таймера
    }

    // Возврат в транзакцию: user_rsp мог быть перезаписан syscall'ами задач,
    // исполнявшихся в парковке — восстанавливаем свой под cli.
    hal.cli();
    scheduler.user_rsp = my_rsp;
    scheduler.in_win32_syscall = 1;
    hal.sti();
    // будильник снят (или снимется при следующем dispatch)
    if (scheduler.current_task_id < scheduler.task_count) {
        scheduler.tasks[scheduler.current_task_id].wake_tick = 0;
    }
}

// ─── v0.12.0 (threading-волна): НАСТОЯЩИЕ Win64-треды ────────────────────────

/// CreateThread-примитив: запись exit-адреса в user-стек (CR3 = PML4
/// процесса — syscall-контекст!) + scheduler.createUserThreadTask.
/// Хэндл = THREAD_HANDLE_BASE(0x1000) + task_id.
fn kCreateThreadOp(start: u64, param: u64, stack_top: u64, exit_va: u64) u64 {
    const c = (crt.ctx orelse return 0);
    // [rsp] = exit-адрес: имитация call-кадра ThreadProc
    const sp: *volatile u64 = @ptrFromInt(stack_top - 8);
    sp.* = exit_va;
    // верх стека 16-выровнен → RSP = stack_top-8 даёт entry RSP ≡ 8 (mod 16)
    const id = scheduler.createUserThreadTask(start, c.pml4, stack_top - 8, param) catch return 0;
    return scheduler.THREAD_HANDLE_BASE + id;
}

/// ExitThread: убить ТЕКУЩУЮ задачу (hlt до вытеснения — как kExit).
fn kExitTask() void {
    if (scheduler.current_task_id == 0) return;
    scheduler.exitCurrentTask();
    while (true) {
        asm volatile ("hlt");
    }
}

/// Объект сигнален? Тред-хэндл (0x1000+id) — сигнал = задача Killed
/// (WaitForSingleObject(thread) у curl: резолвер закончил работу).
fn kObjectSignaled(handle: u64) bool {
    return scheduler.threadHandleDead(handle);
}

/// Реальный TID: task_id + 0x1000 — уникален для главного треда и резолвера.
fn kCurrentTid() u64 {
    return 0x1000 + scheduler.current_task_id;
}

// ─── Точка входа syscall #6 (hal.win32SyscallCallback) ──────────────────────

pub fn syscallDispatch(entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    return crt.syscallDispatch(entry_id, a1, a2, a3, a4);
}

// ─── Платформенные примитивы (kernel) ───────────────────────────────────────

/// Walk таблиц PML4 процесса: каждая страница диапазона обязана быть present
/// и USER (иначе это не память приложения — kernel-VA/подделка → отказ).
/// Постраничная гранулярность: диапазон может пересекать границы страниц.
fn validateRange(va: u64, len: u64, want_write: bool) bool {
    const c = (crt.ctx orelse return false);
    if (len == 0) return true;
    if (len > MAX_VALIDATE_LEN) return false;
    if (va < 0x1000) return false; // NULL-страница — не бывает user-данных

    var off: u64 = 0;
    while (off < len) {
        const p = va + off;
        const leaf = vmm.userLeafFlags(c.pml4, p) orelse return false;
        if (leaf & vmm.PTE_USER == 0) return false; // security: supervisor-VA
        if (want_write and (leaf & vmm.PTE_WRITABLE == 0)) return false;
        off += PAGE_SIZE - (p & (PAGE_SIZE - 1)); // до конца текущей страницы
    }
    return true;
}

fn kValidateRead(va: u64, len: u64) bool {
    return validateRange(va, len, false);
}

fn kValidateWrite(va: u64, len: u64) bool {
    return validateRange(va, len, true);
}

/// Выделить и замапить страницы heap-региона [va, va+bytes): PMM (обнулённые)
/// + VMM (RW+USER+NX) в PML4 процесса. va обязан быть page-aligned
/// (вызывают только kmalloc/virtualAlloc с выровненными курсорами).
fn kMapUser(va: u64, bytes: u64) bool {
    const c = (crt.ctx orelse return false);
    if (va % PAGE_SIZE != 0 or bytes == 0 or bytes > MAX_VALIDATE_LEN) return false;
    const pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const pa = pmm.allocContiguousZeroed(1) orelse return false;
        vmm.mapPageInPML4(c.pml4, va + i * PAGE_SIZE, pa, vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE) catch return false;
    }
    return true;
}

fn kReadTsc() u64 {
    return hal.readMsr(0x10); // IA32_TSC
}

fn kWriteConsole(s: []const u8) void {
    hal.Serial.puts(s);
}

fn kLog(s: []const u8) void {
    hal.Serial.puts(s);
}

/// Завершение PE-процесса: exitCallback (планировщик пометит задачу Killed),
/// дальше hlt до вытеснения. Возврата нет — syscall-обработчик не вернётся.
fn kExit(code: u64) void {
    hal.Serial.puts("[WIN32] ExitProcess(");
    hal.Serial.putHex(code);
    hal.Serial.puts(") — PE-процесс завершился штатно\n");
    if (hal.exitCallback) |cb| cb();
    while (true) {
        asm volatile ("hlt");
    }
}

// ============================================================================
// v0.12.0 (CDD №3): МОСТ ЗАПУСКА WIN64-КОЛБЭКА (InitOnceExecuteOnce)
// ============================================================================
//
// Прямой call user-кода из CPL=0 запрещён архитектурно: колбэк, вызвав любой
// импорт-трамплин, сделает SYSCALL из Ring 0, а SYSRET всегда возвращает CPL=3
// → ядро продолжит исполнение в Ring 3 → #PF на supervisor-страницах.
//
// Схема (артефакты кода генерирует win32_stubs.buildCallbackBridge):
//
//   curl(R3) → impl-стаб InitOnce → SYSCALL#6 [кадр сохранён в syscall_frame
//   при IF=0] → dispatch → initOnceExecuteOnce → kLaunchCallback:
//     1. снапшот syscall-кадра (RCX/R11/RBX/RBP/R12-15, user_rsp) → CallbackState
//     2. dedicated callback-стек 16КБ из block-heap (RSP 16-aligned)
//     3. mailbox ← {init_once, parameter, context, init_fn} (identity-запись)
//     4. ucl_pending=1 → isr64.S после обработчика делает sysretq В LAUNCHER
//   launcher(R3): RCX/RDX/R8 ← mailbox; push trampoline; jmp InitFn
//   колбэк исполняется НАСТОЯЩИМ Ring 3 (может звать любые стабы — syscall
//   из Ring 3 теперь легален!) → ret → trampoline:
//     mov rsi,rax; movabs rdi,cookie; movabs rax,7; SYSCALL
//   syscall#7 → callbackDone: помечает INIT_ONCE=2, ПЕРЕЗАПИСЫВАЕТ кадр
//   asm-возврата сохранёнными значениями (cli — атомарно) → asm поп-ы →
//   sysretq → ВОЗВРАТ В ТОЧКУ ПОСЛЕ ИСХОДНОГО SYSCALL'а, RAX=TRUE/FALSE.
//
// Инвариант однопроцессности CDD: user_rsp/syscall_frame/ucl_* — глобальные
// переменные; единственный Ring-3 процесс в системе — PE-задача (шелл и
// воркеры — kernel-задачи без syscall), поэтому конкуренции за них нет.

/// Состояние моста. isr64.S читает ucl_* (launch-path) через .extern.
pub export var ucl_pending: u64 = 0; // 1 = после syscall-обработчика уйти в launcher
pub export var ucl_rsp: u64 = 0; // RSP колбэка (16-aligned dedicated-стек)
pub export var ucl_rip: u64 = 0; // RCX для sysretq = VA launcher'а
pub export var ucl_rflags: u64 = 0; // R11 для sysretq = user-RFLAGS исходного syscall

/// Артефакты моста в user-VA (заполняет main64.cmd_peload после генерации
/// стабов: launcher/trampoline/mailbox в хвосте стаб-региона).
pub var bridge: ?win32.Dispatcher.CallbackBridge = null;

/// Saved-состояние ОДНОЙ транзакции моста (запуск колбэка + возврат).
const CallbackState = struct {
    active: bool = false,
    init_once: u64, // пометить 2 при успехе колбэка
    cookie: u64, // секрет трассировки trampoline → callbackDone
    resume_rip: u64, // RCX исходного syscall'а (точка после syscall-инструкции)
    resume_rsp: u64, // user_rsp исходного syscall'а (кадр стаба: rdi/rsi/ret)
    resume_rflags: u64, // R11 исходного syscall'а
    resume_rbx: u64,
    resume_rbp: u64,
    resume_r12: u64,
    resume_r13: u64,
    resume_r14: u64,
    resume_r15: u64,
};

/// Стек транзакций (v0.12.0-fix): curl может запустить InitOnce ВНУТРИ
/// колбэка (глубокая инициализация: global_init → ssl → schannel).
/// Каждый syscall #6 InitOnce PUSHит транзакцию; syscall #7 (trampoline)
/// POPает верхнюю и восстанавливает ЕЁ кадр — возврат внутрь внешнего
/// колбэка. Глубина 8 — с запасом; исчерпание → отказ запуска (колбэк
/// увидит FALSE — честная деградация, не катастрофа).
const CB_DEFAULT: CallbackState = .{
    .active = false,
    .init_once = 0,
    .cookie = 0,
    .resume_rip = 0,
    .resume_rsp = 0,
    .resume_rflags = 0,
    .resume_rbx = 0,
    .resume_rbp = 0,
    .resume_r12 = 0,
    .resume_r13 = 0,
    .resume_r14 = 0,
    .resume_r15 = 0,
};
var cb_stack: [8]CallbackState = .{CB_DEFAULT} ** 8;
var cb_depth: usize = 0; // число активных транзакций (cb_stack[0..cb_depth])

/// Cookie транзакции = значение, ЗАПЕЧЁННОЕ в trampoline при генерации
/// моста (win32.CALLBACK_COOKIE): тройка launcher/mailbox/trampoline
/// существует в единственном экземпляре на процесс — этого достаточно.
const CB_COOKIE_BAKED: u64 = win32.CALLBACK_COOKIE;

/// ops.launch_callback (syscall #6 → win32_crt.initOnceExecuteOnce).
/// true → isr64.S уводит возврат в launcher (сам возврат dispatch — мусор).
/// v0.12.0-fix: PUSHит транзакцию в cb_stack — вложенные InitOnce
/// (колбэк, запускающий свой InitOnce) поддержаны до глубины 8.
fn kLaunchCallback(init_once: u64, init_fn: u64, parameter: u64, context: u64) bool {
    if (cb_depth >= cb_stack.len) return false; // глубина исчерпана
    const br = bridge orelse return false;
    if (win32.activeDispatcher() == null) return false;

    // Валидация: колбэк — код процесса (читаем), INIT_ONCE — user-память
    if (!kValidateRead(init_fn, 16)) return false;
    if (!kValidateWrite(init_once, 8)) return false;

    // 1. Снимок syscall-кадра: isr64.S записал 8 слов в scheduler.syscall_frame
    //    ДО sti() (IF=0 от SYSCALL/SFMASK) — данные атомарны, стек мог быть
    //    затёрт таймером уже ПОСЛЕ, но нам нужен только снимок.
    //    Раскладка: [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx [6]=r11 [7]=rcx
    const sf = scheduler.syscall_frame;
    cb_stack[cb_depth] = .{
        .active = true,
        .init_once = init_once,
        .cookie = CB_COOKIE_BAKED,
        .resume_rip = sf[7], // RCX: RIP после syscall-инструкции стаба
        .resume_rsp = scheduler.user_rsp, // кадр стаба (rdi/rsi + ret-адрес)
        .resume_rflags = sf[6], // R11: RFLAGS приложения
        .resume_rbx = sf[5],
        .resume_rbp = sf[4],
        .resume_r12 = sf[3],
        .resume_r13 = sf[2],
        .resume_r14 = sf[1],
        .resume_r15 = sf[0],
    };
    cb_depth += 1;

    // 2. Dedicated callback-стек: 16КБ block-heap (RW+USER), 16-aligned.
    //    НЕ user-стек задачи: колбэк-фрейм не должен затереть кадр стаба.
    //    Каждой транзакции — СВОЙ стек (возврат внутрь внешнего колбэка
    //    продолжается на его собственном стеке).
    const stack = crt.kmalloc(0x4000);
    if (stack == 0) {
        cb_depth -= 1;
        cb_stack[cb_depth].active = false;
        return false;
    }
    ucl_rsp = (stack + 0x4000) & ~@as(u64, 15);

    // 3. Mailbox моста: identity-запись в стаб-регион (CPL=0, активный CR3).
    //    mailbox_off кратен 8, база региона page-aligned → выравнивание ок.
    const disp = win32.activeDispatcher().?;
    const mb: *volatile [4]u64 = @ptrCast(@alignCast(disp.code.?[br.mailbox_off..][0..32]));
    mb[0] = init_once;
    mb[1] = parameter;
    mb[2] = context;
    mb[3] = init_fn;

    // 4. Launch-контекст для isr64.S (sysretq: RCX→RIP, R11→RFLAGS, RSP свой)
    ucl_rip = br.launcher_va;
    ucl_rflags = cb_stack[cb_depth - 1].resume_rflags;
    ucl_pending = 1;

    hal.Serial.puts("[CB] InitOnce: запуск колбэка ");
    hal.Serial.putHex(init_fn);
    if (cb_depth > 1) {
        hal.Serial.puts(" (вложенный, глубина=");
        hal.Serial.putDecimal(cb_depth);
        hal.Serial.puts(")");
    }
    hal.Serial.puts(" через мост (launcher=");
    hal.Serial.putHex(br.launcher_va);
    hal.Serial.puts(")\n");
    return true;
}

/// Syscall #7 (win32_cb_done): trampoline колбэка отчитался.
/// Восстанавливает СОХРАНЁННЫЙ syscall-кадр ВЕРХНЕЙ транзакции (POP) и
/// возвращает управление в точку после ЕЁ исходного syscall'а с
/// RAX = результату колбэка (для вложенных — внутрь внешнего колбэка).
/// Вызывается из hal.zig через win32CbDoneCallback.
pub fn callbackDone(cookie: u64, result: u64) u64 {
    if (cb_depth == 0 or !cb_stack[cb_depth - 1].active or cookie != cb_stack[cb_depth - 1].cookie) {
        hal.Serial.puts("[CB] WARN: неверный cookie — trampoline останется в jmp $\n");
        return 0;
    }
    const st = cb_stack[cb_depth - 1];

    // INIT_ONCE: колбэк вернул TRUE → «инициализация завершена»
    const ok = result != 0;
    if (kValidateWrite(st.init_once, 8)) {
        @as(*volatile u64, @ptrFromInt(st.init_once)).* = if (ok) 2 else 0;
    }

    // Перезапись кадра asm-возврата (слоты [top-64..top)) — под cli:
    // между записью и pop'ами в isr64.S не должно быть прерываний.
    hal.cli();
    const top = scheduler.current_kernel_stack;
    const f: *volatile [8]u64 = @ptrFromInt(top - 64);
    f[0] = st.resume_r15;
    f[1] = st.resume_r14;
    f[2] = st.resume_r13;
    f[3] = st.resume_r12;
    f[4] = st.resume_rbp;
    f[5] = st.resume_rbx;
    f[6] = st.resume_rflags;
    f[7] = st.resume_rip;
    // asm сделает `movq user_rsp(%rip), %rsp; sysretq` — подставляем исходный
    scheduler.user_rsp = st.resume_rsp;

    cb_stack[cb_depth - 1].active = false;
    cb_depth -= 1;
    // ⚠ ucl_pending НЕ трогаем: после запуска колбэка флаг чист
    // (.ucl_launch сбрасывает), asm-путь syscall #7 идёт по обычным pop'ам.

    hal.Serial.puts("[CB] InitOnce: колбэк завершён, ret=");
    hal.Serial.putHex(result);
    if (cb_depth > 0) {
        hal.Serial.puts(" — возврат во внешний колбэк (глубина=");
        hal.Serial.putDecimal(cb_depth);
        hal.Serial.puts(")\n");
    } else {
        hal.Serial.puts(" — возврат в точку исходного syscall\n");
    }
    return if (ok) 1 else 0; // InitOnceExecuteOnce: BOOL
}

/// ops.stack_arg: Win64-аргументы 5+ лежат в user-стеке вызывающего.
/// ⚠ v0.12-fix: у CALLEE arg5 = [entry_rsp+0x28] — ПОСЛЕ 32Б shadow-
/// пространства (подтверждено дизассемблированием curl: MultiByteToWideChar
/// кладёт arg5 в 0x20(%rsp) у caller'а → +8 (ret) + 0x20 (shadow) = 0x28).
/// При входе в стаб [rsp]=ret; стаб сделал 2 push (rsi/rdi) → при SYSCALL
/// user_rsp = entry_rsp-16 → arg5 = +0x38, arg6 = +0x40.
fn kStackArg(idx: u64) u64 {
    // v0.14.0 (CDD №5): расширено до arg10 (InitializeSecurityContext —
    // 10 аргументов: pInput=arg7/[0], phNewContext=arg9, pOutput=arg10)
    if (idx > 5) return 0;
    const addr = scheduler.user_rsp + 0x38 + idx * 8;
    if (!kValidateRead(addr, 8)) return 0;
    return @as(*align(1) const u64, @ptrFromInt(addr)).*;
}
