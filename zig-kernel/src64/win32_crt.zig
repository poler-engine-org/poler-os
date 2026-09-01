// ============================================================================
// POLER-OS Win32/CRT Semantic Core — CDD-цикл №2 (v0.11.0)
// ============================================================================
//
// ЧИСТАЯ семантика Win32/CRT-функций БЕЗ hal/pmm/vmm — тестируется нативно на
// реальном исполнении (прецедент — LoaderOps из pe_loader.zig): ядро через
// win32_api.zig подключает НАСТОЯЩИЙ PMM/VMM/Serial/TSC (Ops-инъекция), тесты —
// фейковую память (обычные Zig-указатели играют роль user-VA).
//
// Что добавлено в цикле №2 (по логу CDD-цепочки v0.10.0, 17 функций):
//   KERNEL32.dll!GetProcAddress              — динамический резолв по реестру
//                                             стабов (возврат user-VA трамплина)
//   KERNEL32.dll!QueryPerformanceFrequency   — записывает TSC-частоту (калибр.
//                                             по тикам, см. main64)
//   KERNEL32.dll!QueryPerformanceCounter     — текущий TSC (hal.readMsr(0x10))
//   KERNEL32.dll!GetConsoleMode              — режим консоли (различимые флаги)
//   KERNEL32.dll!GetConsoleScreenBufferInfo  — 80x3000-терминал для curl
//   KERNEL32.dll!GetCurrentThreadId          — TID (ленивый, =2 как в TEB)
//   KERNEL32.dll!Acquire/ReleaseSRWLockExclusive — no-op (однопоточность CDD)
//   KERNEL32.dll!SetUnhandledExceptionFilter — 0 (прошлого фильтра нет)
//   api-ms-win-crt-stdio!setvbuf/fputs/fputc/fflush — вывод приложения в нашу
//                                             консоль (МОМЕНТ ИСТИНЫ: текст
//                                             curl.exe на serial)
//   api-ms-win-crt-heap!realloc              — block-heap с заголовками
//   api-ms-win-crt-string!memset/strlen      (+ native-стабы, win32_stubs.zig)
//   api-ms-win-crt-private!memcpy/memmove    (+ native-стабы)
//   WS2_32.dll!WSAStartup/WSACleanup         — каркас Winsock 2.2
//
// Что добавлено в цикле №3 (по логу CDD-цепочки v0.11.0, волна блокировки
// перехода к сети — «curl: error initializing curl library», exit 2):
//   KERNEL32.dll!VerSetConditionMask          — 64-битная маска условий
//   KERNEL32.dll!VerifyVersionInfoW           — наш ответ: Windows 10.0
//   KERNEL32.dll!InitOnceExecuteOnce          — once-семантика + запуск
//                                              Win64-колбэка через мост
//                                              (ops.launch_callback →
//                                              sysretq→launcher→callback→
//                                              trampoline→syscall #7)
//   KERNEL32.dll!GetEnvironmentVariableA/W    — пустое окружение → 0 +
//                                              ERROR_ENVVAR_NOT_FOUND
//   KERNEL32.dll!GetLastError/SetLastError    — LastError-контракт
//   KERNEL32.dll!FormatMessageA/W             — тексты ошибок Win32/Winsock
//   Secur32.dll!InitSecurityInterfaceA/W      — SSPI-таблица: user-VA, поля →
//                                              extra-стабы реестра
//                                              (QuerySecurityPackageInfo…,
//                                              AcquireCredentialsHandle… —
//                                              SEC_E_UNSUPPORTED)
//   WS2_32.dll!socket/connect/closesocket/ioctlsocket — сокетные заглушки
//                                              с логированием IP/портов
//   WS2_32.dll!getaddrinfo/freeaddrinfo       — синтез TEST-NET (DNS: №4)
//   WS2_32.dll!send/recv                      — SOCKET_ERROR: стек сети в
//                                              следующем цикле
//   WS2_32.dll!htons/htonl/ntohs/ntohl/WSAGetLastError
//
// ИНВАРИАНТ ДОСТУПА К USER-ПАМЯТИ (жизненно важный):
//   Все записи/чтения по user-VA идут ПРЯМЫМ разыменованием ПОСЛЕ
//   ops.validate_read/write(va, len). В ядре это валидно ТОЛЬКО из
//   syscall-обработчика: CR3 = PML4 процесса (планировщик загрузил его при
//   диспетчеризации задачи), CPL=0 свободно читает USER-страницы; validate
//   страхует ядро от #PF-паники на мусорном указателе и от протечки в
//   supervisor-память (leaf обязан иметь USER-бит — «Ring 3 мог бы сам»).
//   ⚠ НИКАКИЕ функции этого модуля нельзя звать из kernel-контекста с чужим
//   CR3 (например, из cmd_peload при CR3 shell-задачи) — только из syscall №6
//   или нативных тестов. Всё, что строится при peload — чистые числа в Ctx.
//
// Ленивые CRT-структуры (iob-массив, argc/argv, __p__*-указатели) строятся
// при ПЕРВОМ вызове соответствующей функции — это syscall-контекст ✓, и это
// чинит баг v0.10 «__p__fmode при каждом вызове возвращал НОВУЮ страницу»
// (CRT пишет дефолт в один адрес, потом читает из другого).
// ============================================================================

const std = @import("std");
const win32 = @import("win32_stubs.zig");

pub const PAGE_SIZE: u64 = 4096;

/// Псевдо-хэндлы std-потоков (ненулевые, различимые в логах/отчётах).
pub const FAKE_STDIN: u64 = 0x0000_0000_F000_0001;
pub const FAKE_STDOUT: u64 = 0x0000_0000_F000_0002;
pub const FAKE_STDERR: u64 = 0x0000_0000_F000_0003;

// ─── Инъекция платформенных примитивов ──────────────────────────────────────

/// Платформенные примитивы. Дефолт — параноик: всё false/noop (неустановленные
/// ops не могут уронить ядро — падает только вызов). Ядро ставит реальные
/// реализацией win32_api.installOps(); тесты — свои фейки.
pub const Ops = struct {
    /// [va, va+len) замаплен и читаем процессом (ядро: walk PML4, USER-бит)
    validate_read: *const fn (va: u64, len: u64) bool,
    /// [va, va+len) замаплен, USER + WRITABLE (kernel-VA не пройдёт)
    validate_write: *const fn (va: u64, len: u64) bool,
    /// Замапить страницы heap-региона [va, va+bytes) (ядро: PMM+VMM; тест: тач)
    map_user: *const fn (va: u64, bytes: u64) bool,
    /// Чтение TSC (ядро: hal.readMsr(0x10); тест: счётчик)
    read_tsc: *const fn () u64,
    /// Вывод в консоль ОС (ядро: Serial; тест: буфер) — текст приложения!
    write_console: *const fn (s: []const u8) void,
    /// Лог ядра [WIN32]/[CDD] (ядро: Serial; тест: буфер)
    log: *const fn (s: []const u8) void,
    /// Завершение PE-процесса (ядро: exitCallback + hlt; тест: флаг)
    exit: *const fn (code: u64) void,
    /// v0.12.0 (InitOnceExecuteOnce): запуск Win64-колбэка приложения.
    /// Ядро: сохраняет syscall-кадр, заполняет mailbox моста и выставляет
    /// ucl_pending — isr64.S после обработчика уводит sysretq в launcher;
    /// возврат в исходную точку — через syscall #7 (trampoline). Тест: фейк
    /// (отмечает запуск и возвращает true).
    launch_callback: *const fn (init_once: u64, init_fn: u64, parameter: u64, context: u64) bool,
    /// v0.12.0 (FormatMessage и 5+-аргументные функции): Win64-аргументы 5+
    /// лежат в user-стеке ВЫЗЫВАЮЩЕГО (ядро: scheduler.user_rsp + 0x18 +
    /// idx*8; тест: пресет). idx=0 → arg5.
    stack_arg: *const fn (idx: u64) u64,
    /// v0.12.0 (event-волна): CreateThread — настоящий Win64-тред.
    /// Ядро: запись exit-адреса в user-стек + scheduler.createUserThreadTask
    /// (та же PML4 — общее адресное пространство). Возврат — хэндл 0x1000+.
    /// Тест: фейк (записывает параметры, возвращает фиксированный хэндл).
    create_thread: *const fn (start: u64, param: u64, stack_top: u64, exit_va: u64) u64,
    /// v0.12.0: ExitThread/возврат из ThreadProc — убить ТЕКУЩУЮ задачу
    /// (планировщик пометит Killed; hlt до вытеснения).
    exit_task: *const fn () void,
    /// v0.12.0: объект сигнален? (thread-handle → задача Killed; WSA-event
    /// — никогда: curl не импортирует SetEvent/WSASetEvent).
    object_signaled: *const fn (handle: u64) bool,
    /// v0.12.0: текущий TID (scheduler.current_task_id + 0x1000) — ГЛАВНЫЙ
    /// тред и тред резолвера получают РАЗНЫЕ GetCurrentThreadId().
    current_tid: *const fn () u64,
};

fn denyAll(_: u64, _: u64) bool {
    return false;
}
fn noop() u64 {
    return 0;
}
fn denyLaunch(_: u64, _: u64, _: u64, _: u64) bool {
    return false;
}
fn nullStackArg(_: u64) u64 {
    return 0;
}
fn denyCreateThread(_: u64, _: u64, _: u64, _: u64) u64 {
    return 0;
}
fn noopExitTask() void {}
fn denySignaled(_: u64) bool {
    return false;
}
fn fakeTid() u64 {
    return 2;
}

/// Дефолт: параноик. win32_api.installOps() ставит настоящие примитивы.
pub var ops: Ops = .{
    .validate_read = denyAll,
    .validate_write = denyAll,
    .map_user = denyAll,
    .read_tsc = noop,
    .write_console = emptyWriter,
    .log = emptyWriter,
    .exit = emptyExit,
    .launch_callback = denyLaunch,
    .stack_arg = nullStackArg,
    .create_thread = denyCreateThread,
    .exit_task = noopExitTask,
    .object_signaled = denySignaled,
    .current_tid = fakeTid,
};

fn emptyWriter(_: []const u8) void {}
fn emptyExit(_: u64) void {}

// ─── Контекст активного PE-процесса ─────────────────────────────────────────

pub const Ctx = struct {
    pml4: u64, // PML4 процесса (валидация, маппинг heap-страниц)
    image_base: u64, // база образа (GetModuleHandle/GetProcAddress)

    // Командная строка (user-VA в params-странице; ANSI — NUL-терминирована)
    cmdline_a: u64,
    cmdline_w: u64,

    // VirtualAlloc-регион: сырые СТРАНИЦЫ, page-granular bump (Win32 API)
    vheap_base: u64,
    vheap_limit: u64,
    vheap_cursor: u64,
    vallocs: usize,

    // Block-heap: CRT malloc-семья, заголовки 16Б, sub-page bump (см. ниже)
    bheap_base: u64,
    bheap_limit: u64,
    bheap_cursor: u64,
    bheap_mapped: u64, // страницы [bheap_base, bheap_mapped) уже замаплены

    // Ленивые CRT-структуры (0 = ещё не построена; строится при первом вызове)
    iob_array: u64, // 3×80Б FILE-массив (__acrt_iob_func)
    argc_ptr: u64, // int* (__p___argc)
    argv_slot: u64, // char***-слот: *slot = argv-массив (__p___argv)
    environ_slot: u64, // char***-слот: *slot = NULL-таблица (__p__environ)
    fmode_ptr: u64, // int* (__p__fmode) — ОТДЕЛЬНО от commode (разные
    commode_ptr: u64, // int* (__p__commode) — переменные CRT! v0.11-фикс)
    errno_ptr: u64, // int* (_errno) — тоже отдельный блок

    // Прочее
    tsc_freq: u64, // QueryPerformanceFrequency (калибровка в main64)
    tid: u64, // GetCurrentThreadId (0 → выдать 2 при первом вызове, как TEB)
    implemented_calls: usize, // статистика syscall-трамплинов

    // v0.12.0 (CDD №3)
    last_error: u32, // GetLastError/SetLastError (в т.ч. ERROR_ENVVAR_NOT_FOUND)
    next_socket_fd: u64, // socket(): псевдо-хэндлы с 0x100
    sockets_opened: usize, // статистика WS2
    sspi_table: u64, // InitSecurityInterfaceA: кэш таблицы (0 = нет)
    locale_str: u64, // setlocale: ленивый слот "C" (0 = не выделен)
    next_event_handle: u64, // WSACreateEvent/CreateEventA: пул 0x200+
};

pub var ctx: ?Ctx = null;

// ─── Block-heap (malloc/calloc/realloc/free) ────────────────────────────────

/// Заголовок блока (16Б, перед user-указателем):
///   [0..4)  magic  — «это наш блок» (валидация realloc/free)
///   [4..8)  pad    — выравнивание
///   [8..16) size   — размер user-области (уже выровнен к 16)
/// User-указатель = block + 16 → 16-байтная гранулярность Win64-malloc ✓
/// (bheap_base page-aligned, total кратен 16 → cursor всегда 16-aligned).
const HEAP_HDR_MAGIC: u32 = 0x4550_4C45; // "ELPE"
const HEAP_HDR_SIZE: u64 = 16;

const HeapHdr = extern struct {
    magic: u32,
    _pad: u32,
    size: u64,
};

/// MAX_STR_LEN — верхняя граница пользовательских строк (GetProcAddress-имена,
/// fputs-строки). Длиннее — мусорный указатель → отказ.
pub const MAX_STR_LEN: u64 = 4096;

// ─── Прямой доступ к user-памяти (после validate!) ──────────────────────────

inline fn userPtr(va: u64) [*]u8 {
    return @ptrFromInt(va);
}
inline fn userQ(va: u64) *u64 {
    return @ptrFromInt(va);
}
inline fn userD(va: u64) *u32 {
    return @ptrFromInt(va);
}
inline fn userW(va: u64) *u16 {
    return @ptrFromInt(va);
}

/// Длина NUL-строки в user-памяти с ПОСТРАНИЧНОЙ валидацией (строка может
/// пересекать границу страницы). null = мусорный указатель/нет NUL в лимите.
pub fn userStrLen(va: u64) ?u64 {
    if (!ops.validate_read(va, 1)) return null;
    var page: u64 = va & ~(PAGE_SIZE - 1);
    var validated_until: u64 = page + PAGE_SIZE; // абсолютный адрес конца стр.
    var i: u64 = 0;
    while (i < MAX_STR_LEN) : (i += 1) {
        if (va + i >= validated_until) {
            page += PAGE_SIZE;
            if (!ops.validate_read(page, 1)) return null;
            validated_until = page + PAGE_SIZE;
        }
        if (userPtr(va)[@as(usize, @intCast(i))] == 0) return i;
    }
    return null;
}

fn logf(comptime fmt: []const u8, args: anytype) void {
    var buf: [192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    ops.log(msg);
}

// ─── Block-heap API ─────────────────────────────────────────────────────────

/// malloc(size): bump с заголовком; страницы по требованию через ops.map_user.
/// malloc(0) — уникальный минимальный блок (конвенция CRT).
pub fn kmalloc(size: u64) u64 {
    const c = &(ctx orelse return 0);
    const want: u64 = if (size == 0) 16 else (size + 15) & ~@as(u64, 15);
    const total = HEAP_HDR_SIZE + want;
    if (want > 64 * 1024 * 1024) return 0; // sanity: блоки >64МБ — не к нам
    if (c.bheap_cursor + total > c.bheap_limit) return 0; // OOM процесса

    // Добираем страницы (bheap_mapped всегда page-aligned)
    if (c.bheap_cursor + total > c.bheap_mapped) {
        const need = c.bheap_cursor + total - c.bheap_mapped;
        if (!ops.map_user(c.bheap_mapped, need)) return 0;
        c.bheap_mapped = (c.bheap_cursor + total + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    }

    // Заголовок (прямой доступ: страницы только что гарантированы)
    const hdr: *HeapHdr = @ptrFromInt(c.bheap_cursor);
    hdr.magic = HEAP_HDR_MAGIC;
    hdr.size = want;

    const p = c.bheap_cursor + HEAP_HDR_SIZE;
    c.bheap_cursor += total;
    return p;
}

/// calloc(nmemb, size): malloc + обнуление (переполнение n*s проверяется).
pub fn kcalloc(nmemb: u64, size: u64) u64 {
    if (size != 0 and nmemb > std.math.maxInt(u64) / size) return 0;
    const total = nmemb * size;
    const p = kmalloc(total);
    if (p == 0) return 0;
    const want = (if (total == 0) @as(u64, 16) else (total + 15) & ~@as(u64, 15));
    @memset(userPtr(p)[0..@intCast(want)], 0);
    return p;
}

/// free(ptr): проверка magic; ПАМЯТЬ НЕ ВОЗВРАЩАЕТСЯ (bump без reuse) —
/// честная утечка CDD-цикла №2 (страницы умрут вместе с задачей; повторное
/// использование блоков = free-list — цикл №3).
pub fn kfree(p: u64) void {
    if (p == 0) return;
    if (p % 8 != 0) return; // невыровненный — не наш указатель
    const c = &(ctx orelse return);
    if (p < c.bheap_base + HEAP_HDR_SIZE or p > c.bheap_cursor) return; // чужой
    const hdr: *const HeapHdr = @ptrFromInt(p - HEAP_HDR_SIZE);
    if (hdr.magic != HEAP_HDR_MAGIC) return; // не наш — молча игнорируем
    // (no-op: блок не переиспользуется)
}

/// realloc(ptr, size): ptr=NULL → malloc; size=0 → free+NULL (MSVC);
/// иначе — новый блок + копия пересечения (старый размер читается из
/// заголовка — ТО, чего не хватало v0.10), старый «освобождается» (утечка).
/// Чужой/битый указатель → NULL (не роняем ядро на мусоре приложения).
pub fn krealloc(p: u64, size: u64) u64 {
    if (p == 0) return kmalloc(size);
    if (size == 0) {
        kfree(p);
        return 0; // MSVC: realloc(p, 0) = free + NULL
    }
    const c = &(ctx orelse return 0);
    if (p % 8 != 0) return 0; // невыровненный — мусор, не роняем ядро
    if (p < c.bheap_base + HEAP_HDR_SIZE or p > c.bheap_cursor) return 0;
    const hdr: *const HeapHdr = @ptrFromInt(p - HEAP_HDR_SIZE);
    if (hdr.magic != HEAP_HDR_MAGIC) return 0;

    const old = hdr.size;
    const np = kmalloc(size);
    if (np == 0) return 0;
    const new_aligned: u64 = (size + 15) & ~@as(u64, 15);
    const n: usize = @intCast(@min(old, new_aligned));
    @memcpy(userPtr(np)[0..n], userPtr(p)[0..n]);
    return np;
}

// ─── Реализации Win32/CRT ───────────────────────────────────────────────────

/// GetStdHandle(nStdHandle): STD_INPUT(-11)/STD_OUTPUT(-10)/STD_ERROR(-12).
fn getStdHandle(n_std: u64) u64 {
    return switch (n_std & 0xFFFFFFFF) {
        0xFFFFFFF5 => FAKE_STDIN, // (DWORD)-11
        0xFFFFFFF6 => FAKE_STDOUT, // (DWORD)-10
        0xFFFFFFF4 => FAKE_STDERR, // (DWORD)-12
        else => 0,
    };
}

/// VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
/// сырой page-granular bump в vheap-регионе (Win32 API — крупные запросы).
fn virtualAlloc(lp_address: u64, dw_size: u64, alloc_type: u64, protect: u64) u64 {
    _ = protect; // права всегда RW+NX+USER (v0.10 — без вариаций)
    if (dw_size == 0 or dw_size > 64 * 1024 * 1024) return 0;
    if (alloc_type & 0x3000 == 0) return 0; // нужен MEM_COMMIT/RESERVE

    const c = &(ctx orelse return 0);
    const pages = (dw_size + PAGE_SIZE - 1) / PAGE_SIZE;

    var base: u64 = 0;
    if (lp_address == 0) {
        base = (c.vheap_cursor + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    } else {
        if (lp_address % PAGE_SIZE != 0) return 0;
        if (lp_address < c.vheap_base or lp_address + pages * PAGE_SIZE > c.vheap_limit) return 0;
        base = lp_address;
    }
    if (base + pages * PAGE_SIZE > c.vheap_limit) return 0; // OOM процесса

    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        if (!ops.map_user(base + i * PAGE_SIZE, PAGE_SIZE)) return 0;
    }
    if (base + pages * PAGE_SIZE > c.vheap_cursor) {
        c.vheap_cursor = base + pages * PAGE_SIZE;
    }
    c.vallocs += 1;
    return base;
}

/// GetProcAddress(hModule, lpProcName): динамический резолв по НАШЕМУ реестру
/// стабов — приложение получает user-VA трамплина (trap → CDD-лог при вызове;
/// impl/native → живая функция). Чужое имя → NULL (приложение само деградирует
/// на optional-фичи — честный Windows-паттерн). Ординалы (<0x10000) → NULL.
fn getProcAddress(disp: *win32.Dispatcher, h_module: u64, lp_proc_name: u64) u64 {
    if (h_module == 0) return 0; // NULL-модуль
    if (lp_proc_name == 0 or lp_proc_name >= 0x10000_0000_0000) return 0;
    if (lp_proc_name < 0x10000) return 0; // MAKEINTRESOURCE-ординал

    const len = userStrLen(lp_proc_name) orelse return 0;
    if (len == 0 or len > 64) return 0;
    const name = userPtr(lp_proc_name)[0..@intCast(len)];

    if (disp.findByNameAnyDll(name)) |stub| {
        logf("[WIN32] GetProcAddress(\"{s}\") -> 0x{x}\n", .{ name, stub.stub_addr });
        return stub.stub_addr;
    }
    logf("[CDD] GetProcAddress(\"{s}\") -> NULL (нет в реестре стабов)\n", .{name});
    return 0;
}

/// QueryPerformanceFrequency(lpFrequency): частота TSC (калибровка при peload
/// по тикам APIC-таймера; fallback 10 МГц — HPET-класс).
fn queryPerformanceFrequency(lp_frequency: u64) u64 {
    if (!ops.validate_write(lp_frequency, 8)) return 0;
    const c = &(ctx orelse return 0);
    userQ(lp_frequency).* = if (c.tsc_freq != 0) c.tsc_freq else 10_000_000;
    return 1; // TRUE
}

/// QueryPerformanceCounter(lpPerformanceCount): текущий 64-битный TSC.
fn queryPerformanceCounter(lp_counter: u64) u64 {
    if (!ops.validate_write(lp_counter, 8)) return 0;
    userQ(lp_counter).* = ops.read_tsc();
    return 1; // TRUE
}

/// GetConsoleMode(hConsoleHandle, lpMode): различимые флаги для std-потоков
/// (curl по ним решает: прогресс-бар vs простой вывод).
fn getConsoleMode(handle: u64, lp_mode: u64) u64 {
    if (!ops.validate_write(lp_mode, 4)) return 0;
    const mode: u32 = if (handle == FAKE_STDIN)
        0x1F7 // input: PROCESSED|LINE|ECHO|WINDOW|MOUSE|EXTENDED|QUICKEDIT
    else
        0x3; // output: PROCESSED_OUTPUT|WRAP_AT_EOL_OUTPUT
    userD(lp_mode).* = mode;
    return 1; // TRUE
}

/// GetConsoleScreenBufferInfo(hConsoleOutput, lpInfo): 22Б-структура —
/// терминал 80x3000, курсор (0,0), окно 80x25 (curl считает ширину для
/// прогресс-бара и переносов).
fn getConsoleScreenBufferInfo(handle: u64, lp_info: u64) u64 {
    _ = handle;
    if (!ops.validate_write(lp_info, 22)) return 0;
    @memset(userPtr(lp_info)[0..22], 0);
    userW(lp_info + 0).* = 80; // dwSize.X
    userW(lp_info + 2).* = 3000; // dwSize.Y
    userW(lp_info + 4).* = 0; // dwCursorPosition.X
    userW(lp_info + 6).* = 0; // dwCursorPosition.Y
    userW(lp_info + 8).* = 0x07; // wAttributes
    userW(lp_info + 10).* = 0; // srWindow.Left
    userW(lp_info + 12).* = 0; // srWindow.Top
    userW(lp_info + 14).* = 79; // srWindow.Right
    userW(lp_info + 16).* = 24; // srWindow.Bottom
    userW(lp_info + 18).* = 80; // dwMaximumWindowSize.X
    userW(lp_info + 20).* = 3000; // dwMaximumWindowSize.Y
    return 1; // TRUE
}

/// WSAStartup(wVersionRequested, lpWSAData): каркас Winsock 2.2 — обнуляем
/// 400Б, ставим версию, описание; возврат 0 = NO_ERROR (curl пойдёт дальше —
/// до первого socket()-вызова, это уже цикл №3).
fn wsaStartup(w_version_requested: u64, lp_wsa_data: u64) u64 {
    if (!ops.validate_write(lp_wsa_data, 400)) return 10014; // WSAEFAULT
    @memset(userPtr(lp_wsa_data)[0..400], 0);
    const lo = w_version_requested & 0xFF;
    const hi = (w_version_requested >> 8) & 0xFF;
    // Отвечаем запрошенным (или максимумом 2.2, что выше)
    const out_lo: u16 = @intCast(if (lo > 2) 2 else lo);
    const out_hi: u16 = @intCast(@min(@max(hi, 2), 2));
    userW(lp_wsa_data + 0).* = (out_hi << 8) | out_lo; // wVersion
    userW(lp_wsa_data + 2).* = 0x0202; // wHighVersion
    const desc = "POLER-OS Winsock shim (CDD-2)";
    @memcpy(userPtr(lp_wsa_data + 8)[0..desc.len], desc);
    return 0; // NO_ERROR
}

/// WSACleanup(): 0 = NO_ERROR.
fn wsaCleanup() u64 {
    return 0;
}

/// fputs(str, stream): ПЕЧАТЬ ТЕКСТА ПРИЛОЖЕНИЯ в консоль ОС. Возврат 1
/// (nonneg = успех, CRT-контракт). Мусорный указатель → 0 (EOF).
fn fputs(str_va: u64, stream: u64) u64 {
    _ = stream; // stdout/stderr одинаково идут в serial (CDD-упрощение)
    const len = userStrLen(str_va) orelse return 0;
    if (len == 0) return 1;
    ops.write_console(userPtr(str_va)[0..@intCast(len)]);
    return 1;
}

/// fputc(c, stream): один символ; возврат записанного байта (int-контракт).
fn fputc(c: u64, stream: u64) u64 {
    _ = stream;
    const ch: [1]u8 = .{@truncate(c)};
    ops.write_console(&ch);
    return c & 0xFF;
}

/// fwrite(ptr=RCX, size=RDX, nmemb=R8, stream=R9) → число ПОЛНЫХ записанных
/// элементов (v0.12-fix: trap-стаб возвращал 0 → curl считал запись
/// ПРОВАЛЕННОЙ и терял куски вывода, например префикс «curl: » перед текстом
/// ошибки — helpf() пишет его через fwrite). Байты идут в виртуальную
/// консоль; аргумент 4-й (stream) в Win64 — R9, диспетчер передаёт a4.
fn fwrite(ptr: u64, size: u64, nmemb: u64, stream: u64) u64 {
    _ = stream; // stdout/stderr — в serial одинаково (CDD-упрощение)
    if (size == 0 or nmemb == 0) return 0;
    const total = size * nmemb;
    if (total > 16 * 1024 * 1024) return 0; // защитный лимит
    if (!ops.validate_read(ptr, total)) return 0; // поток ошибочен → 0
    ops.write_console(userPtr(ptr)[0..@intCast(total)]);
    return nmemb; // контракт CRT: успех → nmemb
}

// ─── v0.12.0 (CDD №3): версионирование ОС, окружение, ошибки ───────────────

// LastError-контракт
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_OLD_WIN_VERSION: u32 = 1150;
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;

/// Winsock-коды (WSAGetLastError == GetLastError в нашей модели).
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAEFAULT: u32 = 10014;
const WSAEINVAL: u32 = 10022;
const WSAENETDOWN: u32 = 10050;
const WSAETIMEDOUT: u32 = 10060;
const INVALID_SOCKET: u64 = 0xFFFF_FFFF_FFFF_FFFF;

fn setLastError(code: u32) void {
    if (ctx) |*c| c.last_error = code;
}

/// Наша «версия Windows» (нативный контракт: ядро отвечает за окружение,
/// которое ожидает бинарник): Windows 10.0 build 19041, NT, workstation.
const OS_ACTUAL = struct {
    const major: u32 = 10;
    const minor: u32 = 0;
    const build: u32 = 19041;
    const platform: u32 = 2; // VER_PLATFORM_WIN32_NT
    const sp_major: u32 = 0;
    const sp_minor: u32 = 0;
    const suite: u32 = 0x0100; // VER_SUITE_SINGLEUSERAPPS (workstation)
    const product: u32 = 1; // VER_NT_WORKSTATION
};

// VER_*-константы (winnt.h)
const VER_MINORVERSION: u32 = 0x0000_0001;
const VER_MAJORVERSION: u32 = 0x0000_0002;
const VER_BUILDNUMBER: u32 = 0x0000_0004;
const VER_PLATFORMID: u32 = 0x0000_0008;
const VER_SERVICEPACKMINOR: u32 = 0x0000_0010;
const VER_SERVICEPACKMAJOR: u32 = 0x0000_0020;
const VER_SUITENAME: u32 = 0x0000_0040;
const VER_PRODUCTTYPE: u32 = 0x0000_0080;

const VER_EQUAL: u32 = 1;
const VER_GREATER: u32 = 2;
const VER_GREATER_EQUAL: u32 = 3;
const VER_LESS: u32 = 4;
const VER_LESS_EQUAL: u32 = 5;
const VER_AND: u32 = 6;
const VER_OR: u32 = 7;

/// Позиция 8-битного поля условия для VER_*-флага в dwlConditionMask
/// (минор — биты 0-7, мажор — 8-15, …, тип продукта — 56-63).
fn conditionShift(type_bit: u32) ?u6 {
    return switch (type_bit) {
        VER_MINORVERSION => 0,
        VER_MAJORVERSION => 8,
        VER_BUILDNUMBER => 16,
        VER_PLATFORMID => 24,
        VER_SERVICEPACKMINOR => 32,
        VER_SERVICEPACKMAJOR => 40,
        VER_SUITENAME => 48,
        VER_PRODUCTTYPE => 56,
        else => null,
    };
}

/// VerSetConditionMask(dwlConditionMask, dwTypeBitMask, dwCondition):
/// выставить 8-битное поле условия для ОДНОГО поля-проверки (VER_MAJORVERSION
/// и т.п.); возврат — обновлённая маска (curl вызывает дважды, цепочкой:
/// mask = VSCM(VSCM(0, MAJOR, GE), MINOR, GE)).
fn verSetConditionMask(mask: u64, type_bit: u64, condition: u64) u64 {
    if (type_bit == 0 or type_bit > 0xFF) return mask; // не-VER_* флаг — не трогаем
    const shift = conditionShift(@intCast(type_bit)) orelse return mask;
    const cond: u64 = condition & 0xFF;
    if (cond == 0) return mask; // сброс условия нулем не определён — игнор
    return (mask & ~(@as(u64, 0xFF) << shift)) | (cond << shift);
}

/// OSVERSIONINFOEXW: dwOSVersionInfoSize@0, major@4, minor@8, build@0xC,
/// platform@0x10, szCSDVersion[128]u16@0x14 (256Б!), wServicePackMajor@0x114,
/// wServicePackMinor@0x116, wSuiteMask@0x118, wProductType@0x11A,
/// wReserved@0x11B. sizeof=284. ⚠ v0.12-урок: szCSDVersion — 128 WCHAR
/// (256 байт), НЕ 128 байт — неверный размер 156 заваливал curl-проверку
/// версии (диагностика: «size=284 ≠156») → FALSE вместо нативного TRUE.
const OSVEXW_SIZE: u64 = 284;
const OSVEXW_SP_MAJOR: u64 = 0x114;
const OSVEXW_SP_MINOR: u64 = 0x116;
const OSVEXW_SUITE: u64 = 0x118;
const OSVEXW_PRODUCT: u64 = 0x11A;

/// Сравнение «нашего» поля с запрошенным по условию из маски.
fn evalCondition(cond: u32, req: u32, act: u32) bool {
    return switch (cond) {
        VER_EQUAL => act == req,
        VER_GREATER => act > req,
        VER_GREATER_EQUAL => act >= req,
        VER_LESS => act < req,
        VER_LESS_EQUAL => act <= req,
        else => false,
    };
}

/// VerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask):
/// сверка запрошенных условий с нашей Windows 10.0. curl спрашивает
/// major>=6/minor>=1 (Win7+) — отвечаем TRUE: «поддерживаю функционал
/// версии 10.0, продолжай». Несовпадение → FALSE + ERROR_OLD_WIN_VERSION.
fn verifyVersionInfoW(lp_info: u64, type_mask: u64, cond_mask: u64) u64 {
    if (!ops.validate_read(lp_info, OSVEXW_SIZE)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const size = userD(lp_info + 0).*;
    if (size != OSVEXW_SIZE) {
        // curl передаёт OSVERSIONINFOEXW; другой размер — контракта нет
        logf("[WIN32] VerifyVersionInfoW: size={d} (≠{d}) — контракт отсутствует\n", .{ size, OSVEXW_SIZE });
        setLastError(ERROR_OLD_WIN_VERSION);
        return 0;
    }
    // CDD-диагностика: реальные параметры запроса приложения
    logf("[WIN32] VerifyVersionInfoW: req={d}.{d} mask=0x{x} cm=0x{x}\n", .{
        userD(lp_info + 4).*, userD(lp_info + 8).*, type_mask, cond_mask,
    });

    var ok = true;
    var have_check = false;
    const req_major = userD(lp_info + 4).*;
    const req_minor = userD(lp_info + 8).*;
    const req_build = userD(lp_info + 0xC).*;
    const req_platform = userD(lp_info + 0x10).*;
    const req_sp_major = userW(lp_info + OSVEXW_SP_MAJOR).*;
    const req_sp_minor = userW(lp_info + OSVEXW_SP_MINOR).*;
    const req_suite = userW(lp_info + OSVEXW_SUITE).*;
    const req_product = userPtr(lp_info + OSVEXW_PRODUCT)[0];

    // Пара (major, minor) сравнивается как КОРТЕЖ — семантика Win32
    // (Version-Helper-паттерн): минор проверяется ТОЛЬКО при равном мажоре,
    // иначе «(10.0) >= (6.1)» ломалось бы и на настоящей Windows 10.
    const maj_masked = type_mask & VER_MAJORVERSION != 0;
    const min_masked = type_mask & VER_MINORVERSION != 0;
    var version_pair_done = false;
    if (maj_masked and min_masked) {
        have_check = true;
        version_pair_done = true;
        const c_maj: u32 = @intCast((cond_mask >> 8) & 0xFF);
        const c_min: u32 = @intCast(cond_mask & 0xFF);
        if (c_maj == 0 or c_min == 0) {
            ok = false; // условия не заданы → отказ (MSDN)
        } else if (req_major != OS_ACTUAL.major) {
            ok = evalCondition(c_maj, req_major, OS_ACTUAL.major);
        } else {
            ok = evalCondition(c_maj, req_major, OS_ACTUAL.major) and
                evalCondition(c_min, req_minor, OS_ACTUAL.minor);
        }
    }

    const checks = [_]u32{
        VER_MINORVERSION, VER_MAJORVERSION,     VER_BUILDNUMBER, VER_PLATFORMID,
        VER_SERVICEPACKMINOR, VER_SERVICEPACKMAJOR, VER_SUITENAME,  VER_PRODUCTTYPE,
    };
    for (checks) |flag| {
        if (type_mask & flag == 0) continue;
        if (version_pair_done and (flag == VER_MAJORVERSION or flag == VER_MINORVERSION)) continue;
        have_check = true;
        const shift = conditionShift(flag).?;
        const cond: u32 = @intCast((cond_mask >> shift) & 0xFF);
        if (cond == 0) {
            ok = false; // поле проверяется, условие не задано → отказ (MSDN)
            continue;
        }
        ok = ok and switch (flag) {
            VER_MINORVERSION => evalCondition(cond, req_minor, OS_ACTUAL.minor),
            VER_MAJORVERSION => evalCondition(cond, req_major, OS_ACTUAL.major),
            VER_BUILDNUMBER => evalCondition(cond, req_build, OS_ACTUAL.build),
            VER_PLATFORMID => evalCondition(cond, req_platform, OS_ACTUAL.platform),
            VER_SERVICEPACKMINOR => evalCondition(cond, req_sp_minor, OS_ACTUAL.sp_minor),
            VER_SERVICEPACKMAJOR => evalCondition(cond, req_sp_major, OS_ACTUAL.sp_major),
            VER_SUITENAME => switch (cond) {
                VER_AND => (OS_ACTUAL.suite & req_suite) == req_suite,
                VER_OR => (OS_ACTUAL.suite & req_suite) != 0,
                else => false,
            },
            VER_PRODUCTTYPE => evalCondition(cond, req_product, OS_ACTUAL.product),
            else => false,
        };
    }
    if (!ok or !have_check) {
        setLastError(ERROR_OLD_WIN_VERSION);
        return 0;
    }
    return 1; // TRUE
}

/// Длина NUL-terminated UTF-16LE строки в user-памяти (в WCHAR-ах).
pub fn userStrLenW(va: u64) ?u64 {
    if (!ops.validate_read(va, 2)) return null;
    var i: u64 = 0;
    while (i < MAX_STR_LEN / 2) : (i += 1) {
        if (!ops.validate_read(va + i * 2, 2)) return null;
        if (userW(va + i * 2).* == 0) return i;
    }
    return null;
}

/// GetEnvironmentVariableA/W: окружение процесса в v0.12 ПУСТО → переменная
/// не найдена: возврат 0 + LastError=ERROR_ENVVAR_NOT_FOUND (контракт curl:
/// «нет переменной» → дефолтное поведение, не ошибка). Буфер не трогаем.
fn getEnvironmentVariableA(name_va: u64, buf: u64, size: u64) u64 {
    _ = buf;
    _ = size;
    const len = userStrLen(name_va) orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (len == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const name = userPtr(name_va)[0..@intCast(len)];
    logf("[WIN32] GetEnvironmentVariableA(\"{s}\") -> 0 (окружение пусто)\n", .{name});
    setLastError(ERROR_ENVVAR_NOT_FOUND);
    return 0;
}

fn getEnvironmentVariableW(name_va: u64, buf: u64, size: u64) u64 {
    _ = buf;
    _ = size;
    const len = userStrLenW(name_va) orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (len == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    logf("[WIN32] GetEnvironmentVariableW(L\"{d} wchars\") -> 0 (окружение пусто)\n", .{len});
    setLastError(ERROR_ENVVAR_NOT_FOUND);
    return 0;
}

/// Тексты частых ошибок Win32/Winsock (FormatMessageA; curl печатает их в
/// diagnose-выводе). Прочие коды → «Unrecognized error code (N)».
var fm_fallback_buf: [64]u8 = undefined;

fn winErrorText(code: u32) []const u8 {
    return switch (code) {
        0 => "The operation completed successfully.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough memory resources are available to process this command.",
        14 => "Not enough storage is available to complete this operation.",
        87 => "The parameter is incorrect.",
        122 => "The data area passed to a system call is too small.",
        203 => "The system could not find the environment option that was entered.",
        10013 => "An attempt was made to access a socket in a way forbidden by its access permissions.",
        10035 => "A non-blocking socket operation could not be completed immediately.",
        10038 => "An operation was attempted on something that is not a socket.",
        10048 => "Only one usage of each socket address is normally permitted.",
        10050 => "A socket operation encountered a dead network.",
        10051 => "A socket operation was attempted to an unreachable network.",
        10053 => "An established connection was aborted by the software in your host machine.",
        10054 => "An existing connection was forcibly closed by the remote host.",
        10055 => "An operation on a socket could not be performed because the system lacked sufficient buffer space.",
        10060 => "A connection attempt failed because the connected party did not properly respond after a period of time.",
        10061 => "No connection could be made because the target machine actively refused it.",
        10065 => "A socket operation was attempted to an unreachable host.",
        11001 => "Host not found.",
        11004 => "The requested name is valid, but no data of the requested type was found.",
        else => std.fmt.bufPrint(&fm_fallback_buf, "Unrecognized error code ({d}).", .{code}) catch "Unrecognized error code.",
    };
}

const FORMAT_MESSAGE_ALLOCATE_BUFFER: u64 = 0x100;
const FORMAT_MESSAGE_FROM_SYSTEM: u64 = 0x1000;

/// FormatMessageA(flags, source, msg_id, lang, lpBuffer, nSize, args):
/// FROM_SYSTEM → текст кода ошибки в буфер (или ALLOCATE_BUFFER → наш
/// block-heap, освободит LocalFree — пока утечка по CDD-модели). Аргументы
/// 5-7 приходят ЧЕРЕЗ СТЕК вызывающего (Win64) — ops.stack_arg.
fn formatMessageA(flags: u64, source: u64, msg_id: u64, lang: u64) u64 {
    _ = source;
    _ = lang;
    if (flags & FORMAT_MESSAGE_FROM_SYSTEM == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const text = winErrorText(@truncate(msg_id));
    const lp_buffer = ops.stack_arg(0);
    const n_size = ops.stack_arg(1);

    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0) {
        if (!ops.validate_write(lp_buffer, 8)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        const p = kmalloc(text.len + 1);
        if (p == 0) return 0;
        @memcpy(userPtr(p)[0..text.len], text);
        userPtr(p)[text.len] = 0;
        userQ(lp_buffer).* = p;
        return text.len;
    }
    if (n_size == 0 or n_size > MAX_STR_LEN) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (!ops.validate_write(lp_buffer, n_size)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (text.len + 1 > n_size) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    @memcpy(userPtr(lp_buffer)[0..text.len], text);
    userPtr(lp_buffer)[text.len] = 0;
    return text.len;
}

/// FormatMessageW: то же, но UTF-16LE (возврат — число WCHAR).
fn formatMessageW(flags: u64, source: u64, msg_id: u64, lang: u64) u64 {
    _ = source;
    _ = lang;
    if (flags & FORMAT_MESSAGE_FROM_SYSTEM == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const text = winErrorText(@truncate(msg_id));
    const lp_buffer = ops.stack_arg(0);
    const n_size = ops.stack_arg(1); // в TCHAR = WCHAR

    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0) {
        if (!ops.validate_write(lp_buffer, 8)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        const p = kmalloc(text.len * 2 + 2);
        if (p == 0) return 0;
        for (text, 0..) |ch, i| userW(p + i * 2).* = ch;
        userW(p + text.len * 2).* = 0;
        userQ(lp_buffer).* = p;
        return text.len;
    }
    if (n_size == 0 or n_size > MAX_STR_LEN) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (text.len + 1 > n_size) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (!ops.validate_write(lp_buffer, (text.len + 1) * 2)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    for (text, 0..) |ch, i| userW(lp_buffer + i * 2).* = ch;
    userW(lp_buffer + text.len * 2).* = 0;
    return text.len;
}

// ─── v0.12.0 (CDD №3): InitOnceExecuteOnce + мост Win64-колбэка ───────────

/// InitOnceExecuteOnce(InitOnce, InitFn, Parameter, Context):
///   *InitOnce: 0 = свежая, 1 = выполняется, 2 = завершено (INIT_ONCE_…
/// значения нашей модели; curl сам их не инспектирует).
/// Завершено → TRUE без колбэка. Иначе — ПОМЕЧАЕМ «выполняется» и
/// запускаем InitFn ЧЕРЕЗ МОСТ (ops.launch_callback): ядро сохраняет
/// syscall-кадр, sysretq уводит в launcher → колбэк исполняется в Ring 3
/// с Win64-аргументами (RCX=InitOnce, RDX=Parameter, R8=&Context) →
/// trampoline → syscall #7 восстанавливает кадр → управление возвращается
/// в точку ПОСЛЕ исходного syscall'а c RAX=TRUE/FALSE по результату колбэка.
/// Тесты подменяют launch_callback фейком (транзакция без реального моста).
fn initOnceExecuteOnce(init_once: u64, init_fn: u64, parameter: u64, context: u64) u64 {
    if (!ops.validate_write(init_once, 8)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const state = userQ(init_once).*;
    if (state == 2) return 1; // уже инициализировано (once-семантика)
    if (state == 1) return 1; // «выполняется» — однопоточный CDD: успех
    if (init_fn == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    userQ(init_once).* = 1; // метка «выполняется» (колбэк увидит InitOnce=1)
    if (!ops.launch_callback(init_once, init_fn, parameter, context)) {
        userQ(init_once).* = state; // мост не смог — ОТКАТ (транзакция)
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return 1; // реальный RAX придёт из syscall #7 (по результату колбэка)
}

// ─── v0.12.0 (CDD №3): SSPI (Secur32) ──────────────────────────────────────

/// SecurityFunctionTableA (sspi.h, NT5-порядок полей mingw): таблица
/// указателей, которые curl вызывает ЧЕРЕЗ ТАБЛИЦУ (не через IAT!) —
/// поэтому каждой SSPI-функции нужен СВОЙ вызываемый адрес: extra-стабы
/// реестра (main64 addExtraStub). dwVersion=2.
const SEC_E_OK: u64 = 0;
const SEC_E_UNSUPPORTED_METHOD: u64 = 0x8009_0302;

const SFT = struct {
    const DW_VERSION: u64 = 0x00;
    const ENUMERATE_SECURITY_PACKAGES_A: u64 = 0x08;
    const ENUMERATE_SECURITY_PACKAGES_W: u64 = 0x10;
    const QUERY_SECURITY_PACKAGE_INFO_A: u64 = 0x18;
    const QUERY_SECURITY_PACKAGE_INFO_W: u64 = 0x20;
    const FREE_CONTEXT_BUFFER: u64 = 0x28;
    const IMPORT_SECURITY_CONTEXT_A: u64 = 0x30;
    const IMPORT_SECURITY_CONTEXT_W: u64 = 0x38;
    const ACCEPT_SECURITY_CONTEXT: u64 = 0x40;
    const IMPERSONATE_SECURITY_CONTEXT: u64 = 0x48;
    const REVERT_SECURITY_CONTEXT: u64 = 0x50;
    const QUERY_SECURITY_CONTEXT_TOKEN: u64 = 0x58;
    const DELETE_SECURITY_CONTEXT: u64 = 0x60;
    const APPLY_CONTROL_TOKEN: u64 = 0x68;
    const QUERY_CONTEXT_ATTRIBUTES_A: u64 = 0x70;
    const QUERY_CONTEXT_ATTRIBUTES_W: u64 = 0x78;
    const QUERY_CREDENTIALS_ATTRIBUTES_A: u64 = 0x80;
    const QUERY_CREDENTIALS_ATTRIBUTES_W: u64 = 0x88;
    const FREE_CREDENTIALS_HANDLE: u64 = 0x90;
    const ACQUIRE_CREDENTIALS_HANDLE_A: u64 = 0x98;
    const ACQUIRE_CREDENTIALS_HANDLE_W: u64 = 0xA0;
    const ADD_CREDENTIALS_A: u64 = 0xA8;
    const ADD_CREDENTIALS_W: u64 = 0xB0;
    const COMPLETE_AUTH_TOKEN: u64 = 0xB8;
    const INITIALIZE_SECURITY_CONTEXT_A: u64 = 0xC0;
    const INITIALIZE_SECURITY_CONTEXT_W: u64 = 0xC8;
};

/// Имена SSPI-функций для extra-стабов (реестр Secur32) — main64 добавляет
/// их в реестр ДО старта задачи; здесь таблица только заполняется.
const SSPI_FIELDS = [_]struct { off: u64, name: []const u8 }{
    .{ .off = SFT.ENUMERATE_SECURITY_PACKAGES_A, .name = "EnumerateSecurityPackagesA" },
    .{ .off = SFT.ENUMERATE_SECURITY_PACKAGES_W, .name = "EnumerateSecurityPackagesW" },
    .{ .off = SFT.QUERY_SECURITY_PACKAGE_INFO_A, .name = "QuerySecurityPackageInfoA" },
    .{ .off = SFT.QUERY_SECURITY_PACKAGE_INFO_W, .name = "QuerySecurityPackageInfoW" },
    .{ .off = SFT.FREE_CONTEXT_BUFFER, .name = "FreeContextBuffer" },
    .{ .off = SFT.IMPORT_SECURITY_CONTEXT_A, .name = "ImportSecurityContextA" },
    .{ .off = SFT.IMPORT_SECURITY_CONTEXT_W, .name = "ImportSecurityContextW" },
    .{ .off = SFT.ACCEPT_SECURITY_CONTEXT, .name = "AcceptSecurityContext" },
    .{ .off = SFT.IMPERSONATE_SECURITY_CONTEXT, .name = "ImpersonateSecurityContext" },
    .{ .off = SFT.REVERT_SECURITY_CONTEXT, .name = "RevertSecurityContext" },
    .{ .off = SFT.QUERY_SECURITY_CONTEXT_TOKEN, .name = "QuerySecurityContextToken" },
    .{ .off = SFT.DELETE_SECURITY_CONTEXT, .name = "DeleteSecurityContext" },
    .{ .off = SFT.APPLY_CONTROL_TOKEN, .name = "ApplyControlToken" },
    .{ .off = SFT.QUERY_CONTEXT_ATTRIBUTES_A, .name = "QueryContextAttributesA" },
    .{ .off = SFT.QUERY_CONTEXT_ATTRIBUTES_W, .name = "QueryContextAttributesW" },
    .{ .off = SFT.QUERY_CREDENTIALS_ATTRIBUTES_A, .name = "QueryCredentialsAttributesA" },
    .{ .off = SFT.QUERY_CREDENTIALS_ATTRIBUTES_W, .name = "QueryCredentialsAttributesW" },
    .{ .off = SFT.FREE_CREDENTIALS_HANDLE, .name = "FreeCredentialsHandle" },
    .{ .off = SFT.ACQUIRE_CREDENTIALS_HANDLE_A, .name = "AcquireCredentialsHandleA" },
    .{ .off = SFT.ACQUIRE_CREDENTIALS_HANDLE_W, .name = "AcquireCredentialsHandleW" },
    .{ .off = SFT.ADD_CREDENTIALS_A, .name = "AddCredentialsA" },
    .{ .off = SFT.ADD_CREDENTIALS_W, .name = "AddCredentialsW" },
    .{ .off = SFT.COMPLETE_AUTH_TOKEN, .name = "CompleteAuthToken" },
    .{ .off = SFT.INITIALIZE_SECURITY_CONTEXT_A, .name = "InitializeSecurityContextA" },
    .{ .off = SFT.INITIALIZE_SECURITY_CONTEXT_W, .name = "InitializeSecurityContextW" },
};

/// InitSecurityInterfaceA/W: вернуть user-VA SecurityFunctionTableA/W,
/// заполненной указателями на extra-стабы Secur32 (находятся по именам в
/// реестре). curl (schannel) зовёт это в global-init: NULL таблицы =
/// CURLE_FAILED_INIT («error initializing curl library»).
fn initSecurityInterface(disp: *win32.Dispatcher, wide: bool) u64 {
    const c = &(ctx orelse return 0);
    if (c.sspi_table == 0) {
        const p = kmalloc(0x200);
        if (p == 0) return 0;
        @memset(userPtr(p)[0..0x200], 0);
        c.sspi_table = p;
    }
    const tbl = c.sspi_table;
    userD(tbl + SFT.DW_VERSION).* = 2; // SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2

    var filled: usize = 0;
    for (SSPI_FIELDS) |f| {
        if (disp.findByNameAnyDll(f.name)) |stub| {
            userQ(tbl + f.off).* = stub.stub_addr;
            filled += 1;
        }
    }
    logf("[WIN32] InitSecurityInterface{c}: таблица 0x{x}, {d}/{d} SSPI-стабов\n", .{
        @as(u8, if (wide) 'W' else 'A'), tbl, filled, SSPI_FIELDS.len,
    });
    return tbl;
}

// ─── v0.12.0 (CDD №3): WS2_32 — сокетные заглушки (цель: socket/connect) ───

/// socket(af, type, protocol): псевдо-хэндл из ctx (с 0x100, различимы в
/// логах). Поддерживаем AF_INET(2)/AF_INET6(23) — прочее WSAEAFNOSUPPORT.
fn wsaSocket(af: u64, sock_type: u64, protocol: u64) u64 {
    const c = &(ctx orelse return INVALID_SOCKET);
    if (af != 2 and af != 23) {
        setLastError(WSAEAFNOSUPPORT);
        return INVALID_SOCKET;
    }
    const fd = c.next_socket_fd;
    c.next_socket_fd += 1;
    c.sockets_opened += 1;
    logf("[WS2] socket(af={d}, type={d}, proto={d}) -> fd=0x{x}\n", .{ af, sock_type, protocol, fd });
    return fd;
}

/// connect(s, name, namelen): sockaddr разбирается и ЛОГИРУЕТСЯ (цель
/// атаки: IP:порт) — это CDD-маяк волны. Возврат 0 = «соединён мгновенно»
/// (loopback-семантика шима): curl пойдёт к send → честный SOCKET_ERROR.
fn wsaConnect(s: u64, name_va: u64, namelen: u64) u64 {
    if (namelen < 2 or !ops.validate_read(name_va, 2)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    const family = userW(name_va).*;
    if (family == 2 and namelen >= 16 and ops.validate_read(name_va, 16)) {
        const port = std.mem.bigToNative(u16, userW(name_va + 2).*);
        const ip = userPtr(name_va + 4)[0..4];
        logf("[WS2] connect(fd=0x{x}, AF_INET, {d}.{d}.{d}.{d}:{d})\n", .{ s, ip[0], ip[1], ip[2], ip[3], port });
        return 0; // мгновенное «соединение» (шим; сеть — цикл №4)
    }
    if (family == 23 and namelen >= 28 and ops.validate_read(name_va, 28)) {
        const port = std.mem.bigToNative(u16, userW(name_va + 2).*);
        const ip = userPtr(name_va + 8)[0..16];
        logf("[WS2] connect(fd=0x{x}, AF_INET6, [{d}:{d}:{d}:{d}…]:{d})\n", .{ s, ip[0], ip[1], ip[2], ip[3], port });
        return 0;
    }
    setLastError(WSAEINVAL);
    return INVALID_SOCKET;
}

/// closesocket(s): 0 = NO_ERROR.
fn wsaClosesocket(s: u64) u64 {
    logf("[WS2] closesocket(fd=0x{x})\n", .{s});
    return 0;
}

/// ioctlsocket(s, cmd, argp): FIONBIO(0x8004667E) читает u_long-флаг —
/// логируем режим; FIONREAD пишет 0. Возврат 0.
fn wsaIoctlsocket(s: u64, cmd: u64, argp: u64) u64 {
    const FIONBIO: u64 = 0x8004_667E;
    const FIONREAD: u64 = 0x4004_667F;
    if (cmd == FIONBIO) {
        if (!ops.validate_read(argp, 4)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        const mode = userD(argp).*;
        logf("[WS2] ioctlsocket(fd=0x{x}, FIONBIO, {d}) — {s}\n", .{ s, mode, if (mode != 0) "nonblocking" else "blocking" });
        return 0;
    }
    if (cmd == FIONREAD) {
        if (!ops.validate_write(argp, 4)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        userD(argp).* = 0;
        return 0;
    }
    logf("[WS2] ioctlsocket(fd=0x{x}, cmd=0x{x}) — no-op\n", .{ s, cmd });
    return 0;
}

/// send(s, buf, len, flags): сетевого стека в v0.12 нет — честный
/// SOCKET_ERROR + WSAENETDOWN (curl напечатает через FormatMessageA).
fn wsaSend(s: u64, buf: u64, len: u64, flags: u64) u64 {
    _ = flags;
    if (len > 64 * 1024 * 1024) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    if (len > 0 and !ops.validate_read(buf, len)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    logf("[WS2] send(fd=0x{x}, len={d}) — SOCKET_ERROR WSAENETDOWN (стек сети: цикл №4)\n", .{ s, len });
    setLastError(WSAENETDOWN);
    return INVALID_SOCKET;
}

/// recv(s, buf, len, flags): SOCKET_ERROR + WSAETIMEDOUT (нет сети).
fn wsaRecv(s: u64, buf: u64, len: u64, flags: u64) u64 {
    _ = buf;
    _ = len;
    _ = flags;
    logf("[WS2] recv(fd=0x{x}) — SOCKET_ERROR WSAETIMEDOUT (стек сети: цикл №4)\n", .{s});
    setLastError(WSAETIMEDOUT);
    return INVALID_SOCKET;
}

/// htons/htonl/ntohs/ntohl: byte-swap (little-endian хост).
fn wsaHtons(v: u64) u64 {
    return @as(u64, @byteSwap(@as(u16, @truncate(v))));
}
fn wsaHtonl(v: u64) u64 {
    return @as(u64, @byteSwap(@as(u32, @truncate(v))));
}

/// getaddrinfo(node, service, hints, ppResult): DNS-резолвера нет —
/// СИНТЕЗ (RFC 5737 TEST-NET-1: 192.0.2.1): адресinfo-список в block-heap,
/// порт — из service (если числовой). Честный CDD: резолв = цикл №4.
/// Возврат 0 (успех) — curl дойдёт до socket()/connect() и осмысленно
/// залогирует цель (настоящий IP придёт с DNS).
fn wsaGetAddrInfo(node_va: u64, serv_va: u64, hints_va: u64, pp_result: u64) u64 {
    if (!ops.validate_write(pp_result, 8)) {
        return WSAEFAULT;
    }
    var hostname: []const u8 = "";
    if (node_va != 0) {
        if (userStrLen(node_va)) |len| {
            if (len > 0 and len < 64) hostname = userPtr(node_va)[0..@intCast(len)];
        }
    }
    var port: u16 = 0;
    if (serv_va != 0) {
        if (userStrLen(serv_va)) |len| {
            if (len > 0 and len <= 5) {
                const s = userPtr(serv_va)[0..@intCast(len)];
                port = std.fmt.parseInt(u16, s, 10) catch 0;
            }
        }
    }
    if (hints_va != 0) {
        _ = ops.validate_read(hints_va, 0x18); // hints читаем, но синтез один
    }

    // addrinfo (0x30Б) + sockaddr_in (16Б) в block-heap
    const ai = kmalloc(0x30);
    const sa = kmalloc(16);
    if (ai == 0 or sa == 0) return WSAEFAULT; // 10014? — EAI_MEMORY~WSAEFAULT
    @memset(userPtr(ai)[0..0x30], 0);
    @memset(userPtr(sa)[0..16], 0);
    userD(ai + 0x04).* = 2; // ai_family = AF_INET
    userD(ai + 0x08).* = 1; // ai_socktype = SOCK_STREAM
    userD(ai + 0x0C).* = 6; // ai_protocol = IPPROTO_TCP
    userQ(ai + 0x10).* = 16; // ai_addrlen
    userQ(ai + 0x18).* = 0; // ai_canonname
    userQ(ai + 0x20).* = sa; // ai_addr
    userQ(ai + 0x28).* = 0; // ai_next
    userW(sa + 0).* = 2; // sin_family
    userW(sa + 2).* = std.mem.nativeToBig(u16, port); // sin_port (BE)
    const ip4 = userPtr(sa + 4)[0..4];
    ip4[0] = 192;
    ip4[1] = 0;
    ip4[2] = 2;
    ip4[3] = 1; // TEST-NET-1
    userQ(pp_result).* = ai;
    logf("[WS2] getaddrinfo(\"{s}\") -> синтез 192.0.2.1:{d} (DNS-резолвер: цикл №4)\n", .{ hostname, port });
    return 0; // 0 = успех (EAI_SUCCESS)
}

/// freeaddrinfo(res): no-op (block-heap без reuse — страница с задачей).
fn wsaFreeAddrInfo(res: u64) u64 {
    _ = res;
    return 0;
}

// ─── v0.12.0 (CDD №3, event-волна): WSA-event loop ─────────────────────────
// Драйвер: «curl: (27) Out of memory» — WSACreateEvent(trap) → NULL →
// curl трактует как OOM. События — краеугольный камень Win-сокет-модели:
// WSAEventSelect(асинхр. уведомления) + WSAWaitForMultipleEvents(цикл).
// Событийный дескриптор: ненулевой, ≠ -1, уникальный (пул 0x200+).

const WSA_WAIT_EVENT_0: u64 = 0;
const WSA_WAIT_TIMEOUT: u64 = 258;
const WAIT_OBJECT_0: u64 = 0;
const WAIT_TIMEOUT: u64 = 258;

fn wsaCreateEvent() u64 {
    const c = &(ctx orelse return 0);
    const h = c.next_event_handle;
    c.next_event_handle += 1;
    logf("[WS2] WSACreateEvent -> handle=0x{x}\n", .{h});
    return h;
}

/// WSACloseEvent(h): TRUE (1) — событие «закрыто».
fn wsaCloseEvent(h: u64) u64 {
    logf("[WS2] WSACloseEvent(handle=0x{x})\n", .{h});
    return 1;
}

/// WSAResetEvent(h): TRUE — событие сброшено (не в сигнальном состоянии).
fn wsaResetEvent(h: u64) u64 {
    _ = h;
    return 1;
}

/// WSAEventSelect(s, h, events): 0 = успех. События сокета НЕ приходят
/// (нет сетевого стека) — curl узнает об этом через EnumNetworkEvents.
fn wsaEventSelect(s: u64, h: u64, events: u64) u64 {
    logf("[WS2] WSAEventSelect(fd=0x{x}, handle=0x{x}, events=0x{x}) -> 0\n", .{ s, h, events });
    return 0;
}

/// WSAEnumNetworkEvents(s, h, lpNetworkEvents): 0 = успех, структура
/// обнулена (событий нет). WSANETWORKEVENTS: fd=0,s1=0,dw=0,fd2=0… iErrorCode[6].
fn wsaEnumNetworkEvents(s: u64, h: u64, lp: u64) u64 {
    if (lp != 0 and ops.validate_write(lp, 32)) {
        @memset(userPtr(lp)[0..32], 0); // lNetworkEvents = 0
    }
    logf("[WS2] WSAEnumNetworkEvents(fd=0x{x}) -> 0 событий\n", .{s});
    _ = h;
    return 0;
}

/// WSAWaitForMultipleEvents(n, events, waitAll, timeout, alertable):
/// события никогда не сигналятся → WSA_WAIT_TIMEOUT. Это честная граница
/// (нет сигнальных объектов — kernel-task не блокируется, планировщик
/// переключает задачи; curl крутит свой неблокирующий цикл).
fn wsaWaitForMultipleEvents(n: u64, events_va: u64, wait_all: u64, timeout: u64, alertable: u64) u64 {
    if (n == 0 or n > 64) return @as(u64, WSA_INVALID_HANDLE);
    if (events_va == 0 or !ops.validate_read(events_va, n * 8)) {
        return @as(u64, WSA_INVALID_HANDLE);
    }
    // сигнальный объект? (тред-хэндл завершившегося резолвера)
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        if (ops.object_signaled(userQ(events_va + i * 8).*)) {
            logf("[WS2] WSAWaitForMultipleEvents(n={d}) -> EVENT {d} signaled\n", .{ n, i });
            return WSA_WAIT_EVENT_0 + i;
        }
    }
    // поллинг-горячий путь (<1с) — не логируем каждую 1мс-итерацию
    if (timeout >= 1000) {
        logf("[WS2] WSAWaitForMultipleEvents(n={d}, waitAll={d}, timeout=0x{x})\n", .{ n, wait_all, timeout });
    }
    _ = alertable;
    return WSA_WAIT_TIMEOUT;
}

const WSA_INVALID_HANDLE: u64 = 6;

/// WaitForSingleObject(h, ms): сигнальный объект → WAIT_OBJECT_0
/// (тред-хэндл: задача Killed), иначе — WAIT_TIMEOUT.
fn kWaitForSingleObject(h: u64, ms: u64) u64 {
    if (ops.object_signaled(h)) {
        logf("[WIN32] WaitForSingleObject(handle=0x{x}) -> WAIT_OBJECT_0 (сигнален)\n", .{h});
        return WAIT_OBJECT_0;
    }
    logf("[WIN32] WaitForSingleObject(handle=0x{x}, timeout={d}ms) -> timeout\n", .{ h, ms });
    return WAIT_TIMEOUT;
}

fn kWaitForSingleObjectEx(h: u64, ms: u64, alertable: u64) u64 {
    _ = alertable;
    return kWaitForSingleObject(h, ms);
}

/// WaitForMultipleObjects(n, handles, waitAll, ms): сигнальный → индекс+WAIT_OBJECT_0.
fn kWaitForMultipleObjects(n: u64, handles_va: u64, wait_all: u64, ms: u64) u64 {
    if (n == 0 or n > 64) return 0xFFFFFFFF; // WAIT_FAILED
    if (handles_va == 0 or !ops.validate_read(handles_va, n * 8)) {
        return 0xFFFFFFFF;
    }
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        if (ops.object_signaled(userQ(handles_va + i * 8).*)) {
            logf("[WIN32] WaitForMultipleObjects(n={d}) -> object {d} signaled\n", .{ n, i });
            return WAIT_OBJECT_0 + i;
        }
    }
    logf("[WIN32] WaitForMultipleObjects(n={d}, waitAll={d}, timeout={d}ms) -> timeout\n", .{ n, wait_all, ms });
    return WAIT_TIMEOUT;
}

/// CreateEventA (KERNEL32): тот же пул событий, что у WSA — хэндлы едины.
fn kCreateEventA(attrs: u64, manual_reset: u64, initial: u64, name_va: u64) u64 {
    _ = attrs;
    _ = manual_reset;
    _ = initial;
    if (name_va != 0) {
        const nlen = userStrLen(name_va) orelse 0;
        if (nlen > 0 and ops.validate_read(name_va, @min(nlen, 64))) {
            logf("[WIN32] CreateEventA(\"{s}\")\n", .{userPtr(name_va)[0..@intCast(@min(nlen, 64))]});
        }
    } else {
        logf("[WIN32] CreateEventA(unnamed)\n", .{});
    }
    const c = &(ctx orelse return 0);
    const h = c.next_event_handle;
    c.next_event_handle += 1;
    return h;
}

/// __WSAFDIsSet(s, fd_set): тело макроса select() — «есть ли s в наборе?».
/// fd_set: { u32 fd_count; SOCKET fd_array[64]; } — массив с СМЕЩЕНИЯ 8
/// (count 4Б + padding 4Б до выравнивания SOCKET=8). Возврат: ненулевое
/// при обнаружении (реальная семантика WS2_32, не стаб!).
fn wsaFdIsSet(s: u64, fd_set: u64) u64 {
    if (fd_set == 0 or !ops.validate_read(fd_set, 4)) return 0;
    const count: u32 = @as(*align(1) const u32, @ptrFromInt(fd_set)).*;
    if (count == 0 or count > 64) return 0;
    if (!ops.validate_read(fd_set + 8, @as(u64, count) * 8)) return 0;
    const arr = fd_set + 8;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        if (userQ(arr + i * 8).* == s) return 1;
    }
    return 0;
}

/// WSAIoctl(s, code, inbuf, inlen, outbuf, outlen, ...): unsupported —
/// честный SOCKET_ERROR + WSAEOPNOTSUPP (сетевой стек — цикл №4).
fn wsaIoctl(s: u64, code: u64) u64 {
    logf("[WS2] WSAIoctl(fd=0x{x}, code=0x{x}) -> WSAEOPNOTSUPP\n", .{ s, code });
    setLastError(WSAEOPNOTSUPP);
    return INVALID_SOCKET;
}

const WSAEOPNOTSUPP: u32 = 10045;

/// WSASetLastError(e): сохранить в ctx (WSAGetLastError вернёт).
fn wsaSetLastError(e: u64) u64 {
    if (ctx) |*c| c.last_error = @truncate(e);
    return 0;
}

// ─── v0.12.0 (CDD №3, threading-волна): НАСТОЯЩИЕ Win64-треды ───────────────
// Драйвер: curl доходит до socket() → CreateThread(резолвер) → trap-NULL →
// вечный 1мс-поллинг WSAWaitForMultipleEvents (141К итераций). Тред = задача
// планировщика на той же PML4: общий heap/IAT/ctx — как процесс Windows.

/// CreateThread(attrs, stackSize, start, param, flags, pThreadId):
/// стек — VirtualAlloc (RW+NX, vheap); exit — Return-трамплин ExitThread
/// (extra-запись реестра, impl-trampoline); RCX=param при входе.
/// Возврат: хэндл 0x1000+task_id. pThreadId (если указан) — тоже пишем.
fn kCreateThread(disp: *win32.Dispatcher, stack_size: u64, start: u64, param: u64, flags: u64, p_tid: u64) u64 {
    if (flags & 0x1 != 0) {
        setLastError(87); // ERROR_INVALID_PARAMETER: CREATE_SUSPENDED
        return 0; // неприостановленные треды не поддержаны
    }
    // стек: минимум 64КБ (Win64 default для CRT-треда ~1МБ — но vheap 512МБ,
    // бережём; резолверу curl хватает)
    const want: u64 = if (stack_size < 0x10000) 0x10000 else (stack_size + 0xFFF) & ~@as(u64, 0xFFF);
    const stack = virtualAlloc(0, want, 0x3000, 4); // MEM_COMMIT|RESERVE, RW
    if (stack == 0) {
        setLastError(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    // exit-трамплин: find-or-create «ExitThread» в реестре
    var exit_va: u64 = 0;
    if (disp.findByNameAnyDll("ExitThread")) |e| {
        exit_va = e.stub_addr;
    } else if (disp.addExtraStub("KERNEL32.dll", "ExitThread", .impl) != null) {
        if (disp.findByNameAnyDll("ExitThread")) |e| exit_va = e.stub_addr;
    }
    if (exit_va == 0) return 0; // без exit-пути тред запускать нельзя
    // 16-байтовое выравнивание верха + [rsp]=exit (имитация call-кадра)
    const stack_top = stack + want;
    const handle = ops.create_thread(start, param, stack_top, exit_va);
    if (handle == 0) {
        setLastError(8);
        return 0;
    }
    if (p_tid != 0 and ops.validate_write(p_tid, 4)) {
        @as(*align(1) u32, @ptrFromInt(p_tid)).* = @truncate(handle);
    }
    logf("[WIN32] CreateThread(start=0x{x}, param=0x{x}, stack=0x{x}..0x{x}) -> handle=0x{x}\n", .{ start, param, stack, stack_top, handle });
    return handle;
}

/// ExitThread(code) / возврат из ThreadProc: убить ТЕКУЩУЮ задачу.
fn kExitThread(code: u64) u64 {
    logf("[WIN32] ExitThread(0x{x}) — тред завершился\n", .{code});
    ops.exit_task();
    return 0; // недостижимо в ядре (hlt до вытеснения)
}

/// memchr(s, c, n): указатель на ПЕРВОЕ вхождение байта в n байтах
/// (в отличие от strchr — без NUL-терминации, чисто длина).
pub fn kmemchr(s: u64, c: u64, n: u64) u64 {
    if (n > 64 * 1024 * 1024) return 0;
    if (n == 0) return 0;
    if (!ops.validate_read(s, n)) return 0;
    const want: u8 = @truncate(c);
    const str = userPtr(s)[0..@intCast(n)];
    if (std.mem.indexOfScalar(u8, str, want)) |off| return s + off;
    return 0;
}

/// _time64(t): секунды UNIX. TSC-часы не привязаны к эпохе (нет RTC-драйвера)
/// — честная граница: возвращаем СТАБИЛЬНЫЙ момент (2026-01-01 UTC,
/// 1767225600): не «сейчас», но детерминированно и далеко от 0 (curl
/// использует время для кэша/Retry-After, не для криптографии).
fn kTime64(t: u64) u64 {
    const now: u64 = 1767225600;
    if (t != 0 and ops.validate_write(t, 8)) {
        std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(t))), now, .little);
    }
    return now;
}

/// GetSystemTimeAsFileTime(lpSystemTimeAsFileTime): 64-бит FILETIME
/// (100нс-интервалы с 1601-01-01). 2026-01-01 = 133951872000000000.
fn kGetSystemTimeAsFileTime(lp: u64) u64 {
    if (lp == 0 or !ops.validate_write(lp, 8)) return 0;
    std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(lp))), 133_951_872_000_000_000, .little);
    return 0;
}

/// GetTickCount64(): миллисекунды с бута — TSC/частота.
fn kGetTickCount64() u64 {
    if (ctx) |c| {
        if (c.tsc_freq > 1000) return ops.read_tsc() / (c.tsc_freq / 1000);
    }
    return 0;
}

/// Condition-variable семья (curl: CV+CS = синхронизация резолвера):
/// однопоточно-совместимая семантика — Sleep-вариант сразу «просыпается»
/// (как Windows для незанятой CV), Wake — no-op.
fn kSleepConditionVariableCS(cv: u64, cs: u64, ms: u64) u64 {
    logf("[WIN32] SleepConditionVariableCS(0x{x}, ms={d}) -> TRUE (CV свободна)\n", .{ cv, ms });
    _ = cs;
    return 1;
}

// ─── v0.12.0 (CDD №3, event-волна): stdio-интроспекция + конверсия ─────────

/// _fileno(FILE*): stdin/stdout/stdstderr → 0/1/2 (по позиции в iob-массиве),
/// чужой FILE* → -1 (errno EINVAL). Статическая FILE-модель CRT.
fn kfileno(file: u64) u64 {
    const c = &(ctx orelse return @bitCast(@as(i64, -1)));
    if (file == 0) return @bitCast(@as(i64, -1));
    if (c.iob_array != 0 and file >= c.iob_array and file < c.iob_array + 3 * 80) {
        const idx = (file - c.iob_array) / 80;
        return idx;
    }
    return @bitCast(@as(i64, -1));
}

/// _isatty(fd): 0/1/2 — наш сериальный КОНСОЛЬ = настоящий терминал (1);
/// прочее — не tty (0). curl решает: раскраска/прогресс vs pipe-режим.
fn kisatty(fd: u64) u64 {
    return if (fd <= 2) 1 else 0;
}

/// _setmode(fd, mode): возвращает ПРЕДЫДУЩИЙ режим (UCRT-конвенция).
/// Наш конвейер текстовый: _O_TEXT = 0x4000.
fn ksetmode(fd: u64, mode: u64) u64 {
    logf("[CRT] _setmode(fd={d}, mode=0x{x}) -> _O_TEXT\n", .{ fd, mode });
    return 0x4000; // _O_TEXT (прошлый режим; конвейер текстовый)
}

/// strcspn(s, reject): длина префикса ДО первого символа из reject.
/// Классика: разбора URL (поиск «?#»), разделителей конфигов.
pub fn kstrcspn(s: u64, reject: u64) u64 {
    const len = userStrLen(s) orelse return 0;
    const rlen = userStrLen(reject) orelse return len;
    if (!ops.validate_read(s, len) or !ops.validate_read(reject, rlen)) return 0;
    const str = userPtr(s)[0..@intCast(len)];
    const rej = userPtr(reject)[0..@intCast(rlen)];
    var i: usize = 0;
    outer: while (i < str.len) : (i += 1) {
        for (rej) |r| {
            if (str[i] == r) break :outer;
        }
    }
    return i;
}

/// mbstowcs_s(ret, wcstr, size, mbstr, count): ANSI → UTF-16LE.
/// *ret = число сконвертированных (без NUL). Возврат 0 = успех.
/// rc=0 или битые указатели → EINVAL (не паника).
fn kmbstowcsS(ret_va: u64, wcstr: u64, size_in: u64, mbstr: u64, count: u64) u64 {
    const EINVAL: u64 = 22;
    if (ret_va == 0 or mbstr == 0) return EINVAL;
    if (!ops.validate_write(ret_va, 8)) return EINVAL;
    const len = userStrLen(mbstr) orelse return EINVAL;
    const take: u64 = if (count < len) count else len;
    // буфер wcstr: sizewchar, пишем take+1 (NUL) если size хватает
    if (wcstr != 0 and size_in > 0) {
        if (!ops.validate_write(wcstr, size_in * 2)) return EINVAL;
        if (take + 1 > size_in) { // не влезает с NUL → ERANGE
            std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(ret_va))), 0, .little);
            return 34; // ERANGE
        }
        var i: u64 = 0;
        while (i < take) : (i += 1) {
            std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(userPtr(wcstr + i * 2))), @intCast(userPtr(mbstr)[@as(usize, @intCast(i))]), .little);
        }
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(userPtr(wcstr + take * 2))), 0, .little);
    }
    std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(ret_va))), take, .little);
    return 0;
}

/// _fsopen(path, mode, share): файловой системы нет → NULL + errno ENOENT
/// («файл не найден» — честная граница; конфиг .curlrc у нас и не должен
/// существовать). Режим тоже валидируем по первой букве (r/w/a).
fn kfsopen(path_va: u64, mode_va: u64, share: u64) u64 {
    var name_buf: [48]u8 = undefined;
    var name_len: u64 = 0;
    if (path_va != 0) {
        if (userStrLen(path_va)) |l| {
            name_len = @min(l, 47);
            if (name_len > 0 and ops.validate_read(path_va, name_len)) {
                @memcpy(name_buf[0..@intCast(name_len)], userPtr(path_va)[0..@intCast(name_len)]);
                name_buf[@intCast(name_len)] = 0;
            }
        }
    }
    if (ctx) |*cc| {
        if (cc.errno_ptr != 0) {
            if (ops.validate_write(cc.errno_ptr, 4)) {
                @as(*align(1) u32, @ptrFromInt(cc.errno_ptr)).* = 2; // ENOENT
            }
        }
    }
    var mode: u8 = '?';
    if (mode_va != 0 and ops.validate_read(mode_va, 1)) {
        mode = userPtr(mode_va)[0];
    }
    logf("[CRT] _fsopen(\"{s}\", mode='{c}') -> NULL (нет ФС, ENOENT)\n", .{ name_buf[0..@intCast(name_len)], mode });
    _ = share;
    return 0;
}

// ─── v0.12.0 (CDD №3): module-walk KERNEL32 (цепочка с URL-аргументами) ────

/// Псевдо-хэндл снапшота модулей (ненулевой, ≠ INVALID_HANDLE_VALUE(-1)):
/// curl примет его как валидный, Module32First ответит FALSE — walk
/// завершится чисто (у нас один «модуль» — сам PE-образ, перечислять
/// нечего — честная граница DLL-энумерации).
const FAKE_SNAPSHOT: u64 = 0x4A2C_0001;

fn createToolhelp32Snapshot(flags: u64, pid: u64) u64 {
    logf("[WIN32] CreateToolhelp32Snapshot(flags=0x{x}, pid={d}) -> псевдо-хэндл 0x{x} (модулей нет — мы один PE)\n", .{ flags, pid, FAKE_SNAPSHOT });
    return FAKE_SNAPSHOT;
}

/// Module32FirstW(hSnapshot, lpme): FALSE — список модулей пуст.
fn module32First(h: u64, lp_me: u64) u64 {
    _ = lp_me;
    if (h != FAKE_SNAPSHOT) return 0;
    logf("[WIN32] Module32First -> FALSE (снапшот пуст)\n", .{});
    return 0;
}

/// Module32NextW(hSnapshot, lpme): FALSE.
fn module32Next(h: u64, lp_me: u64) u64 {
    _ = h;
    _ = lp_me;
    return 0;
}

/// CloseHandle(hObject): TRUE (закрываем что угодно — псевдо-объекты).
fn closeHandle(h: u64) u64 {
    logf("[WIN32] CloseHandle(0x{x}) -> TRUE\n", .{h});
    return 1;
}

/// GetModuleFileNameA(hModule, lpFilename, nSize): путь ОБРАЗА процесса.
/// curl выводит из него каталог для .curlrc/CA-бандла. hModule==NULL (или
/// image_base — как отдаёт GetModuleHandleA) → путь образа; иное → 0.
/// Пишем «\curl.exe» (корень без каталогов — честная модель одного PE).
fn getModuleFileNameA(h_module: u64, lp_filename: u64, n_size: u64) u64 {
    const c = &(ctx orelse return 0);
    if (h_module != 0 and h_module != c.image_base) return 0; // чужой модуль
    const path = "\\curl.exe";
    if (n_size < path.len + 1) {
        setLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (!ops.validate_write(lp_filename, path.len + 1)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    @memcpy(userPtr(lp_filename)[0..path.len], path);
    userPtr(lp_filename)[path.len] = 0;
    return path.len; // без NUL — контракт Win32
}

// ─── Ленивые CRT-структуры ──────────────────────────────────────────────────

/// __acrt_iob_func(idx): СТАБИЛЬНЫЙ массив 3×80Б (stdin=0, stdout=1, stderr=2).
/// v0.10-баг: каждый вызов аллоцировал НОВУЮ страницу — CRT терял записанное
/// в FILE-структуры состояние. Теперь массив один, кэшируется в ctx.
fn acrtIobFunc(idx: u64) u64 {
    const c = &(ctx orelse return 0);
    if (idx > 2) return 0;
    if (c.iob_array == 0) {
        const arr = kmalloc(3 * 80);
        if (arr == 0) return 0;
        @memset(userPtr(arr)[0..3 * 80], 0);
        c.iob_array = arr;
    }
    return c.iob_array + idx * 80;
}

/// Общий ленивый 16-байтный нулевой блок (для всех «верни указатель, CRT сам
/// туда пишет»-функций: __p__fmode/__p__commode/_errno).
fn lazyPtr16(field_ptr: *u64) u64 {
    if (field_ptr.* == 0) {
        const p = kmalloc(16);
        if (p == 0) return 0;
        @memset(userPtr(p)[0..16], 0);
        field_ptr.* = p;
    }
    return field_ptr.*;
}

/// Токенизация командной строки НА МЕСТЕ (пробелы → NUL) + построение
/// argc/argv в block-heap. Вызывается лениво из __p___argc/__p___argv —
/// это syscall-контекст, прямая запись в params-страницу легальна.
/// «curl.exe --version x» → argc=3, argv[0]="curl.exe"…
fn ensureArgv() void {
    const c = &(ctx orelse return);
    if (c.argv_slot != 0) return; // уже построено

    var tokens: [64]u64 = undefined;
    var ntok: usize = 0;
    if (c.cmdline_a != 0 and ops.validate_write(c.cmdline_a, 0x100)) {
        var i: u64 = 0;
        var in_tok = false;
        while (i < 0x100) : (i += 1) {
            const ch = userPtr(c.cmdline_a)[@as(usize, @intCast(i))];
            if (ch == 0) break; // конец строки — последний токен уже терминирован
            if (ch == ' ' or ch == 9) {
                if (in_tok) {
                    userPtr(c.cmdline_a)[@as(usize, @intCast(i))] = 0;
                    in_tok = false;
                }
            } else {
                if (!in_tok and ntok < tokens.len) {
                    tokens[ntok] = c.cmdline_a + i;
                    ntok += 1;
                }
                in_tok = true;
            }
        }
    }

    // int* argc
    c.argc_ptr = kmalloc(16);
    if (c.argc_ptr == 0) return;
    @memset(userPtr(c.argc_ptr)[0..16], 0);
    userD(c.argc_ptr).* = @intCast(ntok);

    // char** argv = {token…, NULL}
    const arr = kmalloc(8 * (ntok + 1));
    if (arr == 0) return;
    for (tokens[0..ntok], 0..) |t, k| {
        userQ(arr + k * 8).* = t;
    }
    userQ(arr + ntok * 8).* = 0;

    // char***-слот: __p___argv() возвращает R, CRT читает argv = *R
    const slot = kmalloc(8);
    if (slot == 0) return;
    userQ(slot).* = arr;
    c.argv_slot = slot;

    // CDD-диагностика: что ПРИЛОЖЕНИЕ реально увидит в argv (разбор
    // «option …: is unknown» — классификация URL/опции в curl).
    logf("[WIN32] ensureArgv: argc={d}", .{ntok});
    for (tokens[0..ntok], 0..) |t, k| {
        const tl = userStrLen(t) orelse 0;
        if (tl > 0 and tl <= 64) {
            logf(" argv[{d}]=\"{s}\"", .{ k, userPtr(t)[0..@intCast(tl)] });
        } else {
            logf(" argv[{d}]=0x{x}", .{ k, t });
        }
    }
    logf("\n", .{});
}

// ─── Диспетчер syscall #6 (win32_call) ──────────────────────────────────────

/// Точка входа из hal.zig через win32_api.syscallDispatch.
pub fn syscallDispatch(entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    const disp = win32.activeDispatcher() orelse return 0;
    return dispatch(disp, entry_id, a1, a2, a3, a4);
}

/// Диспетчер по entry_id реестра стабов: имя → реализация. DLL-имена
/// case-insensitive; api-ms-win-crt-* — UCRT-обёртки mingw.
pub fn dispatch(disp: *win32.Dispatcher, entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    if (entry_id >= disp.count) return 0;
    const e = &disp.entries[@intCast(entry_id)];
    const name = switch (e.func) {
        .by_name => |n| n,
        .by_ordinal => return 0, // ординал-импорты не реализованы (v0.11)
    };

    var ret: u64 = 0;
    var handled = true;

    if (std.ascii.eqlIgnoreCase(e.dll, "KERNEL32.dll")) {
        if (std.mem.eql(u8, name, "GetStdHandle")) {
            ret = getStdHandle(a1);
        } else if (std.mem.eql(u8, name, "GetCommandLineA")) {
            ret = if (ctx) |c| c.cmdline_a else 0;
        } else if (std.mem.eql(u8, name, "GetCommandLineW")) {
            ret = if (ctx) |c| c.cmdline_w else 0;
        } else if (std.mem.eql(u8, name, "VirtualAlloc")) {
            ret = virtualAlloc(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "ExitProcess")) {
            ops.exit(a1); // ядро не возвращается (hlt); тесты ставят флаг
            return 0;
        } else if (std.mem.eql(u8, name, "GetModuleHandleA") or std.mem.eql(u8, name, "GetModuleHandleW")) {
            ret = if (ctx) |c| c.image_base else 0;
        } else if (std.mem.eql(u8, name, "GetProcAddress")) {
            ret = getProcAddress(disp, a1, a2);
        } else if (std.mem.eql(u8, name, "QueryPerformanceFrequency")) {
            ret = queryPerformanceFrequency(a1);
        } else if (std.mem.eql(u8, name, "QueryPerformanceCounter")) {
            ret = queryPerformanceCounter(a1);
        } else if (std.mem.eql(u8, name, "GetConsoleMode")) {
            ret = getConsoleMode(a1, a2);
        } else if (std.mem.eql(u8, name, "GetConsoleScreenBufferInfo")) {
            ret = getConsoleScreenBufferInfo(a1, a2);
        } else if (std.mem.eql(u8, name, "GetCurrentThreadId")) {
            // v0.12.0: реальный TID — главный тред и тред резолвера различаются
            ret = ops.current_tid();
        } else if (std.mem.eql(u8, name, "AcquireSRWLockExclusive") or
            std.mem.eql(u8, name, "ReleaseSRWLockExclusive") or
            std.mem.eql(u8, name, "Sleep"))
        {
            ret = 0; // no-op: однопоточный CDD-процесс (честная граница)
        } else if (std.mem.eql(u8, name, "SetUnhandledExceptionFilter")) {
            ret = 0; // предыдущего фильтра не было
        } else if (std.mem.eql(u8, name, "VerSetConditionMask")) {
            ret = verSetConditionMask(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "VerifyVersionInfoW")) {
            ret = verifyVersionInfoW(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "GetEnvironmentVariableA")) {
            ret = getEnvironmentVariableA(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "GetEnvironmentVariableW")) {
            ret = getEnvironmentVariableW(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "FormatMessageA")) {
            ret = formatMessageA(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "FormatMessageW")) {
            ret = formatMessageW(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "GetLastError")) {
            ret = if (ctx) |c| c.last_error else 0;
        } else if (std.mem.eql(u8, name, "SetLastError")) {
            if (ctx) |*c| c.last_error = @truncate(a1);
        } else if (std.mem.eql(u8, name, "InitOnceExecuteOnce")) {
            ret = initOnceExecuteOnce(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "CreateToolhelp32Snapshot")) {
            ret = createToolhelp32Snapshot(a1, a2);
        } else if (std.mem.eql(u8, name, "Module32First") or std.mem.eql(u8, name, "Module32FirstW")) {
            ret = module32First(a1, a2);
        } else if (std.mem.eql(u8, name, "Module32Next") or std.mem.eql(u8, name, "Module32NextW")) {
            ret = module32Next(a1, a2);
        } else if (std.mem.eql(u8, name, "CloseHandle")) {
            ret = closeHandle(a1);
        } else if (std.mem.eql(u8, name, "InitializeCriticalSection") or
            std.mem.eql(u8, name, "EnterCriticalSection") or
            std.mem.eql(u8, name, "LeaveCriticalSection") or
            std.mem.eql(u8, name, "DeleteCriticalSection"))
        {
            // void-функции: однопоточный CDD-процесс — секция всегда «свободна»
            ret = 0;
        } else if (std.mem.eql(u8, name, "GetModuleFileNameA")) {
            ret = getModuleFileNameA(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "CreateEventA")) {
            // event-волна: единый пул хэндлов с WSACreateEvent (4 рег-аргумента)
            ret = kCreateEventA(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "WaitForSingleObject")) {
            ret = kWaitForSingleObject(a1, a2);
        } else if (std.mem.eql(u8, name, "WaitForSingleObjectEx")) {
            ret = kWaitForSingleObjectEx(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "WaitForMultipleObjects")) {
            ret = kWaitForMultipleObjects(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "InitializeCriticalSectionEx")) {
            // CS-семья: однопоточный CDD-процесс — честный успех
            ret = 0;
        } else if (std.mem.eql(u8, name, "InitializeConditionVariable")) {
            ret = 0; // void: CV проинициализирована (свободна)
        } else if (std.mem.eql(u8, name, "WakeConditionVariable")) {
            ret = 0; // void: некому будить — no-op
        } else if (std.mem.eql(u8, name, "SleepConditionVariableCS")) {
            // CV свободна (никто не ждёт под тем же CS) — мгновенный TRUE
            ret = kSleepConditionVariableCS(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "CreateThread")) {
            // threading-волна: RCX=attrs, RDX=stackSize, R8=start, R9=param,
            // стек[0]=flags, стек[1]=pThreadId
            ret = kCreateThread(disp, a2, a3, a4, ops.stack_arg(0), ops.stack_arg(1));
        } else if (std.mem.eql(u8, name, "ExitThread")) {
            // тред ≠ процесс: убираем только ТЕКУЩУЮ задачу
            ret = kExitThread(a1);
        } else if (std.mem.eql(u8, name, "GetSystemTimeAsFileTime")) {
            _ = kGetSystemTimeAsFileTime(a1);
            ret = 0;
        } else if (std.mem.eql(u8, name, "GetTickCount64")) {
            ret = kGetTickCount64();
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-stdio-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "__acrt_iob_func")) {
            ret = acrtIobFunc(a1);
        } else if (std.mem.eql(u8, name, "__p__fmode")) {
            const c = &(ctx orelse return 0);
            ret = lazyPtr16(&c.fmode_ptr);
        } else if (std.mem.eql(u8, name, "__p__commode")) {
            const c = &(ctx orelse return 0);
            ret = lazyPtr16(&c.commode_ptr);
        } else if (std.mem.eql(u8, name, "setvbuf")) {
            ret = 0; // режимы буферизации FILE* — no-op (консоль небуферизована)
        } else if (std.mem.eql(u8, name, "fputs")) {
            ret = fputs(a1, a2);
        } else if (std.mem.eql(u8, name, "fputc")) {
            ret = fputc(a1, a2);
        } else if (std.mem.eql(u8, name, "fwrite")) {
            // fwrite(ptr, size, nmemb, stream): Win64 RCX/RDX/R8/R9 → a1..a4
            ret = fwrite(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "fflush")) {
            ret = 0; // консоль пишется сразу — нечего сбрасывать
        } else if (std.mem.eql(u8, name, "_fileno")) {
            // event-волна: FILE* → fd (stdin/stdout/stderr = 0/1/2)
            ret = kfileno(a1);
        } else if (std.mem.eql(u8, name, "_isatty")) {
            ret = kisatty(a1);
        } else if (std.mem.eql(u8, name, "_setmode")) {
            ret = ksetmode(a1, a2);
        } else if (std.mem.eql(u8, name, "_fsopen")) {
            ret = kfsopen(a1, a2, a3);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-time-l1-1-0.dll")) {
        // threading-волна: время (Retry-After, кэши, прогресс-бар)
        if (std.mem.eql(u8, name, "_time64")) {
            ret = kTime64(a1);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-runtime-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "exit") or std.mem.eql(u8, name, "_exit")) {
            ops.exit(a1);
            return 0;
        }
        if (std.mem.eql(u8, name, "abort")) {
            ops.exit(3); // SIGABRT-код
            return 0;
        }
        if (std.mem.eql(u8, name, "strerror")) {
            // fix-волна №3: NULL у trap-стаба = пустые сообщения об ошибках
            ret = kstrerror(a1);
        } else if (std.mem.eql(u8, name, "__p___argc")) {
            ensureArgv();
            ret = if (ctx) |*c| c.argc_ptr else 0;
        } else if (std.mem.eql(u8, name, "__p___argv")) {
            ensureArgv();
            ret = if (ctx) |*c| c.argv_slot else 0;
        } else if (std.mem.eql(u8, name, "_errno")) {
            const c = &(ctx orelse return 0);
            ret = lazyPtr16(&c.errno_ptr); // отдельный ленивый int*-блок
        } else if (std.mem.eql(u8, name, "_crt_atexit") or
            std.mem.eql(u8, name, "_set_app_type") or
            std.mem.eql(u8, name, "_set_invalid_parameter_handler") or
            std.mem.eql(u8, name, "_initialize_onexit_table") or
            std.mem.eql(u8, name, "_register_onexit_function") or
            std.mem.eql(u8, name, "_configure_narrow_argv") or
            std.mem.eql(u8, name, "_initialize_narrow_environment") or
            std.mem.eql(u8, name, "_initterm") or
            std.mem.eql(u8, name, "_initterm_e") or
            std.mem.eql(u8, name, "_cexit") or
            std.mem.eql(u8, name, "_seh_filter_exe"))
        {
            ret = 0; // сеттеры/инициализаторы: успех
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-heap-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "malloc")) {
            ret = kmalloc(a1);
        } else if (std.mem.eql(u8, name, "calloc")) {
            ret = kcalloc(a1, a2);
        } else if (std.mem.eql(u8, name, "realloc")) {
            ret = krealloc(a1, a2);
        } else if (std.mem.eql(u8, name, "free")) {
            kfree(a1);
            ret = 0;
        } else if (std.mem.eql(u8, name, "_set_new_mode")) {
            ret = 0;
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-string-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "memset")) {
            ret = kmemset(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "strlen")) {
            ret = userStrLen(a1) orelse 0;
        } else if (std.mem.eql(u8, name, "_strdup")) {
            // fix-волна №3: NULL у trap-стаба → «out of memory» у curl
            ret = kstrdup(a1);
        } else if (std.mem.eql(u8, name, "_stricmp")) {
            ret = kstricmp(a1, a2);
        } else if (std.mem.eql(u8, name, "_strnicmp")) {
            ret = kstrnicmp(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "tolower")) {
            ret = ktolower(a1);
        } else if (std.mem.eql(u8, name, "toupper")) {
            ret = ktoupper(a1);
        } else if (std.mem.eql(u8, name, "isspace")) {
            ret = kisspace(a1);
        } else if (std.mem.eql(u8, name, "strcspn")) {
            // event-волна: разбор URL/конфигов — префикс до символа из набора
            ret = kstrcspn(a1, a2);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-private-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "memcpy")) {
            ret = kmemcpy(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "memmove")) {
            ret = kmemmove(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "memcmp")) {
            ret = kmemcmp(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "strchr")) {
            ret = kstrchr(a1, a2);
        } else if (std.mem.eql(u8, name, "strrchr")) {
            ret = kstrrchr(a1, a2);
        } else if (std.mem.eql(u8, name, "strstr")) {
            ret = kstrstr(a1, a2);
        } else if (std.mem.eql(u8, name, "memchr")) {
            // threading-волна: пайплайн разбора (напр. поиск в буферах)
            ret = kmemchr(a1, a2, a3);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-convert-l1-1-0.dll")) {
        // v0.12.0 fix-волна: парсинг чисел (порты, таймауты опций)
        if (std.mem.eql(u8, name, "atoi")) {
            ret = katoi(a1);
        } else if (std.mem.eql(u8, name, "strtol")) {
            ret = kstrtol(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "strtoul")) {
            ret = kstrtoul(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "mbstowcs_s")) {
            // event-волна: ANSI → UTF-16LE (конфиг/argv → широкие строки)
            ret = kmbstowcsS(a1, a2, a3, a4, ops.stack_arg(0));
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-locale-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "_configthreadlocale")) {
            ret = 0; // «C»-локаль по умолчанию
        } else if (std.mem.eql(u8, name, "setlocale")) {
            ret = ksetlocale(a1, a2);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-environment-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "__p__environ")) {
            ret = lazyEnvironSlot();
        } else if (std.mem.eql(u8, name, "getenv")) {
            ret = 0; // переменная не найдена (безопасный NULL)
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "WS2_32.dll")) {
        if (std.mem.eql(u8, name, "WSAStartup")) {
            ret = wsaStartup(a1, a2);
        } else if (std.mem.eql(u8, name, "WSACleanup")) {
            ret = wsaCleanup();
        } else if (std.mem.eql(u8, name, "socket")) {
            ret = wsaSocket(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "connect")) {
            ret = wsaConnect(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "closesocket")) {
            ret = wsaClosesocket(a1);
        } else if (std.mem.eql(u8, name, "ioctlsocket")) {
            ret = wsaIoctlsocket(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "send")) {
            ret = wsaSend(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "recv")) {
            ret = wsaRecv(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "htons")) {
            ret = wsaHtons(a1);
        } else if (std.mem.eql(u8, name, "htonl")) {
            ret = wsaHtonl(a1);
        } else if (std.mem.eql(u8, name, "ntohs")) {
            ret = wsaHtons(a1);
        } else if (std.mem.eql(u8, name, "ntohl")) {
            ret = wsaHtonl(a1);
        } else if (std.mem.eql(u8, name, "WSAGetLastError")) {
            ret = if (ctx) |c| c.last_error else 0;
        } else if (std.mem.eql(u8, name, "getaddrinfo")) {
            ret = wsaGetAddrInfo(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "freeaddrinfo")) {
            ret = wsaFreeAddrInfo(a1);
        } else if (std.mem.eql(u8, name, "WSACreateEvent")) {
            // event-волна: trap-NULL → «(27) Out of memory» у curl
            ret = wsaCreateEvent();
        } else if (std.mem.eql(u8, name, "WSACloseEvent")) {
            ret = wsaCloseEvent(a1);
        } else if (std.mem.eql(u8, name, "WSAResetEvent")) {
            ret = wsaResetEvent(a1);
        } else if (std.mem.eql(u8, name, "WSAEventSelect")) {
            ret = wsaEventSelect(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "WSAEnumNetworkEvents")) {
            ret = wsaEnumNetworkEvents(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "WSAWaitForMultipleEvents")) {
            // 5-й аргумент (alertable) — через стек Win64-вызова
            ret = wsaWaitForMultipleEvents(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "WSAIoctl")) {
            ret = wsaIoctl(a1, a2);
        } else if (std.mem.eql(u8, name, "WSASetLastError")) {
            ret = wsaSetLastError(a1);
        } else if (std.mem.eql(u8, name, "__WSAFDIsSet")) {
            ret = wsaFdIsSet(a1, a2);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "Secur32.dll")) {
        // v0.12.0 (CDD №3): SSPI. curl.exe импортирует только
        // InitSecurityInterfaceA; остальные имена — extra-записи реестра
        // (таблица SSPI), диспетчеризуются тем же syscall-трамплином.
        if (std.mem.eql(u8, name, "InitSecurityInterfaceA")) {
            ret = initSecurityInterface(disp, false);
        } else if (std.mem.eql(u8, name, "InitSecurityInterfaceW")) {
            ret = initSecurityInterface(disp, true);
        } else if (std.mem.eql(u8, name, "FreeContextBuffer")) {
            ret = SEC_E_OK; // освобождение NULL/нашего буфера — успех
        } else {
            // QuerySecurityPackageInfo/AcquireCredentials/Initialize…:
            // метод не поддержан — БЕЗ записи в out-параметры (SEC_E_*
            // не ноль! trap-стаб вернул бы 0 = SEC_E_OK и мусор в указателях)
            ret = SEC_E_UNSUPPORTED_METHOD;
        }
    } else {
        handled = false;
    }

    if (!handled) {
        // Стаб остался trap → вызов пришёл бы через int3, а не syscall.
        // Сюда попадаем только при рассинхроне реестра и API-таблицы — WARN.
        logf("[WIN32] WARN: {s}!{s} пришёл syscall'ом, но реализации нет\n", .{ e.dll, name });
        return 0;
    }

    // Лог первого вызова каждой реализованной функции (CDD-трейс)
    e.hits += 1;
    if (e.hits == 1) {
        logf("[WIN32] {s}!{s} — OK, ret=0x{x}\n", .{ e.dll, name, ret });
    }
    if (ctx) |*c| c.implemented_calls += 1;
    return ret;
}

/// __p__environ: char***-слот, *slot = NULL (пустое окружение — CRT-валидно).
fn lazyEnvironSlot() u64 {
    const c = &(ctx orelse return 0);
    if (c.environ_slot == 0) {
        const p = kmalloc(16);
        if (p == 0) return 0;
        @memset(userPtr(p)[0..16], 0); // *slot = 0 → NULL-таблица
        c.environ_slot = p;
    }
    return c.environ_slot;
}

/// memset (syscall-путь — основная дорога это native-стаб; здесь —
/// полнота таблицы + defensive-покрытие через GetProcAddress-резолв).
fn kmemset(dst: u64, val: u64, len: u64) u64 {
    if (len > 64 * 1024 * 1024) return 0;
    if (len > 0 and !ops.validate_write(dst, len)) return 0;
    if (len > 0) {
        @memset(userPtr(dst)[0..@intCast(len)], @truncate(val));
    }
    return dst; // memset возвращает dst
}

fn kmemcpy(dst: u64, src: u64, len: u64) u64 {
    if (len > 64 * 1024 * 1024) return 0;
    if (len > 0) {
        if (!ops.validate_write(dst, len) or !ops.validate_read(src, len)) return 0;
        @memcpy(userPtr(dst)[0..@intCast(len)], userPtr(src)[0..@intCast(len)]);
    }
    return dst;
}

fn kmemmove(dst: u64, src: u64, len: u64) u64 {
    if (len > 64 * 1024 * 1024) return 0;
    if (len > 0) {
        if (!ops.validate_write(dst, len) or !ops.validate_read(src, len)) return 0;
        if (dst == src) return dst;
        const d = userPtr(dst)[0..@intCast(len)];
        const s = userPtr(src)[0..@intCast(len)];
        if (dst < src) {
            std.mem.copyForwards(u8, d, s); // overlap: dst ниже — вперёд
        } else {
            std.mem.copyBackwards(u8, d, s); // overlap: dst выше — назад
        }
    }
    return dst;
}

// ─── String-family (v0.12.0 fix-волна CDD №3) ────────────────────────────────
// Драйвер: «curl: option http://…: out of memory» — trap-_strdup возвращал
// NULL; strrchr(NULL) ломал путь конфига. Семейство закрывается ЦЕЛИКОМ:
// strchr/strrchr/strstr/memcmp/_stricmp/_strnicmp/tolower/isspace (string/
// private), _strdup (string), strerror (runtime), setlocale (locale),
// atoi/strtol/strtoul (convert).

/// strdup(s): kmalloc(len+1) + копия с NUL. NULL при OOM/невалидном указателе.
pub fn kstrdup(src: u64) u64 {
    const len = userStrLen(src) orelse return 0;
    const p = kmalloc(len + 1);
    if (p == 0) return 0;
    if (!ops.validate_write(p, len + 1) or !ops.validate_read(src, len)) return 0;
    @memcpy(userPtr(p)[0..@intCast(len)], userPtr(src)[0..@intCast(len)]);
    userPtr(p)[@intCast(len)] = 0;
    return p;
}

/// strchr(s, c): первое вхождение байта; C-контракт: c==0 → указатель на
/// терминатор. PAGE-безопасный скан (как userStrLen).
pub fn kstrchr(s: u64, c: u64) u64 {
    if (!ops.validate_read(s, 1)) return 0;
    const want: u8 = @truncate(c);
    var page: u64 = s & ~(PAGE_SIZE - 1);
    var until: u64 = page + PAGE_SIZE;
    var i: u64 = 0;
    while (i < MAX_STR_LEN) : (i += 1) {
        if (s + i >= until) {
            page += PAGE_SIZE;
            if (!ops.validate_read(page, 1)) return 0;
            until = page + PAGE_SIZE;
        }
        const ch = userPtr(s)[@as(usize, @intCast(i))];
        if (ch == want) return s + i;
        if (ch == 0) return 0;
    }
    return 0;
}

/// strrchr(s, c): ПОСЛЕДНЕЕ вхождение; c==0 → указатель на терминатор.
pub fn kstrrchr(s: u64, c: u64) u64 {
    if (!ops.validate_read(s, 1)) return 0;
    const len = userStrLen(s) orelse return 0;
    if (!ops.validate_read(s, len + 1)) return 0;
    const want: u8 = @truncate(c);
    if (want == 0) return s + len; // терминатор
    var i: u64 = len;
    while (i > 0) : (i -= 1) {
        if (userPtr(s)[@as(usize, @intCast(i - 1))] == want) return s + i - 1;
    }
    return 0;
}

/// strstr(h, n): первое вхождение подстроки; n=="" → h (C-контракт).
pub fn kstrstr(hay: u64, needle: u64) u64 {
    const nlen = userStrLen(needle) orelse return 0;
    const hlen = userStrLen(hay) orelse return 0;
    if (nlen == 0) return hay;
    if (nlen > hlen) return 0;
    if (!ops.validate_read(hay, hlen) or !ops.validate_read(needle, nlen)) return 0;
    const h = userPtr(hay)[0..@intCast(hlen)];
    const n = userPtr(needle)[0..@intCast(nlen)];
    if (std.mem.indexOf(u8, h, n)) |off| return hay + off;
    return 0;
}

/// memcmp(a, b, n): int-результат C-конвенции (signed diff, <0 / 0 / >0).
pub fn kmemcmp(a: u64, b: u64, n: u64) u64 {
    if (n > 64 * 1024 * 1024) return 0;
    if (n > 0) {
        if (!ops.validate_read(a, n) or !ops.validate_read(b, n)) return 0;
        const r = std.mem.order(u8, userPtr(a)[0..@intCast(n)], userPtr(b)[0..@intCast(n)]);
        return switch (r) {
            .lt => @bitCast(@as(i64, -1)),
            .eq => 0,
            .gt => 1,
        };
    }
    return 0;
}

/// _stricmp(a, b): регистронезависимое сравнение до NUL.
pub fn kstricmp(a: u64, b: u64) u64 {
    const la = userStrLen(a) orelse return 0;
    const lb = userStrLen(b) orelse return 0;
    if (!ops.validate_read(a, la) or !ops.validate_read(b, lb)) return 0;
    const ca = userPtr(a)[0..@intCast(la)];
    const cb = userPtr(b)[0..@intCast(lb)];
    const r = std.ascii.orderIgnoreCase(ca, cb);
    return switch (r) {
        .lt => @bitCast(@as(i64, -1)),
        .eq => 0,
        .gt => 1,
    };
}

/// _strnicmp(a, b, n): регистронезависимое сравнение n байт.
pub fn kstrnicmp(a: u64, b: u64, n: u64) u64 {
    if (n > MAX_STR_LEN) return 0;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        if (!ops.validate_read(a + i, 1) or !ops.validate_read(b + i, 1)) return 0;
        const ca = std.ascii.toUpper(userPtr(a)[@as(usize, @intCast(i))]);
        const cb = std.ascii.toUpper(userPtr(b)[@as(usize, @intCast(i))]);
        if (ca != cb) return if (ca < cb) @bitCast(@as(i64, -1)) else 1;
        if (ca == 0) return 0; // оба NUL
    }
    return 0;
}

/// tolower(c) / toupper(c): ASCII-трансформация одного байта.
pub fn ktolower(c: u64) u64 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

pub fn ktoupper(c: u64) u64 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
}

/// isspace(c): ' ' \\t \\n \\v \\f \\r → ненулевое (конвенция CRT: 1).
pub fn kisspace(c: u64) u64 {
    return switch (c) {
        ' ', '\t', '\n', 0x0B, 0x0C, '\r' => 1,
        else => 0,
    };
}

/// atoi(s): int-парсинг с ведущим пробелом/знаком (семантика strtol base 10,
/// без переполнения — C говорит UB, мы зажимаем в i32).
pub fn katoi(s: u64) u64 {
    return kstrtolInner(s, 10, std.math.maxInt(u32)) & 0xFFFFFFFF;
}

/// strtol(s, endptr, base): парсинг; endptr (в user-памяти!) = позиция
/// остановки (C-контракт: провал → *endptr = s, успех → после последней
/// цифры/знака/префикса).
pub fn kstrtol(s: u64, endptr: u64, base: u64) u64 {
    const val = kstrtolInner(s, base, std.math.maxInt(i32));
    if (endptr != 0) {
        // endptr валиден на запись? запись 8Б только если указан
        if (ops.validate_write(endptr, 8)) {
            const consumed = (val >> 32) & 0x7FFFFFFF; // слово потребления
            const ep: u64 = if (consumed == 0x7FFFFFFF) s else s + consumed;
            std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(endptr))), ep, .little);
        }
    }
    return signExtend32(val);
}

fn signExtend32(v: u64) u64 {
    // int32 → int64 с сохранением знака (strtoul-ветка сюда не попадает)
    const lo: i32 = @bitCast(@as(u32, @truncate(v)));
    return @bitCast(@as(i64, lo));
}

/// Внутренний парсер: [пробелы][знак][0x/0b/0][цифры] по базе.
/// Низкие 32 бита = значение, биты 32..62 = сколько байт съедено
/// (0x7FFFFFFF = провал парса, endptr = s). clamp — домен значения
/// (LONG_MAX для strtol, ULONG_MAX для strtoul — оба 32-битны на Windows).
fn kstrtolInner(s: u64, base_in: u64, clamp: u64) u64 {
    if (!ops.validate_read(s, 1)) return fail;
    const len = userStrLen(s) orelse return fail;
    if (!ops.validate_read(s, len)) return fail;
    const str = userPtr(s)[0..@intCast(len)];

    var i: usize = 0;
    while (i < str.len and (str[i] == ' ' or str[i] == '\t' or str[i] == '\n' or
        str[i] == 0x0B or str[i] == 0x0C or str[i] == '\r')) i += 1;
    var neg = false;
    if (i < str.len and (str[i] == '+' or str[i] == '-')) {
        neg = (str[i] == '-');
        i += 1;
    }
    var base: u64 = base_in;
    if (base == 0) {
        if (i + 1 < str.len and str[i] == '0' and (str[i + 1] == 'x' or str[i + 1] == 'X')) {
            base = 16;
        } else if (i < str.len and str[i] == '0') {
            base = 8;
        } else {
            base = 10;
        }
    }
    if (base == 16) {
        if (i + 1 < str.len and str[i] == '0' and (str[i + 1] == 'x' or str[i + 1] == 'X')) {
            const after = str[i + 2];
            if (after != 0 and std.ascii.isHex(after)) i += 2; // 0x без цифр — «0»
        }
    }
    var acc: u64 = 0;
    const start_digits = i;
    while (i < str.len) : (i += 1) {
        const d = digitVal(str[i]) orelse break;
        if (d >= base) break;
        acc = acc *% base +% d;
        if (acc > clamp) acc = clamp; // зажимаем (переполнение — UB в C)
    }
    if (i == start_digits) return fail; // ни одной цифры
    if (neg) acc = 0 -% acc; // u32-домен: ULONG_MAX+1-x (CRT-конвенция)
    return (i << 32) | (acc & 0xFFFFFFFF);
}

const fail: u64 = 0x7FFFFFFF_00000000; // consumed=sentinel + value 0

fn digitVal(ch: u8) ?u64 {
    if (ch >= '0' and ch <= '9') return ch - '0';
    if (ch >= 'a' and ch <= 'z') return ch - 'a' + 10;
    if (ch >= 'A' and ch <= 'Z') return ch - 'A' + 10;
    return null;
}

/// strtoul(s, endptr, base): беззнаковый вариант (отрицательный → заворачиваем
/// вокруг u32 по CRT-конвенции ULONG_MAX+1+x; здесь честный u32).
pub fn kstrtoul(s: u64, endptr: u64, base: u64) u64 {
    // u32-домен (ULONG = 32 бита на Windows); отрицательный → обёртка
    const raw = kstrtolInner(s, base, std.math.maxInt(u32));
    if (endptr != 0) {
        if (ops.validate_write(endptr, 8)) {
            const consumed = (raw >> 32) & 0x7FFFFFFF;
            const ep: u64 = if (consumed == 0x7FFFFFFF) s else s + consumed;
            std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(endptr))), ep, .little);
        }
    }
    return raw & 0xFFFFFFFF;
}

/// strerror(errnum): текст ошибки CRT. Выделяем 64Б-блок в heap (bump —
/// ошибки редки, утечка ограничена числом вызовов). errno-таблица: 7 общих.
pub fn kstrerror(errnum: u64) u64 {
    const msg: []const u8 = switch (errnum) {
        0 => "No error",
        1 => "Operation not permitted",
        2 => "No such file or directory",
        3 => "No such process",
        4 => "Interrupted function call",
        5 => "Input/output error",
        6 => "No such device or address",
        12 => "Not enough space",
        13 => "Permission denied",
        14 => "Bad address",
        17 => "File exists",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        24 => "Too many open files",
        28 => "No space left on device",
        38 => "Filename too long",
        48 => "Address family not supported by protocol family",
        49 => "Address already in use",
        100 => "Address family not supported by protocol family",
        104 => "Connection reset by peer",
        110 => "Connection timed out",
        111 => "Connection refused",
        113 => "No route to host",
        122 => "Disk quota exceeded",
        else => "Unknown error",
    };
    const p = kmalloc(64);
    if (p == 0) return 0;
    if (!ops.validate_write(p, msg.len + 1)) return 0;
    @memcpy(userPtr(p)[0..msg.len], msg);
    userPtr(p)[msg.len] = 0;
    return p;
}

/// setlocale(category, locale): «C»-локаль. Ленивый слот, КЭШИРУЕМЫЙ —
/// указатель стабилен между вызовами (CRT-контракт).
pub fn ksetlocale(category: u64, locale: u64) u64 {
    _ = category;
    // locale==NULL = запрос текущей — возвращаем кэш;
    // иначе «устанавливаем» C (единственная поддержанная) — тоже кэш.
    _ = locale;
    const c = &(ctx orelse return 0);
    if (c.locale_str == 0) {
        const p = kmalloc(4);
        if (p == 0) return 0;
        if (!ops.validate_write(p, 2)) return 0;
        userPtr(p)[0] = 'C';
        userPtr(p)[1] = 0;
        c.locale_str = p;
    }
    return c.locale_str;
}

// ============================================================================
// Тесты (нативно): user-VA = обычные Zig-указатели, ops = фейки, ctx на
// реальном буфере. Полная семантика каждой новой функции цикла №2 покрыта
// ИСПОЛНЕНИЕМ — включая dispatch по synthetic-реестру стабов.
// ============================================================================

const testing = std.testing;

// ─── Тестовое окружение ─────────────────────────────────────────────────────

var t_console: [8192]u8 = undefined;
var t_console_len: usize = 0;
var t_log: [16384]u8 = undefined;
var t_log_len: usize = 0;
var t_tsc: u64 = 0;
var t_exited: ?u64 = null;
var t_map_calls: usize = 0;

// v0.12.0: фейк моста колбэка (InitOnce) и стек-аргументов (FormatMessage)
var t_launch_calls: usize = 0;
var t_launch_ok: bool = true;
var t_launched_init_once: u64 = 0;
var t_launched_init_fn: u64 = 0;
var t_launched_parameter: u64 = 0;
var t_launched_context: u64 = 0;
var t_stack_args: [3]u64 = .{ 0, 0, 0 };

fn tReset() void {
    t_console_len = 0;
    t_log_len = 0;
    t_tsc = 0;
    t_exited = null;
    t_map_calls = 0;
    t_launch_calls = 0;
    t_launch_ok = true;
    t_launched_init_once = 0;
    t_launched_init_fn = 0;
    t_launched_parameter = 0;
    t_launched_context = 0;
    t_stack_args = .{ 0, 0, 0 };
    t_thread_calls = 0;
    t_thread_start = 0;
    t_thread_param = 0;
    t_thread_stack_top = 0;
    t_thread_exit_va = 0;
    t_exit_task_calls = 0;
    t_signaled_handle = 0;
}

fn tValidateTrue(va: u64, len: u64) bool {
    // Реалистичный фейк: «замаплено» всё в g_mem/g_heap (наши буферы),
    // прочие адреса (0x9990…) — мусор → отказ, как kernel-walk.
    _ = len;
    const mem_lo: u64 = @intFromPtr(&g_mem);
    const heap_lo: u64 = @intFromPtr(&g_heap);
    return (va >= mem_lo and va < mem_lo + g_mem.len) or
        (va >= heap_lo and va < heap_lo + g_heap.len);
}
fn tMapUser(va: u64, bytes: u64) bool {
    _ = va;
    _ = bytes;
    t_map_calls += 1;
    return true;
}
fn tReadTsc() u64 {
    return t_tsc;
}
fn tWriteConsole(s: []const u8) void {
    const n = @min(s.len, t_console.len - t_console_len);
    @memcpy(t_console[t_console_len .. t_console_len + n], s[0..n]);
    t_console_len += n;
}
fn tLog(s: []const u8) void {
    const n = @min(s.len, t_log.len - t_log_len);
    @memcpy(t_log[t_log_len .. t_log_len + n], s[0..n]);
    t_log_len += n;
}
fn tExit(code: u64) void {
    t_exited = code;
}

fn tLaunchCallback(init_once: u64, init_fn: u64, parameter: u64, context: u64) bool {
    t_launch_calls += 1;
    t_launched_init_once = init_once;
    t_launched_init_fn = init_fn;
    t_launched_parameter = parameter;
    t_launched_context = context;
    return t_launch_ok;
}

fn tStackArg(idx: u64) u64 {
    if (idx > 2) return 0;
    return t_stack_args[@intCast(idx)];
}

fn tOps() Ops {
    return .{
        .validate_read = tValidateTrue,
        .validate_write = tValidateTrue,
        .map_user = tMapUser,
        .read_tsc = tReadTsc,
        .write_console = tWriteConsole,
        .log = tLog,
        .exit = tExit,
        .launch_callback = tLaunchCallback,
        .stack_arg = tStackArg,
        .create_thread = tCreateThread,
        .exit_task = tExitTask,
        .object_signaled = tObjectSignaled,
        .current_tid = tCurrentTid,
    };
}

// v0.12.0 threading-фейки: параметры CreateThread записываются в глобалы,
// сигнальность — презет t_signaled_handle (0x1000 = «тред мёртв»).
var t_thread_calls: usize = 0;
var t_thread_start: u64 = 0;
var t_thread_param: u64 = 0;
var t_thread_stack_top: u64 = 0;
var t_thread_exit_va: u64 = 0;
var t_exit_task_calls: usize = 0;
var t_signaled_handle: u64 = 0;

fn tCreateThread(start: u64, param: u64, stack_top: u64, exit_va: u64) u64 {
    t_thread_calls += 1;
    t_thread_start = start;
    t_thread_param = param;
    t_thread_stack_top = stack_top;
    t_thread_exit_va = exit_va;
    return 0x1003; // фиксированный «хэндл треда» (task 3)
}

fn tExitTask() void {
    t_exit_task_calls += 1;
}

fn tObjectSignaled(handle: u64) bool {
    return handle != 0 and handle == t_signaled_handle;
}

fn tCurrentTid() u64 {
    return 0x1002;
}

fn logHas(needle: []const u8) bool {
    return std.mem.indexOf(u8, t_log[0..t_log_len], needle) != null;
}
fn consoleHas(needle: []const u8) bool {
    return std.mem.indexOf(u8, t_console[0..t_console_len], needle) != null;
}

/// Фейковая «user-память»: обычный выровненный буфер.
const FakeUserMem = struct {
    buf: []align(4096) u8,

    fn init(self: *FakeUserMem, comptime tag: u8) void {
        @memset(self.buf, tag);
    }
    fn va(self: *const FakeUserMem) u64 {
        return @intFromPtr(self.buf.ptr);
    }
};

var g_heap: [16384]u8 align(4096) = undefined;
var g_mem: [8192]u8 align(4096) = undefined;

/// Ctx на РЕАЛЬНОМ буфере: block-heap = g_heap (весь «замаплен»),
/// vheap = отдельный регион g_heap хвоста; cmdline/структуры — g_mem.
fn tCtx(cmdline: []const u8) void {
    @memset(&g_heap, 0);
    @memset(&g_mem, 0xAA);
    const hb: u64 = @intFromPtr(&g_heap);
    const mb: u64 = @intFromPtr(&g_mem);
    if (cmdline.len > 0) {
        @memcpy(g_mem[0..cmdline.len], cmdline);
        // NUL-терминатор уже есть (буфер обнулён нельзя — 0xAA! ставим сами)
        g_mem[cmdline.len] = 0;
    }
    ctx = .{
        .pml4 = 0x12345000,
        .image_base = 0x140000000,
        .cmdline_a = if (cmdline.len > 0) mb else 0,
        .cmdline_w = 0,
        .vheap_base = hb + 8192,
        .vheap_limit = hb + 16384,
        .vheap_cursor = hb + 8192,
        .vallocs = 0,
        .bheap_base = hb,
        .bheap_limit = hb + 8192,
        .bheap_cursor = hb,
        .bheap_mapped = hb + 8192, // «всё замаплено» (тест)
        .iob_array = 0,
        .argc_ptr = 0,
        .argv_slot = 0,
        .environ_slot = 0,
        .fmode_ptr = 0,
        .commode_ptr = 0,
        .errno_ptr = 0,
        .tsc_freq = 3_000_000_000,
        .tid = 0,
        .implemented_calls = 0,
        .last_error = 0,
        .next_socket_fd = 0x100,
        .sockets_opened = 0,
        .sspi_table = 0,
        .locale_str = 0,
        .next_event_handle = 0x200,
    };
}

/// Synthetic-реестр стабов: без PE-файла, записи вручную.
const FakeRegistry = struct {
    entries: [48]win32.StubEntry,
    disp: win32.Dispatcher,

    fn init(self: *FakeRegistry) void {
        self.disp = .{
            .entries = &self.entries,
            .count = 0,
            .mode = .int3,
        };
    }

    fn add(self: *FakeRegistry, dll: []const u8, func: []const u8, stub_addr: u64) usize {
        const id = self.disp.count;
        self.entries[id] = .{
            .dll = dll,
            .func = .{ .by_name = func },
            .kind = .impl,
            .stub_addr = stub_addr,
            .iat_rva = 0,
            .slot_index = 0,
            .code_off = id * win32.STUB_CODE_SIZE,
        };
        self.disp.count += 1;
        return id;
    }

    fn call(self: *FakeRegistry, id: usize, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
        return dispatch(&self.disp, id, a1, a2, a3, a4);
    }
};

// ─── Тесты: block-heap ──────────────────────────────────────────────────────

test "heap: malloc — 16-выравнивание, уникальность, OOM" {
    ops = tOps();
    tReset();
    tCtx("");
    const hb: u64 = @intFromPtr(&g_heap);

    const p1 = kmalloc(100);
    try testing.expectEqual(hb + 16, p1); // первый блок после заголовка
    try testing.expectEqual(@as(u64, 0), p1 % 16); // 16-байтная гранулярность
    // заголовок
    const hdr: *const HeapHdr = @ptrFromInt(p1 - 16);
    try testing.expectEqual(HEAP_HDR_MAGIC, hdr.magic);
    try testing.expectEqual(@as(u64, 112), hdr.size); // 100 → aligned 112

    const p2 = kmalloc(0); // malloc(0) — уникальный минимальный блок
    try testing.expect(p2 != 0);
    try testing.expect(p2 != p1);

    // OOM: запрос больше bheap-региона
    try testing.expectEqual(@as(u64, 0), kmalloc(64 * 1024 * 1024));
    // bump растёт: p2 = p1 + 112 + 16
    try testing.expectEqual(p1 + 112 + 16, p2);
}

test "heap: calloc — обнуление «грязного» буфера + переполнение" {
    ops = tOps();
    tReset();
    tCtx("");
    // g_heap обнулён в tCtx — «грязрём» вручную для проверки обнуления
    @memset(&g_heap, 0xEE);
    const p = kcalloc(3, 40); // 120Б
    try testing.expect(p != 0);
    for (userPtr(p)[0..120]) |b| try testing.expectEqual(@as(u8, 0), b);
    // переполнение nmemb*size
    try testing.expectEqual(@as(u64, 0), kcalloc(0xFFFF_FFFF_FFFF_FFFF, 16));
    // calloc(0,x) → минимальный блок, тоже нулевой
    const z = kcalloc(0, 8);
    try testing.expect(z != 0);
    for (userPtr(z)[0..16]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "heap: realloc — рост с копией, сжатие, NULL/0/мусор" {
    ops = tOps();
    tReset();
    tCtx("");

    const p = kmalloc(32);
    try testing.expect(p != 0);
    const magic = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    @memcpy(userPtr(p)[0..32], magic);

    // рост: контент сохраняется (старый размер из ЗАГОЛОВКА — суть цикла №2)
    const big = krealloc(p, 200);
    try testing.expect(big != 0);
    try testing.expect(big != p);
    try testing.expectEqualStrings(magic, @as([*]u8, @ptrFromInt(big))[0..32]);

    // сжатие: первые байты сохраняются
    const small = krealloc(big, 8);
    try testing.expect(small != 0);
    try testing.expectEqualStrings("01234567", @as([*]u8, @ptrFromInt(small))[0..8]);

    // realloc(NULL, n) = malloc(n)
    const fresh = krealloc(0, 64);
    try testing.expect(fresh != 0);

    // realloc(p, 0) = free → NULL (MSVC)
    try testing.expectEqual(@as(u64, 0), krealloc(fresh, 0));

    // мусорный указатель → NULL (не паника!)
    try testing.expectEqual(@as(u64, 0), krealloc(0x1000, 64));
    // указатель внутрь блока (не на начало) → magic не сойдётся → NULL
    try testing.expectEqual(@as(u64, 0), krealloc(small + 8, 64));

    // free — no-op, не падает на мусоре
    kfree(0x1234);
    kfree(small + 4);
}

// ─── Тесты: mem-семья и strlen через dispatch ───────────────────────────────

test "dispatch: memset/memcpy/memmove/strlen (syscall-путь)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    _ = reg.add("api-ms-win-crt-string-l1-1-0.dll", "memset", 0xA000);
    _ = reg.add("api-ms-win-crt-private-l1-1-0.dll", "memcpy", 0xA030);
    _ = reg.add("api-ms-win-crt-private-l1-1-0.dll", "memmove", 0xA060);
    const id_strlen = reg.add("api-ms-win-crt-string-l1-1-0.dll", "strlen", 0xA090);

    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0);

    // memset: заполнение + возврат dst
    const ret_ms = reg.call(0, mb + 0x100, 0x5A, 32, 0);
    try testing.expectEqual(mb + 0x100, ret_ms);
    for (g_mem[0x100..0x120]) |b| try testing.expectEqual(@as(u8, 0x5A), b);

    // memcpy: копия
    @memcpy(g_mem[0x200..0x200 + 11], "POLER-OS!!!");
    const ret_mc = reg.call(1, mb + 0x300, mb + 0x200, 11, 0);
    try testing.expectEqual(mb + 0x300, ret_mc);
    try testing.expectEqualStrings("POLER-OS!!!", g_mem[0x300..0x30B]);

    // memmove: перекрытие dst > src
    @memcpy(g_mem[0x400..0x400 + 26], "abcdefghijklmnopqrstuvwxyz");
    _ = reg.call(2, mb + 0x402, mb + 0x400, 26, 0);
    try testing.expectEqualStrings("ab" ++ "abcdefghijklmnopqrstuvwx", g_mem[0x400..0x400 + 26]);

    // strlen
    @memcpy(g_mem[0x500..0x500 + 5], "hello");
    g_mem[0x505] = 0;
    try testing.expectEqual(@as(u64, 5), reg.call(id_strlen, mb + 0x500, 0, 0, 0));
    // лог первого вызова
    try testing.expect(logHas("strlen — OK, ret=0x5"));
}

// ─── Тесты: GetProcAddress ──────────────────────────────────────────────────

test "dispatch: GetProcAddress — резолв по реестру, NULL, ординал" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_gpa = reg.add("KERNEL32.dll", "GetProcAddress", 0);
    _ = reg.add("KERNEL32.dll", "CreateFileA", 0xABCD00);
    _ = reg.add("WS2_32.dll", "WSASocketW", 0xABCD30);

    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 11], "CreateFileA");
    g_mem[0x10B] = 0;

    // резолв по имени → user-VA стаба
    const r1 = reg.call(id_gpa, 0x140000000, mb + 0x100, 0, 0);
    try testing.expectEqual(@as(u64, 0xABCD00), r1);
    try testing.expect(logHas("GetProcAddress(\"CreateFileA\") -> 0xabcd00"));

    // несуществующее имя → NULL + CDD-лог (видимость для следующего цикла)
    @memcpy(g_mem[0x120..0x120 + 7], "NoExist");
    g_mem[0x127] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gpa, 0x140000000, mb + 0x120, 0, 0));
    try testing.expect(logHas("GetProcAddress(\"NoExist\") -> NULL"));

    // ординал (lpProcName < 0x10000) → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_gpa, 0x140000000, 0x42, 0, 0));
    // hModule=NULL → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_gpa, 0, mb + 0x100, 0, 0));
    // мусорный указатель имени → NULL (без паники)
    try testing.expectEqual(@as(u64, 0), reg.call(id_gpa, 0x140000000, 0x9990, 0, 0));
}

// ─── Тесты: QPF/QPC, консоль, WSAStartup ────────────────────────────────────

test "dispatch: QPF/QPC — TSC-частота и счётчик" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_qpf = reg.add("KERNEL32.dll", "QueryPerformanceFrequency", 0);
    const id_qpc = reg.add("KERNEL32.dll", "QueryPerformanceCounter", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // QPF: записывает tsc_freq из ctx (3 ГГц из tCtx)
    try testing.expectEqual(@as(u64, 1), reg.call(id_qpf, mb + 0x100, 0, 0, 0));
    try testing.expectEqual(@as(u64, 3_000_000_000), std.mem.readInt(u64, g_mem[0x100..0x108], .little));

    // QPC: читает TSC из ops
    t_tsc = 0xDEAD_BEEF_1234;
    try testing.expectEqual(@as(u64, 1), reg.call(id_qpc, mb + 0x200, 0, 0, 0));
    try testing.expectEqual(t_tsc, std.mem.readInt(u64, g_mem[0x200..0x208], .little));

    // мусорный указатель → 0 (FALSE), без записи
    try testing.expectEqual(@as(u64, 0), reg.call(id_qpc, 0x9990, 0, 0, 0));
}

test "dispatch: GetConsoleMode/ScreenBufferInfo/WSAStartup — структуры" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_mode = reg.add("KERNEL32.dll", "GetConsoleMode", 0);
    const id_csbi = reg.add("KERNEL32.dll", "GetConsoleScreenBufferInfo", 0);
    const id_wsa = reg.add("WS2_32.dll", "WSAStartup", 0);
    const id_clean = reg.add("WS2_32.dll", "WSACleanup", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // GetConsoleMode: stdin → 0x1F7, stdout → 3
    try testing.expectEqual(@as(u64, 1), reg.call(id_mode, FAKE_STDIN, mb + 0x100, 0, 0));
    try testing.expectEqual(@as(u32, 0x1F7), std.mem.readInt(u32, g_mem[0x100..0x104], .little));
    try testing.expectEqual(@as(u64, 1), reg.call(id_mode, FAKE_STDOUT, mb + 0x104, 0, 0));
    try testing.expectEqual(@as(u32, 0x3), std.mem.readInt(u32, g_mem[0x104..0x108], .little));

    // ScreenBufferInfo: 80x3000, окно 0..79/0..24
    try testing.expectEqual(@as(u64, 1), reg.call(id_csbi, FAKE_STDOUT, mb + 0x200, 0, 0));
    try testing.expectEqual(@as(u16, 80), std.mem.readInt(u16, g_mem[0x200..0x202], .little));
    try testing.expectEqual(@as(u16, 3000), std.mem.readInt(u16, g_mem[0x202..0x204], .little));
    try testing.expectEqual(@as(u16, 79), std.mem.readInt(u16, g_mem[0x200 + 14 .. 0x200 + 16], .little));
    try testing.expectEqual(@as(u16, 24), std.mem.readInt(u16, g_mem[0x200 + 16 .. 0x200 + 18], .little));

    // WSAStartup: 0 (NO_ERROR), версия 2.2, описание
    try testing.expectEqual(@as(u64, 0), reg.call(id_wsa, 0x0202, mb + 0x300, 0, 0));
    try testing.expectEqual(@as(u16, 0x0202), std.mem.readInt(u16, g_mem[0x300..0x302], .little));
    try testing.expectEqualStrings("POLER-OS Winsock shim", g_mem[0x308..0x308 + 21]);
    // WSACleanup → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_clean, 0, 0, 0, 0));
}

// ─── Тесты: ленивые CRT-структуры ───────────────────────────────────────────

test "dispatch: argc/argv — токенизация cmdline на месте" {
    ops = tOps();
    tReset();
    tCtx("curl.exe --version extra");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_argc = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc", 0);
    const id_argv = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv", 0);

    const mb: u64 = @intFromPtr(&g_mem);

    // __p___argc → int* со значением 3
    const argc_ptr = reg.call(id_argc, 0, 0, 0, 0);
    try testing.expect(argc_ptr != 0);
    const argc: *u32 = @ptrFromInt(argc_ptr);
    try testing.expectEqual(@as(u32, 3), argc.*);

    // __p___argv → char***-слот: *slot = argv-массив
    const argv_slot_va = reg.call(id_argv, 0, 0, 0, 0);
    try testing.expect(argv_slot_va != 0);
    const argv_slot: *u64 = @ptrFromInt(argv_slot_va);
    const arr: [*]u64 = @ptrFromInt(argv_slot.*);
    // argv[0]="curl.exe", [1]="--version", [2]="extra", [3]=NULL
    try testing.expectEqualStrings("curl.exe", std.mem.span(@as([*:0]const u8, @ptrFromInt(arr[0]))));
    try testing.expectEqualStrings("--version", std.mem.span(@as([*:0]const u8, @ptrFromInt(arr[1]))));
    try testing.expectEqualStrings("extra", std.mem.span(@as([*:0]const u8, @ptrFromInt(arr[2]))));
    try testing.expectEqual(@as(u64, 0), arr[3]);

    // Повторный вызов — ТЕ ЖЕ указатели (кэш; v0.10 давал новые каждый раз)
    try testing.expectEqual(argc_ptr, reg.call(id_argc, 0, 0, 0, 0));
    try testing.expectEqual(argv_slot_va, reg.call(id_argv, 0, 0, 0, 0));

    // cmdline токенизирован на месте (пробелы → NUL)
    try testing.expectEqualStrings("curl.exe", std.mem.span(@as([*:0]const u8, @ptrFromInt(mb))));
}

test "dispatch: __acrt_iob_func — стабильный массив 3 FILE" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_iob = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func", 0);

    const s0 = reg.call(id_iob, 0, 0, 0, 0);
    const s1 = reg.call(id_iob, 1, 0, 0, 0);
    const s2 = reg.call(id_iob, 2, 0, 0, 0);
    try testing.expect(s0 != 0);
    try testing.expectEqual(s0 + 80, s1);
    try testing.expectEqual(s0 + 160, s2);
    // повторные вызовы — тот же массив (v0.10 давал новые страницы!)
    try testing.expectEqual(s0, reg.call(id_iob, 0, 0, 0, 0));
    // idx > 2 → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_iob, 3, 0, 0, 0));

    // FILE-структуры нулевые (CRT сам их заполнит)
    for (@as([*]u8, @ptrFromInt(s0))[0..80]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "dispatch: __p__fmode/__p__environ — ленивые блоки, стабильные, РАЗДЕЛЬНЫЕ" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_fmode = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "__p__fmode", 0);
    const id_commode = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "__p__commode", 0);
    const id_errno = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "_errno", 0);
    const id_env = reg.add("api-ms-win-crt-environment-l1-1-0.dll", "__p__environ", 0);
    const id_getenv = reg.add("api-ms-win-crt-environment-l1-1-0.dll", "getenv", 0);

    const p1 = reg.call(id_fmode, 0, 0, 0, 0);
    try testing.expect(p1 != 0);
    try testing.expectEqual(p1, reg.call(id_fmode, 0, 0, 0, 0)); // кэш
    // fmode/commode/errno — РАЗНЫЕ переменные CRT → разные блоки
    const p2 = reg.call(id_commode, 0, 0, 0, 0);
    try testing.expect(p2 != 0);
    try testing.expect(p2 != p1);
    const p3 = reg.call(id_errno, 0, 0, 0, 0);
    try testing.expect(p3 != 0);
    try testing.expect(p3 != p1);
    try testing.expect(p3 != p2);

    // __p__environ: слот, *slot = NULL (пустое окружение)
    const slot = reg.call(id_env, 0, 0, 0, 0);
    try testing.expect(slot != 0);
    try testing.expectEqual(@as(u64, 0), @as(*u64, @ptrFromInt(slot)).*);
    // getenv → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_getenv, 0, 0, 0, 0));
}

// ─── Тесты: вывод приложения (МОМЕНТ ИСТИНЫ цикла №2) ──────────────────────

test "dispatch: fputs/fputc/fflush/setvbuf — текст приложения в консоль" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_fputs = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fputs", 0);
    const id_fputc = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fputc", 0);
    const id_fwrite = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fwrite", 0);
    const id_fflush = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fflush", 0);
    const id_setvbuf = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "setvbuf", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const msg = "curl: try 'curl --help' or 'curl --manual' for more information\n";
    @memcpy(g_mem[0x100..0x100 + msg.len], msg);
    g_mem[0x100 + msg.len] = 0;

    // fputs: текст уходит в консоль ОС
    try testing.expectEqual(@as(u64, 1), reg.call(id_fputs, mb + 0x100, 0x5000, 0, 0));
    try testing.expect(consoleHas("curl: try 'curl --help'"));

    // fwrite(ptr, size, nmemb, stream): байты БЛОКОМ в консоль, ретурн nmemb
    const wmsg = "curl: "; // реальный префикс helpf() — терялся в trap-мире
    @memcpy(g_mem[0x200..0x200 + wmsg.len], wmsg);
    try testing.expectEqual(@as(u64, 1), reg.call(id_fwrite, mb + 0x200, wmsg.len, 1, 0x5000));
    try testing.expect(consoleHas("curl: "));
    // 10×3 = 30 байт → ретурн 3 (nmemb)
    @memcpy(g_mem[0x210..0x210 + 10], "0123456789");
    try testing.expectEqual(@as(u64, 3), reg.call(id_fwrite, mb + 0x210, 10, 3, 0x5000));
    // size=0 / nmemb=0 → 0; мусорный ptr → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_fwrite, mb + 0x200, 0, 1, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_fwrite, mb + 0x200, 1, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_fwrite, 0x9990, 1, 1, 0));

    // fputc: символ, возврат = код символа
    try testing.expectEqual(@as(u64, 0x41), reg.call(id_fputc, 0x41, 0x5000, 0, 0));
    try testing.expectEqual(@as(u64, 0x42), reg.call(id_fputc, 0x142, 0x5000, 0, 0)); // (int)'B'... с мусором сверху
    try testing.expect(consoleHas("AB"));

    // fflush/setvbuf: no-op успех
    try testing.expectEqual(@as(u64, 0), reg.call(id_fflush, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_setvbuf, 0x5000, 0, 2, 0));

    // мусорный указатель fputs → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_fputs, 0x9990, 0x5000, 0, 0));
}

test "dispatch: VirtualAlloc — vheap-регион (page-granular)" {
    ops = tOps();
    tReset();
    tCtx("");
    const hb: u64 = @intFromPtr(&g_heap);
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_va = reg.add("KERNEL32.dll", "VirtualAlloc", 0);

    const vbase = hb + 8192; // vheap-регион: 8КБ (тестовый budget)
    // NULL → page-aligned bump
    const a1 = reg.call(id_va, 0, 0x1000, 0x1000, 4);
    try testing.expectEqual(vbase, a1);
    const a2 = reg.call(id_va, 0, 0x800, 0x1000, 4); // 1 страница
    try testing.expectEqual(vbase + 0x1000, a2);
    // OOM: не хватает остатка региона
    try testing.expectEqual(@as(u64, 0), reg.call(id_va, 0, 0x8000, 0x1000, 4));
    // отказы: size=0, неверный тип, невыровненный фикс, фикс вне региона
    try testing.expectEqual(@as(u64, 0), reg.call(id_va, 0, 0, 0x1000, 4));
    try testing.expectEqual(@as(u64, 0), reg.call(id_va, 0, 0x1000, 0, 4));
    try testing.expectEqual(@as(u64, 0), reg.call(id_va, vbase + 0x1, 0x1000, 0x1000, 4));
    try testing.expectEqual(@as(u64, 0), reg.call(id_va, vbase + 0x8000, 0x1000, 0x1000, 4));
}

test "dispatch: exit-семья и GetStdHandle/GetModuleHandle/GetCurrentThreadId" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_exit = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "exit", 0);
    const id_abort = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "abort", 0);
    const id_expp = reg.add("KERNEL32.dll", "ExitProcess", 0);
    const id_std = reg.add("KERNEL32.dll", "GetStdHandle", 0);
    const id_gmh = reg.add("KERNEL32.dll", "GetModuleHandleA", 0);
    const id_tid = reg.add("KERNEL32.dll", "GetCurrentThreadId", 0);
    const id_suf = reg.add("KERNEL32.dll", "SetUnhandledExceptionFilter", 0);
    const id_srw = reg.add("KERNEL32.dll", "AcquireSRWLockExclusive", 0);

    // exit(7) → ops.exit(7) (тест — флаг, не hlt)
    _ = reg.call(id_exit, 7, 0, 0, 0);
    try testing.expectEqual(@as(u64, 7), t_exited.?);
    // abort → exit(3)
    _ = reg.call(id_abort, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 3), t_exited.?);
    // ExitProcess(5)
    _ = reg.call(id_expp, 5, 0, 0, 0);
    try testing.expectEqual(@as(u64, 5), t_exited.?);

    // GetStdHandle: -11/-10/-12 → различимые псевдо-хэндлы
    try testing.expectEqual(FAKE_STDIN, reg.call(id_std, 0xFFFF_FFFF_FFFF_FFF5, 0, 0, 0));
    try testing.expectEqual(FAKE_STDOUT, reg.call(id_std, 0xFFFF_FFFF_FFFF_FFF6, 0, 0, 0));
    try testing.expectEqual(FAKE_STDERR, reg.call(id_std, 0xFFFF_FFFF_FFFF_FFF4, 0, 0, 0));

    // GetModuleHandleA → image_base
    try testing.expectEqual(@as(u64, 0x140000000), reg.call(id_gmh, 0, 0, 0, 0));

    // GetCurrentThreadId: реальный TID (фейк-оп: 0x1002, как задача 2)
    try testing.expectEqual(@as(u64, 0x1002), reg.call(id_tid, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0x1002), reg.call(id_tid, 0, 0, 0, 0));

    // no-op'ы
    try testing.expectEqual(@as(u64, 0), reg.call(id_suf, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_srw, 0x1000, 0, 0, 0));
}

test "dispatch: дефолтные ops-параноики — отказ без паники" {
    // ctx/ops не установлены реальными — всё возвращает 0/не падает
    ops = .{
        .validate_read = denyAll,
        .validate_write = denyAll,
        .map_user = denyAll,
        .read_tsc = noop,
        .write_console = emptyWriter,
        .log = emptyWriter,
        .exit = emptyExit,
        .launch_callback = denyLaunch,
        .stack_arg = nullStackArg,
        .create_thread = denyCreateThread,
        .exit_task = noopExitTask,
        .object_signaled = denySignaled,
        .current_tid = fakeTid,
    };
    ctx = null;
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_qpc = reg.add("KERNEL32.dll", "QueryPerformanceCounter", 0);
    const id_malloc = reg.add("api-ms-win-crt-heap-l1-1-0.dll", "malloc", 0);
    const id_fputs = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fputs", 0);

    // validate отказывает → функции не трогают память, возврат 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_qpc, 0x1000, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_malloc, 100, 0, 0, 0)); // ctx null → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_fputs, 0x1000, 0, 0, 0));
}

// ─── Тесты: волна №3 (версионирование, окружение, ошибки) ──────────────────

test "version: VerSetConditionMask — поля 8-бит, цепочка вызовов" {
    const VSM = verSetConditionMask;
    // мажор в битах 8-15, GE(3)
    try testing.expectEqual(@as(u64, 3) << 8, VSM(0, VER_MAJORVERSION, VER_GREATER_EQUAL));
    // цепочка (как curl): mask = VSCM(VSCM(0, MAJOR, GE), MINOR, GE)
    const m = VSM(VSM(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL);
    try testing.expectEqual((@as(u64, 3) << 8) | 3, m);
    // build в битах 16-23, тип продукта в 56-63
    try testing.expectEqual(@as(u64, 5) << 16, VSM(0, VER_BUILDNUMBER, VER_LESS_EQUAL));
    try testing.expectEqual(@as(u64, 1) << 56, VSM(0, VER_PRODUCTTYPE, VER_EQUAL));
    // перезапись поля не трогает соседние
    const m2 = VSM(m, VER_MAJORVERSION, VER_EQUAL);
    try testing.expectEqual((@as(u64, 1) << 8) | 3, m2);
    // чужие флаги — маска не меняется
    try testing.expectEqual(m, VSM(m, 0x33, VER_EQUAL));
}

/// Заполнить OSVERSIONINFOEXW в g_mem по смещению off.
fn tFillOsv(off: usize, major: u32, minor: u32) u64 {
    @memset(g_mem[off .. off + 284], 0);
    const mb: u64 = @intFromPtr(&g_mem);
    userD(mb + off + 0).* = 284; // dwOSVersionInfoSize
    userD(mb + off + 4).* = major;
    userD(mb + off + 8).* = minor;
    userD(mb + off + 0x10).* = 2; // VER_PLATFORM_WIN32_NT
    userW(mb + off + OSVEXW_SUITE).* = 0; // suite
    userPtr(mb + off + OSVEXW_PRODUCT)[0] = 1; // VER_NT_WORKSTATION
    return mb + off;
}

test "version: VerifyVersionInfoW — curl-вопрос «>= Win7?» → TRUE (10.0)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_v = reg.add("KERNEL32.dll", "VerifyVersionInfoW", 0);

    // curl: major>=6, minor>=1 → наша Win10.0 подходит
    const osv = tFillOsv(0x100, 6, 1);
    const mask = verSetConditionMask(verSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL);
    try testing.expectEqual(@as(u64, 1), reg.call(id_v, osv, VER_MAJORVERSION | VER_MINORVERSION, mask, 0));
    // Win10-вопрос (major>=10) — тоже TRUE
    const osv2 = tFillOsv(0x200, 10, 0);
    try testing.expectEqual(@as(u64, 1), reg.call(id_v, osv2, VER_MAJORVERSION | VER_MINORVERSION, mask, 0));
    // будущая версия (major>=11) — FALSE + ERROR_OLD_WIN_VERSION
    const osv3 = tFillOsv(0x300, 11, 0);
    try testing.expectEqual(@as(u64, 0), reg.call(id_v, osv3, VER_MAJORVERSION | VER_MINORVERSION, mask, 0));
    try testing.expectEqual(@as(u32, 1150), ctx.?.last_error);
    // EQUAL build 19041 → TRUE; чужой build → FALSE
    const osv4 = tFillOsv(0x400, 10, 0);
    userD(osv4 + 0xC).* = 19041;
    const bm = verSetConditionMask(0, VER_BUILDNUMBER, VER_EQUAL);
    try testing.expectEqual(@as(u64, 1), reg.call(id_v, osv4, VER_BUILDNUMBER, bm, 0));
    userD(osv4 + 0xC).* = 7601;
    try testing.expectEqual(@as(u64, 0), reg.call(id_v, osv4, VER_BUILDNUMBER, bm, 0));
    // поле без условия в маске → FALSE (MSDN-контракт)
    try testing.expectEqual(@as(u64, 0), reg.call(id_v, tFillOsv(0x500, 6, 1), VER_MAJORVERSION, 0, 0));
    // мусорный указатель → 0 + ERROR_INVALID_PARAMETER, без паники
    try testing.expectEqual(@as(u64, 0), reg.call(id_v, 0x9990, VER_MAJORVERSION, mask, 0));
    try testing.expectEqual(@as(u32, 87), ctx.?.last_error);
}

test "env: GetEnvironmentVariableA/W — пустое окружение, LastError-контракт" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_a = reg.add("KERNEL32.dll", "GetEnvironmentVariableA", 0);
    const id_w = reg.add("KERNEL32.dll", "GetEnvironmentVariableW", 0);
    const id_gle = reg.add("KERNEL32.dll", "GetLastError", 0);
    const id_sle = reg.add("KERNEL32.dll", "SetLastError", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const name = "CURL_SSL_BACKEND";
    @memcpy(g_mem[0x100..0x100 + name.len], name);
    g_mem[0x100 + name.len] = 0;

    // переменной нет: 0 + ERROR_ENVVAR_NOT_FOUND
    try testing.expectEqual(@as(u64, 0), reg.call(id_a, mb + 0x100, mb + 0x200, 64, 0));
    try testing.expectEqual(@as(u32, 203), ctx.?.last_error);
    try testing.expect(logHas("GetEnvironmentVariableA(\"CURL_SSL_BACKEND\")"));
    // GetLastError → 203
    try testing.expectEqual(@as(u64, 203), reg.call(id_gle, 0, 0, 0, 0));
    // SetLastError(0) + GetLastError → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_sle, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_gle, 0, 0, 0, 0));

    // W-вариант: имя в UTF-16
    const wname = "ALL_PROXY";
    for (wname, 0..) |ch, i| userW(mb + 0x300 + i * 2).* = ch;
    userW(mb + 0x300 + wname.len * 2).* = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_w, mb + 0x300, mb + 0x400, 64, 0));
    try testing.expectEqual(@as(u32, 203), ctx.?.last_error);

    // мусорные указатели → 0 + 87, без паники
    try testing.expectEqual(@as(u64, 0), reg.call(id_a, 0x9990, 0, 0, 0));
    try testing.expectEqual(@as(u32, 87), ctx.?.last_error);
}

test "errors: FormatMessageA/W — FROM_SYSTEM, стек-аргументы, ALLOCATE" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_a = reg.add("KERNEL32.dll", "FormatMessageA", 0);
    const id_w = reg.add("KERNEL32.dll", "FormatMessageW", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const FROM_SYSTEM: u64 = 0x1000;
    const ALLOC: u64 = 0x100;

    // буфер (arg5) и размер (arg6) приходят из СТЕКА вызывающего — фейк ops
    t_stack_args[0] = mb + 0x100; // lpBuffer
    t_stack_args[1] = 128; // nSize
    const len = reg.call(id_a, FROM_SYSTEM, 0, 10061, 0);
    try testing.expect(len > 0); // текст «actively refused»
    try testing.expectEqualStrings("No connection could be made because the target machine actively refused it.", std.mem.span(@as([*:0]const u8, @ptrFromInt(mb + 0x100))));
    // неизвестный код → generic-текст с номером
    _ = reg.call(id_a, FROM_SYSTEM, 0, 424242, 0);
    try testing.expectEqualStrings("Unrecognized error code (424242).", std.mem.span(@as([*:0]const u8, @ptrFromInt(mb + 0x100))));
    // буфер мал → 0 + ERROR_INSUFFICIENT_BUFFER
    t_stack_args[1] = 8;
    try testing.expectEqual(@as(u64, 0), reg.call(id_a, FROM_SYSTEM, 0, 10061, 0));
    try testing.expectEqual(@as(u32, 122), ctx.?.last_error);

    // ALLOCATE_BUFFER: указатель на наш block-heap пишется в *lpBuffer
    t_stack_args[0] = mb + 0x500; // PVOID* lpBuffer
    t_stack_args[1] = 0;
    const len2 = reg.call(id_a, FROM_SYSTEM | ALLOC, 0, 10060, 0);
    try testing.expect(len2 > 0);
    const heap_p = @as(*align(1) u64, @ptrFromInt(mb + 0x500)).*;
    try testing.expect(heap_p >= @intFromPtr(&g_heap));
    try testing.expectEqualStrings("A connection attempt failed because the connected party did not properly respond after a period of time.", std.mem.span(@as([*:0]const u8, @ptrFromInt(heap_p))));

    // W-вариант: UTF-16LE
    t_stack_args[0] = mb + 0x600; // WCHAR*
    t_stack_args[1] = 64;
    const len3 = reg.call(id_w, FROM_SYSTEM, 0, 11001, 0);
    try testing.expect(len3 > 0);
    var wbuf: [64]u8 = undefined;
    var wi: usize = 0;
    while (userW(mb + 0x600 + wi * 2).* != 0) : (wi += 1) wbuf[wi] = @intCast(userW(mb + 0x600 + wi * 2).*);
    try testing.expectEqualStrings("Host not found.", wbuf[0..wi]);
    // без FROM_SYSTEM → 0 + 87
    try testing.expectEqual(@as(u64, 0), reg.call(id_a, 0, 0, 10061, 0));
}

// ─── Тесты: InitOnceExecuteOnce + SSPI ──────────────────────────────────────

test "once: InitOnceExecuteOnce — состояния, мост, транзакция-откат" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id = reg.add("KERNEL32.dll", "InitOnceExecuteOnce", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const init_once = mb + 0x100;

    // свежая (0): мост запускается, InitOnce→1, возврат TRUE
    userQ(init_once).* = 0;
    try testing.expectEqual(@as(u64, 1), reg.call(id, init_once, 0xAB00, 0x11, 0x22));
    try testing.expectEqual(@as(usize, 1), t_launch_calls);
    try testing.expectEqual(init_once, t_launched_init_once);
    try testing.expectEqual(@as(u64, 0xAB00), t_launched_init_fn);
    try testing.expectEqual(@as(u64, 0x11), t_launched_parameter);
    try testing.expectEqual(@as(u64, 0x22), t_launched_context);
    try testing.expectEqual(@as(u64, 1), userQ(init_once).*); // «выполняется»

    // завершена (2): TRUE без повторного запуска колбэка
    userQ(init_once).* = 2;
    try testing.expectEqual(@as(u64, 1), reg.call(id, init_once, 0xAB00, 0, 0));
    try testing.expectEqual(@as(usize, 1), t_launch_calls); // не вырос

    // «выполняется» (1) — однопоточный CDD: TRUE
    userQ(init_once).* = 1;
    try testing.expectEqual(@as(u64, 1), reg.call(id, init_once, 0, 0, 0));

    // мост отказал (валидация/etc): ОТКАТ состояния + FALSE
    userQ(init_once).* = 0;
    t_launch_ok = false;
    try testing.expectEqual(@as(u64, 0), reg.call(id, init_once, 0xAB00, 0, 0));
    try testing.expectEqual(@as(u64, 0), userQ(init_once).*); // откат к 0
    try testing.expectEqual(@as(u32, 87), ctx.?.last_error);

    // InitFn=NULL → FALSE; мусорный InitOnce-указатель → 0 без паники
    userQ(init_once).* = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id, init_once, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id, 0x9990, 0xAB00, 0, 0));
}

test "sspi: InitSecurityInterfaceA — таблица, extra-стабы, SEC_E_UNSUPPORTED" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_isi = reg.add("Secur32.dll", "InitSecurityInterfaceA", 0);
    // extra-записи реестра — как их добавляет main64 (адреса = стабы)
    const qspi_addr: u64 = 0xAB00_0001;
    const ach_addr: u64 = 0xAB00_0002;
    const fcb_addr: u64 = 0xAB00_0003;
    const id_qspi = reg.add("Secur32.dll", "QuerySecurityPackageInfoA", qspi_addr);
    _ = reg.add("Secur32.dll", "AcquireCredentialsHandleA", ach_addr);
    _ = reg.add("Secur32.dll", "FreeContextBuffer", fcb_addr);

    // таблица: user-VA в block-heap, dwVersion=2, поля → адреса стабов
    const tbl = reg.call(id_isi, 0, 0, 0, 0);
    try testing.expect(tbl != 0);
    try testing.expect(tbl >= @intFromPtr(&g_heap));
    try testing.expectEqual(@as(u32, 2), userD(tbl).*); // dwVersion
    try testing.expectEqual(qspi_addr, userQ(tbl + 0x18).*); // QuerySecurityPackageInfoA
    try testing.expectEqual(ach_addr, userQ(tbl + 0x98).*); // AcquireCredentialsHandleA
    try testing.expectEqual(fcb_addr, userQ(tbl + 0x28).*); // FreeContextBuffer
    try testing.expectEqual(@as(u64, 0), userQ(tbl + 0xC0).*); // InitializeSecurityContextA — не добавлен
    // повторный вызов — ТА ЖЕ таблица (кэш)
    try testing.expectEqual(tbl, reg.call(id_isi, 0, 0, 0, 0));
    try testing.expect(logHas("InitSecurityInterfaceA: таблица"));

    // диспетчеризация extra-записи: SEC_E_UNSUPPORTED (не SEC_E_OK —
    // ноль затирал бы out-параметры мусором!)
    try testing.expectEqual(@as(u64, 0x8009_0302), reg.call(id_qspi, 0x1000, 0x2000, 0, 0));

    // FreeContextBuffer → SEC_E_OK (id_fcb указывает на запись с этим именем)
    const id_fcb = reg.add("Secur32.dll", "FreeContextBuffer", fcb_addr);
    try testing.expectEqual(@as(u64, 0), reg.call(id_fcb, 0x1234, 0, 0, 0));
}

// ─── Тесты: WS2_32 — сокетные заглушки волны №3 ────────────────────────────

test "ws2: socket/connect/closesocket/ioctlsocket — хэндлы и логирование" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sock = reg.add("WS2_32.dll", "socket", 0);
    const id_conn = reg.add("WS2_32.dll", "connect", 0);
    const id_close = reg.add("WS2_32.dll", "closesocket", 0);
    const id_ioctl = reg.add("WS2_32.dll", "ioctlsocket", 0);

    const mb: u64 = @intFromPtr(&g_mem);

    // socket(AF_INET, SOCK_STREAM, 0) → fd=0x100, 0x101
    try testing.expectEqual(@as(u64, 0x100), reg.call(id_sock, 2, 1, 0, 0));
    try testing.expectEqual(@as(u64, 0x101), reg.call(id_sock, 2, 1, 6, 0));
    try testing.expectEqual(@as(usize, 2), ctx.?.sockets_opened);
    try testing.expect(logHas("[WS2] socket(af=2, type=1, proto=0) -> fd=0x100"));
    // чужое семейство → INVALID_SOCKET + WSAEAFNOSUPPORT
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_sock, 99, 1, 0, 0));
    try testing.expectEqual(@as(u32, 10047), ctx.?.last_error);

    // sockaddr_in {AF_INET, port=80 BE, 93.184.216.34} → connect: лог + 0
    const sa = mb + 0x200;
    userW(sa + 0).* = 2;
    userW(sa + 2).* = std.mem.nativeToBig(u16, 80);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 93, 184, 216, 34 });
    try testing.expectEqual(@as(u64, 0), reg.call(id_conn, 0x100, sa, 16, 0));
    try testing.expect(logHas("[WS2] connect(fd=0x100, AF_INET, 93.184.216.34:80)"));
    // AF_INET6
    const sa6 = mb + 0x300;
    userW(sa6 + 0).* = 23;
    userW(sa6 + 2).* = std.mem.nativeToBig(u16, 443);
    try testing.expectEqual(@as(u64, 0), reg.call(id_conn, 0x100, sa6, 28, 0));
    try testing.expect(logHas("AF_INET6"));
    // битый namelen → INVALID + WSAEINVAL
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_conn, 0x100, sa, 4, 0));
    try testing.expectEqual(@as(u32, 10022), ctx.?.last_error);

    // ioctlsocket(FIONBIO, 1): лог режима
    userD(mb + 0x400).* = 1;
    try testing.expectEqual(@as(u64, 0), reg.call(id_ioctl, 0x100, 0x8004_667E, mb + 0x400, 0));
    try testing.expect(logHas("FIONBIO"));
    // closesocket → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_close, 0x100, 0, 0, 0));
    try testing.expect(logHas("[WS2] closesocket(fd=0x100)"));
}

test "ws2: htons/htonl/ntohs/ntohl + WSAGetLastError" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_htons = reg.add("WS2_32.dll", "htons", 0);
    const id_htonl = reg.add("WS2_32.dll", "htonl", 0);
    const id_ntohs = reg.add("WS2_32.dll", "ntohs", 0);
    const id_ntohl = reg.add("WS2_32.dll", "ntohl", 0);
    const id_wgle = reg.add("WS2_32.dll", "WSAGetLastError", 0);

    try testing.expectEqual(@as(u64, 0x3412), reg.call(id_htons, 0x1234, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0x3412), reg.call(id_ntohs, 0x1234, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0x5000_0000), reg.call(id_htonl, 80, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0x3412_0000), reg.call(id_ntohl, 0x1234, 0, 0, 0));

    ctx.?.last_error = 10060;
    try testing.expectEqual(@as(u64, 10060), reg.call(id_wgle, 0, 0, 0, 0));
}

test "ws2: send/recv — SOCKET_ERROR (честная граница: нет сетевого стека)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_send = reg.add("WS2_32.dll", "send", 0);
    const id_recv = reg.add("WS2_32.dll", "recv", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 14], "GET / HTTP/1.1");
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_send, 0x100, mb + 0x100, 16, 0));
    try testing.expectEqual(@as(u32, 10050), ctx.?.last_error);
    try testing.expect(logHas("send(fd=0x100, len=16)"));
    // мусорный буфер → SOCKET_ERROR + WSAEFAULT (не паника)
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_send, 0x100, 0x9990, 16, 0));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
    // recv → SOCKET_ERROR + WSAETIMEDOUT
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_recv, 0x100, mb + 0x200, 64, 0));
    try testing.expectEqual(@as(u32, 10060), ctx.?.last_error);
}

test "ws2: getaddrinfo/freeaddrinfo — синтез TEST-NET-1 + порт из service" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_gai = reg.add("WS2_32.dll", "getaddrinfo", 0);
    const id_fai = reg.add("WS2_32.dll", "freeaddrinfo", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const host = "example.com";
    @memcpy(g_mem[0x100..0x100 + host.len], host);
    g_mem[0x100 + host.len] = 0;
    @memcpy(g_mem[0x140..0x143], "80\x00");

    // *ppResult (arg4) — out-указатель
    try testing.expectEqual(@as(u64, 0), reg.call(id_gai, mb + 0x100, mb + 0x140, 0, mb + 0x200));
    try testing.expect(logHas("getaddrinfo(\"example.com\")"));
    const ai = @as(*align(1) u64, @ptrFromInt(mb + 0x200)).*;
    try testing.expect(ai != 0);
    // addrinfo: AF_INET/SOCK_STREAM/IPPROTO_TCP, addrlen=16
    try testing.expectEqual(@as(u32, 2), userD(ai + 0x04).*);
    try testing.expectEqual(@as(u32, 1), userD(ai + 0x08).*);
    try testing.expectEqual(@as(u32, 6), userD(ai + 0x0C).*);
    try testing.expectEqual(@as(u64, 16), userQ(ai + 0x10).*);
    const sa = userQ(ai + 0x20).*;
    try testing.expectEqual(@as(u16, 2), userW(sa).*);
    try testing.expectEqual(std.mem.nativeToBig(u16, 80), userW(sa + 2).*);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, @as([*]u8, @ptrFromInt(sa + 4))[0..4]);
    // ai_next = NULL (один синтез-адрес)
    try testing.expectEqual(@as(u64, 0), userQ(ai + 0x28).*);

    // service=NULL → порт 0 (curl проставит порт сам перед connect)
    try testing.expectEqual(@as(u64, 0), reg.call(id_gai, mb + 0x100, 0, 0, mb + 0x208));
    const ai2 = @as(*align(1) u64, @ptrFromInt(mb + 0x208)).*;
    try testing.expectEqual(@as(u16, 0), userW(userQ(ai2 + 0x20).* + 2).*);

    // битый out-указатель → WSAEFAULT (не паника)
    try testing.expectEqual(@as(u64, 10014), reg.call(id_gai, mb + 0x100, 0, 0, 0x9990));
    // freeaddrinfo — no-op, не падает
    try testing.expectEqual(@as(u64, 0), reg.call(id_fai, ai, 0, 0, 0));
}

// ─── Тесты: string-family (fix-волна №3) ────────────────────────────────────

test "str: _strdup — копия в heap, NUL, OOM/битый указатель" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sd = reg.add("api-ms-win-crt-string-l1-1-0.dll", "_strdup", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 18], "http://example.com");
    g_mem[0x100 + 18] = 0;

    const p = reg.call(id_sd, mb + 0x100, 0, 0, 0);
    try testing.expect(p != 0);
    // копия в bheap (g_heap), а НЕ в исходном буфере
    try testing.expect(p >= @intFromPtr(&g_heap) and p < @intFromPtr(&g_heap) + g_heap.len);
    try testing.expectEqualStrings("http://example.com", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(p)), 0));

    // повторный strdup — ДРУГОЙ адрес (каждая копия своя)
    const p2 = reg.call(id_sd, mb + 0x100, 0, 0, 0);
    try testing.expect(p2 != p);

    // битый указатель → NULL (не паника)
    try testing.expectEqual(@as(u64, 0), reg.call(id_sd, 0x9990, 0, 0, 0));
}

test "str: strchr/strrchr — контракты C (включая c==0 → терминатор)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sc = reg.add("api-ms-win-crt-private-l1-1-0.dll", "strchr", 0);
    const id_src = reg.add("api-ms-win-crt-private-l1-1-0.dll", "strrchr", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const s = "curl.exe";
    @memcpy(g_mem[0x100..0x100 + s.len], s);
    g_mem[0x100 + s.len] = 0;
    const base = mb + 0x100;

    // strchr: '.' — единственное вхождение
    try testing.expectEqual(base + 4, reg.call(id_sc, base, '.', 0, 0));
    // strchr: 'z' — нет → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_sc, base, 'z', 0, 0));
    // strchr: c==0 → указатель на ТЕРМИНАТОР (C-контракт)
    try testing.expectEqual(base + s.len, reg.call(id_sc, base, 0, 0, 0));

    // strrchr на строке с двумя 'l'
    const s2 = "hello world";
    @memcpy(g_mem[0x180..0x180 + s2.len], s2);
    g_mem[0x180 + s2.len] = 0;
    const b2 = mb + 0x180;
    // strrchr: 'l' — ПОСЛЕДНЕЕ (world), не первое (hello)
    try testing.expectEqual(b2 + 9, reg.call(id_src, b2, 'l', 0, 0));
    // strrchr: 'o' — в "world" (позиция 7), не в "hello"
    try testing.expectEqual(b2 + 7, reg.call(id_src, b2, 'o', 0, 0));
    // strrchr: c==0 → терминатор
    try testing.expectEqual(b2 + s2.len, reg.call(id_src, b2, 0, 0, 0));
    // strrchr: 'z' — нет → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_src, b2, 'z', 0, 0));
}

test "str: strstr/memcmp — подстроки и блочное сравнение" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_ss = reg.add("api-ms-win-crt-private-l1-1-0.dll", "strstr", 0);
    const id_mc = reg.add("api-ms-win-crt-private-l1-1-0.dll", "memcmp", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const h = "curl: option http://example.com: is unknown";
    @memcpy(g_mem[0x100..0x100 + h.len], h);
    g_mem[0x100 + h.len] = 0;
    const base = mb + 0x100;

    const n = "http";
    @memcpy(g_mem[0x200..0x200 + n.len], n);
    g_mem[0x200 + n.len] = 0;

    try testing.expectEqual(base + 13, reg.call(id_ss, base, mb + 0x200, 0, 0));
    @memcpy(g_mem[0x200..0x200 + 3], "zzz");
    try testing.expectEqual(@as(u64, 0), reg.call(id_ss, base, mb + 0x200, 0, 0));
    // пустая игла → haystack (C-контракт)
    g_mem[0x300] = 0;
    try testing.expectEqual(base, reg.call(id_ss, base, mb + 0x300, 0, 0));

    // memcmp: equal / less / greater (int-семантика)
    @memcpy(g_mem[0x400..0x405], "abcde");
    @memcpy(g_mem[0x500..0x505], "abcde");
    try testing.expectEqual(@as(u64, 0), reg.call(id_mc, mb + 0x400, mb + 0x500, 5, 0));
    g_mem[0x500 + 4] = 'z';
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_mc, mb + 0x400, mb + 0x500, 5, 0));
    try testing.expectEqual(@as(u64, 1), reg.call(id_mc, mb + 0x500, mb + 0x400, 5, 0));
    // n=0 → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_mc, mb + 0x400, mb + 0x500, 0, 0));
}

test "str: _stricmp/_strnicmp/tolower/isspace — классификация" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_si = reg.add("api-ms-win-crt-string-l1-1-0.dll", "_stricmp", 0);
    const id_sni = reg.add("api-ms-win-crt-string-l1-1-0.dll", "_strnicmp", 0);
    const id_tl = reg.add("api-ms-win-crt-string-l1-1-0.dll", "tolower", 0);
    const id_is = reg.add("api-ms-win-crt-string-l1-1-0.dll", "isspace", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 3], "URL");
    g_mem[0x100 + 3] = 0;
    @memcpy(g_mem[0x180..0x180 + 3], "url");
    g_mem[0x180 + 3] = 0;

    // регистронезависимое равенство
    try testing.expectEqual(@as(u64, 0), reg.call(id_si, mb + 0x100, mb + 0x180, 0, 0));
    @memcpy(g_mem[0x180..0x180 + 3], "zzz");
    g_mem[0x183] = 0;
    // «URL» vs «zzz»: 'U'(0x55) < 'z'(0x7A) → отрицательный результат
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_si, mb + 0x100, mb + 0x180, 0, 0));

    // strnicmp: первые 3 символа «URL» vs «zzz» → 'U'-'z' < 0
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_sni, mb + 0x100, mb + 0x180, 3, 0));

    // tolower
    try testing.expectEqual(@as(u64, 'a'), reg.call(id_tl, 'A', 0, 0, 0));
    try testing.expectEqual(@as(u64, 'a'), reg.call(id_tl, 'a', 0, 0, 0));
    try testing.expectEqual(@as(u64, '5'), reg.call(id_tl, '5', 0, 0, 0));

    // isspace
    try testing.expectEqual(@as(u64, 1), reg.call(id_is, ' ', 0, 0, 0));
    try testing.expectEqual(@as(u64, 1), reg.call(id_is, '\t', 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_is, 'x', 0, 0, 0));
}

test "str: atoi/strtol/strtoul — базы, знаки, endptr-контракт" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_atoi = reg.add("api-ms-win-crt-convert-l1-1-0.dll", "atoi", 0);
    const id_strtol = reg.add("api-ms-win-crt-convert-l1-1-0.dll", "strtol", 0);
    const id_strtoul = reg.add("api-ms-win-crt-convert-l1-1-0.dll", "strtoul", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // «  -42abc» → atoi = -42 (EAX-биты: 0xFFFFFFD6); NUL обязателен —
    // после tCtx буфер заполнен 0xAA (не нулями!)
    @memcpy(g_mem[0x100..0x100 + 8], "  -42abc");
    g_mem[0x108] = 0;
    try testing.expectEqual(@as(u64, @as(u32, @bitCast(@as(i32, -42)))), reg.call(id_atoi, mb + 0x100, 0, 0, 0));

    // strtol с endptr: «8080/srv» → 8080, endptr → «/srv»
    @memcpy(g_mem[0x140..0x140 + 8], "8080/srv");
    g_mem[0x148] = 0;
    try testing.expectEqual(@as(u64, 8080), reg.call(id_strtol, mb + 0x140, mb + 0x400, 10, 0));
    try testing.expectEqual(mb + 0x144, userQ(mb + 0x400).*);

    // strtol base 16: «0x1F8» → 504
    @memcpy(g_mem[0x180..0x180 + 5], "0x1F8");
    g_mem[0x185] = 0;
    try testing.expectEqual(@as(u64, 504), reg.call(id_strtol, mb + 0x180, 0, 16, 0));

    // strtol base 0 (автоопределение): «0777» → 8-ричное 511
    @memcpy(g_mem[0x1C0..0x1C0 + 4], "0777");
    g_mem[0x1C4] = 0;
    try testing.expectEqual(@as(u64, 511), reg.call(id_strtol, mb + 0x1C0, 0, 0, 0));

    // провал парса: «abc» → 0, endptr = s (C-контракт)
    @memcpy(g_mem[0x200..0x200 + 3], "abc");
    g_mem[0x203] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_strtol, mb + 0x200, mb + 0x408, 10, 0));
    try testing.expectEqual(mb + 0x200, userQ(mb + 0x408).*);

    // strtoul: «4294967295» → max u32
    @memcpy(g_mem[0x240..0x240 + 10], "4294967295");
    g_mem[0x24A] = 0;
    try testing.expectEqual(@as(u64, 0xFFFFFFFF), reg.call(id_strtoul, mb + 0x240, 0, 10, 0));

    // отрицательный strtol → знаковое значение
    @memcpy(g_mem[0x280..0x280 + 2], "-7");
    g_mem[0x282] = 0;
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -7))), reg.call(id_strtol, mb + 0x280, 0, 10, 0));
}

test "str: strerror/setlocale — статические строки, стабильный указатель" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_se = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "strerror", 0);
    const id_sl = reg.add("api-ms-win-crt-locale-l1-1-0.dll", "setlocale", 0);

    // strerror: известный код
    const p = reg.call(id_se, 22, 0, 0, 0);
    try testing.expect(p != 0);
    try testing.expectEqualStrings("Invalid argument", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(p)), 0));
    // неизвестный код — тоже строка, не NULL
    try testing.expect(reg.call(id_se, 9999, 0, 0, 0) != 0);

    // setlocale: указатель СТАБИЛЕН между вызовами (CRT-контракт)
    const l1 = reg.call(id_sl, 0, 0, 0, 0); // LC_ALL, NULL — запрос
    const l2 = reg.call(id_sl, 6, 0, 0, 0); // повторный вызов
    try testing.expect(l1 != 0 and l1 == l2);
    try testing.expectEqualStrings("C", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(l1)), 0));
}

// ─── Тесты: event-волна (WSA-event loop + stdio-интроспекция) ───────────────

test "ws2: WSACreateEvent/Close/Reset/EventSelect — пул хэндлов 0x200+" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_ce = reg.add("WS2_32.dll", "WSACreateEvent", 0);
    const id_cl = reg.add("WS2_32.dll", "WSACloseEvent", 0);
    const id_rs = reg.add("WS2_32.dll", "WSAResetEvent", 0);
    const id_es = reg.add("WS2_32.dll", "WSAEventSelect", 0);
    const id_en = reg.add("WS2_32.dll", "WSAEnumNetworkEvents", 0);

    // пул: ненулевые, уникальные, нарастающие
    const h1 = reg.call(id_ce, 0, 0, 0, 0);
    const h2 = reg.call(id_ce, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 0x200), h1);
    try testing.expectEqual(@as(u64, 0x201), h2);
    try testing.expect(h1 != h2);

    // Close/Reset → TRUE
    try testing.expectEqual(@as(u64, 1), reg.call(id_cl, h1, 0, 0, 0));
    try testing.expectEqual(@as(u64, 1), reg.call(id_rs, h1, 0, 0, 0));

    // EventSelect → 0 (события не приходят — Enum подтвердит)
    try testing.expectEqual(@as(u64, 0), reg.call(id_es, 0x100, h1, 0x1F, 0));

    // EnumNetworkEvents: WSANETWORKEVENTS обнулён, 0 = успех
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(g_mem[0x100..0x124], 0xEE);
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, 0x100, h1, mb + 0x100, 0));
    for (g_mem[0x100..0x120]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "ws2: WSAWaitForMultipleEvents — таймаут (события не сигналятся)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_w = reg.add("WS2_32.dll", "WSAWaitForMultipleEvents", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    @memset(g_mem[0x100..0x110], 0);
    g_mem[0x108] = 0; // events[1] = 0

    // валидный массив из 2 событий → WAIT_TIMEOUT (258)
    try testing.expectEqual(@as(u64, 258), reg.call(id_w, 2, mb + 0x100, 0, 1000));
    // n=0 → ошибка, не таймаут
    try testing.expectEqual(@as(u64, 6), reg.call(id_w, 0, mb + 0x100, 0, 1000));
    // битый массив → WSA_INVALID_HANDLE
    try testing.expectEqual(@as(u64, 6), reg.call(id_w, 2, 0x9990, 0, 1000));
}

test "ws2: __WSAFDIsSet — реальная семантика fd_set (не стаб!)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_is = reg.add("WS2_32.dll", "__WSAFDIsSet", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // fd_set: count=3 (смещение 0), sockets с СМЕЩЕНИЯ 8: {0x100, 0x101, 0x102}
    userD(mb + 0x100).* = 3;
    userQ(mb + 0x108).* = 0x100;
    userQ(mb + 0x110).* = 0x101;
    userQ(mb + 0x118).* = 0x102;

    try testing.expectEqual(@as(u64, 1), reg.call(id_is, 0x101, mb + 0x100, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_is, 0x999, mb + 0x100, 0, 0));
    // пустой набор → 0
    userD(mb + 0x200).* = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_is, 0x100, mb + 0x200, 0, 0));
    // битый указатель → 0 (не паника)
    try testing.expectEqual(@as(u64, 0), reg.call(id_is, 0x100, 0x9990, 0, 0));
}

test "win32: CreateEventA/WaitFor-семья — единый пул, WAIT_TIMEOUT" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_ca = reg.add("KERNEL32.dll", "CreateEventA", 0);
    const id_ws = reg.add("KERNEL32.dll", "WaitForSingleObject", 0);
    const id_wm = reg.add("KERNEL32.dll", "WaitForMultipleObjects", 0);

    // CreateEventA продолжает пул WSA (0x200+), имя логируется
    const h = reg.call(id_ca, 0, 1, 0, 0);
    try testing.expectEqual(@as(u64, 0x200), h);
    try testing.expect(logHas("CreateEventA"));

    // WaitForSingleObject → WAIT_TIMEOUT (258)
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, h, 50, 0, 0));
    // WaitForMultipleObjects: 1 хэндл → WAIT_TIMEOUT
    const mb: u64 = @intFromPtr(&g_mem);
    userQ(mb + 0x100).* = h;
    try testing.expectEqual(@as(u64, 258), reg.call(id_wm, 1, mb + 0x100, 0, 100));
    // WAIT_FAILED (0xFFFFFFFF) на n=0
    try testing.expectEqual(@as(u64, 0xFFFFFFFF), reg.call(id_wm, 0, mb + 0x100, 0, 100));
}

test "crt: _fileno/_isatty/_setmode/_fsopen — stdio-интроспекция" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_fn = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_fileno", 0);
    const id_ia = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_isatty", 0);
    const id_sm = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_setmode", 0);
    const id_fo = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_fsopen", 0);
    const id_iob = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func", 0);

    // __acrt_iob_func(1) → FILE* stdout; _fileno → 1
    const stdout_file = reg.call(id_iob, 1, 0, 0, 0);
    try testing.expect(stdout_file != 0);
    try testing.expectEqual(@as(u64, 1), reg.call(id_fn, stdout_file, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_fn, reg.call(id_iob, 0, 0, 0, 0), 0, 0, 0));
    try testing.expectEqual(@as(u64, 2), reg.call(id_fn, reg.call(id_iob, 2, 0, 0, 0), 0, 0, 0));
    // чужой FILE* → -1
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_fn, 0x9990, 0, 0, 0));

    // isatty: наш сериальный ВЫВОД — настоящий терминал
    try testing.expectEqual(@as(u64, 1), reg.call(id_ia, 1, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_ia, 7, 0, 0, 0));

    // setmode: прошлый режим _O_TEXT (0x4000)
    try testing.expectEqual(@as(u64, 0x4000), reg.call(id_sm, 1, 0x8000, 0, 0));

    // fsopen: NULL (нет ФС), errno не паникует
    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 7], ".curlrc");
    g_mem[0x107] = 0;
    @memcpy(g_mem[0x120..0x120 + 2], "rb");
    g_mem[0x122] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_fo, mb + 0x100, mb + 0x120, 1, 0));
    try testing.expect(logHas("_fsopen(\".curlrc\""));
}

test "str: strcspn — префикс до символа из набора" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_cs = reg.add("api-ms-win-crt-string-l1-1-0.dll", "strcspn", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // классика URL: «http://example.com» — до «?#»
    @memcpy(g_mem[0x100..0x100 + 18], "http://example.com");
    g_mem[0x100 + 18] = 0;
    @memcpy(g_mem[0x140..0x140 + 2], "?#");
    g_mem[0x142] = 0;
    try testing.expectEqual(@as(u64, 18), reg.call(id_cs, mb + 0x100, mb + 0x140, 0, 0));

    // '?' есть в строке → префикс до него
    @memcpy(g_mem[0x180..0x180 + 14], "path?q=1&x=2#f");
    g_mem[0x180 + 14] = 0;
    try testing.expectEqual(@as(u64, 4), reg.call(id_cs, mb + 0x180, mb + 0x140, 0, 0));

    // пустой reject → длина всей строки
    g_mem[0x160] = 0;
    try testing.expectEqual(@as(u64, 14), reg.call(id_cs, mb + 0x180, mb + 0x160, 0, 0));
}

test "crt: mbstowcs_s — ANSI → UTF-16LE с NUL и счётчиком" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_mw = reg.add("api-ms-win-crt-convert-l1-1-0.dll", "mbstowcs_s", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x100 + 11], "example.com");
    g_mem[0x100 + 11] = 0;

    // успешная конверсия: *ret=11, wbuf = UTF-16LE + NUL; 5-й аргумент
    // (count) идёт через стек Win64 — в тесте это t_stack_args[0]
    t_stack_args[0] = 16;
    try testing.expectEqual(@as(u64, 0), reg.call(id_mw, mb + 0x400, mb + 0x200, 16, mb + 0x100));
    try testing.expectEqual(@as(u64, 11), userQ(mb + 0x400).*);
    try testing.expectEqual(@as(u16, 'e'), userW(mb + 0x200).*);
    try testing.expectEqual(@as(u16, 'x'), userW(mb + 0x202).*);
    try testing.expectEqual(@as(u16, 0), userW(mb + 0x200 + 11 * 2).*); // NUL

    // буфера мало (11+1 > 8) → ERANGE (34), *ret=0
    try testing.expectEqual(@as(u64, 34), reg.call(id_mw, mb + 0x408, mb + 0x200, 8, mb + 0x100));
    try testing.expectEqual(@as(u64, 0), userQ(mb + 0x408).*);

    // count усекает: count=4 → «exam» + NUL
    t_stack_args[0] = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_mw, mb + 0x410, mb + 0x200, 16, mb + 0x100));
    try testing.expectEqual(@as(u64, 4), userQ(mb + 0x410).*);
    try testing.expectEqual(@as(u16, 0), userW(mb + 0x200 + 4 * 2).*);

    // rc=NULL → EINVAL
    try testing.expectEqual(@as(u64, 22), reg.call(id_mw, 0, mb + 0x200, 16, mb + 0x100));
}

// ─── Тесты: threading-волна (CreateThread/ExitThread/Wait-сигналы) ───────────

test "thread: CreateThread — стек vheap, exit-трамплин, хэндл" {
    ops = tOps();
    tReset();
    tCtx("");
    // vheap-регион 256КБ под стек треда (реальная память — mmap)
    const vh = try std.posix.mmap(null, 0x40000, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    defer std.posix.munmap(vh);
    if (ctx) |*c| {
        c.vheap_base = @intFromPtr(vh.ptr);
        c.vheap_limit = @intFromPtr(vh.ptr) + 0x40000;
        c.vheap_cursor = @intFromPtr(vh.ptr);
    }
    // код-регион для динамического ExitThread-стаба
    const cb = try std.posix.mmap(null, 4096, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    defer std.posix.munmap(cb);

    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    reg.disp.code = cb;
    const id_ct = reg.add("KERNEL32.dll", "CreateThread", 0);

    // CreateThread(attrs=0, stack=0→64КБ, start=0x14000b000, param=0x9999)
    t_stack_args[0] = 0; // flags: 0 (не suspended)
    t_stack_args[1] = 0; // pThreadId: NULL
    const h = reg.call(id_ct, 0, 0, 0x14000b000, 0x9999);
    try testing.expectEqual(@as(u64, 0x1003), h); // фейк-хэндл ops.create_thread

    // параметры дошли до ops.create_thread нетронутыми
    try testing.expectEqual(@as(usize, 1), t_thread_calls);
    try testing.expectEqual(@as(u64, 0x14000b000), t_thread_start);
    try testing.expectEqual(@as(u64, 0x9999), t_thread_param);
    // стек — в vheap-регионе, верх выровнен, 64КБ
    try testing.expect(t_thread_stack_top >= @intFromPtr(vh.ptr) + 0x10000 - 8);
    try testing.expect(t_thread_stack_top <= @intFromPtr(vh.ptr) + 0x10000);
    // exit-трамплин создан как extra-запись (не 0)
    try testing.expect(t_thread_exit_va != 0);

    // CREATE_SUSPENDED (flags=1) → отказ: NULL + ERROR_INVALID_PARAMETER
    t_stack_args[0] = 1;
    try testing.expectEqual(@as(u64, 0), reg.call(id_ct, 0, 0, 0x14000b000, 0));
    try testing.expectEqual(@as(usize, 1), t_thread_calls); // повторного запуска НЕ было
    if (ctx) |c| try testing.expectEqual(@as(u32, 87), c.last_error);
}

test "thread: WaitFor-семья видит сигнальный thread-handle" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_ws = reg.add("KERNEL32.dll", "WaitForSingleObject", 0);
    const id_wm = reg.add("KERNEL32.dll", "WaitForMultipleObjects", 0);
    const id_ww = reg.add("WS2_32.dll", "WSAWaitForMultipleEvents", 0);
    const id_et = reg.add("KERNEL32.dll", "ExitThread", 0);

    const mb: u64 = @intFromPtr(&g_mem);

    // НЕ сигнален → WAIT_TIMEOUT (258)
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, 0x1003, 100, 0, 0));

    // сигнален (резолвер умер) → WAIT_OBJECT_0 (0)
    t_signaled_handle = 0x1003;
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, 0x1003, 100, 0, 0));
    try testing.expect(logHas("WAIT_OBJECT_0"));

    // WaitForMultipleObjects: [event_0x200(не сигнален), thread_0x1003(сигнален)]
    userQ(mb + 0x100).* = 0x200;
    userQ(mb + 0x108).* = 0x1003;
    try testing.expectEqual(@as(u64, 1), reg.call(id_wm, 2, mb + 0x100, 0, 100)); // индекс 1

    // WSAWaitForMultipleEvents: то же самое, events[0]=thread
    userQ(mb + 0x200).* = 0x1003;
    try testing.expectEqual(@as(u64, 0), reg.call(id_ww, 1, mb + 0x200, 0, 1000)); // WSA_WAIT_EVENT_0

    // ExitThread → ops.exit_task вызван (флаг в тесте)
    _ = reg.call(id_et, 0, 0, 0, 0);
    try testing.expectEqual(@as(usize, 1), t_exit_task_calls);
}

test "crt: memchr/_time64/GetSystemTimeAsFileTime/GetTickCount64" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_mc = reg.add("api-ms-win-crt-private-l1-1-0.dll", "memchr", 0);
    const id_tm = reg.add("api-ms-win-crt-time-l1-1-0.dll", "_time64", 0);
    const id_ft = reg.add("KERNEL32.dll", "GetSystemTimeAsFileTime", 0);
    const id_tc = reg.add("KERNEL32.dll", "GetTickCount64", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    // memchr: найден/не найден/за границей n
    @memcpy(g_mem[0x100..0x100 + 11], "hello world");
    try testing.expectEqual(mb + 0x102, reg.call(id_mc, mb + 0x100, 'l', 11, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_mc, mb + 0x100, 'z', 11, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_mc, mb + 0x100, 'w', 5, 0)); // 'w' за n=5
    // n=0 → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_mc, mb + 0x100, 'h', 0, 0));

    // _time64: стабильный 2026-01-01 (1767225600), out-параметр записан
    try testing.expectEqual(@as(u64, 1767225600), reg.call(id_tm, mb + 0x300, 0, 0, 0));
    try testing.expectEqual(@as(u64, 1767225600), userQ(mb + 0x300).*);

    // GetSystemTimeAsFileTime: 64-бит FILETIME
    _ = reg.call(id_ft, mb + 0x380, 0, 0, 0);
    try testing.expectEqual(@as(u64, 133_951_872_000_000_000), userQ(mb + 0x380).*);

    // GetTickCount64: TSC 3ГГц → мс
    t_tsc = 3_000_000_000; // 1 секунда
    try testing.expectEqual(@as(u64, 1000), reg.call(id_tc, 0, 0, 0, 0));
}
