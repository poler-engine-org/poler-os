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
};

fn denyAll(_: u64, _: u64) bool {
    return false;
}
fn noop() u64 {
    return 0;
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
            const c = &(ctx orelse return 0);
            if (c.tid == 0) c.tid = 2; // консистентно с TEB.ClientId (v0.10)
            ret = c.tid;
        } else if (std.mem.eql(u8, name, "AcquireSRWLockExclusive") or
            std.mem.eql(u8, name, "ReleaseSRWLockExclusive") or
            std.mem.eql(u8, name, "Sleep"))
        {
            ret = 0; // no-op: однопоточный CDD-процесс (честная граница)
        } else if (std.mem.eql(u8, name, "SetUnhandledExceptionFilter")) {
            ret = 0; // предыдущего фильтра не было
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
        } else if (std.mem.eql(u8, name, "fflush")) {
            ret = 0; // консоль пишется сразу — нечего сбрасывать
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
        if (std.mem.eql(u8, name, "__p___argc")) {
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
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-private-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "memcpy")) {
            ret = kmemcpy(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "memmove")) {
            ret = kmemmove(a1, a2, a3);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-locale-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "_configthreadlocale")) {
            ret = 0; // «C»-локаль по умолчанию
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
        } else {
            handled = false;
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

fn tReset() void {
    t_console_len = 0;
    t_log_len = 0;
    t_tsc = 0;
    t_exited = null;
    t_map_calls = 0;
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

fn tOps() Ops {
    return .{
        .validate_read = tValidateTrue,
        .validate_write = tValidateTrue,
        .map_user = tMapUser,
        .read_tsc = tReadTsc,
        .write_console = tWriteConsole,
        .log = tLog,
        .exit = tExit,
    };
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
    };
}

/// Synthetic-реестр стабов: без PE-файла, записи вручную.
const FakeRegistry = struct {
    entries: [24]win32.StubEntry,
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
    const id_fflush = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fflush", 0);
    const id_setvbuf = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "setvbuf", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const msg = "curl: try 'curl --help' or 'curl --manual' for more information\n";
    @memcpy(g_mem[0x100..0x100 + msg.len], msg);
    g_mem[0x100 + msg.len] = 0;

    // fputs: текст уходит в консоль ОС
    try testing.expectEqual(@as(u64, 1), reg.call(id_fputs, mb + 0x100, 0x5000, 0, 0));
    try testing.expect(consoleHas("curl: try 'curl --help'"));

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

    // GetCurrentThreadId: ленивый TID=2, стабильный
    try testing.expectEqual(@as(u64, 2), reg.call(id_tid, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 2), reg.call(id_tid, 0, 0, 0, 0));

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
