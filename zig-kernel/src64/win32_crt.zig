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
//   WS2_32.dll!socket/connect/closesocket/ioctlsocket — SocketState: опции,
//                                              состояние, события FD_* (№4)
//   WS2_32.dll!getaddrinfo/freeaddrinfo       — синтез TEST-NET (DNS: №4)
//   WS2_32.dll!setsockopt/getsockopt/getsockname/getpeername/shutdown —
//                                              сокетные опции/адреса (№4)
//   WS2_32.dll!select — мультиплексор: fd_set перезаписывается (готовые)
//   WS2_32.dll!send/recv — loopback-шим: [HTTP-SEND] запроса, синтет-ответ
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
    /// v0.14.0 (CDD №5): реальный сетевой обмен через virtio-net (ядро:
    /// драйвер + SLIRP; тесты: параноики — fallback на loopback-синтетику).
    /// Драйвер инициализирован?
    net_ready: *const fn () bool,
    /// DNS-резолв (реальный UDP→10.0.2.3): host → u64-упаковка BE-байт IP
    /// (ip[0] — старший байт u64; 0 = не резолвится).
    net_dns_resolve: *const fn (host: [*]const u8, host_len: usize) u64,
    /// TCP-connect (SYN→SYN-ACK→ACK): слот соединения или -1.
    net_tcp_connect: *const fn (be_ip: u64, port: u16) i64,
    /// Отправка данных слота: сколько ушло или -1.
    net_tcp_send: *const fn (slot: i64, data: [*]const u8, len: usize) i64,
    /// Приём: >0 — байты, 0 — нет данных, -1 — соединение закрыто.
    net_tcp_recv: *const fn (slot: i64, out: [*]u8, cap: usize) i64,
    /// Активный поллинг RX (select-путь): байт в ринге после полла.
    net_tcp_poll: *const fn (slot: i64) i64,
    /// Закрытие соединения (FIN).
    net_tcp_close: *const fn (slot: i64) void,
    /// v0.15.0 (CDD №6): сон ТЕКУЩЕЙ задачи — планировщик не даёт слайс до
    /// истечения ms (парковка воркер-тредов; ядро — scheduler.setTaskSleep).
    sleep_task: *const fn (ms: u64) void,
    /// v0.16.0 (CDD №7): КРИПТО-заполнение буфера энтропией ядра — PUF-хаб
    /// (джиттер кремния + тайминги шины + IRQ). Ядро: main64.pufCryptoFill
    /// (PolerPrng на сиде PUF-binding + live-фолды хаба); тест: advancing
    /// xorshift — ГЛАВНОЕ СВОЙСТВО: два вызова дают РАЗНЫЕ байты (статический
    /// сид 0x7E5C_A01B был rot-козлом ML-KEM-декапсуляции в v0.15.0).
    entropy_fill: *const fn (buf: [*]u8, len: usize) void,
    /// v0.16.0 (CDD №7): VFS — размер файла по имени (CPIO initrd + FAT32
    /// через virtio-blk). Возврат 0xFFFF_FFFF_FFFF_FFFF = не найден.
    /// Имя — НОРМАЛИЗОВАННОЕ ядром (без диска/слэшей, case-insensitive).
    vfs_file_size: *const fn (name: [*]const u8, name_len: usize) u64,
    /// v0.16.0 (CDD №7): чтение [offset..offset+len) файла → out (USER-VA,
    /// валидация НА ВЫЗЫВАЮЩЕМ до вызова). Возврат = прочитано байт.
    vfs_file_read: *const fn (name: [*]const u8, name_len: usize, offset: u64, out: [*]u8, len: usize) u64,
    /// v0.17.0 (CDD №8): ЗАПИСЬ data в [offset..) файла по имени (FAT32 RW;
    /// initrd — RO → 0). Возврат = записано байт.
    vfs_file_write: *const fn (name: [*]const u8, name_len: usize, offset: u64, data: [*]const u8, len: usize) u64,
    /// v0.17.0 (CDD №8): создать файл (FAT32 createFile; 1 = ок/существует).
    vfs_file_create: *const fn (name: [*]const u8, name_len: usize) u64,
    /// v0.17.0 (CDD №8): усечь/расширить до new_size (FAT32 setFileSize).
    vfs_file_truncate: *const fn (name: [*]const u8, name_len: usize, new_size: u64) u64,
    /// v0.17.0 (CDD №8): удалить файл (FAT32 deleteFile; initrd — 0).
    vfs_file_delete: *const fn (name: [*]const u8, name_len: usize) u64,
    /// v0.17.0 (CDD №8): число логических CPU (GetSystemInfo — 7-Zip
    /// бенчмарк заводит треды по этому числу). Ядро: acpi.cpu_count.
    cpu_count: *const fn () u64,
    /// v0.17.0 (CDD №8): физическая память КБ (GlobalMemoryStatusEx).
    /// Ядро: pmm.getStats().total_kb; тесты: фиксированное число.
    phys_mem_kb: *const fn () u64,
    /// v0.16.0 (CDD №7): РЕАЛЬНОЕ wall-clock время (Unix-секунды, CMOS RTC
    /// — QEMU подаёт время хоста). null по умолчанию → статика v0.12-эпохи
    /// (нативные тесты не зависят от живой даты). Потребители: _time64
    /// (X509-verify OpenSSL: notBefore/notAfter), GetSystemTimeAsFileTime.
    wall_time: ?*const fn () u64 = null,
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
fn denyNet() bool {
    return false;
}
fn noDns(_: [*]const u8, _: usize) u64 {
    return 0;
}
fn noConnect(_: u64, _: u16) i64 {
    return -1;
}
fn noSend(_: i64, _: [*]const u8, _: usize) i64 {
    return -1;
}
fn noRecv(_: i64, _: [*]u8, _: usize) i64 {
    return 0;
}
fn noPoll(_: i64) i64 {
    return 0;
}
fn noClose(_: i64) void {}
fn noSleep(_: u64) void {} // фейк: без парковки (нативные тесты)
fn noEntropy(_: [*]u8, _: usize) void {} // фейк: без энтропии (заполнять НЕЛЬЗЯ — см. kBCryptGenRandom)
fn noVfsSize(_: [*]const u8, _: usize) u64 {
    return 0xFFFF_FFFF_FFFF_FFFF; // VFS недоступен → «файл не найден»
}
fn noVfsRead(_: [*]const u8, _: usize, _: u64, _: [*]u8, _: usize) u64 {
    return 0;
}
fn noVfsWrite(_: [*]const u8, _: usize, _: u64, _: [*]const u8, _: usize) u64 {
    return 0; // RO-бекенд (нативные тесты без ФС)
}
fn noVfsCreate(_: [*]const u8, _: usize) u64 {
    return 0;
}
fn noVfsTruncate(_: [*]const u8, _: usize, _: u64) u64 {
    return 0;
}
fn noVfsDelete(_: [*]const u8, _: usize) u64 {
    return 0;
}
fn fakeCpuCount() u64 {
    return 2; // тесты: двухъядерная модель
}
fn fakePhysMemKb() u64 {
    return 262144; // 256МБ
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
    .net_ready = denyNet,
    .net_dns_resolve = noDns,
    .net_tcp_connect = noConnect,
    .net_tcp_send = noSend,
    .net_tcp_recv = noRecv,
    .net_tcp_poll = noPoll,
    .net_tcp_close = noClose,
    .sleep_task = noSleep,
    .entropy_fill = noEntropy,
    .vfs_file_size = noVfsSize,
    .vfs_file_read = noVfsRead,
    .vfs_file_write = noVfsWrite,
    .vfs_file_create = noVfsCreate,
    .vfs_file_truncate = noVfsTruncate,
    .vfs_file_delete = noVfsDelete,
    .cpu_count = fakeCpuCount,
    .phys_mem_kb = fakePhysMemKb,
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

    // v0.14.0 (CDD №5)
    next_mutex_handle: u64, // CreateMutexA: пул 0x400+ (сигнальные всегда)
    tls_sessions: [MAX_TLS]TlsSession, // SSPI/SChannel TLS-контексты
    tls_last_fd: u64, // сокет последней TLS-активности (ISC-связка)

    // v0.13.0 (CDD №4)
    sockets: [MAX_SOCKS]Sock, // состояния сокетов (fd = 0x100 + индекс)

    // v0.16.0 (CDD №7)
    next_file_handle: u64, // CreateFileA/W: пул 0x800+ (файлы VFS)
    files: [MAX_FILES]FileState, // дескрипторы открытых файлов (RW-VFS)

    // v0.17.0 (CDD №8): события/семафоры с РЕАЛЬНЫМ сигнальным состоянием
    // (7-Zip: WaitForSingleObject(event, INFINITE) на вореорах — без этого
    // мгновенный WAIT_TIMEOUT ломал синхронизацию тредов бенчмарка).
    events: [MAX_EVENTS]EventState,
    /// v0.17.0 (CDD №8): блок DATA-импортов msvcrt (_fmode/_commode/__initenv/
    /// _iob) — патчится в IAT (patchDataImports, main64); FILE* из этого
    /// блока в stdio-функциях маршрутизируются на консоль.
    iob_block: u64 = 0,
    /// v0.17.0 (CDD №8): argv-массив (ensureArgv) — для __getmainargs.
    argv_arr: u64 = 0,
    env_arr: u64 = 0,
};

/// v0.17.0 (CDD №8): состояние события/семафора (хэндлы 0x200+).
pub const MAX_EVENTS: usize = 32;
pub const EventState = struct {
    in_use: bool = false,
    signaled: bool = false,
    manual_reset: bool = false,
    /// Семафор: текущий счётчик (ReleaseSemaphore += n, Wait -= 1, floor 0).
    is_semaphore: bool = false,
    count: u32 = 0,
};

/// v0.17.0 (CDD №8): диапазон хэндлов событий (совпадает с WSA-пулом v0.12 —
/// события едины; SetEvent теперь меняет РЕАЛЬНОЕ состояние).
pub const EVENT_HANDLE_BASE: u64 = 0x200;
pub const EVENT_HANDLE_LIMIT: u64 = 0x400;

fn eventByHandle(h: u64) ?*EventState {
    if (h < EVENT_HANDLE_BASE or h >= EVENT_HANDLE_BASE + MAX_EVENTS) return null;
    const c = &(ctx orelse return null);
    const ev = &c.events[@as(usize, @intCast(h - EVENT_HANDLE_BASE))];
    if (!ev.in_use) return null;
    return ev;
}

pub var ctx: ?Ctx = null;

// ─── v0.16.0 (CDD №7): VFS-файлы (CPIO initrd + FAT32) + окружение ──────────

/// MAX_FILES — файловые дескрипторы CreateFileA/W (curl: cacert.pem +
/// .curlrc + вывод — пары дескрипторов достаточно; 16 = запас).
pub const MAX_FILES: usize = 16;
pub const MAX_PATH_LEN: usize = 260;

/// Хэндлы файлов: 0x800 + индекс (не пересекается: сокеты 0x100+,
/// события 0x200+, мьютексы 0x400+).
pub const FILE_HANDLE_BASE: u64 = 0x800;
pub const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const VFS_NOT_FOUND: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Состояние открытого файла (RO-VFS): имя + позиция. Чтение — по имени
/// через ops.vfs_file_read (ядерный CPIO/FAT32 — бекенд-агностично).
pub const FileState = struct {
    in_use: bool = false,
    name: [MAX_PATH_LEN]u8 = [_]u8{0} ** MAX_PATH_LEN,
    name_len: usize = 0,
    pos: u64 = 0,
    size: u64 = 0,
    eof: bool = false, // CRT-семантика: флаг ставится при ЧТЕНИИ ЗА концом
    /// v0.17.0 (CDD №8): файл открыт на запись (GENERIC_WRITE / fopen «w/a/+")
    /// — WriteFile/fwrite/_write пишут в FAT32 через ops.vfs_file_write.
    writable: bool = false,
};

/// Запись окружения процесса (ядро-предоставленные переменные; тест — свои).
/// v0.16.0 (CDD №7): CURL_CA_BUNDLE=cacert.pem — верификация SSL без -k.
pub const EnvEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// Таблица окружения: ядро устанавливает перед стартом PE-процесса
/// (main64), тесты — свои значения. ПУСТАЯ по умолчанию (как v0.12–v0.15).
pub var env_table: []const EnvEntry = &.{};

/// Поиск в env-таблице (case-insensitive — Windows-семантика).
fn envLookup(name: []const u8) ?[]const u8 {
    for (env_table) |e| {
        if (std.ascii.eqlIgnoreCase(e.name, name)) return e.value;
    }
    return null;
}

/// Нормализация пути Win32 → имя VFS: срез диска «X:», ведущие '/'/'\\',
/// префикс «./», '\\'-разделители → '/' (CPIO-имена плоские; FAT32 — путь).
/// Возвращает срез ОТОБРАЖАЕМОГО имени (в буфере вызывающего) или null
/// (пусто/мусор).
fn vfsNormalizePath(src: []const u8, out: *[MAX_PATH_LEN]u8) ?[]const u8 {
    var s = src;
    // «X:/path» или «X:\\path» — диск
    if (s.len >= 2 and s[1] == ':' and std.ascii.isAlphabetic(s[0])) s = s[2..];
    while (s.len > 0 and (s[0] == '/' or s[0] == '\\')) s = s[1..];
    if (s.len >= 2 and s[0] == '.' and (s[1] == '/' or s[1] == '\\')) s = s[2..];
    while (s.len > 0 and (s[0] == '/' or s[0] == '\\')) s = s[1..];
    if (s.len == 0 or s.len > MAX_PATH_LEN - 1) return null;
    var n: usize = 0;
    for (s) |ch| {
        // FAT32/VFS не понимают UNC-префиксы и «..»-навигацию выше корня —
        // но «dir/file» — валидный путь. Проверки не режем — честный VFS.
        out[n] = if (ch == '\\') '/' else ch;
        n += 1;
    }
    return out[0..n];
}

// ─── v0.16.0 (CDD №7): Win32 File API поверх VFS ──────────────────────────

// LastError-коды файловой волны (Win32)
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE_FILE: u32 = 6;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_FILE_EXISTS: u32 = 80;

/// CreateFile-диспозиции (dwCreationDisposition)
const CREATE_NEW: u64 = 1;
const CREATE_ALWAYS: u64 = 2;
const OPEN_EXISTING: u64 = 3;
const OPEN_ALWAYS: u64 = 4;
const TRUNCATE_EXISTING: u64 = 5;

/// dwDesiredAccess: запись в RO-VFS запрещена (честная граница)
const GENERIC_WRITE: u64 = 0x4000_0000;

/// GetFileAttributes / GetFileType
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const FILE_TYPE_DISK: u64 = 1;
const FILE_TYPE_CHAR: u64 = 2;

/// SetFilePointer-методы
const FILE_BEGIN: u64 = 0;
const FILE_CURRENT: u64 = 1;
const FILE_END: u64 = 2;

/// FILE*-блок CRT-stdio (80Б = UCRT-размер): заголовок-пропуск наш —
/// [0..4) magic, [4..8) индекс FileState. std-потоки (iob-массив) magic
/// НЕ имеют → автоматически отличаем «наш файл» от stdout/stderr.
const CRT_FILE_MAGIC: u32 = 0x454C_4946; // "FILE"
const CRT_FILE_SIZE: u64 = 80;

/// Хэндл → FileState (пул 0x800+; хэндл валиден пока слот жив).
fn fileByHandle(h: u64) ?*FileState {
    if (h < FILE_HANDLE_BASE or h >= FILE_HANDLE_BASE + MAX_FILES) return null;
    const c = &(ctx orelse return null);
    const f = &c.files[@as(usize, @intCast(h - FILE_HANDLE_BASE))];
    if (!f.in_use) return null;
    return f;
}

/// FILE* (CRT-stdio) → индекс FileState. null = не наш файл (std-поток).
fn crtFileIdx(stream: u64) ?usize {
    if (stream == 0) return null;
    if (!ops.validate_read(stream, 8)) return null;
    const base = userPtr(stream);
    if (std.mem.readInt(u32, base[0..4], .little) != CRT_FILE_MAGIC) return null;
    const idx: usize = std.mem.readInt(u32, base[4..8], .little);
    if (idx >= MAX_FILES) return null;
    const c = &(ctx orelse return null);
    if (!c.files[idx].in_use) return null;
    return idx;
}

/// Открытие FileState по нормализованному имени: слот + кэш размера.
fn fileSlotAlloc(norm: []const u8, size: u64) ?usize {
    const c = &(ctx orelse return null);
    for (&c.files, 0..) |*f, i| {
        if (!f.in_use) {
            f.* = .{};
            f.in_use = true;
            @memcpy(f.name[0..norm.len], norm);
            f.name_len = norm.len;
            f.size = size;
            c.next_file_handle += 1; // статистика открытых файлов
            return i;
        }
    }
    return null;
}

/// Поиск файла по user-пути: нормализация + ops.vfs_file_size.
/// Возврат: .{ norm, size } или null (не найден / мусорный путь).
const VfsFound = struct { norm: []const u8, size: u64 };
fn vfsOpenByName(path_va: u64, wide: bool) ?VfsFound {
    const len = if (wide) userStrLenW(path_va) orelse return null else userStrLen(path_va) orelse return null;
    if (len == 0 or len > MAX_PATH_LEN - 2) return null;
    var raw: [MAX_PATH_LEN]u8 = undefined;
    if (wide) {
        // UTF-16LE → байты (BMP-символы >0x7F — честно «?»; пути у нас ASCII)
        var i: u64 = 0;
        while (i < len) : (i += 1) {
            const ch = userW(path_va + i * 2).*;
            raw[@intCast(i)] = if (ch < 128) @intCast(ch) else '?';
        }
    } else {
        @memcpy(raw[0..@intCast(len)], userPtr(path_va)[0..@intCast(len)]);
    }
    // Скретч нормализации — статическая страница модуля (один PE-процесс:
    // конкуренции за буфер нет; имя копируется в FileState до возврата).
    const norm_buf: *[MAX_PATH_LEN]u8 = &vfs_norm_scratch;
    const norm = vfsNormalizePath(raw[0..@intCast(len)], norm_buf) orelse return null;
    const size = ops.vfs_file_size(norm.ptr, norm.len);
    if (size == VFS_NOT_FOUND) return null;
    return .{ .norm = norm, .size = size };
}

/// Статический скретч нормализации (один PE-процесс — конкуренции нет).
var vfs_norm_scratch: [MAX_PATH_LEN]u8 = undefined;

/// CreateFileA/W (7 аргументов; диспозиция — arg5/стек[0], доступ — arg2).
/// v0.17.0 (CDD №8): ПОЛНЫЙ RW — диспозиции 1..5 по Win32-семантике:
///   CREATE_NEW(1)      — есть → ERROR_FILE_EXISTS; нет → создать (FAT32)
///   CREATE_ALWAYS(2)   — есть → усечь в 0; нет → создать
///   OPEN_EXISTING(3)   — нет → ERROR_FILE_NOT_FOUND
///   OPEN_ALWAYS(4)     — есть → открыть; нет → создать
///   TRUNCATE_EXISTING(5) — есть → усечь; нет → 2
/// GENERIC_WRITE → writable (WriteFile/fwrite/_write пишут на FAT32-диск;
/// initrd — RO: создание/запись → ACCESS_DENIED, как в v0.16).
fn createFileCommon(lp_file_name: u64, desired_access: u64, creation: u64, wide: bool) u64 {
    const want_write = (desired_access & GENERIC_WRITE) != 0;
    const found = vfsOpenByName(lp_file_name, wide);

    // ── Диспозиции создания/усечения ──
    if (creation == CREATE_NEW or creation == CREATE_ALWAYS or creation == TRUNCATE_EXISTING or creation == OPEN_ALWAYS) {
        if (found == null and (creation == CREATE_NEW or creation == CREATE_ALWAYS or creation == OPEN_ALWAYS)) {
            // Создать файл через бекенд (FAT32). Initrd/RO → 0 → ACCESS_DENIED.
            if (!createVfsFile(lp_file_name, wide)) {
                setLastError(ERROR_ACCESS_DENIED);
                logf("[WIN32] CreateFile{c}(?) -> INVALID (RO-VFS: создание запрещено)\n", .{if (wide) @as(u8, 'W') else @as(u8, 'A')});
                return INVALID_HANDLE_VALUE;
            }
        } else if (found == null) {
            // TRUNCATE_EXISTING без файла
            setLastError(ERROR_FILE_NOT_FOUND);
            logf("[WIN32] CreateFile{c}(?) -> INVALID (VFS: не найден, 2)\n", .{if (wide) @as(u8, 'W') else @as(u8, 'A')});
            return INVALID_HANDLE_VALUE;
        } else if (creation == CREATE_NEW) {
            setLastError(ERROR_FILE_EXISTS);
            logf("[WIN32] CreateFile{c}(\"{s}\") -> INVALID (уже есть, 80)\n", .{ if (wide) @as(u8, 'W') else @as(u8, 'A'), found.?.norm });
            return INVALID_HANDLE_VALUE;
        }
        if (creation == CREATE_ALWAYS or creation == TRUNCATE_EXISTING) {
            // Усечь до 0; отказ бекенда (initrd-RO) → честный ACCESS_DENIED —
            // как Windows на RO-носителе (граница v0.16 сохранена).
            if (found) |fex| {
                if (ops.vfs_file_truncate(fex.norm.ptr, fex.norm.len, 0) != 1) {
                    setLastError(ERROR_ACCESS_DENIED);
                    logf("[WIN32] CreateFile{c}(\"{s}\") -> INVALID (RO-файл: усечение запрещено)\n", .{ if (wide) @as(u8, 'W') else @as(u8, 'A'), fex.norm });
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    } else if (creation != OPEN_EXISTING) {
        // Неизвестная диспозиция — Win32 ERROR_INVALID_PARAMETER
        setLastError(87);
        return INVALID_HANDLE_VALUE;
    }

    // Перечитываем состояние ПОСЛЕ create/truncate (диспозиции меняют размер).
    const f = (if (creation != OPEN_EXISTING) vfsOpenByName(lp_file_name, wide) else found) orelse {
        setLastError(ERROR_FILE_NOT_FOUND);
        logf("[WIN32] CreateFile{c}(?) -> INVALID (VFS: не найден, 2)\n", .{if (wide) @as(u8, 'W') else @as(u8, 'A')});
        return INVALID_HANDLE_VALUE;
    };
    const size = f.size;

    const idx = fileSlotAlloc(f.norm, size) orelse {
        setLastError(ERROR_FILE_NOT_FOUND); // таблица полна — как «нет файла»
        return INVALID_HANDLE_VALUE;
    };
    // v0.17.0: флаг записи — НО initrd-файлы (create=0) остаются RO: запись
    // пойдёт через ops.vfs_file_write, который для initrd вернёт 0 → честный
    // частичный отказ (как Win32 на RO-носителе: WriteFile=FALSE, 5).
    const c = &(ctx orelse return INVALID_HANDLE_VALUE);
    c.files[idx].writable = want_write;
    if (want_write and creation == CREATE_ALWAYS) c.files[idx].pos = 0;
    setLastError(0);
    logf("[WIN32] CreateFile{c}(\"{s}\") -> 0x{x} (VFS, {d}Б, {s})\n", .{ if (wide) @as(u8, 'W') else @as(u8, 'A'), f.norm, FILE_HANDLE_BASE + idx, size, if (want_write) "RW" else "RO" });
    return FILE_HANDLE_BASE + idx;
}

/// Создание файла по user-пути (createFileCommon): true = создан/существует.
fn createVfsFile(lp_file_name: u64, wide: bool) bool {
    // Переиспользуем нормализатор: собрать путь заново (vfsOpenByName вернул
    // null — значит файла НЕТ; путь всё равно валиден для создания).
    const len = if (wide) userStrLenW(lp_file_name) orelse return false else userStrLen(lp_file_name) orelse return false;
    if (len == 0 or len > MAX_PATH_LEN - 2) return false;
    var raw: [MAX_PATH_LEN]u8 = undefined;
    if (wide) {
        var i: u64 = 0;
        while (i < len) : (i += 1) {
            const ch = userW(lp_file_name + i * 2).*;
            raw[@intCast(i)] = if (ch < 128) @intCast(ch) else '?';
        }
    } else {
        @memcpy(raw[0..@intCast(len)], userPtr(lp_file_name)[0..@intCast(len)]);
    }
    const norm_buf: *[MAX_PATH_LEN]u8 = &vfs_norm_scratch;
    const norm = vfsNormalizePath(raw[0..@intCast(len)], norm_buf) orelse return false;
    return ops.vfs_file_create(norm.ptr, norm.len) == 1;
}

/// ReadFile(h, buf, n, lpRead, lpOverlapped): Win64 a1..a4 + стек[0].
/// TRUE + *lpRead=байт; EOF → TRUE + 0. Консоль-псевдохэндлы: stdin=0Б.
fn readFileCommon(h: u64, buf: u64, n: u64, lp_read: u64, lp_overlapped: u64) u64 {
    if (lp_overlapped != 0) {
        setLastError(ERROR_INVALID_PARAMETER); // async-модель не поддержана
        return 0;
    }
    if (h == FAKE_STDIN) {
        if (lp_read != 0 and ops.validate_write(lp_read, 4)) userD(lp_read).* = 0;
        return 1; // TRUE: stdin пуст (EOF сразу)
    }
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    var got: u64 = 0;
    if (n > 0 and buf != 0) {
        if (!ops.validate_write(buf, n)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        const want = @min(n, f.size - f.pos);
        if (want > 0) {
            got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(buf), @intCast(want));
            f.pos += got;
        }
    }
    if (lp_read != 0 and ops.validate_write(lp_read, 4)) userD(lp_read).* = @truncate(got);
    if (f.pos >= f.size) f.eof = true;
    return 1; // TRUE
}

/// WriteFile(h, buf, n, lpWritten, lpOverlapped): Win64 a1..a4 + стек[0].
/// stdout/stderr → консоль ОС. v0.17.0 (CDD №8): файл, открытый с
/// GENERIC_WRITE → РЕАЛЬНАЯ запись в FAT32 через ops.vfs_file_write
/// (offset = позиция файла; pos+len > size → size расширяется).
fn writeFileCommon(h: u64, buf: u64, n: u64, lp_written: u64, lp_overlapped: u64) u64 {
    if (lp_overlapped != 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (h == FAKE_STDOUT or h == FAKE_STDERR) {
        if (n > 0) {
            if (!ops.validate_read(buf, n)) {
                setLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
            ops.write_console(userPtr(buf)[0..@intCast(n)]);
        }
        if (lp_written != 0 and ops.validate_write(lp_written, 4)) userD(lp_written).* = @truncate(n);
        return 1;
    }
    if (fileByHandle(h)) |f| {
        // v0.17.0 (CDD №8): RW-файл — писать на диск
        if (!f.writable) {
            setLastError(ERROR_ACCESS_DENIED); // RO (initrd или открыли без записи)
            logf("[WIN32] WriteFile(файл VFS RO) -> FALSE (5)\n", .{});
            return 0;
        }
        if (n == 0) {
            if (lp_written != 0 and ops.validate_write(lp_written, 4)) userD(lp_written).* = 0;
            return 1;
        }
        if (!ops.validate_read(buf, n)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // Позиция может быть за концом (SetFilePointer RW) — «дыра» нулями
        // покрывается FAT32-цепочкой (кластеры обнулены allocCluster'ом).
        const wrote = ops.vfs_file_write(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(buf), @intCast(n));
        if (wrote == 0) {
            setLastError(ERROR_ACCESS_DENIED); // initrd-RO / диск полный
            logf("[WIN32] WriteFile(\"{s}\") -> FALSE (бекенд RO/полон)\n", .{f.name[0..@min(f.name_len, 40)]});
            return 0;
        }
        f.pos += wrote;
        if (f.pos > f.size) f.size = f.pos; // расширение (SetEndOfFile-семантика)
        f.eof = false;
        if (lp_written != 0 and ops.validate_write(lp_written, 4)) userD(lp_written).* = @truncate(wrote);
        setLastError(0);
        logf("[WIN32] WriteFile(\"{s}\", {d}Б @+{d}) -> TRUE (FAT32)\n", .{ f.name[0..@min(f.name_len, 40)], wrote, f.pos - wrote });
        return 1;
    }
    setLastError(ERROR_INVALID_HANDLE_FILE);
    return 0;
}

/// v0.17.0 (CDD №8): SetEndOfFile(h) — усечь/расширить до ТЕКУЩЕЙ позиции.
/// TRUE/FALSE (Win32). Расширение — нулями (FAT32 setFileSize).
fn kSetEndOfFile(h: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    if (!f.writable) {
        setLastError(ERROR_ACCESS_DENIED);
        return 0;
    }
    if (ops.vfs_file_truncate(f.name[0..f.name_len].ptr, f.name_len, f.pos) == 1) {
        f.size = f.pos;
        if (f.pos > 0) f.eof = false;
        setLastError(0);
        logf("[WIN32] SetEndOfFile(\"{s}\") -> {d}Б\n", .{ f.name[0..@min(f.name_len, 40)], f.size });
        return 1;
    }
    setLastError(ERROR_ACCESS_DENIED);
    return 0;
}

/// v0.17.0 (CDD №8): FlushFileBuffers(h) — FAT32-записи синхронны (кластер
/// пишется сразу); честный TRUE. Файл-хэндл проверяем для валидности.
fn kFlushFileBuffers(h: u64) u64 {
    if (h == FAKE_STDOUT or h == FAKE_STDERR) return 1;
    if (fileByHandle(h) == null) {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    }
    return 1;
}

/// GetFileSize(h, lpHigh): младший 32-бит размера; старший — по указателю.
fn getFileSizeCommon(h: u64, lp_high: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0xFFFF_FFFF; // INVALID_FILE_SIZE
    };
    if (lp_high != 0 and ops.validate_write(lp_high, 4)) {
        userD(lp_high).* = @truncate(f.size >> 32);
    }
    return @truncate(f.size);
}

/// GetFileSizeEx(h, lpFileSize): u64-размер по указателю → TRUE.
fn getFileSizeExCommon(h: u64, lp_size: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    if (lp_size == 0 or !ops.validate_write(lp_size, 8)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    userQ(lp_size).* = f.size;
    return 1;
}

/// SetFilePointer(h, dist(±), lpHigh, method): навигация RO-VFS.
/// Возврат — младшие 32 позиции; не-файл → 0xFFFFFFFF + 6.
fn setFilePointerCommon(h: u64, dist: u64, lp_high: u64, method: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0xFFFF_FFFF;
    };
    var off: i64 = @bitCast(dist);
    if (lp_high != 0 and ops.validate_read(lp_high, 4)) {
        const hi: u32 = userD(lp_high).*;
        off = @bitCast(dist | (@as(u64, hi) << 32));
    }
    const base: i64 = switch (method) {
        FILE_BEGIN => 0,
        FILE_CURRENT => @bitCast(f.pos),
        FILE_END => @bitCast(f.size),
        else => {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0xFFFF_FFFF;
        },
    };
    var new_pos: i64 = base +% off;
    if (new_pos < 0) new_pos = 0; // отрицательная позиция — клэмп 0
    // v0.17.0 (CDD №8): RW-файл МОЖЕТ позиционироваться за концом (Windows:
    // SetFilePointer + запись → «дыра» нулями; SetEndOfFile — расширение).
    // RO-файл — клэмп в размер (как v0.16).
    if (!f.writable and new_pos > @as(i64, @bitCast(f.size))) new_pos = @bitCast(f.size);
    f.pos = @bitCast(new_pos);
    f.eof = false;
    setLastError(0);
    return @truncate(f.pos);
}

/// SetFilePointerEx(h, liDistance(±i64), lpNew, method) → TRUE.
fn setFilePointerExCommon(h: u64, dist: u64, lp_new: u64, method: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    const off: i64 = @bitCast(dist);
    const base: i64 = switch (method) {
        FILE_BEGIN => 0,
        FILE_CURRENT => @bitCast(f.pos),
        FILE_END => @bitCast(f.size),
        else => {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        },
    };
    var np: i64 = base +% off;
    if (np < 0) np = 0;
    // v0.17.0 (CDD №8): RW — за конец можно (дыры/расширение), RO — клэмп
    if (!f.writable and np > @as(i64, @bitCast(f.size))) np = @bitCast(f.size);
    f.pos = @bitCast(np);
    f.eof = false;
    setLastError(0);
    if (lp_new != 0 and ops.validate_write(lp_new, 8)) userQ(lp_new).* = f.pos;
    return 1;
}

/// GetFileAttributesA(name): файл VFS → FILE_ATTRIBUTE_NORMAL (0x80).
fn getFileAttributesCommonA(lp_file_name: u64) u64 {
    const found = vfsOpenByName(lp_file_name, false) orelse {
        setLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    };
    _ = found.size;
    logf("[WIN32] GetFileAttributesA(\"{s}\") -> 0x80 (NORMAL, VFS)\n", .{found.norm});
    return FILE_ATTRIBUTE_NORMAL;
}

/// GetFileType(h): std-псевдохэндлы → CHAR(консоль), файл VFS → DISK.
fn getFileTypeCommon(h: u64) u64 {
    if (h == FAKE_STDIN or h == FAKE_STDOUT or h == FAKE_STDERR) return FILE_TYPE_CHAR;
    if (fileByHandle(h) != null) return FILE_TYPE_DISK;
    return 0; // FILE_TYPE_UNKNOWN
}

// ─── v0.16.0 (CDD №7): CRT-stdio FILE* поверх VFS ─────────────────────

/// fopen/_fsopen(path, mode[, share]): mode «r*» → FILE* (блок 80Б с
/// заголовком-пропуском); «w*»/«a*» → NULL + errno EACCES (RO-VFS);
/// не найден → NULL + errno ENOENT.
fn kfopenCommon(path_va: u64, mode_va: u64, caller: []const u8) u64 {
    const c = &(ctx orelse return 0);
    var mode: u8 = '?';
    var mode2: u8 = 0; // второй символ («+», «b»)
    if (mode_va != 0 and ops.validate_read(mode_va, 2)) {
        mode = userPtr(mode_va)[0];
        mode2 = userPtr(mode_va)[1];
    }
    // v0.17.0 (CDD №8): режимы записи — «w»/«a» (+ «+»/«b»-суффиксы):
    //   w/w+  — создать/усечь (CREATE_ALWAYS-семантика)
    //   a/a+  — создать если нет, позиция = размер (append)
    //   r+    — открыть RW без усечения
    //   r/rb  — RO (как v0.16)
    const want_write = (mode == 'w' or mode == 'a' or (mode == 'r' and mode2 == '+'));
    var found = vfsOpenByName(path_va, false);

    if (want_write) {
        if (found == null) {
            // создать (FAT32; initrd → отказ EACCES)
            if (mode == 'r') { // «r+» без файла — EINVAL по CRT
                if (c.errno_ptr != 0 and ops.validate_write(c.errno_ptr, 4)) {
                    @as(*align(1) u32, @ptrFromInt(c.errno_ptr)).* = 2;
                }
                logf("[CRT] {s}(mode=\"r+\") -> NULL (файла нет, ENOENT)\n", .{caller});
                return 0;
            }
            if (!createVfsFile(path_va, false)) {
                if (c.errno_ptr != 0 and ops.validate_write(c.errno_ptr, 4)) {
                    @as(*align(1) u32, @ptrFromInt(c.errno_ptr)).* = 13; // EACCES
                }
                logf("[CRT] {s}(mode='{c}') -> NULL (RO-VFS: создание запрещено)\n", .{ caller, mode });
                return 0;
            }
            found = vfsOpenByName(path_va, false);
        } else if (mode == 'w') {
            // усечь; отказ бекенда (initrd-RO) → честный NULL + EACCES
            if (ops.vfs_file_truncate(found.?.norm.ptr, found.?.norm.len, 0) != 1) {
                if (c.errno_ptr != 0 and ops.validate_write(c.errno_ptr, 4)) {
                    @as(*align(1) u32, @ptrFromInt(c.errno_ptr)).* = 13; // EACCES
                }
                logf("[CRT] {s}(\"{s}\", mode='w') -> NULL (RO-файл: усечение запрещено)\n", .{ caller, found.?.norm });
                return 0;
            }
            found = vfsOpenByName(path_va, false); // перечитать (размер 0)
        }
    }

    const f = found orelse {
        if (c.errno_ptr != 0 and ops.validate_write(c.errno_ptr, 4)) {
            @as(*align(1) u32, @ptrFromInt(c.errno_ptr)).* = 2; // ENOENT
        }
        // Лог-контракт v0.11+ (тест _fsopen): имя даже при мусорном пути
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
        logf("[CRT] {s}(\"{s}\", mode='{c}') -> NULL (VFS: не найден, ENOENT)\n", .{ caller, name_buf[0..@intCast(name_len)], mode });
        return 0;
    };
    const idx = fileSlotAlloc(f.norm, f.size) orelse {
        if (c.errno_ptr != 0 and ops.validate_write(c.errno_ptr, 4)) {
            @as(*align(1) u32, @ptrFromInt(c.errno_ptr)).* = 24; // EMFILE
        }
        return 0;
    };
    // v0.17.0 (CDD №8): writable + append-позиция
    if (want_write) c.files[idx].writable = true;
    if (mode == 'a') c.files[idx].pos = f.size;
    const blk_va = kmalloc(CRT_FILE_SIZE);
    if (blk_va == 0) {
        c.files[idx].in_use = false;
        return 0;
    }
    @memset(userPtr(blk_va)[0..CRT_FILE_SIZE], 0);
    std.mem.writeInt(u32, userPtr(blk_va)[0..4], CRT_FILE_MAGIC, .little);
    std.mem.writeInt(u32, userPtr(blk_va)[4..8], @intCast(idx), .little);
    // Формат-контракт cdd7-теста: fopen("cacert.pem") -> FILE* 0x… (VFS, …Б)
    logf("[CRT] {s}(\"{s}\") -> FILE* 0x{x} (VFS, {d}Б, {s})\n", .{ caller, f.norm, blk_va, f.size, if (want_write) "RW" else "RO" });
    return blk_va;
}

/// fread(ptr, size, nmemb, stream): Win64 a1..a4. Полные элементы;
/// eof-флаг — при чтении ЗА концом (CRT-контракт).
fn kfread(ptr: u64, size: u64, nmemb: u64, stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return 0;
    const c = &(ctx orelse return 0);
    const f = &c.files[idx];
    if (size == 0 or nmemb == 0) return 0;
    if (size * nmemb > 16 * 1024 * 1024) return 0; // защитный лимит
    const total = size * nmemb;
    if (!ops.validate_write(ptr, total)) return 0;
    const want: u64 = @min(total, f.size - f.pos);
    var got: u64 = 0;
    if (want > 0) {
        got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(ptr), @intCast(want));
        f.pos += got;
    }
    if (got < total) f.eof = true; // меньше ЗАПРОШЕННОГО → след. чтение за концом
    return got / size; // полные элементы
}

/// fseek(stream, offset(±i32), whence) / _fseeki64(±i64): 0 = успех.
fn kfseekCommon(stream: u64, offset: u64, whence: u64) u64 {
    const idx = crtFileIdx(stream) orelse return @bitCast(@as(i64, -1));
    const c = &(ctx orelse return @bitCast(@as(i64, -1)));
    const f = &c.files[idx];
    const off: i64 = @bitCast(offset);
    const base: i64 = switch (whence) {
        0 => 0, // SEEK_SET
        1 => @bitCast(f.pos), // SEEK_CUR
        2 => @bitCast(f.size), // SEEK_END
        else => return @bitCast(@as(i64, -1)),
    };
    var np: i64 = base +% off;
    if (np < 0) np = 0;
    if (np > @as(i64, @bitCast(f.size))) np = @bitCast(f.size);
    f.pos = @bitCast(np);
    f.eof = false;
    return 0;
}

/// ftell(stream): текущая позиция (файлы VFS < 2^31 в нашей модели).
fn kftell(stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return @bitCast(@as(i64, -1));
    return ctx.?.files[idx].pos;
}

/// feof(stream): 1 только после чтения ЗА концом (EOF-флаг).
fn kfeof(stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return 0;
    return if (ctx.?.files[idx].eof) 1 else 0;
}

/// ferror(stream): RO-VFS читает без ошибок → 0.
fn kferror(stream: u64) u64 {
    _ = stream;
    return 0;
}

/// fclose(stream): слот + заголовок блока → 0 (контракт CRT).
fn kfclose(stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return 0; // чужой/NULL — уже «закрыт»
    const c = &(ctx orelse return 0);
    c.files[idx].in_use = false;
    if (ops.validate_write(stream, 8)) {
        @memset(userPtr(stream)[0..8], 0); // magic гасим — повторное закрытие безопасно
    }
    logf("[CRT] fclose(FILE* 0x{x}) -> 0\n", .{stream});
    return 0;
}

/// rewind(stream): позиция 0, EOF-флаг снят.
fn krewind(stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return 0;
    const f = &ctx.?.files[idx];
    f.pos = 0;
    f.eof = false;
    return 0;
}

/// fgets(buf, size, stream): до size-1Б, '\n' включительно, NUL-хвост.
fn kfgets(buf: u64, size: u64, stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return 0;
    const c = &(ctx orelse return 0);
    const f = &c.files[idx];
    if (size <= 1 or !ops.validate_write(buf, size)) return 0;
    const limit: u64 = size - 1;
    var out_i: u64 = 0;
    var chunk: [128]u8 = undefined;
    var done = false;
    while (out_i < limit and !done) {
        const want: usize = @intCast(@min(@as(u64, chunk.len), limit - out_i));
        const got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, &chunk, want);
        if (got == 0) break; // EOF
        // ищем '\n' в прочитанном
        var nl: ?usize = null;
        var j: usize = 0;
        while (j < got) : (j += 1) {
            if (chunk[j] == '\n') {
                nl = j;
                break;
            }
        }
        const take: usize = if (nl) |k| k + 1 else @intCast(got);
        @memcpy(userPtr(buf + out_i)[0..take], chunk[0..take]);
        out_i += take;
        f.pos += take;
        if (nl != null) done = true;
        if (got < want) break; // конец файла внутри чанка
    }
    if (out_i == 0) {
        f.eof = true;
        return 0; // NULL: ни одного байта
    }
    userPtr(buf)[@intCast(out_i)] = 0;
    if (f.pos >= f.size) f.eof = true;
    return buf;
}

/// getc(stream): 1 байт или -1 (EOF).
fn kgetc(stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return @bitCast(@as(i64, -1));
    const f = &ctx.?.files[idx];
    var b: [1]u8 = undefined;
    const got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, &b, 1);
    if (got == 0) {
        f.eof = true;
        return @bitCast(@as(i64, -1));
    }
    f.pos += 1;
    return b[0];
}

/// ungetc(c, stream): откат позиции на 1 (парсеры PEM читают «посмотрел — вернул»).
fn kungetc(ch: u64, stream: u64) u64 {
    const idx = crtFileIdx(stream) orelse return @bitCast(@as(i64, -1));
    const f = &ctx.?.files[idx];
    if (ch > 0xFF) return @bitCast(@as(i64, -1));
    if (f.pos == 0) return @bitCast(@as(i64, -1));
    f.pos -= 1;
    f.eof = false;
    return ch;
}

// ─── v0.16.0 (CDD №7): lowio (_read/_write/_close/_lseeki64/_sopen_s) ───

/// fd = 3 + индекс (0/1/2 заняты stdio). Слот FileState по fd lowio.
fn fileIdxByFd(fd: u64) ?usize {
    if (fd < 3 or fd >= 3 + MAX_FILES) return null;
    const idx: usize = @intCast(fd - 3);
    if (!ctx.?.files[idx].in_use) return null;
    return idx;
}

/// _read(fd, buf, count): байты или 0 (EOF); не-файловый fd → -1.
fn kread(fd: u64, buf: u64, count: u64) u64 {
    const idx = fileIdxByFd(fd) orelse return @bitCast(@as(i64, -1));
    const f = &ctx.?.files[idx];
    if (count == 0) return 0;
    if (!ops.validate_write(buf, count)) return @bitCast(@as(i64, -1));
    const want = @min(count, f.size - f.pos);
    var got: u64 = 0;
    if (want > 0) {
        got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(buf), @intCast(want));
        f.pos += got;
    }
    if (got < count) f.eof = true;
    return got;
}

/// _write(fd, buf, count): 1/2 → консоль; v0.17.0 (CDD №8): RW-файл →
/// запись в FAT32; RO → -1 (EACCES).
fn kwrite(fd: u64, buf: u64, count: u64) u64 {
    if (fd == 1 or fd == 2) {
        if (count > 0) {
            if (!ops.validate_read(buf, count)) return @bitCast(@as(i64, -1));
            ops.write_console(userPtr(buf)[0..@intCast(count)]);
        }
        return count;
    }
    const idx = fileIdxByFd(fd) orelse return @bitCast(@as(i64, -1));
    const f = &ctx.?.files[idx];
    if (!f.writable) return @bitCast(@as(i64, -1)); // fd 0 / RO-VFS
    if (count == 0) return 0;
    if (!ops.validate_read(buf, count)) return @bitCast(@as(i64, -1));
    const wrote = ops.vfs_file_write(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(buf), @intCast(count));
    if (wrote == 0) return @bitCast(@as(i64, -1));
    f.pos += wrote;
    if (f.pos > f.size) f.size = f.pos;
    return wrote;
}

/// _close(fd): слот освобождён → 0.
fn kclose(fd: u64) u64 {
    const idx = fileIdxByFd(fd) orelse return 0;
    ctx.?.files[idx].in_use = false;
    return 0;
}

/// _lseeki64(fd, offset(±i64), whence): новая позиция или -1.
fn klseeki64(fd: u64, offset: u64, whence: u64) u64 {
    const idx = fileIdxByFd(fd) orelse return @bitCast(@as(i64, -1));
    const f = &ctx.?.files[idx];
    const off: i64 = @bitCast(offset);
    const base: i64 = switch (whence) {
        0 => 0,
        1 => @bitCast(f.pos),
        2 => @bitCast(f.size),
        else => return @bitCast(@as(i64, -1)),
    };
    var np: i64 = base +% off;
    if (np < 0) np = 0;
    // v0.17.0 (CDD №8): RW — за конец можно; RO — клэмп
    if (!f.writable and np > @as(i64, @bitCast(f.size))) np = @bitCast(f.size);
    f.pos = @bitCast(np);
    f.eof = false;
    return f.pos;
}

/// _sopen_s(pfd, path, oflag, shflag, pmode): *pfd = 3+idx.
/// v0.17.0 (CDD №8): MSVC-флаги _O_WRONLY(1)/_O_RDWR(2)/_O_APPEND(8)/
/// _O_CREAT(0x100)/_O_TRUNC(0x200) → create/truncate/append (FAT32 RW).
fn ksopenS(fd_va: u64, path_va: u64, oflag: u64) u64 {
    if (fd_va == 0 or !ops.validate_write(fd_va, 4)) return 22; // EINVAL
    userD(fd_va).* = 0xFFFF_FFFF; // -1 по умолчанию
    const write_flag = oflag & 0x3; // _O_RDONLY=0, _O_WRONLY=1, _O_RDWR=2
    const O_CREAT: u64 = 0x100;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x8;
    var found = vfsOpenByName(path_va, false);
    if (write_flag != 0) {
        if (found == null and (oflag & O_CREAT) != 0) {
            if (!createVfsFile(path_va, false)) return 13; // EACCES (RO-бекенд)
            found = vfsOpenByName(path_va, false);
        }
        if (found == null) return 2; // ENOENT (без _O_CREAT)
        if ((oflag & O_TRUNC) != 0) {
            _ = ops.vfs_file_truncate(found.?.norm.ptr, found.?.norm.len, 0);
            found = vfsOpenByName(path_va, false);
        }
    }
    const f = found orelse return 2; // ENOENT
    const idx = fileSlotAlloc(f.norm, f.size) orelse return 24; // EMFILE
    if (write_flag != 0) ctx.?.files[idx].writable = true;
    if ((oflag & O_APPEND) != 0) ctx.?.files[idx].pos = f.size;
    userD(fd_va).* = @intCast(3 + idx);
    logf("[CRT] _sopen_s(\"{s}\", flags=0x{x}) -> fd={d} ({s})\n", .{ f.norm, oflag, 3 + idx, if (write_flag != 0) "RW" else "RO" });
    return 0;
}

/// _chsize_s(fd, size): v0.17.0 (CDD №8) — РЕАЛЬНОЕ усечение/расширение
/// (FAT32 setFileSize через vfs_file_truncate); RO → EACCES (13).
fn kchsizeS(fd: u64, size: u64) u64 {
    const idx = fileIdxByFd(fd) orelse return 9; // EBADF
    const f = &ctx.?.files[idx];
    if (!f.writable) return 13; // EACCES
    if (ops.vfs_file_truncate(f.name[0..f.name_len].ptr, f.name_len, size) == 1) {
        f.size = size;
        if (f.pos > size) f.pos = size;
        f.eof = false;
        return 0; // успех (контракт _chsize_s: 0 = OK)
    }
    return 13;
}

/// puts(s): строка + '\n' в консоль → неотрицательный код.
fn kputs(s_va: u64) u64 {
    const len = userStrLen(s_va) orelse return @bitCast(@as(i64, -1));
    if (len > 0) ops.write_console(userPtr(s_va)[0..@intCast(len)]);
    ops.write_console("\n");
    return 1;
}

/// putchar(c): байт в консоль → сам байт (контракт int).
fn kputchar(ch: u64) u64 {
    if (ch > 0xFF) return @bitCast(@as(i64, -1));
    var b: [1]u8 = .{@truncate(ch)};
    ops.write_console(&b);
    return ch;
}

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
    // v0.17.0 (CDD №8): FILE* может быть VFS-файлом (запись) — fwrite-путь;
    // stdout/stderr (iob или чужой указатель) — консоль (CDD-упрощение).
    if (crtFileIdx(stream)) |idx| {
        const c = &(ctx orelse return 0);
        const f = &c.files[idx];
        if (!f.writable) return 0;
        const len = userStrLen(str_va) orelse return 0;
        if (len == 0) return 1;
        if (!ops.validate_read(str_va, len)) return 0;
        const wrote = ops.vfs_file_write(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(str_va), @intCast(len));
        if (wrote == 0) return 0;
        f.pos += wrote;
        if (f.pos > f.size) f.size = f.pos;
        return 1;
    }
    const len = userStrLen(str_va) orelse return 0;
    if (len == 0) return 1;
    ops.write_console(userPtr(str_va)[0..@intCast(len)]);
    return 1;
}

/// fputc(c, stream): один символ; возврат записанного байта (int-контракт).
/// v0.17.0 (CDD №8): FILE* VFS → запись (если writable); иначе консоль.
fn fputc(c: u64, stream: u64) u64 {
    if (crtFileIdx(stream)) |idx| {
        const cc = &(ctx orelse return 0);
        const f = &cc.files[idx];
        if (!f.writable) return 0;
        const ch: [1]u8 = .{@truncate(c)};
        const wrote = ops.vfs_file_write(f.name[0..f.name_len].ptr, f.name_len, f.pos, &ch, 1);
        if (wrote == 0) return 0;
        f.pos += 1;
        if (f.pos > f.size) f.size = f.pos;
        return c & 0xFF;
    }
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
    // v0.17.0 (CDD №8): FILE* VFS с writable → РЕАЛЬНАЯ запись (FAT32) —
    // curl -o пишет тело ответа через fwrite/fflush;
    // FILE* RO (initrd) → 0 элементов (отказ записи);
    // stdout/stderr (iob-блоки без magic) — консольный путь (как v0.12).
    if (crtFileIdx(stream)) |idx| {
        const c = &(ctx orelse return 0);
        const f = &c.files[idx];
        if (!f.writable) return 0; // RO-VFS: CRT-контракт «0 элементов»
        if (size == 0 or nmemb == 0) return 0;
        const total = size * nmemb;
        if (total > 16 * 1024 * 1024) return 0; // защитный лимит
        if (!ops.validate_read(ptr, total)) return 0;
        const wrote = ops.vfs_file_write(f.name[0..f.name_len].ptr, f.name_len, f.pos, userPtr(ptr), @intCast(total));
        if (wrote < total) return 0; // частичная запись = ошибка
        f.pos += wrote;
        if (f.pos > f.size) f.size = f.pos;
        return nmemb; // CRT: успех → nmemb
    }
    // msvcrt-_iob FILE* (блок DATA-импортов): stdout/stderr → консоль,
    // stdin → 0. Блок 3×48Б после заголовка (main64.patchDataImports).
    if (isMsvcrtIobStream(stream)) |stream_idx| {
        if (stream_idx == 0) return 0; // stdin
        if (size == 0 or nmemb == 0) return 0;
        const total = size * nmemb;
        if (total > 16 * 1024 * 1024) return 0;
        if (!ops.validate_read(ptr, total)) return 0;
        ops.write_console(userPtr(ptr)[0..@intCast(total)]);
        return nmemb;
    }
    if (size == 0 or nmemb == 0) return 0;
    const total = size * nmemb;
    if (total > 16 * 1024 * 1024) return 0; // защитный лимит
    if (!ops.validate_read(ptr, total)) return 0; // поток ошибочен → 0
    ops.write_console(userPtr(ptr)[0..@intCast(total)]);
    return nmemb; // контракт CRT: успех → nmemb
}

/// v0.17.0 (CDD №8): FILE* из блока _iob (msvcrt DATA-импорт 7-Zip):
/// msvcrt-структура iobuf = 48Б; stdin/_iob[0], stdout/_iob[1], stderr/_iob[2].
/// Возврат: 0/1/2 (индекс потока) или null (не из блока).
fn isMsvcrtIobStream(stream: u64) ?usize {
    const c = &(ctx orelse return null);
    const blk = c.iob_block;
    if (blk == 0) return null;
    if (stream < blk + 0x100 or stream >= blk + 0x100 + 3 * 48) return null;
    if (!ops.validate_read(stream, 48)) return null;
    const idx: usize = @intCast((stream - (blk + 0x100)) / 48);
    if (idx > 2) return null;
    return idx;
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
const WSAEWOULDBLOCK: u32 = 10035; // v0.13.0 (CDD №4): неблокирующий recv
const WSAENOTCONN: u32 = 10057; // v0.13.0 (CDD №4): send/recv без connect
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

/// GetEnvironmentVariableA(name, buf, size): v0.16.0 (CDD №7) — env-таблица
/// процесса (ядро ставит CURL_CA_BUNDLE=cacert.pem и др.; тесты — свои).
/// Контракт Win32: найдено → len (без NUL) + копия; буфер мал → требуемый
/// размер (len+1) + ERROR_INSUFFICIENT_BUFFER; нет → 0 + 203.
fn getEnvironmentVariableA(name_va: u64, buf: u64, size: u64) u64 {
    const len = userStrLen(name_va) orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (len == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const name = userPtr(name_va)[0..@intCast(len)];
    if (envLookup(name)) |val| {
        if (size == 0 or val.len + 1 > size) {
            setLastError(ERROR_INSUFFICIENT_BUFFER);
            logf("[WIN32] GetEnvironmentVariableA(\"{s}\") -> нужно {d}Б (122)\n", .{ name, val.len + 1 });
            return val.len + 1;
        }
        if (!ops.validate_write(buf, val.len + 1)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        @memcpy(userPtr(buf)[0..val.len], val);
        userPtr(buf)[val.len] = 0;
        setLastError(0);
        logf("[WIN32] GetEnvironmentVariableA(\"{s}\") -> \"{s}\"\n", .{ name, val });
        return val.len;
    }
    logf("[WIN32] GetEnvironmentVariableA(\"{s}\") -> 0 (нет переменной)\n", .{name});
    setLastError(ERROR_ENVVAR_NOT_FOUND);
    return 0;
}

/// GetEnvironmentVariableW: env-таблица → UTF-16LE-значение.
fn getEnvironmentVariableW(name_va: u64, buf: u64, size: u64) u64 {
    const len = userStrLenW(name_va) orelse {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if (len == 0) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // имя UTF-16 → ASCII-байты для поиска (переменные окружения у нас ASCII)
    var name_buf: [64]u8 = undefined;
    const n: usize = @intCast(@min(len, 63));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        name_buf[i] = @truncate(userW(name_va + i * 2).*);
    }
    if (envLookup(name_buf[0..n])) |val| {
        if (size == 0 or val.len + 1 > size) {
            setLastError(ERROR_INSUFFICIENT_BUFFER);
            return val.len + 1;
        }
        if (!ops.validate_write(buf, (val.len + 1) * 2)) {
            setLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
        var j: usize = 0;
        while (j < val.len) : (j += 1) {
            userW(buf + j * 2).* = val[j];
        }
        userW(buf + val.len * 2).* = 0;
        setLastError(0);
        logf("[WIN32] GetEnvironmentVariableW(L\"{s}\") -> {d} wchars\n", .{ name_buf[0..n], val.len });
        return val.len;
    }
    logf("[WIN32] GetEnvironmentVariableW(L\"{s}\") -> 0 (нет переменной)\n", .{name_buf[0..n]});
    setLastError(ERROR_ENVVAR_NOT_FOUND);
    return 0;
}

/// getenv (CRT): env-таблица → стабильный heap-блок с NUL (контракт:
/// результат НЕ освобождается приложением; утечка в bump-heap — CDD-граница).
fn kgetenv(name_va: u64) u64 {
    const len = userStrLen(name_va) orelse return 0;
    if (len == 0) return 0;
    const name = userPtr(name_va)[0..@intCast(len)];
    const val = envLookup(name) orelse {
        logf("[CRT] getenv(\"{s}\") -> NULL (нет переменной)\n", .{name});
        return 0;
    };
    const p = kmalloc(val.len + 1);
    if (p == 0) return 0;
    @memcpy(userPtr(p)[0..val.len], val);
    userPtr(p)[val.len] = 0;
    logf("[CRT] getenv(\"{s}\") -> \"{s}\"\n", .{ name, val });
    return p;
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

// ─── v0.14.0 (CDD №5): SSPI/SChannel TLS Engine — SYNTHETIC-TLS ──────────────
//
// Разведка (живой прогон https://example.com на v0.13.0 + дизасм-анализ):
//   1. curl до SSPI-таблицы не доходит: Wave-A-препятствия — CreateMutexA
//      (NULL → WaitForSingleObject(0)-retry-loop), bcrypt!BCryptGenRandom
//      (trap: буфер с мусором), strnlen/inet_pton.
//   2. curl вызывает SSPI-функции ЧЕРЕЗ ТАБЛИЦУ lld-трамплином «jmp rax»
//      (глобал-указатель + call [глобал]) — оффсеты полей читаются из
//      фактического дизасма curl.exe (см. scripts/sspi-offsets*.py).
//
// Дизайн (МОМЕНТ ИСТИНЫ №5 — HTTPS-обмен в Ring 3):
//   AcquireCredentialsHandle → ISC-1 (генерация НАСТОЯЩЕГО TLS ClientHello:
//   record 0x16/0x0301 + handshake 0x01 + random 32Б + cipher suites +
//   extensions SNI/ALPN) → send → recv (синтет. ServerHello+CCS+Finished) →
//   ISC-2 (парсинг ServerHello, established) → EncryptMessage (обёртка
//   в record 0x17 + XOR-key) → send → recv → DecryptMessage (XOR-обратно) →
//   «Hello POLER!» в консоли. Сокет с peer_port==443 переключается в
//   TLS-машину автоматически.

const SEC_I_CONTINUE_NEEDED: u64 = 0x0009_0312; // первый вызов ISC
const SECBUFFER_EMPTY: u32 = 0;
const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_EXTRA: u32 = 5;
const SECBUFFER_STREAM_TRAILER: u32 = 6;
const SECBUFFER_STREAM_HEADER: u32 = 7;
const SECBUFFER_VERSION: u32 = 0;
const SECPKG_ATTR_STREAM_SIZES: u64 = 4; // SecPkgContext_Sizes

/// Название «пакета» SChannel, которое просит curl (UNISP_NAME).
const UNISP_NAME = "Microsoft Unified Security Protocol Provider";

/// SecHandle (Cred/Ctxt): dwLower = слот+1 (1..MAX_TLS), dwUpper = magic.
/// Чтение/запись хэндла в user-памяти: 16Б, {u64, u64}.
fn tlsSessionByHandle(h_va: u64) ?*TlsSession {
    if (h_va == 0 or !ops.validate_read(h_va, 16)) return null;
    const dw_lower = userQ(h_va).*;
    const dw_upper = userQ(h_va + 8).*;
    if (dw_upper != TLS_MAGIC or dw_lower == 0 or dw_lower > MAX_TLS) return null;
    const s = &(ctx orelse return null).tls_sessions[@as(usize, @intCast(dw_lower - 1))];
    if (!s.in_use) return null;
    return s;
}

/// Записать хэндл сессии (16Б) в user-структуру.
fn tlsWriteHandle(h_va: u64, idx: usize) bool {
    if (h_va == 0 or !ops.validate_write(h_va, 16)) return false;
    userQ(h_va).* = idx + 1;
    userQ(h_va + 8).* = TLS_MAGIC;
    return true;
}

/// КЭШЭРОВАННЫЙ лог о непонятных хэндлах: найти свободный слот.
fn tlsAllocSession() ?usize {
    const c = &(ctx orelse return null);
    for (&c.tls_sessions, 0..) |*s, i| {
        if (!s.in_use) {
            s.* = .{};
            s.in_use = true;
            return i;
        }
    }
    return null;
}

/// Псевдо-энтропия (SYNTHETIC): TSC-микс + LCG — для client_random и
/// BCryptGenRandom. НЕ криптостойко — задокументировано в UNISP-логе.
fn tlsEntropy(buf: []u8, seed: u64) void {
    var st: u64 = if (seed != 0) seed else ops.read_tsc() ^ 0xA5A5_5A5A_A5A5_5A5A;
    for (buf) |*b| {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17; // xorshift64
        b.* = @truncate(st >> 32);
    }
}

/// Сессионный ключ: f(client_random, server_random, magic) — XOR-маска.
fn tlsDeriveKey(s: *TlsSession) void {
    const label = "POLER-SYNTHETIC-SCHANNEL";
    for (&s.key, 0..) |*k, i| {
        k.* = s.client_random[i % 32] ^ s.server_random[(i + 7) % 32] ^
            label[i % label.len] ^ @as(u8, @truncate(i *% 31));
    }
}

/// XOR-поток по ключу с индексом от номера записи.
fn tlsCrypt(s: *const TlsSession, data: []u8, seq: u64) void {
    for (data, 0..) |*b, i| {
        const k = (seq *% 37 + i) % 32;
        b.* ^= s.key[@intCast(k)];
    }
}

// ── ClientHello (генерация, ISC-1) ──────────────────────────────────────────

/// Сборка НАСТОЯЩЕГО TLS 1.2 ClientHello (RFC 5246 §7.4.1.2) в буфер out.
/// Record: 0x16 03 01 len16; Handshake: 01 len24 {03 03, random32,
/// session_id_len 0, cipher_suites {1301,1302,1303}, comp {00},
/// extensions {SNI(server), supported_versions(TLS1.3), ALPN(h2,http/1.1)}}.
/// Возврат — размер записанных байт (0 = буфер мал).
pub fn tlsBuildClientHello(s: *TlsSession, out: []u8) usize {
    if (out.len < 160) return 0;
    // Handshake body
    var p: usize = 0;
    out[p] = 0x03;
    out[p + 1] = 0x03; // client_version TLS 1.2
    p += 2;
    @memcpy(out[p .. p + 32], &s.client_random);
    p += 32;
    out[p] = 0; // session_id_len
    p += 1;
    // cipher_suites: 3 × u16 BE
    out[p] = 0;
    out[p + 1] = 6; // len
    p += 2;
    inline for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |cs| {
        out[p] = @intCast(cs >> 8);
        out[p + 1] = @intCast(cs & 0xFF);
        p += 2;
    }
    out[p] = 1; // compression_methods_len
    out[p + 1] = 0; // null
    p += 2;
    // extensions: SNI + supported_versions + ALPN
    var ext: [96]u8 = undefined;
    var q: usize = 0;
    // SNI (0x0000): server_name_list{len16, type 0, len16, name}
    {
        const name_len: u16 = @intCast(s.sni_len);
        const list_len: u16 = 3 + name_len;
        const ext_len: u16 = 2 + list_len;
        ext[q] = 0x00;
        ext[q + 1] = 0x00; // type SNI
        ext[q + 2] = @intCast(ext_len >> 8);
        ext[q + 3] = @intCast(ext_len & 0xFF);
        ext[q + 4] = @intCast(list_len >> 8);
        ext[q + 5] = @intCast(list_len & 0xFF);
        ext[q + 6] = 0x00; // host_name
        ext[q + 7] = @intCast(name_len >> 8);
        ext[q + 8] = @intCast(name_len & 0xFF);
        q += 9;
        @memcpy(ext[q .. q + s.sni_len], s.sni[0..s.sni_len]);
        q += s.sni_len;
    }
    // supported_versions (0x002B): TLS 1.3 (0x0304)
    {
        ext[q] = 0x00;
        ext[q + 1] = 0x2B;
        ext[q + 2] = 0x00;
        ext[q + 3] = 0x03; // ext len 3
        ext[q + 4] = 0x02; // list len
        ext[q + 5] = 0x03;
        ext[q + 6] = 0x04;
        q += 7;
    }
    // ALPN (0x0010): h2, http/1.1
    {
        const protos = [_][]const u8{ "h2", "http/1.1" };
        var body: [32]u8 = undefined;
        var b: usize = 0;
        for (protos) |pr| {
            body[b] = @intCast(pr.len);
            b += 1;
            @memcpy(body[b .. b + pr.len], pr);
            b += pr.len;
        }
        ext[q] = 0x00;
        ext[q + 1] = 0x10;
        ext[q + 2] = 0x00;
        ext[q + 3] = @intCast(b + 2);
        ext[q + 4] = 0x00;
        ext[q + 5] = @intCast(b); // list len
        q += 6;
        @memcpy(ext[q .. q + b], body[0..b]);
        q += b;
    }
    // extensions_len (u16 BE)
    out[p] = @intCast(q >> 8);
    out[p + 1] = @intCast(q & 0xFF);
    p += 2;
    @memcpy(out[p .. p + q], ext[0..q]);
    p += q;

    // Handshake header: 0x01 + len24
    const hs_len = p;
    var hdr: [4]u8 = .{ 0x01, 0, 0, 0 };
    hdr[1] = @intCast(hs_len >> 16);
    hdr[2] = @intCast((hs_len >> 8) & 0xFF);
    hdr[3] = @intCast(hs_len & 0xFF);
    // Record header: 0x16 03 01 len16 (= 4 + hs_len)
    var rec: [5]u8 = .{ 0x16, 0x03, 0x03, 0, 0 };
    const rec_len = hs_len + 4;
    rec[3] = @intCast(rec_len >> 8);
    rec[4] = @intCast(rec_len & 0xFF);
    // сдвиг тела на 9 байт (record 5 + handshake 4)
    std.mem.copyBackwards(u8, out[9 .. 9 + p], out[0..p]);
    @memcpy(out[0..5], &rec);
    @memcpy(out[5..9], &hdr);
    return 9 + p;
}

// ── ServerHello (парсинг ISC-2 + синтез recv-потока) ────────────────────────

/// Парсинг ServerHello-потока (наш синтетический сервер шлёт SH+CCS+Fin):
/// проверяем record 0x16, handshake 0x02, забираем server_random.
pub fn tlsParseServerHello(s: *TlsSession, in: []const u8) bool {
    if (in.len < 47) return false; // 5+4+2+32+1+2+2+... минимум
    if (in[0] != 0x16 or in[1] != 0x03) return false; // record handshake
    if (in[5] != 0x02) return false; // handshake ServerHello
    @memcpy(&s.server_random, in[11..43]); // 5+4+2 = смещение random
    const sid_len = in[43];
    var p: usize = 44 + sid_len;
    if (p + 3 > in.len) return false;
    const cipher: u16 = (@as(u16, in[p]) << 8) | in[p + 1];
    p += 2;
    if (in[p] != 0) return false; // compression null
    _ = cipher;
    return true;
}

/// Синтез серверного потока после ClientHello (recv, stage 2):
/// ServerHello (random+cipher 1301) + ChangeCipherSpec + Finished(synth).
pub fn tlsBuildServerStream(s: *TlsSession, out: []u8) usize {
    if (out.len < 128) return 0;
    // ServerHello body: version, random32, sid_len=0, cipher 1301, comp 0
    var p: usize = 0;
    var body: [40]u8 = undefined;
    body[0] = 0x03;
    body[1] = 0x03;
    @memcpy(body[2..34], &s.server_random);
    body[34] = 0; // session_id_len
    body[35] = 0x13;
    body[36] = 0x01; // cipher TLS_AES_128_GCM_SHA256
    body[37] = 0x00; // compression
    p = 38;
    // Record 0x16 + Handshake 0x02
    const hs_body_len = p;
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = @intCast((hs_body_len + 4) >> 8);
    out[4] = @intCast((hs_body_len + 4) & 0xFF);
    out[5] = 0x02; // handshake type
    out[6] = 0;
    out[7] = @intCast(hs_body_len >> 8);
    out[8] = @intCast(hs_body_len & 0xFF);
    @memcpy(out[9 .. 9 + p], body[0..p]);
    var n = 9 + p;
    // ChangeCipherSpec: 14 03 03 00 01 01
    const ccs = [6]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    @memcpy(out[n .. n + ccs.len], &ccs);
    n += ccs.len;
    // Finished (SYNTHETIC): record 0x16, handshake 0x14, 32Б «подписи»
    out[n] = 0x16;
    out[n + 1] = 0x03;
    out[n + 2] = 0x03;
    out[n + 3] = 0x00;
    out[n + 4] = 0x24; // 36 = 4 + 32
    out[n + 5] = 0x14; // handshake Finished
    out[n + 6] = 0;
    out[n + 7] = 0;
    out[n + 8] = 32;
    tlsEntropy(out[n + 9 .. n + 41], 0x5151_5151); // «HMAC»
    n += 41;
    return n;
}

/// Синтез TLS application-data записи (recv, stage 3): record 0x17 +
/// XOR-«зашифрованный» plaintext + MAC 16Б. size = 5 + len + 16.
pub fn tlsBuildAppRecord(s: *TlsSession, plaintext: []const u8, seq: u64, out: []u8) usize {
    if (out.len < 5 + plaintext.len + 16) return 0;
    out[0] = 0x17;
    out[1] = 0x03;
    out[2] = 0x03;
    const plen: u16 = @intCast(plaintext.len + 16); // ciphertext + MAC
    out[3] = @intCast(plen >> 8);
    out[4] = @intCast(plen & 0xFF);
    @memcpy(out[5 .. 5 + plaintext.len], plaintext);
    tlsCrypt(s, out[5 .. 5 + plaintext.len], seq);
    tlsEntropy(out[5 + plaintext.len .. 5 + plaintext.len + 16], seq); // MAC
    return 5 + plaintext.len + 16;
}

// ── SSPI-функции (SecurityFunctionTable-волна CDD №5) ──────────────────────

/// QuerySecurityPackageInfoA/W(pszPackageName, ppPackageInfo): SecPkgInfo в
/// block-heap (cbMaxToken 16384, флаги SECPKG_FLAG_CONNECTION|INTEGRITY).
/// FreeContextBuffer уже SEC_E_OK (block-heap без reuse).
fn sspiQuerySecurityPackageInfo(pkg_va: u64, pp_va: u64) u64 {
    if (pp_va == 0 or !ops.validate_write(pp_va, 8)) {
        return SEC_E_INVALID_HANDLE;
    }
    var pkg_name: []const u8 = "(null)";
    if (pkg_va != 0) {
        if (userStrLen(pkg_va)) |len| {
            if (len > 0 and len < 128) pkg_name = userPtr(pkg_va)[0..@intCast(len)];
        }
    }
    const name = kmalloc(UNISP_NAME.len + 1);
    const cmt = kmalloc(32);
    const info = kmalloc(32); // SecPkgInfoW: 4+2+2+4+pad+8+8 = 32
    if (name == 0 or cmt == 0 or info == 0) return SEC_E_INSUFFICIENT_MEMORY;
    @memcpy(userPtr(name)[0..UNISP_NAME.len], UNISP_NAME);
    userPtr(name)[UNISP_NAME.len] = 0;
    @memcpy(userPtr(cmt)[0..24], "POLER SYNTHETIC SChannel");
    userPtr(cmt)[24] = 0;
    @memset(userPtr(info)[0..32], 0);
    userD(info + 0).* = 0x0000_0113; // fCapabilities: CONNECTION|INTEGRITY|PRIVACY|STREAM|MUTUAL_AUTH
    userW(info + 4).* = 2; // wVersion
    userW(info + 6).* = 14; // wRPCID (UNISP)
    userD(info + 8).* = 16384; // cbMaxToken
    userQ(info + 16).* = name; // Name (A: char* — curl читает как ANSI)
    userQ(info + 24).* = cmt; // Comment
    userQ(pp_va).* = info;
    logf("[SSPI] QuerySecurityPackageInfo(\"{s}\") -> UNISP, cbMaxToken=16384\n", .{pkg_name});
    return SEC_E_OK;
}

/// AcquireCredentialsHandleA/W (9 аргументов, 5-9 через стек):
/// RCX=principal, RDX=package, R8=fCredentialUse, R9=pvLogonId,
/// стек[0]=pAuthData, [1]=pGetKeyFn, [2]=pvGetKeyArg, [3]=phCredential,
/// [4]=ptsExpiry. Выделяем cred-хэндл (dwLower=0xC100+n, dwUpper=magic)
/// — сессия создаётся позже в InitializeSecurityContext.
fn sspiAcquireCredentialsHandle(pkg_va: u64, ph_cred: u64, pts_expiry: u64) u64 {
    var pkg_name: []const u8 = "(null)";
    if (pkg_va != 0) {
        if (userStrLen(pkg_va)) |len| {
            if (len > 0 and len < 128) pkg_name = userPtr(pkg_va)[0..@intCast(len)];
        }
    }
    const c = &(ctx orelse return SEC_E_INVALID_HANDLE);
    if (ph_cred == 0 or !ops.validate_write(ph_cred, 16)) {
        return SEC_E_INVALID_HANDLE;
    }
    c.next_mutex_handle += 0; // keep struct usage (кред-счётчик в dwLower)
    const cred_id = c.implemented_calls +% 1; // уникальный номер cred
    userQ(ph_cred).* = 0xC100 + cred_id; // dwLower: cred-пул 0xC100+
    userQ(ph_cred + 8).* = TLS_MAGIC; // dwUpper
    if (pts_expiry != 0 and ops.validate_write(pts_expiry, 8)) {
        userQ(pts_expiry).* = 0x0000_01FF_FFFF_FFFF; // far future
    }
    logf("[SSPI] AcquireCredentialsHandle(pkg=\"{s}\") -> cred 0x{x}\n", .{ pkg_name, userQ(ph_cred).* });
    return SEC_E_OK;
}

/// InitializeSecurityContextA/W (10 аргументов): RCX=phCredential,
/// RDX=phContext (NULL/нуль-структура = первый вызов), R8=pszTargetName
/// (SNI!), R9=fContextReq, стек[2]=pInput, стек[3]=Reserved2,
/// стек[4]=phNewContext, стек[5]=pOutput.
fn sspiInitializeSecurityContext(ph_cred: u64, ph_context: u64, target_va: u64, p_input: u64, ph_new: u64, p_output: u64) u64 {
    _ = ph_cred; // cred-хэндл валидирован в AcquireCredentialsHandle
    // Определить: первый вызов или продолжение
    var existing: ?*TlsSession = null;
    if (ph_context != 0 and ops.validate_read(ph_context, 16)) {
        if (userQ(ph_context + 8).* == TLS_MAGIC and userQ(ph_context).* >= 1) {
            existing = tlsSessionByHandle(ph_context);
        }
    }
    if (existing != null) {
        // ── Второй вызов: вход = ServerHello-поток → established ──
        const s = existing.?;
        if (p_input != 0 and ops.validate_read(p_input, 16)) {
            const c_buffers = userD(p_input + 4).*;
            const p_buffers = userQ(p_input + 8).*;
            var i: u32 = 0;
            while (i < c_buffers and i < 8) : (i += 1) {
                const sb_va = p_buffers + @as(u64, i) * 16;
                if (!ops.validate_read(sb_va, 16)) continue;
                const cb = userD(sb_va).*;
                const btype = userD(sb_va + 4).*;
                const pv = userQ(sb_va + 8).*;
                if ((btype == SECBUFFER_TOKEN or btype == SECBUFFER_DATA) and cb > 0 and pv != 0) {
                    if (ops.validate_read(pv, cb)) {
                        if (tlsParseServerHello(s, userPtr(pv)[0..@intCast(@min(cb, 256))])) {
                            tlsDeriveKey(s);
                            s.established = true;
                            // связать с последним TLS-активным сокетом
                            const c = &(ctx orelse return SEC_E_OK);
                            if (c.tls_last_fd != 0) s.fd = c.tls_last_fd;
                            if (sockByFd(s.fd)) |sk| {
                                if (sk.tls_stage == 2) sk.tls_stage = 3;
                            }
                            logf("[SSPI] InitializeSecurityContext: ServerHello принят ({d}Б) — established, SNI \"{s}\"\n", .{
                                cb, s.sni[0..@intCast(s.sni_len)],
                            });
                            return SEC_E_OK;
                        }
                    }
                }
            }
        }
        logf("[SSPI] InitializeSecurityContext: ServerHello НЕ распознан -> SEC_E_INVALID_TOKEN\n", .{});
        return SEC_E_INVALID_TOKEN;
    }

    // ── Первый вызов: создать сессию + ClientHello в pOutput ──
    const idx = tlsAllocSession() orelse {
        logf("[SSPI] InitializeSecurityContext: нет свободных слотов TLS\n", .{});
        return SEC_E_INSUFFICIENT_MEMORY;
    };
    const s = &(ctx orelse return SEC_E_INVALID_HANDLE).tls_sessions[idx];
    // SNI = pszTargetName (имя хоста)
    if (target_va != 0) {
        if (userStrLen(target_va)) |len| {
            const n = @min(len, 63);
            if (n > 0 and ops.validate_read(target_va, n)) {
                @memcpy(s.sni[0..@intCast(n)], userPtr(target_va)[0..@intCast(n)]);
                s.sni_len = @intCast(n);
            }
        }
    }
    tlsEntropy(&s.client_random, 0); // TSC-энтропия
    tlsEntropy(&s.server_random, 0x5E5E_5E5E);
    tlsDeriveKey(s);

    // out-буферы: pOutput → SecBufferDesc {version, count, pBuffers*}
    var hello: [256]u8 = undefined;
    const hello_len = tlsBuildClientHello(s, &hello);
    if (hello_len == 0) return SEC_E_INTERNAL_ERROR;
    var written: usize = 0;
    if (p_output != 0 and ops.validate_read(p_output, 16)) {
        const c_buffers = userD(p_output + 4).*;
        const p_buffers = userQ(p_output + 8).*;
        var i: u32 = 0;
        while (i < c_buffers and i < 8) : (i += 1) {
            const sb_va = p_buffers + @as(u64, i) * 16;
            if (!ops.validate_read(sb_va, 16)) continue;
            const cb = userD(sb_va).*;
            const btype = userD(sb_va + 4).*;
            const pv = userQ(sb_va + 8).*;
            if ((btype == SECBUFFER_TOKEN or btype == SECBUFFER_DATA) and pv != 0 and cb >= hello_len) {
                if (ops.validate_write(pv, hello_len)) {
                    @memcpy(userPtr(pv)[0..hello_len], hello[0..hello_len]);
                    // cbBuffer-поле выходного буфера: фактическая длина
                    if (ops.validate_write(sb_va, 16)) userD(sb_va).* = @intCast(hello_len);
                    written = hello_len;
                    break;
                }
            }
        }
    }
    // phNewContext: хэндл новой сессии
    _ = tlsWriteHandle(ph_new, idx);
    logf("[SSPI] InitializeSecurityContext: ClientHello {d}Б (SNI \"{s}\") -> SEC_I_CONTINUE_NEEDED\n", .{
        hello_len, s.sni[0..@intCast(s.sni_len)],
    });
    if (written == 0) {
        // буферов не было — просто сообщим продолжение (ClientHello в логе)
    }
    return SEC_I_CONTINUE_NEEDED;
}

/// EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo):
/// SECBUFFER_STREAM_HEADER ← record header (5Б), SECBUFFER_DATA ←
/// XOR-«шифрование» in-place, SECBUFFER_STREAM_TRAILER ← MAC 16Б.
fn sspiEncryptMessage(ph_context: u64, p_message: u64) u64 {
    const s = tlsSessionByHandle(ph_context) orelse {
        logf("[SSPI] EncryptMessage: невалидный контекст\n", .{});
        return SEC_E_INVALID_HANDLE;
    };
    if (!s.established) {
        logf("[SSPI] EncryptMessage: handshake не завершён\n", .{});
        return SEC_E_CONTEXT_EXPIRED;
    }
    if (p_message == 0 or !ops.validate_read(p_message, 16)) {
        return SEC_E_INVALID_HANDLE;
    }
    const c_buffers = userD(p_message + 4).*;
    const p_buffers = userQ(p_message + 8).*;
    var data_va: u64 = 0;
    var data_len: u64 = 0;
    var hdr_va: u64 = 0;
    var trailer_va: u64 = 0;
    var i: u32 = 0;
    while (i < c_buffers and i < 8) : (i += 1) {
        const sb_va = p_buffers + @as(u64, i) * 16;
        if (!ops.validate_read(sb_va, 16)) continue;
        const btype = userD(sb_va + 4).*;
        const pv = userQ(sb_va + 8).*;
        switch (btype) {
            SECBUFFER_STREAM_HEADER => hdr_va = pv,
            SECBUFFER_DATA => {
                data_va = pv;
                data_len = userD(sb_va).*;
            },
            SECBUFFER_STREAM_TRAILER => trailer_va = pv,
            else => {},
        }
    }
    if (data_va == 0 or data_len == 0 or !ops.validate_read(data_va, data_len)) {
        return SEC_E_INVALID_TOKEN;
    }
    // первый вызов: лог plaintext (МОМЕНТ ИСТИНЫ №5 — исходящий HTTPS-запрос)
    if (!s.first_data_logged) {
        s.first_data_logged = true;
        var esc: [96]u8 = undefined;
        var n: usize = 0;
        const cap: u64 = @min(data_len, 64);
        var j: u64 = 0;
        while (j < cap and n + 2 < esc.len) : (j += 1) {
            const ch = userPtr(data_va)[@as(usize, @intCast(j))];
            if (ch == '\r') {
                esc[n] = '\\';
                esc[n + 1] = 'r';
                n += 2;
            } else if (ch == '\n') {
                esc[n] = '\\';
                esc[n + 1] = 'n';
                n += 2;
            } else {
                esc[n] = if (ch >= 0x20 and ch < 0x7F) ch else '.';
                n += 1;
            }
        }
        logf("[TLS-SEND] {d}Б plaintext: \"{s}\"\n", .{ data_len, esc[0..n] });
    }
    // «шифрование» DATA in-place
    tlsCrypt(s, userPtr(data_va)[0..@intCast(data_len)], s.send_seq);
    // STREAM_HEADER: record 0x17 03 03 len16 (data+MAC)
    if (hdr_va != 0 and ops.validate_write(hdr_va, 5)) {
        userPtr(hdr_va)[0] = 0x17;
        userPtr(hdr_va)[1] = 0x03;
        userPtr(hdr_va)[2] = 0x03;
        const plen: u16 = @intCast(data_len + 16);
        userPtr(hdr_va)[3] = @intCast(plen >> 8);
        userPtr(hdr_va)[4] = @intCast(plen & 0xFF);
    }
    // STREAM_TRAILER: MAC 16Б
    if (trailer_va != 0 and ops.validate_write(trailer_va, 16)) {
        tlsEntropy(userPtr(trailer_va)[0..16], s.send_seq ^ 0xABCD);
    }
    s.send_seq += 1;
    logf("[SSPI] EncryptMessage: {d}Б DATA (record 0x17, seq={d})\n", .{ data_len, s.send_seq - 1 });
    return SEC_E_OK;
}

/// DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP):
/// DATA-буфер содержит поток record 0x17 (header 5Б + ciphertext + MAC) —
/// расшифровка XOR in-place, cbBuffer ← plaintext-длина, EXTRA ← 0.
fn sspiDecryptMessage(ph_context: u64, p_message: u64) u64 {
    const s = tlsSessionByHandle(ph_context) orelse {
        logf("[SSPI] DecryptMessage: невалидный контекст\n", .{});
        return SEC_E_INVALID_HANDLE;
    };
    if (p_message == 0 or !ops.validate_read(p_message, 16)) {
        return SEC_E_INVALID_HANDLE;
    }
    const c_buffers = userD(p_message + 4).*;
    const p_buffers = userQ(p_message + 8).*;
    var i: u32 = 0;
    while (i < c_buffers and i < 8) : (i += 1) {
        const sb_va = p_buffers + @as(u64, i) * 16;
        if (!ops.validate_read(sb_va, 16)) continue;
        const cb = userD(sb_va).*;
        const btype = userD(sb_va + 4).*;
        const pv = userQ(sb_va + 8).*;
        if (btype != SECBUFFER_DATA or cb < 21 or pv == 0) continue;
        if (!ops.validate_read(pv, @min(cb, 16384))) continue;
        const stream = userPtr(pv)[0..@intCast(@min(cb, 16384))];
        if (stream[0] != 0x17) continue; // application_data
        const plen = (@as(u16, stream[3]) << 8) | stream[4];
        if (5 + @as(u32, plen) > stream.len or plen < 16) continue;
        const plain_len: u32 = plen - 16;
        // расшифровка in-place, plaintext остаётся в pv+5
        tlsCrypt(s, stream[5 .. 5 + plain_len], s.recv_seq);
        s.recv_seq += 1;
        // сдвиг plaintext к началу буфера? НЕТ: SChannel оставляет данные
        // в том же буфере, cbBuffer = plaintext_len, pvBuffer НЕ двигаем
        // (curl читает pvBuffer[0..cbBuffer]); header/trailer остаются в
        // потоке — curl обрезает по cbBuffer.
        if (ops.validate_write(sb_va, 16)) {
            userD(sb_va).* = plain_len; // cbBuffer
            // pvBuffer: указывает на расшифрованные данные (pv+5)
            userQ(sb_va + 8).* = pv + 5;
        }
        // EXTRA-буфер (если есть): 0 непотреблённых байт
        var j: u32 = 0;
        while (j < c_buffers and j < 8) : (j += 1) {
            const eb_va = p_buffers + @as(u64, j) * 16;
            if (!ops.validate_read(eb_va, 16)) continue;
            if (userD(eb_va + 4).* == SECBUFFER_EXTRA and ops.validate_write(eb_va, 16)) {
                userD(eb_va).* = 0;
            }
        }
        logf("[SSPI] DecryptMessage: {d}Б plaintext (seq={d})\n", .{ plain_len, s.recv_seq - 1 });
        return SEC_E_OK;
    }
    logf("[SSPI] DecryptMessage: SECBUFFER_DATA с записью 0x17 не найден\n", .{});
    return SEC_E_INCOMPLETE_MESSAGE;
}

/// QueryContextAttributesA/W(phContext, ulAttribute, pBuffer):
/// SECPKG_ATTR_STREAM_SIZES (4) → SecPkgContext_Sizes (curl буферизует).
fn sspiQueryContextAttributes(ph_context: u64, attr: u64, p_buffer: u64) u64 {
    _ = ph_context;
    if (attr != SECPKG_ATTR_STREAM_SIZES) {
        logf("[SSPI] QueryContextAttributes(attr={d}) — не поддержан\n", .{attr});
        return SEC_E_UNSUPPORTED_METHOD;
    }
    if (p_buffer == 0 or !ops.validate_write(p_buffer, 20)) {
        return SEC_E_INVALID_HANDLE;
    }
    userD(p_buffer + 0).* = 5; // cbHeader: record header
    userD(p_buffer + 4).* = 16; // cbTrailer: MAC
    userD(p_buffer + 8).* = 16384; // cbMaxToken
    userD(p_buffer + 12).* = 1; // cbBlockSize
    userD(p_buffer + 16).* = 16384; // cbMaximumMessage
    logf("[SSPI] QueryContextAttributes(STREAM_SIZES) -> hdr=5, trailer=16, max=16384\n", .{});
    return SEC_E_OK;
}

/// DeleteSecurityContext(phContext): освободить слот сессии.
fn sspiDeleteSecurityContext(ph_context: u64) u64 {
    if (tlsSessionByHandle(ph_context)) |s| {
        s.in_use = false;
        logf("[SSPI] DeleteSecurityContext — сессия освобождена\n", .{});
    }
    return SEC_E_OK;
}

/// FreeCredentialsHandle(phCred): cred-хэндлы — счётчики, освобождение no-op.
fn sspiFreeCredentialsHandle(ph_cred: u64) u64 {
    _ = ph_cred;
    logf("[SSPI] FreeCredentialsHandle -> SEC_E_OK\n", .{});
    return SEC_E_OK;
}

const SEC_E_INVALID_HANDLE: u64 = 0x8009_0004;
const SEC_E_INSUFFICIENT_MEMORY: u64 = 0x8009_0001;
const SEC_E_INVALID_TOKEN: u64 = 0x8009_0855;
const SEC_E_CONTEXT_EXPIRED: u64 = 0x8009_0312 + 0x1000;
const SEC_E_INCOMPLETE_MESSAGE: u64 = 0x8009_0322;
const SEC_E_INTERNAL_ERROR: u64 = 0x8009_0304;

// ─── v0.14.0 (CDD №5): Wave-A — пред-SSPI препятствия (по живому логу) ──────

/// CreateMutexA(attrs, bInitialOwner, lpName): пул хэндлов 0x400+.
/// Мьютекс в однопоточном CDD всегда «свободен» → WaitFor → WAIT_OBJECT_0.
fn kCreateMutexA(attrs: u64, initial_owner: u64, name_va: u64) u64 {
    _ = attrs;
    _ = initial_owner;
    if (name_va != 0) {
        if (userStrLen(name_va)) |len| {
            if (len > 0 and len < 64) {
                logf("[WIN32] CreateMutexA(\"{s}\")\n", .{userPtr(name_va)[0..@intCast(len)]});
            }
        }
    } else {
        logf("[WIN32] CreateMutexA(unnamed)\n", .{});
    }
    const c = &(ctx orelse return 0);
    const h = c.next_mutex_handle;
    c.next_mutex_handle += 1;
    return h;
}

/// ReleaseMutex(h): TRUE — мьютекс «отпущен» (счётчик владельцев не нужен).
fn kReleaseMutex(h: u64) u64 {
    _ = h;
    return 1; // BOOL TRUE
}

/// bcrypt.dll!BCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags):
/// 0 (STATUS_SUCCESS), буфер — КРИПТО-энтропия PUF-хаба ядра.
/// v0.16.0 (CDD №7): статический сид 0x7E5C_A01B (v0.14) заменён на
/// ops.entropy_fill — живой материал UnifiedEntropyHub (джиттер кремния +
/// тайминги шины + IRQ). Статический сид был причиной bad-decrypt при
/// дефолтном гибриде X25519MLKEM768 (декапсуляция ML-KEM): каждый вызов
/// давал ИДЕНТИЧНЫЕ байты → DRBG-экземпляры OpenSSL (главный + резолвер)
/// сидировались одним материалом. Теперь: каждый вызов — новый поток PRNG.
fn kBCryptGenRandom(pb: u64, cb: u64) u64 {
    if (cb == 0) return 0;
    if (cb > 4096) return 0xC000_0009; // STATUS_INVALID_PARAMETER
    if (pb == 0 or !ops.validate_write(pb, cb)) return 0xC000_000D; // STATUS_INVALID_HANDLE? min win
    ops.entropy_fill(userPtr(pb), @intCast(cb));
    return 0; // STATUS_SUCCESS
}

/// strnlen(s, maxsize): длина до NUL, не дальше maxsize.
fn kstrnlen(va: u64, maxsize: u64) u64 {
    if (va == 0 or maxsize == 0) return 0;
    const n = @min(maxsize, MAX_STR_LEN);
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        if (!ops.validate_read(va + i, 1)) return i;
        if (userPtr(va)[@as(usize, @intCast(i))] == 0) return i;
    }
    return i;
}

/// inet_pton(af, src, dst): AF_INET «192.0.2.1» → BE-u32 в dst. AF_INET6 → 0.
fn wsaInetPton(af: u64, src_va: u64, dst_va: u64) u64 {
    if (af != 2) return 0; // AF_INET6 не поддержан (curl идёт IPv4-путём)
    const slen = userStrLen(src_va) orelse return 0;
    if (slen == 0 or slen > 15 or !ops.validate_write(dst_va, 4)) return 0;
    var oct: [4]u8 = .{ 0, 0, 0, 0 };
    var oi: usize = 0;
    var val: u32 = 0;
    var digits: u32 = 0;
    for (userPtr(src_va)[0..@intCast(slen)], 0..) |ch, i| {
        if (ch == '.') {
            if (digits == 0 or oi >= 4) return 0;
            oct[oi] = @intCast(val);
            oi += 1;
            val = 0;
            digits = 0;
        } else if (ch >= '0' and ch <= '9') {
            val = val * 10 + (ch - '0');
            digits += 1;
            if (val > 255) return 0;
        } else return 0;
        _ = i;
    }
    if (digits == 0 or oi != 3) return 0;
    oct[3] = @intCast(val);
    @memcpy(userPtr(dst_va)[0..4], &oct);
    return 1; // успех
}

// ─── v0.13.0 (CDD №4): SocketState — опции, состояние, события, loopback ──

/// FD_*-события (WSAEventSelect/WSAEnumNetworkEvents)
const FD_READ: u32 = 0x01;
const FD_WRITE: u32 = 0x02;
const FD_CONNECT: u32 = 0x10;
const FD_CLOSE: u32 = 0x20;

/// WSANETWORKEVENTS: { long iNetworkEvents; int iErrorCode[FD_MAX_EVENTS]; }
const FD_MAX_EVENTS: usize = 10;
const WSANETWORKEVENTS_SIZE: u64 = 4 + FD_MAX_EVENTS * 4; // 44
const FD_CONNECT_BIT: usize = 4;
const FD_CLOSE_BIT: usize = 5;

/// Уровни/опции сокета
const SOL_SOCKET: u32 = 0xFFFF;
const SO_KEEPALIVE: u32 = 0x0008;
const SO_SNDBUF: u32 = 0x1001;
const SO_RCVBUF: u32 = 0x1002;
const SO_ERROR: u32 = 0x1007;
const SO_TYPE: u32 = 0x1008;
const IPPROTO_TCP: u32 = 6;
const TCP_NODELAY: u32 = 0x0001;
const SOCK_STREAM: u32 = 1;

/// Loopback-ответ шима: минимальный валидный HTTP/1.1 (Content-Length
/// важен — curl завершит передачу ровно по телу, без EOF-ожидания).
const HTTP_RESP = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello POLER!\n";

/// Число отслеживаемых сокетов (curl открывает 2-3: Happy Eyeballs + IPv6).
pub const MAX_SOCKS: usize = 32;

/// Состояние сокета WS2-машины (таблица в Ctx, fd = 0x100 + индекс).
pub const Sock = struct {
    in_use: bool = false,
    family: u16 = 0,
    nonblocking: bool = false, // FIONBIO
    connected: bool = false, // connect() шима = мгновенно
    peer_ip: [4]u8 = .{ 0, 0, 0, 0 }, // адрес «сервера» (getpeername)
    peer_port: u16 = 0,
    local_port: u16 = 0, // эфемерный (getsockname: 127.0.0.1)
    // опции (setsockopt → getsockopt)
    opt_keepalive: bool = false,
    opt_nodelay: bool = false,
    opt_rcvbuf: u32 = 65536,
    opt_sndbuf: u32 = 65536,
    // события: интерес (WSAEventSelect) → pending → отчёт (Enum с авто-сбросом)
    event_handle: u64 = 0,
    event_mask: u32 = 0,
    pending: u32 = 0,
    connect_reported: bool = false, // FD_CONNECT одноразовый
    write_reported: bool = false, // FD_WRITE перезапускается send()
    // v0.14.0 (CDD №5): TLS-машина (https-порт 443 → синтетический SChannel)
    is_tls: bool = false,
    tls_stage: u8 = 0, // 1=ждём ClientHello, 2=отдаём ServerHello-поток, 3=данные 0x17, 4=EOF
    tls_recv_cursor: usize = 0, // позиция в синтетическом серверном потоке
    // v0.14.0 (CDD №5): реальный TCP через virtio-net (слот драйвера)
    net_slot: i64 = -1, // -1 = loopback-синтетика
    // loopback-I/O (http-путь; для https используется tls_recv_cursor)
    sent_bytes: u64 = 0,
    send_logged: bool = false, // первый payload → [HTTP-SEND]
    recv_cursor: usize = 0, // позиция в HTTP_RESP
    recv_eof: bool = false, // ответ исчерпан: recv → 0
};

/// TLS-сессия SSPI/SChannel (CDD №5): SYNTHETIC-TLS — НАСТОЯЩИЙ формат
/// записей (record layer + handshake headers + SNI-extension), но
/// потоковое «шифрование» XOR по сессионному ключу вместо настоящей
/// криптографии (TLS 1.2/1.3 стек — за пределами честного CDD-цикла).
/// Ключ = f(client_random, server_random) — обе стороны наши, контур
/// замкнут в Ring 3, формат байтовый совместим с RFC 5246 §6.2.1.
pub const MAX_TLS: usize = 8;
const TLS_MAGIC: u64 = 0x504F_4C45_5353_4C31; // "POLESSL1"

pub const TlsSession = struct {
    in_use: bool = false,
    established: bool = false, // handshake завершён (ISC-2 вернул SEC_E_OK)
    sni_len: usize = 0, // pszTargetName (SNI для ClientHello + лог)
    sni: [64]u8 = [_]u8{0} ** 64,
    client_random: [32]u8 = [_]u8{0} ** 32,
    server_random: [32]u8 = [_]u8{0} ** 32,
    key: [32]u8 = [_]u8{0} ** 32, // SYNTHETIC stream key (XOR)
    send_seq: u64 = 0, // номер исходящей записи (EncryptMessage)
    recv_seq: u64 = 0, // номер входящей записи (DecryptMessage)
    fd: u64 = 0, // связанный сокет (после send ClientHello)
    first_data_logged: bool = false, // [TLS-SEND] plaintext одноразово
};

/// Socket по fd (таблица 0x100..). null = вне таблицы/не открыт.
fn sockByFd(fd: u64) ?*Sock {
    const c = &(ctx orelse return null);
    if (fd < 0x100) return null;
    const idx: usize = @intCast(fd - 0x100);
    if (idx >= MAX_SOCKS or !c.sockets[idx].in_use) return null;
    return &c.sockets[idx];
}

/// Имена FD-бит для логов ("FD_CONNECT|FD_WRITE").
fn fdNames(mask: u32, buf: []u8) []const u8 {
    var n: usize = 0;
    const entries = [_]struct { bit: u32, name: []const u8 }{
        .{ .bit = FD_READ, .name = "FD_READ" },
        .{ .bit = FD_WRITE, .name = "FD_WRITE" },
        .{ .bit = FD_CONNECT, .name = "FD_CONNECT" },
        .{ .bit = FD_CLOSE, .name = "FD_CLOSE" },
    };
    for (entries) |e| {
        if (mask & e.bit == 0) continue;
        if (n > 0 and n < buf.len) {
            buf[n] = '|';
            n += 1;
        }
        if (n + e.name.len > buf.len) break;
        @memcpy(buf[n .. n + e.name.len], e.name);
        n += e.name.len;
    }
    return buf[0..n];
}

/// socket(af, type, protocol): псевдо-хэндл из ctx (с 0x100, различимы в
/// логах) + запись состояния в таблице. AF_INET(2)/AF_INET6(23) — прочее
/// WSAEAFNOSUPPORT.
fn wsaSocket(af: u64, sock_type: u64, protocol: u64) u64 {
    const c = &(ctx orelse return INVALID_SOCKET);
    if (af != 2 and af != 23) {
        setLastError(WSAEAFNOSUPPORT);
        return INVALID_SOCKET;
    }
    const fd = c.next_socket_fd;
    c.next_socket_fd += 1;
    c.sockets_opened += 1;
    if (fd >= 0x100 + MAX_SOCKS) {
        // за пределами таблицы: хэндл валиден, состояние не трекается
        logf("[WS2] socket(af={d}, type={d}, proto={d}) -> fd=0x{x} (untracked)\n", .{ af, sock_type, protocol, fd });
        return fd;
    }
    const s = &c.sockets[@as(usize, @intCast(fd - 0x100))];
    s.* = .{};
    s.in_use = true;
    s.family = @intCast(af);
    s.local_port = 0xC000 + @as(u16, @truncate(fd - 0x100)); // эфемерный
    logf("[WS2] socket(af={d}, type={d}, proto={d}) -> fd=0x{x}\n", .{ af, sock_type, protocol, fd });
    return fd;
}

/// connect(s, name, namelen): sockaddr разбирается и ЛОГИРУЕТСЯ (цель
/// атаки: IP:порт) — это CDD-маяк волны. Loopback-семантика: 0 = «соединён
/// мгновенно», состояние connected + pending FD_CONNECT — curl узнает о
/// завершении через WSAEnumNetworkEvents/select и перейдёт к send().
fn wsaConnect(s: u64, name_va: u64, namelen: u64) u64 {
    if (namelen < 2 or !ops.validate_read(name_va, 2)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    const family = userW(name_va).*;
    if (family == 2 and namelen >= 16 and ops.validate_read(name_va, 16)) {
        const port = std.mem.bigToNative(u16, userW(name_va + 2).*);
        const ip = userPtr(name_va + 4)[0..4];
        logf("[WS2] connect(fd=0x{x}, AF_INET, {d}.{d}.{d}.{d}:{d}){s}\n", .{ s, ip[0], ip[1], ip[2], ip[3], port, if (port == 443) " — TLS" else "" });
        if (sockByFd(s)) |sk| {
            sk.connected = true;
            sk.peer_ip = .{ ip[0], ip[1], ip[2], ip[3] };
            sk.peer_port = port;
            sk.pending |= FD_CONNECT | FD_WRITE; // событие завершения connect
            // v0.14.0: https-порт → TLS-машина сокета (SYNTHETIC-SChannel;
            // для реального virtio-пути TLS делает сам curl — OpenSSL)
            if (port == 443) {
                sk.is_tls = true;
                sk.tls_stage = 1;
            }
            // v0.14.0: РЕАЛЬНЫЙ TCP через virtio-net (SYN→SYN-ACK→ACK);
            // при отсутствии устройства — loopback-синтетика (плавный fallback)
            if (ops.net_ready()) {
                const be_ip = (@as(u64, ip[0]) << 24) | (@as(u64, ip[1]) << 16) |
                    (@as(u64, ip[2]) << 8) | ip[3];
                const slot = ops.net_tcp_connect(be_ip, port);
                if (slot >= 0) {
                    sk.net_slot = slot;
                    logf("[WS2] connect: РЕАЛЬНОЕ TCP-соединение через virtio-net (slot {d})\n", .{slot});
                } else {
                    logf("[WS2] connect: virtio-TCP не удался — loopback-fallback\n", .{});
                }
            }
        }
        return 0;
    }
    if (family == 23 and namelen >= 28 and ops.validate_read(name_va, 28)) {
        const port = std.mem.bigToNative(u16, userW(name_va + 2).*);
        const ip = userPtr(name_va + 8)[0..16];
        logf("[WS2] connect(fd=0x{x}, AF_INET6, [{d}:{d}:{d}:{d}…]:{d})\n", .{ s, ip[0], ip[1], ip[2], ip[3], port });
        if (sockByFd(s)) |sk| {
            sk.connected = true;
            sk.peer_ip = .{ 0, 0, 0, 0 };
            sk.peer_port = port;
            sk.pending |= FD_CONNECT | FD_WRITE;
        }
        return 0;
    }
    setLastError(WSAEINVAL);
    return INVALID_SOCKET;
}

/// closesocket(s): 0 = NO_ERROR, состояние освобождается.
fn wsaClosesocket(s: u64) u64 {
    if (sockByFd(s)) |sk| {
        // v0.14.0: закрыть реальное TCP-соединение (FIN)
        if (sk.net_slot >= 0) ops.net_tcp_close(sk.net_slot);
        sk.* = .{};
    }
    logf("[WS2] closesocket(fd=0x{x})\n", .{s});
    return 0;
}

/// ioctlsocket(s, cmd, argp): FIONBIO(0x8004667E) читает u_long-флаг —
/// сохраняем nonblocking-режим в SocketState; FIONREAD пишет 0.
fn wsaIoctlsocket(s: u64, cmd: u64, argp: u64) u64 {
    const FIONBIO: u64 = 0x8004_667E;
    const FIONREAD: u64 = 0x4004_667F;
    if (cmd == FIONBIO) {
        if (!ops.validate_read(argp, 4)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        const mode = userD(argp).*;
        if (sockByFd(s)) |sk| sk.nonblocking = mode != 0;
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

/// shutdown(s, how): 0 = ок (loopback: приём «закрывается» — следующий
/// recv вернёт 0/EOF).
fn wsaShutdown(s: u64, how: u64) u64 {
    const hows = [_][]const u8{ "SD_RECEIVE", "SD_SEND", "SD_BOTH" };
    const hw: usize = @intCast(@min(how, 2));
    if (sockByFd(s)) |sk| {
        if (how == 0 or how == 2) sk.recv_eof = true;
    }
    logf("[WS2] shutdown(fd=0x{x}, {s}) -> 0\n", .{ s, hows[hw] });
    return 0;
}

// ── Сокетные опции (setsockopt/getsockopt) и адреса (getsockname/…ername) ──

/// Текстовое имя опции для логов (уровень+optname).
fn sockoptName(lvl: u32, opt: u32, buf: []u8) []const u8 {
    const entries = [_]struct { lvl: u32, opt: u32, name: []const u8 }{
        .{ .lvl = SOL_SOCKET, .opt = SO_KEEPALIVE, .name = "SO_KEEPALIVE" },
        .{ .lvl = SOL_SOCKET, .opt = SO_SNDBUF, .name = "SO_SNDBUF" },
        .{ .lvl = SOL_SOCKET, .opt = SO_RCVBUF, .name = "SO_RCVBUF" },
        .{ .lvl = SOL_SOCKET, .opt = SO_ERROR, .name = "SO_ERROR" },
        .{ .lvl = SOL_SOCKET, .opt = SO_TYPE, .name = "SO_TYPE" },
        .{ .lvl = IPPROTO_TCP, .opt = TCP_NODELAY, .name = "TCP_NODELAY" },
    };
    for (entries) |e| {
        if (e.lvl == lvl and e.opt == opt) return e.name;
    }
    return std.fmt.bufPrint(buf, "opt 0x{x}", .{opt}) catch "opt";
}

/// setsockopt(s, level, optname, optval, optlen): опции СОХРАНЯЮТСЯ в
/// SocketState (getsockopt вернёт сохранённое), возврат 0 = успех.
/// optlen — 5-й арг Win64 (стек вызова).
fn wsaSetsockopt(s: u64, level: u64, optname: u64, optval: u64, optlen: u64) u64 {
    const lvl: u32 = @truncate(level);
    const opt: u32 = @truncate(optname);
    if (optlen == 0) return 0; // пустая опция — принимаем (no-op)
    if (optval == 0 or !ops.validate_read(optval, @min(optlen, 4))) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    const val = userD(optval).*; // int-опции Winsock (bool/размер буфера)
    var nb: [24]u8 = undefined;
    const opt_name = sockoptName(lvl, opt, &nb);
    const lvl_name = if (lvl == SOL_SOCKET) "SOL_SOCKET" else if (lvl == IPPROTO_TCP) "IPPROTO_TCP" else "lvl";
    if (sockByFd(s)) |sk| {
        if (lvl == SOL_SOCKET) {
            switch (opt) {
                SO_KEEPALIVE => sk.opt_keepalive = val != 0,
                SO_RCVBUF => sk.opt_rcvbuf = val,
                SO_SNDBUF => sk.opt_sndbuf = val,
                else => {}, // прочие — no-op (успех)
            }
        } else if (lvl == IPPROTO_TCP and opt == TCP_NODELAY) {
            sk.opt_nodelay = val != 0;
        }
    }
    logf("[WS2] setsockopt(fd=0x{x}, {s}, {s}={d}) -> 0\n", .{ s, lvl_name, opt_name, val });
    return 0;
}

/// getsockopt(s, level, optname, optval, optlen): SO_ERROR → 0 (connect
/// без ошибок — статус неблокирующего соединения), SO_TYPE → SOCK_STREAM,
/// буферы/флаги — из SocketState. optlen — int* (in: размер буфера,
/// out: фактический). 5-й арг — стек.
fn wsaGetsockopt(s: u64, level: u64, optname: u64, optval: u64, optlen: u64) u64 {
    const lvl: u32 = @truncate(level);
    const opt: u32 = @truncate(optname);
    if (optlen == 0 or !ops.validate_read(optlen, 4) or !ops.validate_write(optlen, 4)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    const in_len = userD(optlen).*;
    if (optval == 0 or in_len < 4 or !ops.validate_write(optval, 4)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    var value: u32 = 0;
    if (sockByFd(s)) |sk| {
        if (lvl == SOL_SOCKET) {
            switch (opt) {
                SO_ERROR => value = 0, // соединение установлено без ошибок
                SO_TYPE => value = SOCK_STREAM,
                SO_KEEPALIVE => value = if (sk.opt_keepalive) 1 else 0,
                SO_RCVBUF => value = sk.opt_rcvbuf,
                SO_SNDBUF => value = sk.opt_sndbuf,
                else => {},
            }
        } else if (lvl == IPPROTO_TCP and opt == TCP_NODELAY) {
            value = if (sk.opt_nodelay) 1 else 0;
        }
    } else if (opt == SO_ERROR) {
        value = 0; // не-сокет: пермиссивно (нет ошибок соединения)
    }
    userD(optval).* = value;
    userD(optlen).* = 4;
    var nb: [24]u8 = undefined;
    const opt_name = sockoptName(lvl, opt, &nb);
    const lvl_name = if (lvl == SOL_SOCKET) "SOL_SOCKET" else if (lvl == IPPROTO_TCP) "IPPROTO_TCP" else "lvl";
    logf("[WS2] getsockopt(fd=0x{x}, {s}, {s}) -> {d}\n", .{ s, lvl_name, opt_name, value });
    return 0;
}

/// sockaddr_in (16Б) → user-буфер + *namelen = 16 (семантика Win64).
fn writeSockaddr(name: u64, namelen: u64, ip: [4]u8, port: u16) bool {
    if (!ops.validate_read(namelen, 4) or !ops.validate_write(namelen, 4)) return false;
    if (userD(namelen).* < 16) return false; // буфер меньше sockaddr_in
    if (!ops.validate_write(name, 16)) return false;
    userW(name).* = 2; // sin_family = AF_INET
    userW(name + 2).* = std.mem.nativeToBig(u16, port); // sin_port (BE)
    @memcpy(userPtr(name + 4)[0..4], &ip);
    @memset(userPtr(name + 8)[0..8], 0); // sin_zero
    userD(namelen).* = 16;
    return true;
}

/// getsockname(s, name, namelen): локальный конец соединения —
/// 127.0.0.1:эфемерный_порт (Win64 заполняет после connect).
fn wsaGetsockname(s: u64, name: u64, namelen: u64) u64 {
    var port: u16 = 0;
    if (sockByFd(s)) |sk| port = sk.local_port;
    if (!writeSockaddr(name, namelen, .{ 127, 0, 0, 1 }, port)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    logf("[WS2] getsockname(fd=0x{x}) -> 127.0.0.1:{d}\n", .{ s, port });
    return 0;
}

/// getpeername(s, name, namelen): удалённый конец — адрес из connect().
fn wsaGetpeername(s: u64, name: u64, namelen: u64) u64 {
    const k = sockByFd(s) orelse {
        setLastError(WSAENOTCONN);
        return INVALID_SOCKET;
    };
    if (!k.connected) {
        setLastError(WSAENOTCONN);
        return INVALID_SOCKET;
    }
    if (!writeSockaddr(name, namelen, k.peer_ip, k.peer_port)) {
        setLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }
    logf("[WS2] getpeername(fd=0x{x}) -> {d}.{d}.{d}.{d}:{d}\n", .{ s, k.peer_ip[0], k.peer_ip[1], k.peer_ip[2], k.peer_ip[3], k.peer_port });
    return 0;
}

// ── Мультиплексор select (КЛЮЧЕВОЙ путь волны №4 к send) ──

const SockFilter = enum { read, write };

/// fd_set: { u32 fd_count; SOCKET fd_array[64]; } — массив с СМЕЩЕНИЯ 8.
/// НАСТОЯЩАЯ семантика select: набор ПЕРЕЗАПИСЫВАЕТСЯ — в fd_array
/// остаются только ГОТОВЫЕ дескрипторы, fd_count = их число. null = битый
/// указатель (WSAEFAULT).
fn fdSetFilter(fd_set: u64, kind: SockFilter) ?u64 {
    if (!ops.validate_read(fd_set, 8) or !ops.validate_write(fd_set, 8)) return null;
    const count = userD(fd_set).*;
    if (count > 64) return null; // мусорный count — не наш набор
    if (count > 0 and (!ops.validate_read(fd_set + 8, @as(u64, count) * 8) or
        !ops.validate_write(fd_set + 8, @as(u64, count) * 8))) return null;
    var kept: u64 = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const fd = userQ(fd_set + 8 + i * 8).*;
        const ready = if (sockByFd(fd)) |sk| switch (kind) {
            .write => sk.connected and !sk.recv_eof, // WRITABLE (после connect)
            .read => blk: {
                // v0.14.0: для реального TCP-сокета — активный RX-поллинг
                // (данные пришли в буфер драйвера → READABLE)
                if (sk.net_slot >= 0) {
                    const have = ops.net_tcp_poll(sk.net_slot);
                    if (have > 0) break :blk true;
                    if (have < 0) break :blk true; // закрытие: пусть recv узнает EOF
                    break :blk false;
                }
                break :blk sk.sent_bytes > 0; // READABLE (ответ «пришёл» после send)
            },
        } else false;
        if (ready) {
            userQ(fd_set + 8 + kept * 8).* = fd;
            kept += 1;
        }
    }
    userD(fd_set).* = @truncate(kept);
    return kept;
}

/// select(nfds, readfds, writefds, exceptfds, timeout): мультиплексор
/// дескрипторов. Подключённый сокет — WRITABLE (curl: неблокирующий
/// connect завершён → отправка запроса); после send — READABLE.
/// Наборы перезаписываются (готовые), exceptfds очищается, возврат —
/// число готовых дескрипторов. timeout (timeval*, 5-й арг — стек) не
/// блокируем (неблокирующий опрос — ядро без sleep-примитива для Ring 3).
fn wsaSelect(nfds: u64, readfds: u64, writefds: u64, exceptfds: u64, timeout: u64) u64 {
    _ = nfds; // границы задаёт содержимое наборов (Winsock игнорирует nfds)
    _ = timeout; // {i64 s; i64 us} — не блокируем
    var ready: u64 = 0;
    var wr: u64 = 0;
    if (readfds != 0) {
        if (fdSetFilter(readfds, .read)) |n| {
            ready += n;
        } else {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
    }
    if (writefds != 0) {
        if (fdSetFilter(writefds, .write)) |n| {
            ready += n;
            wr = n;
        } else {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
    }
    if (exceptfds != 0) {
        // исключений нет (out-of-band отсутствует) — набор очищается
        if (ops.validate_read(exceptfds, 4) and ops.validate_write(exceptfds, 4)) {
            userD(exceptfds).* = 0;
        }
    }
    if (ready > 0) {
        logf("[WS2] select -> {d} ready (writable={d}, readable={d})\n", .{ ready, wr, ready - wr });
    }
    return ready;
}

/// send(s, buf, len, flags): loopback-отправка — буфер валидируется
/// (validate_read: USER-страницы!), все len байт «уходят» (возврат len).
/// v0.14.0: TLS-сокет распознаёт записи по типу (0x16 handshake / 0x17
/// data) — [TLS-SEND]-лог (ClientHello —МОМЕНТ ИСТИНЫ №5) + привязка
/// сессии к сокету (ctx.tls_last_fd). После send «приходит» ответ (FD_READ).
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
    if (sockByFd(s)) |sk| {
        if (!sk.connected) {
            setLastError(WSAENOTCONN);
            return INVALID_SOCKET;
        }
        sk.sent_bytes += len;
        sk.pending |= FD_READ; // «ответ пришёл» — событие чтения
        sk.write_reported = false; // буфер «опустошён» — снова WRITABLE
        // v0.14.0: РЕАЛЬНАЯ отправка через virtio-net TCP
        if (sk.net_slot >= 0 and len > 0) {
            const n = ops.net_tcp_send(sk.net_slot, @ptrFromInt(buf), @intCast(len));
            if (n >= 0) {
                logf("[NET-SEND] fd=0x{x}: {d}/{d}Б через virtio-net\n", .{ s, n, len });
                return @intCast(n);
            }
            logf("[NET-SEND] fd=0x{x}: ОШИБКА отправки\n", .{s});
            setLastError(WSAENETDOWN);
            return INVALID_SOCKET;
        }
        if (sk.is_tls and len >= 3) {
            // TLS-запись: 0x16 handshake (ClientHello от curl после ISC-1)
            // или 0x17 data (EncryptMessage-потом: header+data+trailer)
            const rec_type = userPtr(buf)[0];
            const c = &(ctx orelse return len);
            c.tls_last_fd = s;
            if (rec_type == 0x16) {
                if (sk.tls_stage == 1) sk.tls_stage = 2; // ждём recv ServerHello
                var hex: [64]u8 = undefined;
                var hn: usize = 0;
                const hc: u64 = @min(len, 24);
                var b: u64 = 0;
                while (b < hc and hn + 2 < hex.len) : (b += 1) {
                    const v = userPtr(buf)[@as(usize, @intCast(b))];
                    hex[hn] = "0123456789abcdef"[v >> 4];
                    hex[hn + 1] = "0123456789abcdef"[v & 0xF];
                    hn += 2;
                }
                logf("[TLS-SEND] fd=0x{x}: handshake-запись {d}Б (record 0x16): {s}\n", .{ s, len, hex[0..hn] });
                return len;
            }
            logf("[TLS-SEND] fd=0x{x}: data-запись {d}Б (record 0x17, зашифровано)\n", .{ s, len });
            return len;
        }
        if (!sk.send_logged and len > 0) {
            sk.send_logged = true;
            logSendPayload(s, buf, len);
        } else {
            logf("[WS2] send(fd=0x{x}, len={d}) -> {d}\n", .{ s, len, len });
        }
    } else {
        logf("[WS2] send(fd=0x{x}, len={d}) -> {d} (untracked)\n", .{ s, len, len });
    }
    return len;
}

/// Лог первого payload: \r/\n экранируются ("\\r\\n"), до 96 байт.
fn logSendPayload(s: u64, buf: u64, len: u64) void {
    var esc: [128]u8 = undefined;
    var n: usize = 0;
    const cap: u64 = @min(len, 96);
    var i: u64 = 0;
    while (i < cap and n + 2 < esc.len) : (i += 1) {
        const ch = userPtr(buf)[@as(usize, @intCast(i))];
        switch (ch) {
            '\r' => {
                esc[n] = '\\';
                esc[n + 1] = 'r';
                n += 2;
            },
            '\n' => {
                esc[n] = '\\';
                esc[n + 1] = 'n';
                n += 2;
            },
            else => {
                esc[n] = if (ch >= 0x20 and ch < 0x7F) ch else '.';
                n += 1;
            },
        }
    }
    const more = if (len > cap) "..." else "";
    logf("[HTTP-SEND] fd=0x{x}, len={d}: \"{s}\"{s}\n", .{ s, len, esc[0..n], more });
}

/// recv(s, buf, len, flags): loopback-приём. http-сокет — синтетический
/// ответ шима (HTTP/1.1 200 OK + «Hello POLER!\n"). v0.14.0: TLS-сокет —
/// стадиийная машина синтетического SChannel-сервера:
///   stage 2: ServerHello+CCS+Finished (после ClientHello в send)
///   stage 3: запись 0x17 с XOR-«зашифрованным» HTTP-ответом
///   stage 4: EOF (0) + FD_CLOSE — сервер «закрыл» соединение.
fn wsaRecv(s: u64, buf: u64, len: u64, flags: u64) u64 {
    _ = flags;
    const sk = sockByFd(s) orelse {
        setLastError(WSAENOTCONN);
        return INVALID_SOCKET;
    };
    if (sk.sent_bytes == 0) {
        // запрос ещё не «отправлен» — данных нет (неблокирующий сокет)
        setLastError(WSAEWOULDBLOCK);
        return INVALID_SOCKET;
    }
    // v0.14.0: РЕАЛЬНЫЙ приём через virtio-net TCP
    if (sk.net_slot >= 0) {
        const cap: usize = @intCast(@min(len, 64 * 1024 * 1024));
        if (cap > 0 and !ops.validate_write(buf, cap)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        const n = ops.net_tcp_recv(sk.net_slot, @ptrFromInt(buf), cap);
        if (n > 0) {
            logf("[NET-RECV] fd=0x{x}: {d}Б через virtio-net\n", .{ s, n });
            return @intCast(n);
        }
        if (n < 0) {
            sk.pending |= FD_CLOSE; // сервер закрыл
            logf("[NET-RECV] fd=0x{x} -> 0 (EOF)\n", .{s});
            return 0;
        }
        setLastError(WSAEWOULDBLOCK); // данных пока нет
        return INVALID_SOCKET;
    }
    if (sk.is_tls) {
        return wsaRecvTls(s, sk, buf, len);
    }
    if (sk.recv_eof) {
        sk.pending |= FD_CLOSE; // сервер закрыл соединение
        logf("[HTTP-RECV] fd=0x{x} -> 0 (EOF)\n", .{s});
        return 0;
    }
    const total = HTTP_RESP.len;
    const remaining = total - sk.recv_cursor;
    const n = @min(@as(usize, @intCast(@min(len, 64 * 1024 * 1024))), remaining);
    if (n > 0) {
        if (!ops.validate_write(buf, n)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        @memcpy(userPtr(buf)[0..n], HTTP_RESP[sk.recv_cursor .. sk.recv_cursor + n]);
        sk.recv_cursor += n;
    }
    if (sk.recv_cursor >= total) sk.recv_eof = true;
    logf("[HTTP-RECV] fd=0x{x}: {d} байт ({d}/{d})\n", .{ s, n, sk.recv_cursor, total });
    return n;
}

/// recv для TLS-сокета: синтетический серверный поток по стадиям.
/// Сессия находится через ctx.tls_last_fd (последняя TLS-активность —
/// в однопоточном CDD-процессе активна одна handshake-сессия).
fn wsaRecvTls(s: u64, sk: *Sock, buf: u64, len: u64) u64 {
    if (sk.tls_stage >= 4 or (sk.tls_stage == 3 and sk.recv_eof)) {
        sk.pending |= FD_CLOSE;
        logf("[TLS-RECV] fd=0x{x} -> 0 (EOF, соединение закрыто)\n", .{s});
        return 0;
    }
    if (sk.tls_stage == 0 or sk.tls_stage == 1) {
        // handshake ещё не начался — данных нет
        setLastError(WSAEWOULDBLOCK);
        return INVALID_SOCKET;
    }
    const c = &(ctx orelse return 0);
    // найти сессию по fd (или последнюю активную)
    var sess: ?*TlsSession = null;
    for (&c.tls_sessions) |*t| {
        if (t.in_use and t.fd == s) sess = t;
    }
    if (sess == null) {
        for (&c.tls_sessions) |*t| {
            if (t.in_use and c.tls_last_fd == s) {
                t.fd = s;
                sess = t;
            }
        }
    }
    const ss = sess orelse {
        // сессии нет (curl шлёт hello раньше ISC? невозможно, но защита)
        setLastError(WSAEWOULDBLOCK);
        return INVALID_SOCKET;
    };
    var stream: [512]u8 = undefined;
    var total: usize = 0;
    if (sk.tls_stage == 2) {
        // ServerHello + CCS + Finished
        total = tlsBuildServerStream(ss, &stream);
        logf("[TLS-RECV] fd=0x{x}: ServerHello-поток {d}Б\n", .{ s, total });
    } else {
        // stage 3: application-data запись с HTTP-ответом
        total = tlsBuildAppRecord(ss, HTTP_RESP, ss.recv_seq, &stream);
        logf("[TLS-RECV] fd=0x{x}: application-data {d}Б (record 0x17)\n", .{ s, total });
    }
    const remaining = total - sk.tls_recv_cursor;
    const n = @min(@as(usize, @intCast(@min(len, 64 * 1024 * 1024))), remaining);
    if (n > 0) {
        if (!ops.validate_write(buf, n)) {
            setLastError(WSAEFAULT);
            return INVALID_SOCKET;
        }
        @memcpy(userPtr(buf)[0..n], stream[sk.tls_recv_cursor .. sk.tls_recv_cursor + n]);
        sk.tls_recv_cursor += n;
    }
    if (sk.tls_recv_cursor >= total) {
        sk.tls_recv_cursor = 0; // следующая порция
        if (sk.tls_stage == 2) {
            // серверный handshake-поток исчерпан — ISC-2 сделает established,
            // следом curl вызовет EncryptMessage и send(0x17); recv-данные
            sk.tls_stage = 3;
        } else {
            sk.recv_eof = true; // ответ исчерпан — следующий recv: EOF
        }
    }
    return n;
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
    // v0.14.0: РЕАЛЬНЫЙ DNS-резолв через virtio-net (UDP → SLIRP 10.0.2.3);
    // при недоступности — синтез TEST-NET-1 (192.0.2.1) как раньше
    var resolved: ?[4]u8 = null;
    if (ops.net_ready() and hostname.len > 0 and hostname.len < 128) {
        const be_ip = ops.net_dns_resolve(@ptrCast(userPtr(node_va)), @intCast(hostname.len));
        if (be_ip != 0) {
            resolved = .{
                @truncate(be_ip >> 24),
                @truncate(be_ip >> 16),
                @truncate(be_ip >> 8),
                @truncate(be_ip),
            };
        }
    }
    const ip4 = userPtr(sa + 4)[0..4];
    if (resolved) |rip| {
        ip4[0] = rip[0];
        ip4[1] = rip[1];
        ip4[2] = rip[2];
        ip4[3] = rip[3];
        userQ(pp_result).* = ai;
        logf("[WS2] getaddrinfo(\"{s}\") -> РЕАЛЬНЫЙ DNS: {d}.{d}.{d}.{d}:{d} (virtio-net/SLIRP)\n", .{ hostname, rip[0], rip[1], rip[2], rip[3], port });
        return 0;
    }
    ip4[0] = 192;
    ip4[1] = 0;
    ip4[2] = 2;
    ip4[3] = 1; // TEST-NET-1 (fallback — драйвера/резолва нет)
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
    // v0.17.0 (CDD №8): единый пул событий с РЕАЛЬНЫМ состоянием (WSA-события
    // manual-reset по семантике Winsock; WSAEnumNetworkEvents сбрасывает).
    const h = eventAlloc(true, false, false, 0);
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

/// WSAEventSelect(s, h, events): регистрация ИНТЕРЕСА сокета к событиям
/// (events=0 — разарма). Арма «проигрывает» накопленное состояние — событие
/// объекта сигнализирует немедленно (Win64-семантика): не-отчитанный
/// FD_CONNECT, WRITABLE после connect, доступный ответ, EOF.
fn wsaEventSelect(s: u64, h: u64, events: u64) u64 {
    const mask: u32 = @truncate(events);
    if (sockByFd(s)) |sk| {
        sk.event_handle = if (mask != 0) h else 0;
        sk.event_mask = mask;
        if (mask != 0) {
            if (mask & FD_CONNECT != 0 and !sk.connect_reported) sk.pending |= FD_CONNECT;
            if (mask & FD_WRITE != 0 and sk.connected and !sk.write_reported) sk.pending |= FD_WRITE;
            if (mask & FD_READ != 0 and sk.sent_bytes > 0) sk.pending |= FD_READ;
            if (mask & FD_CLOSE != 0 and sk.recv_eof) sk.pending |= FD_CLOSE;
        }
    }
    logf("[WS2] WSAEventSelect(fd=0x{x}, handle=0x{x}, events=0x{x}) -> 0\n", .{ s, h, events });
    return 0;
}

/// WSAEnumNetworkEvents(s, h, lpNetworkEvents): ОТЧЁТ о накопленных
/// событиях сокета (WSANETWORKEVENTS, 44Б) + авто-сброс записей и события
/// объекта (Win64-семантика). КЛЮЧ волны №4: FD_CONNECT с
/// iErrorCode[FD_CONNECT_BIT]=0 — curl узнаёт, что неблокирующий
/// connect() УСПЕШНО завершён, и переходит к send() HTTP-запроса.
fn wsaEnumNetworkEvents(s: u64, h: u64, lp: u64) u64 {
    _ = h;
    var ev: u32 = 0;
    if (sockByFd(s)) |sk| ev = sk.pending;
    if (lp != 0 and ops.validate_write(lp, WSANETWORKEVENTS_SIZE)) {
        // { long iNetworkEvents; int iErrorCode[FD_MAX_EVENTS]; }
        @memset(userPtr(lp)[0..@as(usize, @intCast(WSANETWORKEVENTS_SIZE))], 0);
        if (ev != 0) {
            userD(lp).* = ev; // iNetworkEvents
            if (ev & FD_CONNECT != 0) {
                userD(lp + 4 + FD_CONNECT_BIT * 4).* = 0; // iErrorCode[FD_CONNECT_BIT]: 0 = успех
            }
            if (ev & FD_CLOSE != 0) {
                userD(lp + 4 + FD_CLOSE_BIT * 4).* = 0; // закрытие без ошибок
            }
        }
    }
    if (ev != 0) {
        if (sockByFd(s)) |sk| {
            if (ev & FD_CONNECT != 0) sk.connect_reported = true; // FD_CONNECT одноразовый
            if (ev & FD_WRITE != 0) sk.write_reported = true; // до следующего send
            sk.pending = 0; // авто-сброс: события отчитаны
        }
        var nb: [48]u8 = undefined;
        logf("[WS2] WSAEnumNetworkEvents(fd=0x{x}) -> 0x{x} ({s})\n", .{ s, ev, fdNames(ev, &nb) });
    }
    return 0;
}

/// WSAWaitForMultipleEvents(n, events, waitAll, timeout, alertable):
/// сигнальные объекты — тред-хэндлы (Killed) и WSA-события сокетов
/// (производная сигнальность: pending & mask != 0 — события ПРОИЗОШЛИ
/// и ждут WSAEnumNetworkEvents). Иначе — WSA_WAIT_TIMEOUT (неблокирующее
/// ядро: curl крутит свой цикл, планировщик работает).
fn wsaWaitForMultipleEvents(n: u64, events_va: u64, wait_all: u64, timeout: u64, alertable: u64) u64 {
    if (n == 0 or n > 64) return @as(u64, WSA_INVALID_HANDLE);
    if (events_va == 0 or !ops.validate_read(events_va, n * 8)) {
        return @as(u64, WSA_INVALID_HANDLE);
    }
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const h = userQ(events_va + i * 8).*;
        if (ops.object_signaled(h)) {
            logf("[WS2] WSAWaitForMultipleEvents(n={d}) -> EVENT {d} signaled\n", .{ n, i });
            return WSA_WAIT_EVENT_0 + i;
        }
        if (sockEventSignaled(h)) {
            logf("[WS2] WSAWaitForMultipleEvents(n={d}) -> EVENT {d} (сокетные события)\n", .{ n, i });
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

/// Событие сокета сигнально? Сигнальность ПРОИЗВОДНА от pending —
/// интерес армлен (WSAEventSelect) и есть неотчитанные события.
fn sockEventSignaled(h: u64) bool {
    const c = &(ctx orelse return false);
    var i: usize = 0;
    while (i < MAX_SOCKS) : (i += 1) {
        const sk = &c.sockets[i];
        if (sk.in_use and sk.event_handle == h and sk.event_mask != 0 and
            (sk.pending & sk.event_mask) != 0) return true;
    }
    return false;
}

const WSA_INVALID_HANDLE: u64 = 6;

/// WaitForSingleObject(h, ms): сигнальный объект → WAIT_OBJECT_0
/// (тред-хэндл: задача Killed), иначе — WAIT_TIMEOUT.
/// Мьютексные хэндлы (CDD №5): пул 0x400+. В однопоточном CDD-процессе
/// мьютекс всегда «свободен» — WaitFor → WAIT_OBJECT_0 (curl не крутится
/// в retry-цикле с хэндлом NULL от trap-стаба).
const MUTEX_HANDLE_BASE: u64 = 0x400;
const MUTEX_HANDLE_LIMIT: u64 = 0x500;

/// v0.17.0 (CDD №8): сигнальное состояние хэндла (события/семафоры —
/// ctx.events; тред-хэндлы 0x1000+ — ops.object_signaled как v0.12).
fn objectAlive(h: u64) bool {
    if (eventByHandle(h)) |ev| {
        if (ev.is_semaphore) return ev.count > 0;
        return ev.signaled;
    }
    return ops.object_signaled(h);
}

/// Сигнальный захват (auto-reset event: Wait сбрасывает сигнал; семафор:
/// count -= 1). true = захвачен.
fn objectAcquire(h: u64) bool {
    if (eventByHandle(h)) |ev| {
        if (ev.is_semaphore) {
            if (ev.count == 0) return false;
            ev.count -= 1;
            return true;
        }
        if (!ev.signaled) return false;
        if (!ev.manual_reset) ev.signaled = false; // auto-reset
        return true;
    }
    return ops.object_signaled(h); // тред: состояние читает ядро
}

/// WaitForSingleObject(h, ms): v0.17.0 (CDD №8) — ПАРКОВКА ожидания:
/// цикл «sleep 10мс → проверка сигнала» (воркеры 7-Zip ждут INFINITE на
/// событиях; мгновенный WAIT_TIMEOUT ломал синхронизацию бенчмарка).
/// Возврат: WAIT_OBJECT_0 / WAIT_TIMEOUT / WAIT_FAILED.
fn kWaitForSingleObject(h: u64, ms: u64) u64 {
    // Мьютексы (CreateMutexA-пул 0x400+) — «свободны» (SRWLock-прецедент v0.11)
    if (h >= MUTEX_HANDLE_BASE and h < MUTEX_HANDLE_LIMIT) {
        logf("[WIN32] WaitForSingleObject(mutex=0x{x}) -> WAIT_OBJECT_0 (свободен)\n", .{h});
        return WAIT_OBJECT_0;
    }
    const valid = eventByHandle(h) != null or (h >= 0x1000) or ops.object_signaled(h);
    if (!valid and h != 0) {
        // Совсем неизвестный хэндл — не ждём (как v0.12-CDD), но честно логируем.
        logf("[WIN32] WaitForSingleObject(handle=0x{x}, {d}ms) -> WAIT_FAILED (неизвестный объект)\n", .{ h, ms });
        return 0xFFFFFFFF; // WAIT_FAILED
    }
    // УЖЕ сигнален? — захват без ожидания (fast-path).
    if (objectAcquire(h)) {
        logf("[WIN32] WaitForSingleObject(handle=0x{x}) -> WAIT_OBJECT_0 (сигнален)\n", .{h});
        return WAIT_OBJECT_0;
    }
    if (ms == 0) return WAIT_TIMEOUT; // Win32: нулевой таймаут — только проверка
    const INFINITE: u64 = 0xFFFF_FFFF;
    const deadline_ticks: u64 = if (ms == INFINITE) 0 else (ms / 10) + 1; // 10мс-тики
    var waited: u64 = 0;
    while (true) {
        // Парковка задачи 10мс: тред НЕ жжёт CPU, планировщик отдаёт слайсы
        // другим (крипто/компрессия); SetEvent из другого треда меняет state.
        ops.sleep_task(10);
        waited += 1;
        if (objectAcquire(h)) {
            logf("[WIN32] WaitForSingleObject(handle=0x{x}) -> WAIT_OBJECT_0 после {d}×10мс парковки\n", .{ h, waited });
            return WAIT_OBJECT_0;
        }
        if (deadline_ticks != 0 and waited >= deadline_ticks) {
            logf("[WIN32] WaitForSingleObject(handle=0x{x}, {d}ms) -> WAIT_TIMEOUT\n", .{ h, ms });
            return WAIT_TIMEOUT;
        }
    }
}

fn kWaitForSingleObjectEx(h: u64, ms: u64, alertable: u64) u64 {
    _ = alertable;
    return kWaitForSingleObject(h, ms);
}

/// WaitForMultipleObjects(n, handles, waitAll, ms): v0.17.0 (CDD №8) —
/// парковка: поллинг с sleep 10мс; waitAll=TRUE — все сигнальны (захват
/// всех), FALSE — первый сигнальный (возврат WAIT_OBJECT_0+индекс).
fn kWaitForMultipleObjects(n: u64, handles_va: u64, wait_all: u64, ms: u64) u64 {
    if (n == 0 or n > 64) return 0xFFFFFFFF; // WAIT_FAILED
    if (handles_va == 0 or !ops.validate_read(handles_va, n * 8)) {
        return 0xFFFFFFFF;
    }
    const INFINITE: u64 = 0xFFFF_FFFF;
    const deadline_ticks: u64 = if (ms == INFINITE) 0 else (ms / 10) + 1;
    var waited: u64 = 0;
    while (true) {
        // Снимок хэндлов (массив в user-памяти может быть переиспользован)
        var hs: [64]u64 = undefined;
        for (0..@intCast(n)) |i| hs[i] = userQ(handles_va + i * 8).*;
        if (wait_all != 0) {
            var all = true;
            for (hs[0..@intCast(n)]) |h| {
                if (!objectAlive(h)) {
                    all = false;
                    break;
                }
            }
            if (all) {
                // Захват всех (auto-reset/семафоры)
                for (hs[0..@intCast(n)]) |h| _ = objectAcquire(h);
                logf("[WIN32] WaitForMultipleObjects(n={d}, all) -> WAIT_OBJECT_0\n", .{n});
                return WAIT_OBJECT_0;
            }
        } else {
            for (hs[0..@intCast(n)], 0..) |h, i| {
                if (objectAlive(h)) {
                    _ = objectAcquire(h);
                    logf("[WIN32] WaitForMultipleObjects(n={d}) -> object {d} signaled\n", .{ n, i });
                    return WAIT_OBJECT_0 + i;
                }
            }
        }
        if (ms == 0) return WAIT_TIMEOUT;
        ops.sleep_task(10);
        waited += 1;
        if (deadline_ticks != 0 and waited >= deadline_ticks) {
            logf("[WIN32] WaitForMultipleObjects(n={d}, waitAll={d}, {d}ms) -> WAIT_TIMEOUT\n", .{ n, wait_all, ms });
            return WAIT_TIMEOUT;
        }
    }
}

/// Создание события/семафора: общий пул 0x200+ (WSA/KERNEL32 едины).
fn eventAlloc(manual_reset: bool, initial: bool, is_semaphore: bool, count: u32) u64 {
    const c = &(ctx orelse return 0);
    for (&c.events, 0..) |*ev, i| {
        if (!ev.in_use) {
            ev.* = .{
                .in_use = true,
                .signaled = initial,
                .manual_reset = manual_reset,
                .is_semaphore = is_semaphore,
                .count = count,
            };
            return EVENT_HANDLE_BASE + i;
        }
    }
    return 0; // пул исчерпан
}

/// CreateEventA/W (attrs, manualReset, initial, name) — v0.17.0: РЕАЛЬНОЕ
/// состояние (SetEvent/ResetEvent/Wait работают честно).
fn kCreateEventW(attrs: u64, manual_reset: u64, initial: u64, name_va: u64, wide: bool) u64 {
    _ = attrs;
    if (name_va != 0) {
        if (wide) {
            const nlen = userStrLenW(name_va) orelse 0;
            if (nlen > 0 and nlen <= 64) logf("[WIN32] CreateEvent{c}(name)\n", .{@as(u8, if (wide) 'W' else 'A')});
        } else {
            const nlen = userStrLen(name_va) orelse 0;
            if (nlen > 0 and ops.validate_read(name_va, @min(nlen, 64))) {
                logf("[WIN32] CreateEvent{c}(\"{s}\")\n", .{ @as(u8, if (wide) 'W' else 'A'), userPtr(name_va)[0..@intCast(@min(nlen, 64))] });
            }
        }
    } else {
        logf("[WIN32] CreateEvent{c}(unnamed)\n", .{@as(u8, if (wide) 'W' else 'A')});
    }
    const h = eventAlloc(manual_reset != 0, initial != 0, false, 0);
    if (h == 0) setLastError(8); // ERROR_NOT_ENOUGH_MEMORY
    return h;
}

/// SetEvent(h): сигнал (auto-reset сбросится первым же ждущим Wait'ом).
fn kSetEvent(h: u64) u64 {
    const ev = eventByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    ev.signaled = true;
    return 1;
}

/// ResetEvent(h): снять сигнал.
fn kResetEvent(h: u64) u64 {
    const ev = eventByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    ev.signaled = false;
    return 1;
}

/// CreateSemaphoreW(attrs, initial, max, name): счётчик-семафор пула 0x200+.
fn kCreateSemaphoreW(attrs: u64, initial: u64, maximum: u64, name_va: u64) u64 {
    _ = attrs;
    _ = maximum;
    _ = name_va;
    const h = eventAlloc(true, initial > 0, true, @intCast(@min(initial, 0x7FFFFFFF)));
    logf("[WIN32] CreateSemaphoreW(initial={d}) -> 0x{x}\n", .{ initial, h });
    if (h == 0) setLastError(8);
    return h;
}

/// ReleaseSemaphore(h, n, lpPrev): count += n; *lpPrev = старое.
fn kReleaseSemaphore(h: u64, n: u64, lp_prev: u64) u64 {
    const ev = eventByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    if (!ev.is_semaphore or n == 0 or n > 0x7FFFFFFF) {
        setLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    if (lp_prev != 0 and ops.validate_write(lp_prev, 4)) {
        userD(lp_prev).* = ev.count;
    }
    ev.count = @min(ev.count + @as(u32, @intCast(n)), 0x7FFFFFFF);
    ev.signaled = ev.count > 0;
    return 1;
}

/// OpenEventW(attrs, inherit, name) — имени нет: новый несигнальный auto-event.
fn kOpenEventW(attrs: u64, inherit: u64, name_va: u64) u64 {
    _ = attrs;
    _ = inherit;
    _ = name_va;
    logf("[WIN32] OpenEventW(name) -> новый auto-event (имён-каталога нет)\n", .{});
    return eventAlloc(false, false, false, 0);
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
    // v0.16.0 (CDD №7): живое время из CMOS RTC (ядро) — X509-verify
    // OpenSSL сверяет notBefore/notAfter с time(NULL); статика 2026-01-01
    // проваливала свежие сертификаты («not yet valid (9)»). Фолбэк — прежняя
    // константа (тесты без wall_time видят старое поведение).
    const now: u64 = if (ops.wall_time) |f| f() else 1767225600;
    if (t != 0 and ops.validate_write(t, 8)) {
        std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(t))), now, .little);
    }
    return now;
}

/// GetSystemTimeAsFileTime(lpSystemTimeAsFileTime): 64-бит FILETIME
/// (100нс-интервалы с 1601-01-01). 2026-01-01 = 133951872000000000.
fn kGetSystemTimeAsFileTime(lp: u64) u64 {
    if (lp == 0 or !ops.validate_write(lp, 8)) return 0;
    // v0.16.0 (CDD №7): FILETIME = (Unix + 11644473600) × 10⁷ — живой RTC
    // (или статика v0.12-эпохи, если wall_time не установлен — тесты).
    const unix: u64 = if (ops.wall_time) |f| f() else 13395187200;
    const ft: u64 = (unix + 11644473600) * 10_000_000;
    std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(userPtr(lp))), ft, .little);
    return 0;
}

/// GetTickCount64(): миллисекунды с бута — TSC/частота.
fn kGetTickCount64() u64 {
    if (ctx) |c| {
        if (c.tsc_freq > 1000) return ops.read_tsc() / (c.tsc_freq / 1000);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// v0.17.0 (CDD №8): 7-Zip-волна — CPU/память/события/время/файлы
// ═══════════════════════════════════════════════════════════════════════════

/// GetTickCount(): младшие 32 бита ms-счётчика (wrap ~49 суток — Win32).
fn getTickCount() u64 {
    return @truncate(kGetTickCount64());
}

/// GetSystemTimeAsFileTime-обёртка: текущий FILETIME (u64, 100нс от 1601).
fn currentFileTime() u64 {
    const unix: u64 = if (ops.wall_time) |f| f() else 13395187200;
    return (unix + 11644473600) * 10_000_000;
}

/// SYSTEM_INFO (Win64, 48Б!): MSVC-лейаут —
/// {0: WORD wProcessorArchitecture, 2: WORD wReserved,
///  4: DWORD dwPageSize, 8: LPVOID lpMinAppAddr, 16: LPVOID lpMaxAppAddr,
///  24: DWORD_PTR dwActiveProcessorMask, 32: DWORD dwNumberOfProcessors,
///  36: DWORD dwProcessorType, 40: DWORD dwAllocationGranularity,
///  44: WORD wProcessorLevel, 46: WORD wProcessorRevision} — 48 БАЙТ.
/// ⚠ УРОК CDD №8: первый вариант писал «56-64Б-лейаут» со сдвинутыми полями
/// — memset/write ПЕРЕЗАПИСАЛ слот возврата вызывающего (7za: `SYSTEM_INFO
/// si` = 48Б локал) → ret на 0 → #PF(RIP=0, CR2=0, err=0x15) после
/// GetSystemInfo. Верифицировано трассой QEMU -d exec,in_asm.
/// 7-Zip benchmark читает dwNumberOfProcessors (число тредов).
fn getSystemInfo(lp: u64) u64 {
    if (lp == 0) return 0;
    if (!ops.validate_write(lp, 48)) return 0;
    const page = userPtr(lp);
    @memset(page[0..48], 0);
    std.mem.writeInt(u16, page[0..2], 9, .little); // PROCESSOR_ARCHITECTURE_AMD64
    std.mem.writeInt(u16, page[2..4], 0, .little); // wReserved
    std.mem.writeInt(u32, page[4..8], 4096, .little); // dwPageSize
    userQ(lp + 8).* = 0x10000; // lpMinimumApplicationAddress
    userQ(lp + 16).* = 0x0000_7FFF_FFFF_FFFF; // lpMaximumApplicationAddress
    userQ(lp + 24).* = 0xFF; // dwActiveProcessorMask
    std.mem.writeInt(u32, page[32..36], @truncate(ops.cpu_count()), .little); // dwNumberOfProcessors
    std.mem.writeInt(u32, page[36..40], 8664, .little); // dwProcessorType
    std.mem.writeInt(u32, page[40..44], 65536, .little); // dwAllocationGranularity
    std.mem.writeInt(u16, page[44..46], 0, .little); // wProcessorLevel
    std.mem.writeInt(u16, page[46..48], 0, .little); // wProcessorRevision
    logf("[WIN32] GetSystemInfo -> {d} CPU (AMD64)\n", .{ops.cpu_count()});
    return 0;
}

/// MEMORYSTATUSEX (64-80Б): {0: DWORD dwLength, 4: dwMemoryLoad,
/// 8: u64 ullTotalPhys, 16: ullAvailPhys, 24: TotalPage, 32: AvailPage,
/// 40: TotalVirtual, 48: AvailVirtual, 56: ullAvailExtendedVirtual}.
/// Ядро знает реальную физ-память через ops.phys_mem_kb (PMM-статистика).
fn globalMemoryStatusEx(lp: u64) u64 {
    if (lp == 0) return 0;
    if (!ops.validate_write(lp, 64)) return 0;
    const page = userPtr(lp);
    const struct_len = std.mem.readInt(u32, page[0..4], .little);
    _ = struct_len;
    @memset(page[0..64], 0);
    std.mem.writeInt(u32, page[0..4], 64, .little); // dwLength
    const total_kb = ops.phys_mem_kb();
    const total: u64 = total_kb * 1024;
    std.mem.writeInt(u32, page[4..8], 30, .little); // dwMemoryLoad (30%)
    userQ(lp + 8).* = total; // ullTotalPhys
    userQ(lp + 16).* = total / 2; // ullAvailPhys
    userQ(lp + 24).* = 0; // page-файла нет
    userQ(lp + 32).* = 0;
    userQ(lp + 40).* = 0x0000_7FFF_FFFF_FFFF; // TotalVirtual
    userQ(lp + 48).* = 0x0000_7FFF_FFFF_FFFF / 2;
    userQ(lp + 56).* = 0;
    logf("[WIN32] GlobalMemoryStatusEx: Total={d}КБ\n", .{total_kb});
    return 1;
}

/// OSVERSIONINFOW ({-4: dwOSVersionInfoSize, 0: major, 4: minor, 8: build,
/// 12: platform, 16: szCSDVersion[128]}) — Win10-совместимо (OS_ACTUAL).
fn getVersionExW(lp: u64) u64 {
    if (lp == 0) return 0;
    if (!ops.validate_write(lp, 20)) return 0;
    const page = userPtr(lp);
    @memset(page[0..148], 0);
    std.mem.writeInt(u32, page[0..4], OS_ACTUAL.major, .little);
    std.mem.writeInt(u32, page[4..8], OS_ACTUAL.minor, .little);
    std.mem.writeInt(u32, page[8..12], OS_ACTUAL.build, .little);
    std.mem.writeInt(u32, page[12..16], OS_ACTUAL.platform, .little);
    logf("[WIN32] GetVersionExW -> Win{d}.{d} build {d}\n", .{ OS_ACTUAL.major, OS_ACTUAL.minor, OS_ACTUAL.build });
    return 1;
}

/// ResumeThread(h): треды CREATE_SUSPENDED не создаём — счётчик приостановок
/// 0; честный SUCCESS (возврат prev suspend count).
fn resumeThread(h: u64) u64 {
    _ = h;
    return 0;
}

/// GetProcessTimes(h, lpCreation, lpExit, lpKernel, lpUser):
/// времена процесса (FILETIME): создание = бут, выход = 0, kernel/user
/// делим TSC пополам — бенчмарк 7-Zip печатает CPU Usage из них.
fn getProcessTimes(h: u64, lp_creation: u64, lp_exit: u64, lp_kernel: u64, lp_user: u64) u64 {
    _ = h;
    const now = currentFileTime();
    const cpu_ft: u64 = now / 4; // «четверть времени» — грубая эвристика
    if (lp_creation != 0 and ops.validate_write(lp_creation, 8)) userQ(lp_creation).* = now - 100 * 10_000_000;
    if (lp_exit != 0 and ops.validate_write(lp_exit, 8)) userQ(lp_exit).* = 0;
    if (lp_kernel != 0 and ops.validate_write(lp_kernel, 8)) userQ(lp_kernel).* = cpu_ft;
    if (lp_user != 0 and ops.validate_write(lp_user, 8)) userQ(lp_user).* = cpu_ft;
    return 1;
}

/// SYSTEMTIME {u16 y, m, dow, d, h, min, s, ms} (16Б) из FILETIME (1601-эпоха).
fn fileTimeToSystemTime(lp_ft: u64, lp_st: u64) u64 {
    if (lp_ft == 0 or !ops.validate_read(lp_ft, 8)) return 0;
    if (lp_st == 0 or !ops.validate_write(lp_st, 16)) return 0;
    const ft = userQ(lp_ft).*;
    // 100нс-интервалы → Unix-секунды
    const unix: i64 = @as(i64, @intCast(ft / 10_000_000)) - 11644473600;
    // civil-from-days (Howard Hinnant)
    var days: i64 = @divFloor(unix, 86400);
    var secs: i64 = unix - days * 86400;
    if (secs < 0) {
        secs += 86400;
        days -= 1;
    }
    const z: i64 = days + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: i64 = z - era * 146097;
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m: i64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;
    const page = userPtr(lp_st);
    std.mem.writeInt(u16, page[0..2], @intCast(year), .little);
    std.mem.writeInt(u16, page[2..4], @intCast(m), .little);
    std.mem.writeInt(u16, page[4..6], 0, .little); // день недели (упрощение)
    std.mem.writeInt(u16, page[6..8], @intCast(d), .little);
    std.mem.writeInt(u16, page[8..10], @intCast(@divFloor(secs, 3600)), .little);
    std.mem.writeInt(u16, page[10..12], @intCast(@mod(@divFloor(secs, 60), 60)), .little);
    std.mem.writeInt(u16, page[12..14], @intCast(@mod(secs, 60)), .little);
    std.mem.writeInt(u16, page[14..16], 0, .little);
    return 1;
}

/// FileTimeToLocalFileTime / LocalFileTimeToFileTime: часовой пояс UTC
/// (CMOS-RTC даёт UTC) — копирование без сдвига.
fn fileTimeToLocalFileTime(lp_in: u64, lp_out: u64) u64 {
    if (lp_in == 0 or !ops.validate_read(lp_in, 8)) return 0;
    if (lp_out == 0 or !ops.validate_write(lp_out, 8)) return 0;
    userQ(lp_out).* = userQ(lp_in).*;
    return 1;
}
fn localFileTimeToFileTime(lp_in: u64, lp_out: u64) u64 {
    return fileTimeToLocalFileTime(lp_in, lp_out);
}

/// DosDateTimeToFileTime(wDate, wTime, lpFT): дата DOS ( packed y/m/d ) → FT.
fn dosDateTimeToFileTime(w_date: u64, w_time: u64, lp_ft: u64) u64 {
    if (lp_ft == 0 or !ops.validate_write(lp_ft, 8)) return 0;
    const date: u16 = @truncate(w_date);
    const time: u16 = @truncate(w_time);
    const year: i64 = @as(i64, date >> 9) + 1980;
    const month: i64 = (date >> 5) & 0xF;
    const day: i64 = date & 0x1F;
    const hour: i64 = time >> 11;
    const minute: i64 = (time >> 5) & 0x3F;
    const sec2: i64 = (time & 0x1F) * 2;
    // days_from_civil
    const y2: i64 = if (month <= 2) year - 1 else year;
    const m2: i64 = month;
    const era: i64 = @divFloor(if (y2 >= 0) y2 else y2 - 399, 400);
    const yoe: i64 = y2 - era * 400;
    const mp2: i64 = @mod(m2 + 9, 12);
    const doy: i64 = @divFloor(153 * mp2 + 2, 5) + day - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days: i64 = era * 146097 + doe - 719468;
    const unix: i64 = days * 86400 + hour * 3600 + minute * 60 + sec2;
    userQ(lp_ft).* = @intCast((unix + 11644473600) * 10_000_000);
    return 1;
}

/// FileTimeToDosDateTime(lpFT, lpwDate, lpwTime): обратная конверсия.
fn fileTimeToDosDateTime(lp_ft: u64, lp_date: u64, lp_time: u64) u64 {
    if (lp_ft == 0 or !ops.validate_read(lp_ft, 8)) return 0;
    const ft = userQ(lp_ft).*;
    const unix: i64 = @as(i64, @intCast(ft / 10_000_000)) - 11644473600;
    var days: i64 = @divFloor(unix, 86400);
    const secs: i64 = unix - days * 86400;
    _ = &days;
    const z: i64 = days + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: i64 = z - era * 146097;
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m: i64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;
    if (year < 1980 or year > 2107) return 0;
    if (lp_date != 0 and ops.validate_write(lp_date, 2)) {
        const dw: u16 = (@as(u16, @intCast(year - 1980)) << 9) | (@as(u16, @intCast(m)) << 5) | @as(u16, @intCast(d));
        std.mem.writeInt(u16, userPtr(lp_date)[0..2], dw, .little);
    }
    if (lp_time != 0 and ops.validate_write(lp_time, 2)) {
        const tw: u16 = (@as(u16, @intCast(@divFloor(secs, 3600))) << 11) |
            (@as(u16, @intCast(@mod(@divFloor(secs, 60), 60))) << 5) |
            @as(u16, @intCast(@divFloor(@mod(secs, 60), 2)));
        std.mem.writeInt(u16, userPtr(lp_time)[0..2], tw, .little);
    }
    return 1;
}

/// CompareFileTime(lpFT1, lpFT2): -1/0/1.
fn compareFileTime(lp1: u64, lp2: u64) u64 {
    if (lp1 == 0 or lp2 == 0 or !ops.validate_read(lp1, 8) or !ops.validate_read(lp2, 8)) return 0;
    const a = userQ(lp1).*;
    const b = userQ(lp2).*;
    return if (a < b) @as(u64, @bitCast(@as(i64, -1))) else if (a > b) 1 else 0;
}

/// BY_HANDLE_FILE_INFORMATION (52Б): {0: attrs, 8: index/serial, 24: nlinks,
/// 32: size_lo+hi(u64)}. v0.17.0: реальный размер VFS-файла.
fn getFileInformationByHandle(h: u64, lp: u64) u64 {
    const f = fileByHandle(h) orelse {
        setLastError(ERROR_INVALID_HANDLE_FILE);
        return 0;
    };
    if (lp == 0 or !ops.validate_write(lp, 52)) {
        setLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const page = userPtr(lp);
    @memset(page[0..52], 0);
    std.mem.writeInt(u32, page[0..4], 0x80, .little); // FILE_ATTRIBUTE_NORMAL
    std.mem.writeInt(u32, page[24..28], 1, .little); // nNumberOfLinks
    std.mem.writeInt(u64, page[32..40], f.size, .little); // file size
    return 1;
}

/// GetModuleFileNameW(hModule, lpFilename, nSize): путь образа «C:\7za.exe».
fn getModuleFileNameW(h_module: u64, lp: u64, n: u64) u64 {
    _ = h_module;
    if (lp == 0 or n < 8 or !ops.validate_write(lp, n * 2)) return 0;
    const path = "C:\\7za.exe"; // имя образа (cmdline[0] с путём — beyond-model)
    var i: usize = 0;
    while (i < path.len and i < n - 1) : (i += 1) {
        userW(lp + i * 2).* = path[i];
    }
    userW(lp + i * 2).* = 0;
    return i; // cch без NUL
}

/// WideCharToMultiByte(cp, flags, src(w), cch, dst, cb, lpDefault, lpUsed):
/// UTF-16LE → ANSI/UTF-8 (ASCII-путь; зеркала kMultiByteToWideChar).
fn kWideCharToMultiByte(src_va: u64, cch: u64, dst_va: u64, cb: u64) u64 {
    var n: u64 = 0;
    var nul_term = false;
    if (@as(i64, @bitCast(cch)) == -1) {
        const len = userStrLenW(src_va) orelse return 0;
        n = len + 1;
        nul_term = true;
    } else {
        n = cch;
    }
    if (n > 16 * 1024 * 1024) return 0;
    // Только длину?
    if (dst_va == 0 or cb == 0) {
        if (nul_term) return n;
        return n;
    }
    const out_len = @min(n, cb);
    var i: u64 = 0;
    while (i < out_len) : (i += 1) {
        const w = userW(src_va + i * 2).*;
        userPtr(dst_va)[@intCast(i)] = if (w < 128) @intCast(w) else '?';
    }
    return out_len;
}

/// GetLogicalDriveStringsW(n, lp): «C:\<NUL><NUL>».
fn getLogicalDriveStringsW(n: u64, lp: u64) u64 {
    const need = 4; // "C:\" + NUL + завершающий NUL
    if (lp == 0 or n == 0) return need;
    if (!ops.validate_write(lp, n * 2)) return 0;
    if (n < 4) return 0;
    const s = "C:\\";
    var i: usize = 0;
    while (i < 3) : (i += 1) userW(lp + i * 2).* = s[i];
    userW(lp + 3 * 2).* = 0;
    userW(lp + 4 * 2).* = 0;
    return 4;
}

/// GetTempPathW(n, lp): «\tmp\» (VFS-корень; FС-пути нормализуются).
fn getTempPathW(n: u64, lp: u64) u64 {
    const s = "\\tmp\\";
    const need = s.len + 1;
    if (lp == 0 or n == 0) return need;
    if (!ops.validate_write(lp, n * 2)) return 0;
    if (n < need) return need;
    var i: usize = 0;
    while (i < s.len) : (i += 1) userW(lp + i * 2).* = s[i];
    userW(lp + s.len * 2).* = 0;
    return s.len;
}

/// GetDiskFreeSpaceW(root, lpSectorsPerCluster, lpBytesPerSector,
/// lpFreeClusters, lpTotalClusters): FAT32-геометрия диска (кластер 4096,
/// сектор 512; свободно — по FAT32-статистике ядра, упрощённо половина).
fn getDiskFreeSpaceW(root: u64, lp_spc: u64, lp_bps: u64, lp_free: u64, lp_total: u64) u64 {
    _ = root;
    if (lp_spc != 0 and ops.validate_write(lp_spc, 4)) userD(lp_spc).* = 8;
    if (lp_bps != 0 and ops.validate_write(lp_bps, 4)) userD(lp_bps).* = 512;
    const total_clusters: u32 = 16348; // 64МБ-образ (make-fat32.py)
    if (lp_total != 0 and ops.validate_write(lp_total, 4)) userD(lp_total).* = total_clusters;
    if (lp_free != 0 and ops.validate_write(lp_free, 4)) userD(lp_free).* = total_clusters / 2;
    return 1;
}

/// DeleteFileW(name): удаление VFS-файла (FAT32) через ops.vfs_file_delete.
fn deleteFileW(name_va: u64) u64 {
    if (name_va == 0) return 0;
    const len = userStrLenW(name_va) orelse return 0;
    if (len == 0 or len > MAX_PATH_LEN - 2) {
        setLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    var raw: [MAX_PATH_LEN]u8 = undefined;
    var i: u64 = 0;
    while (i < len) : (i += 1) {
        const ch = userW(name_va + i * 2).*;
        raw[@intCast(i)] = if (ch < 128) @intCast(ch) else '?';
    }
    const norm_buf: *[MAX_PATH_LEN]u8 = &vfs_norm_scratch;
    const norm = vfsNormalizePath(raw[0..@intCast(len)], norm_buf) orelse {
        setLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    if (ops.vfs_file_delete(norm.ptr, norm.len) == 1) {
        logf("[WIN32] DeleteFileW(\"{s}\") -> TRUE\n", .{norm});
        return 1;
    }
    setLastError(ERROR_FILE_NOT_FOUND);
    return 0;
}

/// GetFileAttributesW(name): файл VFS → FILE_ATTRIBUTE_NORMAL.
fn getFileAttributesW(name_va: u64) u64 {
    const found = vfsOpenByNameW(name_va) orelse {
        setLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    };
    _ = found;
    return FILE_ATTRIBUTE_NORMAL;
}

/// WIN32_FIND_DATAW (592Б): минимально валидная запись — имя, размер,
/// атрибуты. v0.17.0: существование файла проверяем через VFS (первый
/// вызов); FindNext — FALSE ERROR_NO_MORE_FILES (одна запись на паттерн).
fn findFirstFileW(pattern_va: u64, lp: u64) u64 {
    const found = vfsOpenByNameW(pattern_va) orelse {
        setLastError(2); // ERROR_FILE_NOT_FOUND
        return 0xFFFFFFFF_FFFF_FFFF; // INVALID_HANDLE_VALUE
    };
    if (lp == 0 or !ops.validate_write(lp, 592)) {
        setLastError(87);
        return 0xFFFFFFFF_FFFF_FFFF;
    }
    const page = userPtr(lp);
    @memset(page[0..592], 0);
    std.mem.writeInt(u32, page[0..4], 0x80, .little); // dwFileAttributes
    std.mem.writeInt(u64, page[28..36], found.size, .little); // nFileSize (64Б в x64)
    // cFileName @44: utf-16 имя
    var i: usize = 0;
    while (i < found.norm.len and i < 259) : (i += 1) {
        userW(lp + 44 + i * 2).* = found.norm[i];
    }
    userW(lp + 44 + i * 2).* = 0;
    return 0xBEEF; // псевдо-хэндл поиска (одна запись)
}

fn findNextFileW(h: u64, lp: u64) u64 {
    _ = h;
    _ = lp;
    setLastError(18); // ERROR_NO_MORE_FILES
    return 0;
}

/// GetCurrentDirectoryW(n, lp): «\» (корень VFS).
fn getCurrentDirectoryW(n: u64, lp: u64) u64 {
    if (n == 0 or lp == 0) return 2;
    if (!ops.validate_write(lp, n * 2)) return 0;
    if (n < 2) return 2;
    userW(lp).* = '\\';
    userW(lp + 2).* = 0;
    return 1;
}

/// vfsOpenByName для W-строк (GetFileAttributesW/FindFirstFileW).
fn vfsOpenByNameW(path_va: u64) ?VfsFound {
    if (path_va == 0) return null;
    const len = userStrLenW(path_va) orelse return null;
    if (len == 0 or len > MAX_PATH_LEN - 2) return null;
    var raw: [MAX_PATH_LEN]u8 = undefined;
    var i: u64 = 0;
    while (i < len) : (i += 1) {
        const ch = userW(path_va + i * 2).*;
        raw[@intCast(i)] = if (ch < 128) @intCast(ch) else '?';
    }
    const norm_buf: *[MAX_PATH_LEN]u8 = &vfs_norm_scratch;
    const norm = vfsNormalizePath(raw[0..@intCast(len)], norm_buf) orelse return null;
    const size = ops.vfs_file_size(norm.ptr, norm.len);
    if (size == VFS_NOT_FOUND) return null;
    return .{ .norm = norm, .size = size };
}

/// VirtualFree(addr, size, type): MEM_DECOMMIT(2)/MEM_RELEASE(0x8000).
/// vheap — page-bump: «декоммит» = обнуление страниц (маска NX остаётся);
/// возврат TRUE (7-Zip не проверяет содержимое после освобождения).
fn virtualFree(addr: u64, size: u64, free_type: u64) u64 {
    _ = free_type;
    if (addr == 0) {
        setLastError(87);
        return 0;
    }
    if (size == 0) return 1; // size=0 с MEM_RELEASE — валидно
    // Обнуляем (не снимаем маппинг — bump-аллокатор не переиспользует)
    var off: u64 = 0;
    while (off < size) : (off += 4096) {
        const va = addr + off;
        if (ops.validate_write(va, 4096)) {
            @memset(userPtr(va)[0..4096], 0);
        } else break;
    }
    logf("[WIN32] VirtualFree(0x{x}, {d}Б) -> TRUE (обнуление)\n", .{ addr, size });
    return 1;
}

/// CharUpperW(lpsz): in-place верхний регистр (ASCII-диапазон).
fn kCharUpperW(s_va: u64) u64 {
    if (s_va == 0) return 0;
    const len = userStrLenW(s_va) orelse return s_va;
    var i: u64 = 0;
    while (i < len) : (i += 1) {
        const w = userW(s_va + i * 2).*;
        if (w >= 'a' and w <= 'z') {
            userW(s_va + i * 2).* = w - 32;
        }
    }
    return s_va;
}

/// Condition-variable семья (curl: CV+CS = синхронизация резолвера):
/// v0.15.0 (CDD №6): НАСТОЯЩИЙ сон — парковка задачи до wake_tick
/// (мс-таймаут честный; пробуждения по WakeConditionVariable нет —
/// поллинговая семантика таймаута, как у Windows при занятой очереди).
/// Возврат TRUE = «CV свободна» (пользователь воспринимает как пробуждение).
fn kSleepConditionVariableCS(cv: u64, cs: u64, ms: u64) u64 {
    logf("[WIN32] SleepConditionVariableCS(0x{x}, ms={d}) — парковка\n", .{ cv, ms });
    _ = cs;
    ops.sleep_task(ms);
    return 1;
}

// ─── v0.12.0 (CDD №3, event-волна): stdio-интроспекция + конверсия ─────────

/// _fileno(FILE*): stdin/stdout/stderr → 0/1/2 (по позиции в iob-массиве),
/// наш VFS-FILE* → 3+idx (lowio-fd); чужой FILE* → -1. Статическая модель CRT.
fn kfileno(file: u64) u64 {
    const c = &(ctx orelse return @bitCast(@as(i64, -1)));
    if (file == 0) return @bitCast(@as(i64, -1));
    if (crtFileIdx(file)) |idx| return 3 + idx; // v0.16.0: VFS-файл
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

/// _get_osfhandle(fd): int fd → Win32 HANDLE (mingw-UCRT печатает тело
/// ответа fwrite'ом через osfhandle-путь; 0/1/2 → stdio-псевдохэндлы;
/// v0.16.0: fd ≥3 → файловый хэндл 0x800+idx VFS).
fn kGetOsfHandle(fd: u64) u64 {
    const h: u64 = if (fd >= 3 and fd < 3 + MAX_FILES)
        FILE_HANDLE_BASE + (fd - 3) // VFS-файл
    else
        switch (fd) {
            0 => FAKE_STDIN,
            1 => FAKE_STDOUT,
            2 => FAKE_STDERR,
            else => 0xFFFFFFFF_FFFF_FFFF, // -1: не-stdio fd
        };
    logf("[WIN32] _get_osfhandle({d}) -> 0x{x}\n", .{ fd, h });
    return h;
}

/// MultiByteToWideChar(cp, flags, src, cb, dst, cch): ANSI/UTF-8 →
/// UTF-16LE. ASCII-маппинг (байт → u16); не-ASCII байты — '.' (честный
/// CDD: реальная таблица CP — цикл №5 при не-ASCII потребности).
/// cb=-1: NUL-терминированный источник (NUL копируется, входит в счёт).
/// dst=0/cch=0: только ДЛИНА (UCRT-двухфазный вызов). 0 = неудача.
fn kMultiByteToWideChar(src_va: u64, cb_in: u64, dst_va: u64, cch: u64) u64 {
    const cp_flags_unused = true; // cp/flags: CP_ACP/CP_UTF8 экв. для ASCII
    _ = cp_flags_unused;
    // Длина источника
    var n: u64 = 0;
    var nul_term = false;
    if (@as(i64, @bitCast(cb_in)) == -1) {
        const len = userStrLen(src_va) orelse return 0; // битый указатель
        n = len + 1; // с NUL
        nul_term = true;
    } else {
        n = cb_in;
        if (n > MAX_STR_LEN) return 0;
    }
    if (n > 0 and !ops.validate_read(src_va, n)) return 0;

    // Двухфазность: запрос длины
    if (dst_va == 0 or cch == 0) {
        return n;
    }
    if (cch < n) {
        setLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    if (!ops.validate_write(dst_va, n * 2)) return 0;

    // Копирование ASCII → UTF-16LE
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        var ch: u16 = userPtr(src_va)[@as(usize, @intCast(i))];
        if (ch >= 0x80) {
            ch = '.'; // не-ASCII — CDD-граница (таблицы CP: цикл №5)
        }
        if (nul_term and i + 1 == n) ch = 0; // завершающий NUL
        userW(dst_va + i * 2).* = ch;
    }
    logf("[WIN32] MultiByteToWideChar: {d} симв\n", .{n});
    return n;
}

/// WriteConsoleW(h, lpBuffer(WCHAR*), nChars, lpWritten, lpReserved):
/// ФИНАЛ печати: UTF-16LE-буфер → консоль ОС (побайтово в UTF-8-терминал).
/// UCRT: fwrite(stdout) → MB2WC → WriteConsoleW. Тело «Hello POLER!»
/// приходит сюда (v0.13.0, CDD №4 — замыкание HTTP-обмена).
fn kWriteConsoleW(handle: u64, buf_va: u64, n_chars: u64, lp_written: u64) u64 {
    _ = handle;
    if (n_chars > MAX_STR_LEN) return 0;
    if (n_chars > 0 and !ops.validate_read(buf_va, n_chars * 2)) return 0;
    var utf8: [512]u8 = undefined;
    var n: usize = 0;
    var i: u64 = 0;
    while (i < n_chars and n < utf8.len) : (i += 1) {
        const ch = userW(buf_va + i * 2).*;
        if (ch < 0x80) {
            utf8[n] = @intCast(ch);
            n += 1;
        } else if (ch < 0x800 and n + 2 < utf8.len) {
            // 2-байтовый UTF-8
            utf8[n] = @intCast(0xC0 | (ch >> 6));
            utf8[n + 1] = @intCast(0x80 | (ch & 0x3F));
            n += 2;
        } else if (n + 3 < utf8.len) {
            utf8[n] = 0xE0;
            utf8[n + 1] = @intCast(0x80 | ((ch >> 6) & 0x3F));
            utf8[n + 2] = @intCast(0x80 | (ch & 0x3F));
            n += 3;
        }
    }
    if (n > 0) ops.write_console(utf8[0..n]);
    if (lp_written != 0 and ops.validate_write(lp_written, 4)) {
        userD(lp_written).* = @intCast(n_chars); // все символы «записаны»
    }
    return 1; // BOOL TRUE
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

/// _fsopen(path, mode, share) — v0.16.0 (CDD №7): VFS (CPIO initrd +
/// FAT32 через ядро). Читаемые режимы → FILE*-блок с FileState-слотом;
/// файл не найден → NULL + ENOENT; запись → NULL + EACCES (RO-VFS).
fn kfsopen(path_va: u64, mode_va: u64, share: u64) u64 {
    _ = share; // share-mode не влияет на RO-чтение
    return kfopenCommon(path_va, mode_va, "_fsopen");
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
    // v0.16.0 (CDD №7): файловые хэндлы освобождают слот VFS
    if (h >= FILE_HANDLE_BASE and h < FILE_HANDLE_BASE + MAX_FILES) {
        if (ctx) |*c| {
            const idx: usize = @intCast(h - FILE_HANDLE_BASE);
            if (c.files[idx].in_use) {
                c.files[idx].in_use = false;
                logf("[WIN32] CloseHandle(0x{x}) -> TRUE (VFS-файл закрыт)\n", .{h});
                return 1;
            }
        }
    }
    // v0.17.0 (CDD №8): события/семафоры — освобождение слота пула
    if (h >= EVENT_HANDLE_BASE and h < EVENT_HANDLE_BASE + MAX_EVENTS) {
        if (ctx) |*c| {
            const idx: usize = @intCast(h - EVENT_HANDLE_BASE);
            if (c.events[idx].in_use) {
                c.events[idx].in_use = false;
                logf("[WIN32] CloseHandle(0x{x}) -> TRUE (event закрыт)\n", .{h});
                return 1;
            }
        }
    }
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

/// v0.17.0 (CDD №8): ветка msvcrt.dll (MSVC-CRT — 7-Zip). __getmainargs/
/// _initterm — стартовый путь CRT; memset/memcpy — syscall-фолбэки
/// (main64 регистрирует NATIVE-стабы для горячих CRT-функций).
fn dispatchMsvcrt(name: []const u8, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    if (std.mem.eql(u8, name, "__getmainargs")) {
        // (pargc:int*, pargv:char***, penvp:char***, doWildcard, si)
        return kGetMainArgs(a1, a2, a3);
    } else if (std.mem.eql(u8, name, "__set_app_type")) {
        return 0; // void
    } else if (std.mem.eql(u8, name, "__setusermatherr")) {
        return 0; // void
    } else if (std.mem.eql(u8, name, "_XcptFilter")) {
        return @bitCast(@as(i64, -1)); // EXCEPTION_CONTINUE_SEARCH
    } else if (std.mem.eql(u8, name, "_onexit") or std.mem.eql(u8, name, "__dllonexit")) {
        return a1; // «зарегистрировано» — вернуть саму функцию
    } else if (std.mem.eql(u8, name, "_purecall")) {
        logf("[WIN32] msvcrt!_purecall — вызов чистой виртуальной функции!\n", .{});
        return 0;
    } else if (std.mem.eql(u8, name, "_CxxThrowException")) {
        logf("[WIN32] msvcrt!_CxxThrowException — исключение (обработчика нет)\n", .{});
        return 0;
    } else if (std.mem.eql(u8, name, "__CxxFrameHandler")) {
        return @bitCast(@as(i64, -1)); // ExceptionContinueSearch
    } else if (std.mem.eql(u8, name, "__C_specific_handler")) {
        return @bitCast(@as(i64, 1)); // ExceptionContinueExecution
    } else if (std.mem.eql(u8, name, "??1type_info@@UEAA@XZ")) {
        return 0; // деструктор type_info — no-op
    } else if (std.mem.eql(u8, name, "?terminate@@YAXXZ")) {
        return 0; // terminate-обработчика нет — no-op (CDD-честно)
    } else if (std.mem.eql(u8, name, "_beginthreadex")) {
        // (security, stack, start, arg, flags, thrd) — CreateThread-эквивалент
        return kCreateThreadThunk(a1, a2, a3, a4);
    } else if (std.mem.eql(u8, name, "exit") or std.mem.eql(u8, name, "_exit")) {
        ops.exit(a1);
        return 0;
    } else if (std.mem.eql(u8, name, "_cexit") or std.mem.eql(u8, name, "_c_exit")) {
        return 0; // очистка CRT — no-op (консоль уже синхронна)
    } else if (std.mem.eql(u8, name, "malloc")) {
        return kmalloc(a1);
    } else if (std.mem.eql(u8, name, "free")) {
        kfree(a1);
        return 0;
    } else if (std.mem.eql(u8, name, "realloc")) {
        return krealloc(a1, a2);
    } else if (std.mem.eql(u8, name, "memset")) {
        return kmemset(a1, a2, a3);
    } else if (std.mem.eql(u8, name, "memcpy")) {
        return kmemcpy(a1, a2, a3);
    } else if (std.mem.eql(u8, name, "memmove")) {
        return kmemmove(a1, a2, a3);
    } else if (std.mem.eql(u8, name, "memcmp")) {
        return kmemcmp(a1, a2, a3);
    } else if (std.mem.eql(u8, name, "strlen")) {
        return userStrLen(a1) orelse 0;
    } else if (std.mem.eql(u8, name, "strcmp")) {
        return kstrcmp(a1, a2);
    } else if (std.mem.eql(u8, name, "wcscmp")) {
        return kwcscmp(a1, a2);
    } else if (std.mem.eql(u8, name, "wcsstr")) {
        return kwcsstr(a1, a2);
    } else if (std.mem.eql(u8, name, "fflush")) {
        return 0; // консоль синхронна
    } else if (std.mem.eql(u8, name, "fputc")) {
        return fputc(a1, a2);
    } else if (std.mem.eql(u8, name, "fputs")) {
        return fputs(a1, a2);
    } else if (std.mem.eql(u8, name, "fgetc")) {
        return kfgetc(a1);
    } else if (std.mem.eql(u8, name, "fclose")) {
        return kfclose(a1);
    } else if (std.mem.eql(u8, name, "_isatty")) {
        return kisatty(a1);
    } else if (std.mem.eql(u8, name, "_iob")) {
        // DATA-импорт — сюда не должен попадать (patchDataImports);
        // на всякий случай: блок _iob (если ядро его выдало)
        if (ctx) |c| return c.iob_block;
        return 0;
    } else if (std.mem.eql(u8, name, "_fmode") or std.mem.eql(u8, name, "_commode") or
        std.mem.eql(u8, name, "__initenv"))
    {
        // DATA-импорт: возвращаем указатель на блок (записываемый) — fallback
        if (ctx) |c| return if (c.iob_block != 0) c.iob_block else 0;
        return 0;
    }
    logf("[WIN32] msvcrt!{s} — нет реализации (CDD-кандидат)\n", .{name});
    return 0;
}

/// __getmainargs(pargc, pargv, penvp, doWildcard, si): argc/argv/envp.
/// ensureArgv строит массив в user-куче; env-массив — из env-таблицы.
fn kGetMainArgs(pargc: u64, pargv: u64, penvp: u64) u64 {
    const c = &(ctx orelse return 0);
    ensureArgv();
    // argc
    if (pargc != 0 and ops.validate_write(pargc, 4)) {
        if (c.argc_ptr != 0) {
            userD(pargc).* = userD(c.argc_ptr).*;
        } else {
            userD(pargc).* = 0;
        }
    }
    // argv = *argv_slot (сам массив)
    if (pargv != 0 and ops.validate_write(pargv, 8)) {
        if (c.argv_slot != 0 and ops.validate_read(c.argv_slot, 8)) {
            userQ(pargv).* = userQ(c.argv_slot).*;
            c.argv_arr = userQ(c.argv_slot).*;
        } else {
            userQ(pargv).* = 0;
        }
    }
    // envp: массив строк «NAME=VALUE\0…» + NUL-финализатор
    if (penvp != 0 and ops.validate_write(penvp, 8)) {
        if (c.env_arr == 0) {
            var total: usize = 0;
            for (env_table) |e| total += e.name.len + 1 + e.value.len + 1;
            total += 1; // финальный NUL-байт двойной терминаторы
            const blk = kmalloc(total + 8);
            if (blk != 0) {
                var off: usize = 0;
                const page = userPtr(blk);
                for (env_table) |e| {
                    @memcpy(page[off..][0..e.name.len], e.name);
                    off += e.name.len;
                    page[off] = '=';
                    off += 1;
                    @memcpy(page[off..][0..e.value.len], e.value);
                    off += e.value.len;
                    page[off] = 0;
                    off += 1;
                }
                page[off] = 0; // terminator
                c.env_arr = blk;
            }
        }
        userQ(penvp).* = c.env_arr;
    }
    logf("[WIN32] __getmainargs: argc={d}, argv=0x{x}, envp=0x{x}\n", .{
        if (pargc != 0 and ops.validate_read(pargc, 4)) userD(pargc).* else 0,
        if (pargv != 0 and ops.validate_read(pargv, 8)) userQ(pargv).* else 0,
        if (penvp != 0 and ops.validate_read(penvp, 8)) userQ(penvp).* else 0,
    });
    return 0; // успех
}

/// _beginthreadex(security, stack, start, arg, flags, thrd): хэндл треда.
/// (Диспетчер передаёт RCX/RDX/R8/R9; 5-й/6-й аргументы — стек — читает
/// CreateThread-обёртка ниже через ops.stack_arg.)
fn kCreateThreadThunk(security: u64, stack: u64, start: u64, arg: u64) u64 {
    _ = security;
    // dispatch не имеет disp-контекста здесь — передаём как CreateThread:
    // flags = стек[0] (5-й арг), pTid = стек[1] (6-й арг)
    const flags = ops.stack_arg(0);
    const p_tid = ops.stack_arg(1);
    _ = stack; // размер ниже сглаживается в kCreateThread
    // Находим активный Dispatcher (как syscallDispatch)
    const disp = win32.activeDispatcher() orelse return 0;
    return kCreateThread(disp, 0x40000, start, arg, flags, p_tid);
}

/// kmemcmp-msvcrt-обёртка — существующий pub kmemcmp переиспользуем (см. ниже).
fn kmemcmpMsvcrt(a: u64, b: u64, n: u64) u64 {
    return kmemcmp(a, b, n);
}

/// kstrcmp(a, b): 0/±1 (семантика strcmp, только знак).
fn kstrcmp(a: u64, b: u64) u64 {
    const la = userStrLen(a) orelse return @bitCast(@as(i64, -1));
    const lb = userStrLen(b) orelse return 1;
    if (!ops.validate_read(a, la + 1) or !ops.validate_read(b, lb + 1)) return 0;
    const x = userPtr(a)[0..@intCast(la)];
    const y = userPtr(b)[0..@intCast(lb)];
    const rel = std.mem.order(u8, x, y);
    return switch (rel) {
        .eq => 0,
        .lt => @bitCast(@as(i64, -1)),
        .gt => 1,
    };
}

/// kwcscmp(a, b): 0/±1 по UTF-16LE строкам.
fn kwcscmp(a: u64, b: u64) u64 {
    const la = userStrLenW(a) orelse return @bitCast(@as(i64, -1));
    const lb = userStrLenW(b) orelse return 1;
    if (!ops.validate_read(a, (la + 1) * 2) or !ops.validate_read(b, (lb + 1) * 2)) return 0;
    var i: u64 = 0;
    const n = @min(la, lb);
    while (i < n) : (i += 1) {
        const ca = userW(a + i * 2).*;
        const cb = userW(b + i * 2).*;
        if (ca != cb) return if (ca < cb) @bitCast(@as(i64, -1)) else 1;
    }
    if (la == lb) return 0;
    return if (la < lb) @bitCast(@as(i64, -1)) else 1;
}

/// kwcsstr(hay, needle): указатель на ПЕРВОЕ вхождение UTF-16 подстроки.
fn kwcsstr(hay: u64, needle: u64) u64 {
    const lh = userStrLenW(hay) orelse return 0;
    const ln = userStrLenW(needle) orelse return 0;
    if (ln == 0) return hay;
    if (ln > lh) return 0;
    if (!ops.validate_read(hay, (lh + 1) * 2) or !ops.validate_read(needle, (ln + 1) * 2)) return 0;
    var i: u64 = 0;
    while (i + ln <= lh) : (i += 1) {
        var j: u64 = 0;
        var ok = true;
        while (j < ln) : (j += 1) {
            if (userW(hay + (i + j) * 2).* != userW(needle + j * 2).*) {
                ok = false;
                break;
            }
        }
        if (ok) return hay + i * 2;
    }
    return 0;
}

/// fgetc(stream): один байт из VFS-файла (msvcrt-stdin → EOF -1).
fn kfgetc(stream: u64) u64 {
    if (crtFileIdx(stream)) |idx| {
        const c = &(ctx orelse return @bitCast(@as(i64, -1)));
        const f = &c.files[idx];
        if (f.pos >= f.size) {
            f.eof = true;
            return @bitCast(@as(i64, -1)); // EOF
        }
        var b: [1]u8 = .{0};
        const got = ops.vfs_file_read(f.name[0..f.name_len].ptr, f.name_len, f.pos, &b, 1);
        if (got == 0) return @bitCast(@as(i64, -1));
        f.pos += 1;
        return b[0];
    }
    if (isMsvcrtIobStream(stream)) |si| {
        if (si == 0) return @bitCast(@as(i64, -1)); // stdin пуст
    }
    return @bitCast(@as(i64, -1)); // не наш поток — EOF
}

// ─── OLEAUT32 (SysString-семья; 7-Zip shell-пути) ───────────────────────────

/// SysAllocString(olestr): BSTR = 4Б длина + utf-16 + NUL.
fn sysAllocString(src_va: u64) u64 {
    const len = userStrLenW(src_va) orelse return 0;
    return sysAllocStringLen(src_va, len);
}

/// SysAllocStringLen(src, chars): BSTR с копией первых chars символов.
fn sysAllocStringLen(src_va: u64, chars: u64) u64 {
    const bytes: u64 = 4 + (chars + 1) * 2;
    const p = kmalloc(bytes);
    if (p == 0) return 0;
    std.mem.writeInt(u32, userPtr(p)[0..4], @intCast(chars * 2), .little); // длина в байтах
    if (src_va != 0 and chars > 0 and ops.validate_read(src_va, chars * 2)) {
        var i: u64 = 0;
        while (i < chars) : (i += 1) {
            userW(p + 4 + i * 2).* = userW(src_va + i * 2).*;
        }
    } else {
        // «wcslen(src)» если chars=0... по спецификации копирует chars; нули уже есть
    }
    userW(p + 4 + chars * 2).* = 0;
    return p + 4; // BSTR указывает ПЕРЕД полем длины
}

/// SysStringLen(bstr): символов (байт/2).
fn sysStringLen(bstr: u64) u64 {
    if (bstr == 0) return 0;
    if (!ops.validate_read(bstr - 4, 4)) return 0;
    return std.mem.readInt(u32, userPtr(bstr - 4)[0..4], .little) / 2;
}
pub fn dispatch(disp: *win32.Dispatcher, entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    if (entry_id >= disp.count) return 0;
    const e = &disp.entries[@intCast(entry_id)];
    // v0.17.0 (CDD №8): ОРДИНАЛ-импорты — OLEAUT32 (7-Zip: SysAllocString и
    // семья). Ординалы: 2=SysAllocString, 4=SysReAllocString, 6=SysAllocStringLen,
    // 7=SysFreeString, 9=SysStringLen, 10=SysStringByteLen.
    const ordinal: u64 = switch (e.func) {
        .by_name => 0,
        .by_ordinal => |o| o,
    };
    if (ordinal != 0) {
        if (std.ascii.eqlIgnoreCase(e.dll, "OLEAUT32.dll")) {
            switch (ordinal) {
                2 => return sysAllocString(a1), // SysAllocString(OLESTR)
                4 => return 0, // SysReAllocString — FALSE (beyond-model)
                6 => return sysAllocStringLen(a1, a2), // SysAllocStringLen
                7 => return 1, // SysFreeString — TRUE (память в bheap — GC-модель)
                9 => return sysStringLen(a1), // SysStringLen
                10 => return sysStringLen(a1) * 2, // SysStringByteLen
                else => {
                    logf("[WIN32] OLEAUT32!#{d} — не реализован (ординал)\n", .{ordinal});
                    return 0;
                },
            }
        }
        logf("[WIN32] {s}!#{d} — ординал вне OLEAUT32 не реализован\n", .{ e.dll, ordinal });
        return 0;
    }
    const name = switch (e.func) {
        .by_name => |n| n,
        .by_ordinal => unreachable,
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
            std.mem.eql(u8, name, "ReleaseSRWLockExclusive"))
        {
            ret = 0; // no-op: однопоточный CDD-процесс (честная граница)
        } else if (std.mem.eql(u8, name, "Sleep")) {
            // v0.15.0 (CDD №6): НАСТОЯЩИЙ сон — парковка задачи до wake_tick
            // (воркеры не жгут CPU, крипто-тред получает слайсы)
            logf("[WIN32] Sleep({d}ms) — парковка задачи\n", .{a1});
            ops.sleep_task(a1);
            ret = 0;
        } else if (std.mem.eql(u8, name, "SetUnhandledExceptionFilter")) {
            ret = 0; // предыдущего фильтра не было
        } else if (std.mem.eql(u8, name, "VerSetConditionMask")) {
            ret = verSetConditionMask(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "VerifyVersionInfoW")) {
            ret = verifyVersionInfoW(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "GetEnvironmentVariableA")) {
            ret = getEnvironmentVariableA(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "MultiByteToWideChar")) {
            // v0.13.0 (CDD №4, финал): CP_UTF8/CP_ACP → UTF-16LE (ASCII-путь —
            // тело ответа «Hello POLER!» печатается UCRT-fwrite через это).
            // Win64: RCX=cp, RDX=flags, R8=src, R9=cb, стек[0]=dst, стек[1]=cch
            ret = kMultiByteToWideChar(a3, a4, ops.stack_arg(0), ops.stack_arg(1));
        } else if (std.mem.eql(u8, name, "WriteConsoleW")) {
            // v0.13.0 (CDD №4, ФИНАЛ): UTF-16LE → консоль ОС — тело ответа
            // Win64: RCX=h, RDX=buf, R8=n, R9=lpWritten, стек[0]=lpReserved
            ret = kWriteConsoleW(a1, a2, a3, a4);
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
        } else if (std.mem.eql(u8, name, "CreateFileA")) {
            // v0.16.0 (CDD №7): файловая волна VFS. Win64: RCX=name, RDX=access,
            // R8=share, R9=secattrs; стек[0]=creation, стек[1]=flags, стек[2]=tmpl
            ret = createFileCommon(a1, a2, ops.stack_arg(0), false);
        } else if (std.mem.eql(u8, name, "CreateFileW")) {
            ret = createFileCommon(a1, a2, ops.stack_arg(0), true);
        } else if (std.mem.eql(u8, name, "ReadFile")) {
            // RCX=h, RDX=buf, R8=n, R9=lpRead; стек[0]=lpOverlapped
            ret = readFileCommon(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "WriteFile")) {
            ret = writeFileCommon(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "GetFileSize")) {
            ret = getFileSizeCommon(a1, a2);
        } else if (std.mem.eql(u8, name, "GetFileSizeEx")) {
            ret = getFileSizeExCommon(a1, a2);
        } else if (std.mem.eql(u8, name, "SetFilePointer")) {
            ret = setFilePointerCommon(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "SetFilePointerEx")) {
            ret = setFilePointerExCommon(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "GetFileAttributesA")) {
            ret = getFileAttributesCommonA(a1);
        } else if (std.mem.eql(u8, name, "GetFileType")) {
            ret = getFileTypeCommon(a1);
        } else if (std.mem.eql(u8, name, "SetHandleInformation") or
            std.mem.eql(u8, name, "SetConsoleCtrlHandler"))
        {
            ret = 1; // TRUE: наследование/CTRL-обработчики — beyond-model
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
            // v0.17.0 (CDD №8): РЕАЛЬНОЕ сигнальное состояние
            ret = kCreateEventW(a1, a2, a3, a4, false);
        } else if (std.mem.eql(u8, name, "CreateEventW")) {
            ret = kCreateEventW(a1, a2, a3, a4, true);
        } else if (std.mem.eql(u8, name, "SetEvent")) {
            ret = kSetEvent(a1);
        } else if (std.mem.eql(u8, name, "ResetEvent")) {
            ret = kResetEvent(a1);
        } else if (std.mem.eql(u8, name, "CreateSemaphoreW")) {
            ret = kCreateSemaphoreW(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "ReleaseSemaphore")) {
            // Win64: RCX=h, RDX=n, R8=lpPrev — все рег-аргументы
            ret = kReleaseSemaphore(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "OpenEventW")) {
            ret = kOpenEventW(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "SetEndOfFile")) {
            ret = kSetEndOfFile(a1);
        } else if (std.mem.eql(u8, name, "FlushFileBuffers")) {
            ret = kFlushFileBuffers(a1);
        } else if (std.mem.eql(u8, name, "VirtualFree")) {
            // v0.17.0 (CDD №8): 7-Zip освобождает буферы бенчмарка.
            // Win64: RCX=addr, RDX=size, R8=freedom-type (MEM_DECOMMIT/MEM_RELEASE).
            // Наш vheap — page-bump без free-list: честно «освобождаем»
            // декоммит-семантикой — обнуляем страницы (NX остаётся).
            ret = virtualFree(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "GetTickCount")) {
            // v0.17.0 (CDD №8): ms с старта (QPC/TSC-путь уже откалиброван)
            ret = getTickCount();
        } else if (std.mem.eql(u8, name, "GetCurrentProcess")) {
            ret = 0xFFFF_FFFF_FFFF_FFFF; // псевдо-хэндл (-1) — Win64-конвенция
        } else if (std.mem.eql(u8, name, "GetCurrentProcessId")) {
            ret = 1; // PID=1 (TEB.UniqueProcess)
        } else if (std.mem.eql(u8, name, "GetSystemInfo")) {
            ret = getSystemInfo(a1);
        } else if (std.mem.eql(u8, name, "GlobalMemoryStatusEx")) {
            ret = globalMemoryStatusEx(a1);
        } else if (std.mem.eql(u8, name, "IsProcessorFeaturePresent")) {
            // PF_XMMI64_INSTRUCTIONS_AVAILABLE=10 и т.д. — всё «есть» (QEMU x64)
            ret = 1;
        } else if (std.mem.eql(u8, name, "GetVersionExW")) {
            ret = getVersionExW(a1);
        } else if (std.mem.eql(u8, name, "GetOEMCP")) {
            ret = 437; // CP437 — консольная OEM-страница (как в QEMU/US)
        } else if (std.mem.eql(u8, name, "SetFileApisToOEM") or
            std.mem.eql(u8, name, "SetFileApisToANSI"))
        {
            ret = 0; // void — кодировка имён файлов (beyond-model)
        } else if (std.mem.eql(u8, name, "LocalFree")) {
            ret = 0; // «освобождено» (блоков FormatMessage не выделяем)
        } else if (std.mem.eql(u8, name, "ResumeThread")) {
            ret = resumeThread(a1);
        } else if (std.mem.eql(u8, name, "SetThreadAffinityMask") or
            std.mem.eql(u8, name, "SetProcessAffinityMask"))
        {
            // v0.17.0 (CDD №8): SMP-маска — вся доступна (возврат = предыдущая)
            ret = 0xFF; // 8 логических CPU «успешно назначено»
        } else if (std.mem.eql(u8, name, "GetProcessAffinityMask")) {
            // (h, lpProcessMask, lpSystemMask): TRUE + маски 0xFF
            if (a2 != 0 and ops.validate_write(a2, 8)) userQ(a2).* = 0xFF;
            if (a3 != 0 and ops.validate_write(a3, 8)) userQ(a3).* = 0xFF;
            ret = 1;
        } else if (std.mem.eql(u8, name, "GetProcessTimes")) {
            ret = getProcessTimes(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "FileTimeToSystemTime")) {
            ret = fileTimeToSystemTime(a1, a2);
        } else if (std.mem.eql(u8, name, "FileTimeToLocalFileTime")) {
            ret = fileTimeToLocalFileTime(a1, a2);
        } else if (std.mem.eql(u8, name, "LocalFileTimeToFileTime")) {
            ret = localFileTimeToFileTime(a1, a2);
        } else if (std.mem.eql(u8, name, "DosDateTimeToFileTime")) {
            ret = dosDateTimeToFileTime(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "FileTimeToDosDateTime")) {
            ret = fileTimeToDosDateTime(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "CompareFileTime")) {
            ret = compareFileTime(a1, a2);
        } else if (std.mem.eql(u8, name, "SetFileTime")) {
            ret = 1; // TRUE: время файла «записано» (dir-entry-даты beyond-model)
        } else if (std.mem.eql(u8, name, "GetFileInformationByHandle")) {
            ret = getFileInformationByHandle(a1, a2);
        } else if (std.mem.eql(u8, name, "GetModuleFileNameW")) {
            ret = getModuleFileNameW(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "LoadLibraryW")) {
            // msvcrt/kernel32 «уже загружены» — вернуть базу образа
            // (7-Zip грузит только системные библиотеки)
            ret = if (ctx) |c| c.image_base else 0;
        } else if (std.mem.eql(u8, name, "FreeLibrary")) {
            ret = 1; // TRUE
        } else if (std.mem.eql(u8, name, "WideCharToMultiByte")) {
            // Win64: RCX=cp, RDX=flags, R8=src, R9=cch, стек[0]=dst, стек[1]=cb
            ret = kWideCharToMultiByte(a3, a4, ops.stack_arg(0), ops.stack_arg(1));
        } else if (std.mem.eql(u8, name, "GetLogicalDriveStringsW")) {
            ret = getLogicalDriveStringsW(a1, a2);
        } else if (std.mem.eql(u8, name, "GetTempPathW")) {
            ret = getTempPathW(a1, a2);
        } else if (std.mem.eql(u8, name, "GetDiskFreeSpaceW")) {
            // Win64: RCX=root, RDX=spc, R8=bps, R9=free, стек[0]=total
            ret = getDiskFreeSpaceW(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "DeviceIoControl")) {
            // (h, code, in, inlen, out, outlen, lpRet, lpOv): неподдержанный
            // код — честный FALSE + ERROR_INVALID_FUNCTION (7-Zip SPI-пути)
            setLastError(1); // ERROR_INVALID_FUNCTION
            ret = 0;
        } else if (std.mem.eql(u8, name, "DeleteFileW")) {
            ret = deleteFileW(a1);
        } else if (std.mem.eql(u8, name, "CreateDirectoryW") or
            std.mem.eql(u8, name, "RemoveDirectoryW"))
        {
            ret = 0; // FALSE + ERROR_ACCESS_DENIED — FS-каталоги beyond-модели
            setLastError(ERROR_ACCESS_DENIED);
        } else if (std.mem.eql(u8, name, "MoveFileW")) {
            ret = 0;
            setLastError(ERROR_ACCESS_DENIED);
        } else if (std.mem.eql(u8, name, "SetCurrentDirectoryW") or
            std.mem.eql(u8, name, "GetCurrentDirectoryW"))
        {
            // CWD beyond-model: Set → FALSE(5); Get → корень «\» (по семантике
            // len-вызова: n=0 → требуемая длина)
            if (std.mem.eql(u8, name, "GetCurrentDirectoryW")) {
                ret = getCurrentDirectoryW(a1, a2);
            } else {
                setLastError(ERROR_ACCESS_DENIED);
                ret = 0;
            }
        } else if (std.mem.eql(u8, name, "SetFileAttributesW")) {
            ret = 1; // TRUE (атрибуты beyond-model)
        } else if (std.mem.eql(u8, name, "GetFileAttributesW")) {
            ret = getFileAttributesW(a1);
        } else if (std.mem.eql(u8, name, "FindFirstFileW")) {
            ret = findFirstFileW(a1, a2);
        } else if (std.mem.eql(u8, name, "FindNextFileW")) {
            ret = findNextFileW(a1, a2);
        } else if (std.mem.eql(u8, name, "FindClose")) {
            ret = 1; // TRUE (итератор закончен после первого FindNext FAIL)
        } else if (std.mem.eql(u8, name, "OpenFileMappingW")) {
            ret = 0; // file-mapping API beyond-model (7-Zip fallback на ReadFile)
        } else if (std.mem.eql(u8, name, "MapViewOfFile") or
            std.mem.eql(u8, name, "UnmapViewOfFile"))
        {
            ret = 0; // честный отказ (NULL)
        } else if (std.mem.eql(u8, name, "SetConsoleMode")) {
            ret = 1; // TRUE (режим консоли принимаем)
        } else if (std.mem.eql(u8, name, "GetProcessHeap")) {
            ret = 0xDEAD_BEE0; // псевдо-хэндл кучи (GetProcessHeap/HeapAlloc)
        } else if (std.mem.eql(u8, name, "CreateMutexA") or
            std.mem.eql(u8, name, "CreateMutexW"))
        {
            // v0.14.0 (CDD №5): Wave-A — сессионный кэш SChannel в curl
            // требует валидный хэндл мьютекса (пул 0x400+)
            ret = kCreateMutexA(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "ReleaseMutex")) {
            ret = kReleaseMutex(a1);
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
        } else if (std.mem.eql(u8, name, "SleepEx")) {
            // v0.15.0 (CDD №6): парковка задачи (alertable игнорируем —
            // APC-очереди нет; возврат 0 = WAIT_IO_COMPLETION-нет)
            logf("[WIN32] SleepEx({d}ms) — парковка задачи\n", .{a1});
            ops.sleep_task(a1);
            ret = 0;
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
        } else if (std.mem.eql(u8, name, "_get_osfhandle")) {
            // v0.13.0 (CDD №4): fd → HANDLE (тело ответа печатается fwrite'ом
            // через osfhandle-путь mingw-UCRT: 0/1/2 → псевдо-хэндлы stdio)
            ret = kGetOsfHandle(a1);
        } else if (std.mem.eql(u8, name, "_isatty")) {
            ret = kisatty(a1);
        } else if (std.mem.eql(u8, name, "_setmode")) {
            ret = ksetmode(a1, a2);
        } else if (std.mem.eql(u8, name, "_fsopen")) {
            ret = kfsopen(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "fopen")) {
            // v0.16.0 (CDD №7): fopen(path, mode) — VFS-файл → FILE*
            ret = kfopenCommon(a1, a2, "fopen");
        } else if (std.mem.eql(u8, name, "fread")) {
            // fread(ptr, size, nmemb, stream): Win64 RCX/RDX/R8/R9 → a1..a4
            ret = kfread(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "fseek")) {
            ret = kfseekCommon(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_fseeki64")) {
            ret = kfseekCommon(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "ftell")) {
            ret = kftell(a1);
        } else if (std.mem.eql(u8, name, "fclose")) {
            ret = kfclose(a1);
        } else if (std.mem.eql(u8, name, "feof")) {
            ret = kfeof(a1);
        } else if (std.mem.eql(u8, name, "ferror")) {
            ret = kferror(a1);
        } else if (std.mem.eql(u8, name, "rewind")) {
            ret = krewind(a1);
        } else if (std.mem.eql(u8, name, "fgets")) {
            ret = kfgets(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "getc")) {
            ret = kgetc(a1);
        } else if (std.mem.eql(u8, name, "ungetc")) {
            ret = kungetc(a1, a2);
        } else if (std.mem.eql(u8, name, "puts")) {
            ret = kputs(a1);
        } else if (std.mem.eql(u8, name, "putchar")) {
            ret = kputchar(a1);
        } else if (std.mem.eql(u8, name, "_read")) {
            ret = kread(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_write")) {
            ret = kwrite(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_close")) {
            ret = kclose(a1);
        } else if (std.mem.eql(u8, name, "_lseeki64")) {
            ret = klseeki64(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_sopen_s")) {
            ret = ksopenS(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_chsize_s")) {
            ret = kchsizeS(a1, a2);
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
        } else if (std.mem.eql(u8, name, "strerror_s")) {
            // v0.15.0 (CDD №6): Annex K secure-вариант — TLS-ошибки curl
            ret = kstrerror_s(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "_wcserror_s")) {
            // v0.15.0 (CDD №6): wide-вариант (UTF-16LE)
            ret = kwcserror_s(a1, a2, a3);
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
        } else if (std.mem.eql(u8, name, "strnlen")) {
            // v0.14.0 (CDD №5): Wave-A — schannel-путь (cbMaxToken-границы)
            ret = kstrnlen(a1, a2);
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
        } else if (std.mem.eql(u8, name, "isalnum")) {
            // v0.14.0 (CDD №5): punycode/IDNA-валидация хостнейма в
            // резолвер-треде (isalnum-trap → livelock-kill задачи).
            ret = @intFromBool(std.ascii.isAlphanumeric(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "isdigit")) {
            ret = @intFromBool(std.ascii.isDigit(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "isalpha")) {
            ret = @intFromBool(std.ascii.isAlphabetic(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "isupper")) {
            ret = @intFromBool(std.ascii.isUpper(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "islower")) {
            ret = @intFromBool(std.ascii.isLower(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "isxdigit")) {
            ret = @intFromBool(std.ascii.isHex(@as(u8, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "ispunct")) {
            const ch: u8 = @truncate(a1);
            ret = @intFromBool(ch >= 0x21 and ch <= 0x7E and !std.ascii.isAlphanumeric(ch));
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
            // v0.16.0 (CDD №7): env-таблица (CURL_CA_BUNDLE для SSL без -k)
            ret = kgetenv(a1);
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
        } else if (std.mem.eql(u8, name, "setsockopt")) {
            // v0.13.0 (CDD №4): опции сокета (optlen — 5-й арг, стек)
            ret = wsaSetsockopt(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "getsockopt")) {
            ret = wsaGetsockopt(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "getsockname")) {
            ret = wsaGetsockname(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "getpeername")) {
            ret = wsaGetpeername(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "select")) {
            // v0.13.0 (CDD №4): мультиплексор (timeout — 5-й арг, стек)
            ret = wsaSelect(a1, a2, a3, a4, ops.stack_arg(0));
        } else if (std.mem.eql(u8, name, "shutdown")) {
            ret = wsaShutdown(a1, a2);
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
        } else if (std.mem.eql(u8, name, "inet_pton")) {
            // v0.14.0 (CDD №5): Wave-A — резолвер curl парсит IP-строки
            ret = wsaInetPton(a1, a2, a3);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-utility-l1-1-0.dll")) {
        // v0.14.0 (CDD №5): byteswap-семейство — OpenSSL htonl/ntohl-путь
        // (TLS-записи); trap → livelock (финальный бэклог живого прогона).
        // bsearch/qsort здесь же — НО они native-стабы (Ring 3), диспетчер
        // сюда их не получит.
        if (std.mem.eql(u8, name, "_byteswap_ulong")) {
            ret = @as(u64, @byteSwap(@as(u32, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "_byteswap_ushort")) {
            ret = @as(u64, @byteSwap(@as(u16, @truncate(a1))));
        } else if (std.mem.eql(u8, name, "_byteswap_uint64")) {
            ret = @byteSwap(a1);
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "Secur32.dll")) {
        // v0.12.0 (CDD №3): SSPI-таблица; v0.14.0 (CDD №5): полный
        // SYNTHETIC-SChannel TLS-движок (вызовы ЧЕРЕЗ ТАБЛИЦУ, lld-трамплин).
        // Сигнатурная разведка: аргументы в лог (сверка оффсетов SFT).
        logf("[SSPI] dispatch: {s}(a1=0x{x}, a2=0x{x}, a3=0x{x}, a4=0x{x}, s0=0x{x}, s2=0x{x}, s3=0x{x}, s4=0x{x})\n", .{
            name, a1, a2, a3, a4, ops.stack_arg(0), ops.stack_arg(2), ops.stack_arg(3), ops.stack_arg(4),
        });
        if (std.mem.eql(u8, name, "InitSecurityInterfaceA")) {
            ret = initSecurityInterface(disp, false);
        } else if (std.mem.eql(u8, name, "InitSecurityInterfaceW")) {
            ret = initSecurityInterface(disp, true);
        } else if (std.mem.eql(u8, name, "FreeContextBuffer")) {
            ret = SEC_E_OK; // освобождение NULL/нашего буфера — успех
        } else if (std.mem.eql(u8, name, "QuerySecurityPackageInfoA") or
            std.mem.eql(u8, name, "QuerySecurityPackageInfoW"))
        {
            ret = sspiQuerySecurityPackageInfo(a1, a2);
        } else if (std.mem.eql(u8, name, "AcquireCredentialsHandleA") or
            std.mem.eql(u8, name, "AcquireCredentialsHandleW"))
        {
            // RCX=principal, RDX=package; phCredential=arg8, ptsExpiry=arg9
            ret = sspiAcquireCredentialsHandle(a2, ops.stack_arg(3), ops.stack_arg(4));
        } else if (std.mem.eql(u8, name, "InitializeSecurityContextA") or
            std.mem.eql(u8, name, "InitializeSecurityContextW"))
        {
            // RCX=phCred, RDX=phContext, R8=targetName, R9=fContextReq;
            // arg7=pInput, arg8=Reserved2, arg9=phNewContext, arg10=pOutput
            // (stack_arg(i) = arg(5+i): pInput=s2, phNew=s4, pOutput=s5)
            ret = sspiInitializeSecurityContext(a1, a2, a3, ops.stack_arg(2), ops.stack_arg(4), ops.stack_arg(5));
        } else if (std.mem.eql(u8, name, "EncryptMessage")) {
            // RCX=phContext, RDX=fQOP, R8=pMessage, R9=MessageSeqNo
            ret = sspiEncryptMessage(a1, a3);
        } else if (std.mem.eql(u8, name, "DecryptMessage")) {
            // RCX=phContext, RDX=pMessage, R8=MessageSeqNo, R9=pfQOP
            ret = sspiDecryptMessage(a1, a2);
        } else if (std.mem.eql(u8, name, "QueryContextAttributesA") or
            std.mem.eql(u8, name, "QueryContextAttributesW"))
        {
            // RCX=phContext, RDX=ulAttribute, R8=pBuffer
            ret = sspiQueryContextAttributes(a1, a2, a3);
        } else if (std.mem.eql(u8, name, "DeleteSecurityContext")) {
            ret = sspiDeleteSecurityContext(a1);
        } else if (std.mem.eql(u8, name, "FreeCredentialsHandle")) {
            ret = sspiFreeCredentialsHandle(a1);
        } else if (std.mem.eql(u8, name, "ApplyControlToken") or
            std.mem.eql(u8, name, "CompleteAuthToken"))
        {
            ret = SEC_E_OK; // контроль-токены: no-op (graceful-shutdown путь)
        } else {
            // EnumerateSecurityPackages/Accept/Impersonate…: не поддержано —
            // БЕЗ записи в out-параметры (SEC_E_* не ноль!)
            ret = SEC_E_UNSUPPORTED_METHOD;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "bcrypt.dll")) {
        // v0.14.0 (CDD №5): Wave-A — BCryptGenRandom (TLS-энтропия curl)
        if (std.mem.eql(u8, name, "BCryptGenRandom")) {
            // RCX=hAlgorithm, RDX=pbBuffer, R8=cbBuffer, R9=dwFlags
            ret = kBCryptGenRandom(a2, a3);
        } else {
            ret = 0xC000_0002; // STATUS_NOT_IMPLEMENTED
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "msvcrt.dll")) {
        // v0.17.0 (CDD №8): MSVC-CRT для 7-Zip (/MD msvcrt.dll — «старая»
        // CRT; mingw-curl использует api-ms-* — та ветка выше). memset/strlen
        // и memmove СЮДА приходят syscall-путём, если natives не перекрыли.
        ret = dispatchMsvcrt(name, a1, a2, a3, a4);
    } else if (std.ascii.eqlIgnoreCase(e.dll, "ADVAPI32.dll")) {
        // v0.17.0 (CDD №8): реестр/токены/привилегии (7-Zip проверяет
        // SeBackupPrivilege; честный отказ — приложение живёт с fallback)
        if (std.mem.eql(u8, name, "SystemFunction036")) {
            // RtlGenRandom(buf, len) — ЭНТРОПИЯ (как BCryptGenRandom)
            ret = kBCryptGenRandom(a1, a2);
        } else if (std.mem.eql(u8, name, "RegCloseKey")) {
            ret = 0; // ERROR_SUCCESS
        } else if (std.mem.eql(u8, name, "RegOpenKeyExW")) {
            setLastError(2); // ERROR_FILE_NOT_FOUND — ключей нет
            ret = 2;
        } else if (std.mem.eql(u8, name, "RegQueryValueExW")) {
            setLastError(2);
            ret = 2;
        } else if (std.mem.eql(u8, name, "OpenProcessToken")) {
            ret = 0; // FALSE: токенов нет (SECURITY-callback 7-Zip fallback)
        } else if (std.mem.eql(u8, name, "AdjustTokenPrivileges") or
            std.mem.eql(u8, name, "LookupPrivilegeValueW"))
        {
            ret = 0; // FALSE
        } else if (std.mem.eql(u8, name, "GetFileSecurityW") or
            std.mem.eql(u8, name, "SetFileSecurityW"))
        {
            ret = 0; // FALSE (SECURITY_DESCRIPTOR beyond-model)
        } else {
            handled = false;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "USER32.dll")) {
        // v0.17.0 (CDD №8): CharUpperW — верхний регистр in-place
        if (std.mem.eql(u8, name, "CharUpperW")) {
            ret = kCharUpperW(a1);
        } else if (std.mem.eql(u8, name, "CharPrevExA")) {
            // (codepage, start, current, flags): предыдущий символ = start
            ret = a2;
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

/// errno → сообщение CRT (общая таблица для strerror/strerror_s/_wcserror_s).
fn strerrorMsg(errnum: u64) []const u8 {
    return switch (errnum) {
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
}

/// strerror(errnum): текст ошибки CRT. Выделяем 64Б-блок в heap (bump —
/// ошибки редки, утечка ограничена числом вызовов). errno-таблица: 7 общих.
pub fn kstrerror(errnum: u64) u64 {
    const msg = strerrorMsg(errnum);
    const p = kmalloc(64);
    if (p == 0) return 0;
    if (!ops.validate_write(p, msg.len + 1)) return 0;
    @memcpy(userPtr(p)[0..msg.len], msg);
    userPtr(p)[msg.len] = 0;
    return p;
}

/// strerror_s(buf, bufsz, errnum) — C11 Annex K (UCRT): копия сообщения
/// в буфер вызывающего, усечение с NUL. Возврат errno_t: 0 = успех,
/// 22 (EINVAL) = buf==NULL или bufsz==0. v0.15.0 (CDD №6): TLS-ошибки
/// curl-OpenSSL печатались пустыми — теперь честный текст.
pub fn kstrerror_s(buf: u64, bufsz: u64, errnum: u64) u64 {
    if (buf == 0 or bufsz == 0) return 22; // EINVAL
    const msg = strerrorMsg(errnum);
    const sz: usize = @intCast(bufsz);
    // копируем min(sz-1, msg.len) байт + NUL — НИКОГДА не покидаем буфер
    const n = @min(sz - 1, msg.len);
    if (!ops.validate_write(buf, n + 1)) return 22;
    if (n > 0) @memcpy(userPtr(buf)[0..n], msg[0..n]);
    userPtr(buf + n)[0] = 0;
    return 0;
}

/// _wcserror_s(wbuf, bufsz_in_wchars, errnum) — wide-вариант (UTF-16LE).
/// Сообщения ASCII → каждый байт = u16. errno_t-семантика как у narrow.
pub fn kwcserror_s(buf: u64, bufsz: u64, errnum: u64) u64 {
    if (buf == 0 or bufsz == 0) return 22; // EINVAL
    const msg = strerrorMsg(errnum);
    const sz: usize = @intCast(bufsz); // в wchar-единицах!
    const n = @min(sz - 1, msg.len);
    if (!ops.validate_write(buf, (n + 1) * 2)) return 22;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        userW(buf + i * 2).* = msg[i];
    }
    userW(buf + n * 2).* = 0;
    return 0;
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
// v0.14.0: 6 стек-аргументов (ISC-10 арг: pInput/arg7, phNew/arg9, pOutput/arg10)
var t_stack_args: [6]u64 = .{ 0, 0, 0, 0, 0, 0 };

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
    t_stack_args = .{ 0, 0, 0, 0, 0, 0 };
    t_thread_calls = 0;
    t_thread_start = 0;
    t_thread_param = 0;
    t_thread_stack_top = 0;
    t_thread_exit_va = 0;
    t_exit_task_calls = 0;
    t_signaled_handle = 0;
    // v0.16.0 (CDD №7): VFS/энтропия/окружение — чистый старт каждого теста
    t_vfs_n = 0;
    // v0.17.0 (CDD №8): RW-фейк тоже чистый
    for (&t_vfs_w) |*f| f.* = .{};
    t_entropy_seed = 0x1234_5678_9ABC_DEF0;
    t_entropy_calls = 0;
    env_table = &.{};
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
    if (idx > 5) return 0;
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
        // v0.14.0: фейк-сети нет — fallback на loopback (как в ядре без virtio)
        .net_ready = denyNet,
        .net_dns_resolve = noDns,
        .net_tcp_connect = noConnect,
        .net_tcp_send = noSend,
        .net_tcp_recv = noRecv,
        .net_tcp_poll = noPoll,
        .net_tcp_close = noClose,
        .sleep_task = noSleep,
        // v0.16.0 (CDD №7): PUF-энтропия (каждый вызов — ДРУГИЕ байты)
        .entropy_fill = tEntropyFill,
        // v0.16.0 (CDD №7): VFS-фейк — t_vfs[0..t_vfs_n] (как мини-initrd)
        // + v0.17.0 (CDD №8): RW-фейк t_vfs_w (как мини-FAT32)
        .vfs_file_size = tVfsSizeRW,
        .vfs_file_read = tVfsReadRW,
        .vfs_file_write = tVfsWrite,
        .vfs_file_create = tVfsCreate,
        .vfs_file_truncate = tVfsTruncate,
        .vfs_file_delete = tVfsDelete,
        .cpu_count = tCpuCount,
        .phys_mem_kb = tPhysMemKb,
    };
}

// v0.16.0 (CDD №7): тестовые фейки энтропии и VFS ─────────────────
var t_entropy_seed: u64 = 0x1234_5678_9ABC_DEF0;
var t_entropy_calls: usize = 0;

/// Энтропия-фейк: xorshift с СЕДОМ, меняющимся на каждый вызов —
/// ГЛАВНОЕ СВОЙСТВО (развал ML-KEM в v0.15): два вызова ≠ байты.
fn tEntropyFill(buf: [*]u8, len: usize) void {
    t_entropy_calls += 1;
    var st: u64 = t_entropy_seed;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        buf[i] = @truncate(st >> 32);
    }
    t_entropy_seed +%= 0x9E37_79B9_7F4A_7C15; // следующий вызов = НОВЫЙ материал
}

const TVfsFile = struct { name: []const u8, data: []const u8 };
var t_vfs: [4]TVfsFile = .{
    .{ .name = "", .data = "" }, .{ .name = "", .data = "" },
    .{ .name = "", .data = "" }, .{ .name = "", .data = "" },
};
var t_vfs_n: usize = 0;

/// v0.17.0 (CDD №8): RW-фейк — t_vfs_w[n] (как мини-FAT32: запись/создание/
/// усечение). Массив отдельный от RO-t_vfs: тесты записи не путают RO-слоты.
const TVfsWFile = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: usize = 0,
    data: [128]u8 = [_]u8{0} ** 128,
    len: usize = 0,
    exists: bool = false,
};
var t_vfs_w: [4]TVfsWFile = .{TVfsWFile{}} ** 4;

fn tVfsWFind(name: []const u8) ?*TVfsWFile {
    for (&t_vfs_w) |*f| {
        if (f.exists and std.mem.eql(u8, f.name[0..f.name_len], name)) return f;
    }
    return null;
}

fn tVfsWAlloc(name: []const u8) ?*TVfsWFile {
    if (name.len > 32) return null;
    for (&t_vfs_w) |*f| {
        if (!f.exists) {
            f.* = .{};
            f.exists = true;
            @memcpy(f.name[0..name.len], name);
            f.name_len = name.len;
            return f;
        }
    }
    return null;
}

fn tVfsWrite(name: [*]const u8, name_len: usize, offset: u64, data: [*]const u8, len: usize) u64 {
    const f = tVfsWFind(name[0..name_len]) orelse return 0;
    if (offset + len > f.data.len) return 0;
    @memcpy(f.data[@intCast(offset)..][0..len], data[0..len]);
    if (offset + len > f.len) f.len = @intCast(offset + len);
    return len;
}

fn tVfsCreate(name: [*]const u8, name_len: usize) u64 {
    if (tVfsWFind(name[0..name_len]) != null) return 1;
    _ = tVfsWAlloc(name[0..name_len]) orelse return 0;
    return 1;
}

fn tVfsTruncate(name: [*]const u8, name_len: usize, new_size: u64) u64 {
    const f = tVfsWFind(name[0..name_len]) orelse return 0;
    if (new_size > f.data.len) {
        // расширение — нулями
        @memset(f.data[f.len..], 0);
        f.len = @intCast(new_size);
    } else {
        @memset(f.data[@intCast(new_size)..f.len], 0);
        f.len = @intCast(new_size);
    }
    return 1;
}

fn tVfsDelete(name: [*]const u8, name_len: usize) u64 {
    if (tVfsWFind(name[0..name_len])) |f| {
        f.* = .{};
        return 1;
    }
    return 0;
}

/// RW-размер (CDD №8-тесты): RO-t_vfs перекрывает (как initrd).
fn tVfsSizeRW(name: [*]const u8, name_len: usize) u64 {
    const ro = tVfsSize(name, name_len);
    if (ro != VFS_NOT_FOUND) return ro;
    if (tVfsWFind(name[0..name_len])) |f| return f.len;
    return VFS_NOT_FOUND;
}

fn tVfsReadRW(name: [*]const u8, name_len: usize, offset: u64, out: [*]u8, len: usize) u64 {
    const ro = tVfsRead(name, name_len, offset, out, len);
    if (ro > 0) return ro;
    if (tVfsWFind(name[0..name_len])) |f| {
        if (offset >= f.len) return 0;
        const take = @min(f.len - @as(usize, @intCast(offset)), len);
        @memcpy(out[0..take], f.data[@intCast(offset)..][0..take]);
        return take;
    }
    return 0;
}

fn tCpuCount() u64 {
    return 4; // тест-модель: 4 CPU
}

fn tPhysMemKb() u64 {
    return 131072; // 128МБ — модель теста
}

fn tVfsAdd(name: []const u8, data: []const u8) void {
    if (t_vfs_n >= t_vfs.len) return;
    t_vfs[t_vfs_n] = .{ .name = name, .data = data };
    t_vfs_n += 1;
}

fn tVfsSize(name: [*]const u8, name_len: usize) u64 {
    const n = name[0..name_len];
    for (t_vfs[0..t_vfs_n]) |f| {
        if (std.mem.eql(u8, f.name, n)) return f.data.len;
    }
    return VFS_NOT_FOUND;
}

fn tVfsRead(name: [*]const u8, name_len: usize, offset: u64, out: [*]u8, len: usize) u64 {
    const n = name[0..name_len];
    for (t_vfs[0..t_vfs_n]) |f| {
        if (std.mem.eql(u8, f.name, n)) {
            if (offset >= f.data.len) return 0;
            const avail = f.data.len - @as(usize, @intCast(offset));
            const take = @min(avail, len);
            @memcpy(out[0..take], f.data[@intCast(offset)..][0..take]);
            return take;
        }
    }
    return 0;
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
        // v0.14.0 (CDD №5)
        .next_mutex_handle = 0x400,
        .tls_sessions = [_]TlsSession{.{}} ** MAX_TLS,
        .tls_last_fd = 0,
        .sockets = [_]Sock{.{}} ** MAX_SOCKS,
        // v0.16.0 (CDD №7)
        .next_file_handle = FILE_HANDLE_BASE,
        .files = [_]FileState{.{}} ** MAX_FILES,
        // v0.17.0 (CDD №8)
        .events = [_]EventState{.{}} ** MAX_EVENTS,
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
        .net_ready = denyNet,
        .net_dns_resolve = noDns,
        .net_tcp_connect = noConnect,
        .net_tcp_send = noSend,
        .net_tcp_recv = noRecv,
        .net_tcp_poll = noPoll,
        .net_tcp_close = noClose,
        .sleep_task = noSleep,
        .entropy_fill = noEntropy,
        .vfs_file_size = noVfsSize,
        .vfs_file_read = noVfsRead,
        .vfs_file_write = noVfsWrite,
        .vfs_file_create = noVfsCreate,
        .vfs_file_truncate = noVfsTruncate,
        .vfs_file_delete = noVfsDelete,
        .cpu_count = fakeCpuCount,
        .phys_mem_kb = fakePhysMemKb,
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

    // диспетчеризация extra-записи (v0.14.0: QuerySecurityPackageInfoA
    // РЕАЛИЗОВАНА — мусорный pp → SEC_E_INVALID_HANDLE, НЕ SEC_E_OK:
    // ноль затирал бы out-параметры мусором!)
    try testing.expectEqual(@as(u64, 0x8009_0004), reg.call(id_qspi, 0x1000, 0x2000, 0, 0));

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

test "ws2: send/recv — loopback HTTP-обмен: [HTTP-SEND], 200 OK, EOF" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sock = reg.add("WS2_32.dll", "socket", 0);
    const id_conn = reg.add("WS2_32.dll", "connect", 0);
    const id_send = reg.add("WS2_32.dll", "send", 0);
    const id_recv = reg.add("WS2_32.dll", "recv", 0);
    const id_sel = reg.add("WS2_32.dll", "select", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const fd = reg.call(id_sock, 2, 1, 6, 0);
    // sockaddr_in {AF_INET, 80 BE, 192.0.2.1}
    const sa = mb + 0x200;
    userW(sa).* = 2;
    userW(sa + 2).* = std.mem.nativeToBig(u16, 80);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 192, 0, 2, 1 });
    try testing.expectEqual(@as(u64, 0), reg.call(id_conn, fd, sa, 16, 0));

    // send ДО connect на ВТОРОМ сокете → WSAENOTCONN
    const fd2 = reg.call(id_sock, 2, 1, 6, 0);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_send, fd2, mb + 0x600, 4, 0));
    try testing.expectEqual(@as(u32, 10057), ctx.?.last_error);

    // recv ДО send (неблокирующий) → WSAEWOULDBLOCK
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_recv, fd, mb + 0x700, 64, 0));
    try testing.expectEqual(@as(u32, 10035), ctx.?.last_error);

    // select(writefds) ДО send: connected → WRITABLE → 1 ready
    const wfds = mb + 0x300;
    userD(wfds).* = 1;
    userQ(wfds + 8).* = fd;
    userQ(wfds + 16).* = fd2;
    userD(wfds).* = 2;
    try testing.expectEqual(@as(u64, 1), reg.call(id_sel, 0, 0, wfds, 0));
    try testing.expectEqual(@as(u32, 1), userD(wfds).*); // набор отфильтрован
    try testing.expectEqual(fd, userQ(wfds + 8).*); // остался ТОЛЬКО готовый
    try testing.expect(logHas("[WS2] select -> 1 ready"));

    // send: GET-запрос (момент истины №4)
    const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    @memcpy(g_mem[0x600 .. 0x600 + req.len], req);
    try testing.expectEqual(@as(u64, req.len), reg.call(id_send, fd, mb + 0x600, req.len, 0));
    try testing.expect(logHas("[HTTP-SEND]"));
    try testing.expect(logHas("GET / HTTP/1.1\\r\\nHost: example.com"));

    // select(readfds) ПОСЛЕ send → READABLE
    const rfds = mb + 0x380;
    userD(rfds).* = 1;
    userQ(rfds + 8).* = fd;
    try testing.expectEqual(@as(u64, 1), reg.call(id_sel, 0, rfds, 0, 0));

    // recv: полный ответ (52Б), тело в конце
    const rb = mb + 0x700;
    try testing.expectEqual(@as(u64, 52), reg.call(id_recv, fd, rb, 4096, 0));
    try testing.expectEqualStrings("HTTP/1.1 200 OK", @as([*]u8, @ptrFromInt(rb))[0..15]);
    try testing.expectEqualStrings("Hello POLER!\n", @as([*]u8, @ptrFromInt(rb))[39..52]);
    try testing.expect(logHas("[HTTP-RECV]"));
    // recv частями: второй сокет, len=10 → 10 байт, потом остаток
    const fd3 = reg.call(id_sock, 2, 1, 6, 0);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 127, 0, 0, 1 });
    try testing.expectEqual(@as(u64, 0), reg.call(id_conn, fd3, sa, 16, 0));
    @memcpy(g_mem[0x640 .. 0x640 + 4], "HEAD");
    _ = reg.call(id_send, fd3, mb + 0x640, 4, 0);
    // мусорный буфер recv при ждущих данных → WSAEFAULT (валидация!)
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_recv, fd3, 0x9990, 16, 0));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
    const rb3 = mb + 0x780;
    try testing.expectEqual(@as(u64, 10), reg.call(id_recv, fd3, rb3, 10, 0));
    try testing.expectEqual(@as(u64, 42), reg.call(id_recv, fd3, rb3, 100, 0));
    // EOF: ответ исчерпан → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_recv, fd3, rb3, 100, 0));
    try testing.expect(logHas("(EOF)"));
    // после EOF fd3 не WRITABLE
    userD(wfds).* = 1;
    userQ(wfds + 8).* = fd3;
    try testing.expectEqual(@as(u64, 0), reg.call(id_sel, 0, 0, wfds, 0));

    // мусорный буфер send → SOCKET_ERROR + WSAEFAULT (валидация!)
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_send, fd, 0x9990, 16, 0));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
}

test "ws2: setsockopt/getsockopt — опции сохраняются, SO_ERROR=0" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sock = reg.add("WS2_32.dll", "socket", 0);
    const id_conn = reg.add("WS2_32.dll", "connect", 0);
    const id_sso = reg.add("WS2_32.dll", "setsockopt", 0);
    const id_gso = reg.add("WS2_32.dll", "getsockopt", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const fd = reg.call(id_sock, 2, 1, 6, 0);
    const sa = mb + 0x200;
    userW(sa).* = 2;
    userW(sa + 2).* = std.mem.nativeToBig(u16, 80);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 192, 0, 2, 1 });
    _ = reg.call(id_conn, fd, sa, 16, 0);

    // setsockopt(TCP_NODELAY, 1): optlen — 5-й арг (стек) = 4
    userD(mb + 0x100).* = 1;
    t_stack_args[0] = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_sso, fd, 6, 0x0001, mb + 0x100));
    try testing.expect(logHas("setsockopt(fd=0x100, IPPROTO_TCP, TCP_NODELAY=1)"));
    // SO_KEEPALIVE = 1
    try testing.expectEqual(@as(u64, 0), reg.call(id_sso, fd, 0xFFFF, 0x0008, mb + 0x100));
    // SO_RCVBUF = 65536
    userD(mb + 0x100).* = 65536;
    try testing.expectEqual(@as(u64, 0), reg.call(id_sso, fd, 0xFFFF, 0x1002, mb + 0x100));

    // getsockopt(SO_ERROR) → 0 (connect без ошибок)
    const val = mb + 0x104;
    const plen = mb + 0x108;
    userD(plen).* = 4;
    t_stack_args[0] = plen;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd, 0xFFFF, 0x1007, val));
    try testing.expectEqual(@as(u32, 0), userD(val).*);
    try testing.expectEqual(@as(u32, 4), userD(plen).*); // out: фактический размер
    try testing.expect(logHas("getsockopt(fd=0x100, SOL_SOCKET, SO_ERROR)"));
    // getsockopt(SO_TYPE) → SOCK_STREAM
    userD(plen).* = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd, 0xFFFF, 0x1008, val));
    try testing.expectEqual(@as(u32, 1), userD(val).*);
    // getsockopt(TCP_NODELAY) → 1 (сохранено setsockopt'ом)
    userD(plen).* = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd, 6, 0x0001, val));
    try testing.expectEqual(@as(u32, 1), userD(val).*);
    // getsockopt(SO_KEEPALIVE) → 1
    userD(plen).* = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd, 0xFFFF, 0x0008, val));
    try testing.expectEqual(@as(u32, 1), userD(val).*);
    // getsockopt(SO_RCVBUF) → 65536
    userD(plen).* = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd, 0xFFFF, 0x1002, val));
    try testing.expectEqual(@as(u32, 65536), userD(val).*);
    // дефолт после нового сокета: SO_KEEPALIVE = 0
    const fd2 = reg.call(id_sock, 2, 1, 6, 0);
    userD(plen).* = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gso, fd2, 0xFFFF, 0x0008, val));
    try testing.expectEqual(@as(u32, 0), userD(val).*);

    // битый optlen-указатель → WSAEFAULT (не паника)
    t_stack_args[0] = 0x9990;
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_gso, fd, 0xFFFF, 0x1007, val));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
    // битый optval у setsockopt → WSAEFAULT
    t_stack_args[0] = 4;
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_sso, fd, 6, 0x0001, 0x9990));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
    // optlen=0 → no-op успех
    t_stack_args[0] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_sso, fd, 6, 0x0001, 0));
}

test "ws2: getsockname/getpeername — sockaddr_in локальный/удалённый" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sock = reg.add("WS2_32.dll", "socket", 0);
    const id_conn = reg.add("WS2_32.dll", "connect", 0);
    const id_gsn = reg.add("WS2_32.dll", "getsockname", 0);
    const id_gpn = reg.add("WS2_32.dll", "getpeername", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const fd = reg.call(id_sock, 2, 1, 6, 0);
    const sa = mb + 0x200;
    userW(sa).* = 2;
    userW(sa + 2).* = std.mem.nativeToBig(u16, 80);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 192, 0, 2, 1 });

    // ДО connect: getpeername → WSAENOTCONN
    const nl = mb + 0x110;
    userD(nl).* = 16;
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_gpn, fd, mb + 0x130, nl, 0));
    try testing.expectEqual(@as(u32, 10057), ctx.?.last_error);
    // но getsockname работает и до connect (порт эфемерный)
    try testing.expectEqual(@as(u64, 0), reg.call(id_gsn, fd, mb + 0x120, nl, 0));
    try testing.expectEqual(@as(u16, 2), userW(mb + 0x120).*); // AF_INET
    try testing.expectEqual(std.mem.nativeToBig(u16, 0xC000), userW(mb + 0x122).*); // порт
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, @as([*]u8, @ptrFromInt(mb + 0x124))[0..4]);
    try testing.expectEqual(@as(u32, 16), userD(nl).*); // *namelen = 16
    try testing.expect(logHas("getsockname(fd=0x100) -> 127.0.0.1:49152"));

    _ = reg.call(id_conn, fd, sa, 16, 0);
    // ПОСЛЕ connect: getpeername → 192.0.2.1:80
    userD(nl).* = 16;
    try testing.expectEqual(@as(u64, 0), reg.call(id_gpn, fd, mb + 0x130, nl, 0));
    try testing.expectEqual(@as(u16, 2), userW(mb + 0x130).*);
    try testing.expectEqual(std.mem.nativeToBig(u16, 80), userW(mb + 0x132).*);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, @as([*]u8, @ptrFromInt(mb + 0x134))[0..4]);
    try testing.expectEqual(@as(u32, 16), userD(nl).*);
    try testing.expect(logHas("getpeername(fd=0x100) -> 192.0.2.1:80"));
    // буфер меньше sockaddr_in → WSAEFAULT
    userD(nl).* = 8;
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_gpn, fd, mb + 0x130, nl, 0));
    try testing.expectEqual(@as(u32, 10014), ctx.?.last_error);
}

test "ws2: WSAEventSelect/Enum/Wait — FD_CONNECT сигнал, авто-сброс" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sock = reg.add("WS2_32.dll", "socket", 0);
    const id_conn = reg.add("WS2_32.dll", "connect", 0);
    const id_es = reg.add("WS2_32.dll", "WSAEventSelect", 0);
    const id_en = reg.add("WS2_32.dll", "WSAEnumNetworkEvents", 0);
    const id_wait = reg.add("WS2_32.dll", "WSAWaitForMultipleEvents", 0);
    const id_send = reg.add("WS2_32.dll", "send", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const fd = reg.call(id_sock, 2, 1, 6, 0);
    const sa = mb + 0x200;
    userW(sa).* = 2;
    userW(sa + 2).* = std.mem.nativeToBig(u16, 80);
    @memcpy(g_mem[0x204..0x208], &[_]u8{ 192, 0, 2, 1 });
    _ = reg.call(id_conn, fd, sa, 16, 0);

    // арм: FD_WRITE|FD_CONNECT|FD_CLOSE (0x32 — как curl)
    try testing.expectEqual(@as(u64, 0), reg.call(id_es, fd, 0x200, 0x32, 0));
    // wait → событие 0 сигнально (pending FD_CONNECT|FD_WRITE)
    userQ(mb + 0x400).* = 0x200;
    try testing.expectEqual(@as(u64, 0), reg.call(id_wait, 1, mb + 0x400, 0, 10));
    try testing.expect(logHas("EVENT 0 (сокетные события)"));
    // enum → 0x12 (FD_CONNECT|FD_WRITE), iErrorCode[FD_CONNECT_BIT]=0
    const ne = mb + 0x500;
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, fd, 0x200, ne, 0));
    try testing.expectEqual(@as(u32, 0x12), userD(ne).*);
    try testing.expectEqual(@as(u32, 0), userD(ne + 4 + 4 * 4).*);
    try testing.expect(logHas("FD_WRITE|FD_CONNECT"));
    // авто-сброс: повторный enum → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, fd, 0x200, ne, 0));
    try testing.expectEqual(@as(u32, 0), userD(ne).*);
    // wait после сброса → TIMEOUT
    try testing.expectEqual(@as(u64, 258), reg.call(id_wait, 1, mb + 0x400, 0, 10));

    // повторный arm: FD_CONNECT одноразовый, FD_WRITE погашен (до send) —
    // авто-сброс семантики: событий 0 (реальный Windows — edge-triggered)
    try testing.expectEqual(@as(u64, 0), reg.call(id_es, fd, 0x200, 0x12, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, fd, 0x200, ne, 0));
    try testing.expectEqual(@as(u32, 0), userD(ne).*);

    // arm без интереса к WRITE (только FD_READ|FD_CLOSE=0x21): pending=0
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, fd, 0x200, ne, 0));
    // …но после send FD_READ появляется
    _ = reg.call(id_es, fd, 0x200, 0x21, 0);
    @memcpy(g_mem[0x600..0x604], "HEAD");
    try testing.expectEqual(@as(u64, 4), reg.call(id_send, fd, mb + 0x600, 4, 0));
    userQ(mb + 0x400).* = 0x200;
    try testing.expectEqual(@as(u64, 0), reg.call(id_wait, 1, mb + 0x400, 0, 10));
    try testing.expectEqual(@as(u64, 0), reg.call(id_en, fd, 0x200, ne, 0));
    try testing.expectEqual(@as(u32, 0x1), userD(ne).*); // FD_READ
    // разарма (events=0): событий нет
    _ = reg.call(id_es, fd, 0x200, 0x21, 0);
    _ = reg.call(id_es, fd, 0x200, 0, 0);
    try testing.expectEqual(@as(u64, 258), reg.call(id_wait, 1, mb + 0x400, 0, 10));
}

test "ws2: shutdown — SD_BOTH, recv-EOF" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_shut = reg.add("WS2_32.dll", "shutdown", 0);
    try testing.expectEqual(@as(u64, 0), reg.call(id_shut, 0x100, 2, 0, 0));
    try testing.expect(logHas("shutdown(fd=0x100, SD_BOTH) -> 0"));
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

// ─── Тесты: v0.15.0 (CDD №6) — strerror_s / _wcserror_s (Annex K) ───────────

test "str: strerror_s — копия, усечение с NUL, EINVAL" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "strerror_s", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // полный копирующийся случай: errno 22 → «Invalid argument» (16Б+NUL)
    @memset(g_mem[0x100..0x140], 0xEE);
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x100, 64, 22, 0));
    try testing.expectEqualStrings("Invalid argument", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(mb + 0x100)), 0));

    // усечение: bufsz=8 → 7 символов + NUL, буфер не покинут
    @memset(g_mem[0x200..0x210], 0xEE);
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x200, 8, 22, 0));
    try testing.expectEqualStrings("Invalid", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(mb + 0x200)), 0));
    try testing.expectEqual(@as(u8, 0xEE), g_mem[0x208]); // за NUL — не тронуто

    // bufsz=1 → только NUL
    g_mem[0x240] = 0xEE;
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x240, 1, 22, 0));
    try testing.expectEqual(@as(u8, 0), g_mem[0x240]);

    // buf=NULL / bufsz=0 → EINVAL(22)
    try testing.expectEqual(@as(u64, 22), reg.call(id, 0, 64, 22, 0));
    try testing.expectEqual(@as(u64, 22), reg.call(id, mb + 0x100, 0, 22, 0));

    // неизвестный errno → «Unknown error»
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x280, 32, 9999, 0));
    try testing.expectEqualStrings("Unknown error", std.mem.sliceTo(@as([*:0]const u8, @ptrFromInt(mb + 0x280)), 0));
}

test "str: _wcserror_s — UTF-16LE, усечение, EINVAL" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id = reg.add("api-ms-win-crt-runtime-l1-1-0.dll", "_wcserror_s", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // errno 2 → «No such file or directory» (25 wchar) — UTF-16LE
    @memset(g_mem[0x100..0x140], 0xEE);
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x100, 32, 2, 0));
    try testing.expectEqual(@as(u16, 'N'), userW(mb + 0x100 + 0).*);
    try testing.expectEqual(@as(u16, 'o'), userW(mb + 0x100 + 2).*);
    try testing.expectEqual(@as(u16, 0), userW(mb + 0x100 + 25 * 2).*); // NUL
    try testing.expectEqual(@as(u8, 0xEE), g_mem[0x100 + 26 * 2]); // не тронуто

    // усечение до 4 wchar: «No \0» (3 символа + NUL — буфер не покидаем)
    @memset(g_mem[0x200..0x220], 0xEE);
    try testing.expectEqual(@as(u64, 0), reg.call(id, mb + 0x200, 4, 2, 0));
    try testing.expectEqual(@as(u16, 'N'), userW(mb + 0x200 + 0).*);
    try testing.expectEqual(@as(u16, 'o'), userW(mb + 0x200 + 2).*);
    try testing.expectEqual(@as(u16, ' '), userW(mb + 0x200 + 4).*);
    try testing.expectEqual(@as(u16, 0), userW(mb + 0x200 + 6).*); // NUL
    try testing.expectEqual(@as(u8, 0xEE), g_mem[0x208]); // за NUL — не тронуто

    // EINVAL
    try testing.expectEqual(@as(u64, 22), reg.call(id, 0, 32, 2, 0));
    try testing.expectEqual(@as(u64, 22), reg.call(id, mb + 0x100, 0, 2, 0));
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

test "crt: MultiByteToWideChar — длина, UTF-16LE, буфер" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_mw = reg.add("KERNEL32.dll", "MultiByteToWideChar", 0);

    const mb: u64 = @intFromPtr(&g_mem);
    const msg = "Hello POLER!\n";
    @memcpy(g_mem[0x100 .. 0x100 + msg.len], msg);
    g_mem[0x100 + msg.len] = 0;

    // Двухфазный вызов: dst=0 → длина (13 + NUL = 14)
    t_stack_args[0] = 0;
    t_stack_args[1] = 0;
    try testing.expectEqual(@as(u64, 14), reg.call(id_mw, 0, 0, mb + 0x100, 0xFFFF_FFFF_FFFF_FFFF));

    // Полный вызов: dst/cch достаточно → 14, UTF-16LE корректен
    const dst = mb + 0x200;
    t_stack_args[0] = dst;
    t_stack_args[1] = 32;
    try testing.expectEqual(@as(u64, 14), reg.call(id_mw, 0, 0, mb + 0x100, 0xFFFF_FFFF_FFFF_FFFF));
    try testing.expectEqual(@as(u16, 'H'), userW(dst).*);
    try testing.expectEqual(@as(u16, 'e'), userW(dst + 2).*);
    var buf: [13]u16 = undefined;
    var i: usize = 0;
    while (i < 13) : (i += 1) buf[i] = userW(dst + i * 2).*;
    var exp: [13]u16 = undefined;
    for ("Hello POLER!\n", 0..) |ch, k| exp[k] = ch;
    try testing.expectEqualSlices(u16, &exp, &buf);
    try testing.expectEqual(@as(u16, 0), userW(dst + 13 * 2).*); // NUL
    // cch < n → 0 + ERROR_INSUFFICIENT_BUFFER
    t_stack_args[0] = dst;
    t_stack_args[1] = 4;
    try testing.expectEqual(@as(u64, 0), reg.call(id_mw, 0, 0, mb + 0x100, 0xFFFF_FFFF_FFFF_FFFF));
    try testing.expectEqual(@as(u32, 122), ctx.?.last_error);
    // явный cb (без NUL): длина = cb
    t_stack_args[0] = 0;
    t_stack_args[1] = 0;
    try testing.expectEqual(@as(u64, 5), reg.call(id_mw, 0, 0, mb + 0x100, 5));
    // битый src → 0 (не паника)
    try testing.expectEqual(@as(u64, 0), reg.call(id_mw, 0, 0, 0x9990, 8));
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

    // GetSystemTimeAsFileTime: 64-бит FILETIME. v0.16.0-фикс (CDD №7):
    // корректная формула (Unix + 11644473600) × 10⁷ (1601-эпоха Windows) —
    // прежний литерал забывал offset 1601 (латент v0.12). Фолбэк-статика
    // 2024-06-13 (13395187200с) → 250396608000000000.
    _ = reg.call(id_ft, mb + 0x380, 0, 0, 0);
    try testing.expectEqual(@as(u64, (13_395_187_200 + 11_644_473_600) * 10_000_000), userQ(mb + 0x380).*);

    // GetTickCount64: TSC 3ГГц → мс
    t_tsc = 3_000_000_000; // 1 секунда
    try testing.expectEqual(@as(u64, 1000), reg.call(id_tc, 0, 0, 0, 0));
}

// ─── Тесты: CDD №5 (SSPI/SChannel SYNTHETIC-TLS + Wave-A) ──────────────────

test "sspi5: QuerySecurityPackageInfo + AcquireCredentialsHandle" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_qspi = reg.add("Secur32.dll", "QuerySecurityPackageInfoA", 0);
    const id_ach = reg.add("Secur32.dll", "AcquireCredentialsHandleA", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0);

    // Пакет: имя на mb+0x100, ppPackageInfo на mb+0x200
    @memcpy(g_mem[0x100..0x100 + 7], "Kerbero");
    g_mem[0x107] = 0;
    const pp = mb + 0x200;
    try testing.expectEqual(@as(u64, 0), reg.call(id_qspi, mb + 0x100, pp, 0, 0));
    const info = std.mem.readInt(u64, g_mem[0x200..0x208], .little);
    try testing.expect(info != 0);
    // SecPkgInfo: fCapabilities, wVersion, wRPCID, cbMaxToken, Name, Comment
    const info_ptr: [*]const u8 = @ptrFromInt(info);
    try testing.expectEqual(@as(u32, 0x113), std.mem.readInt(u32, info_ptr[0..4], .little));
    try testing.expectEqual(@as(u32, 16384), std.mem.readInt(u32, info_ptr[8..12], .little));
    const name_va = std.mem.readInt(u64, info_ptr[16..24], .little);
    try testing.expectEqualStrings(UNISP_NAME, @as([*]const u8, @ptrFromInt(name_va))[0..UNISP_NAME.len]);
    try testing.expect(logHas("QuerySecurityPackageInfo(\"Kerbero\") -> UNISP"));

    // AcquireCredentialsHandle: phCredential = mb+0x300 (стек-арг3), pts = mb+0x310
    t_stack_args[3] = mb + 0x300;
    t_stack_args[4] = mb + 0x310;
    @memcpy(g_mem[0x320..0x320 + UNISP_NAME.len], UNISP_NAME);
    g_mem[0x320 + UNISP_NAME.len] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_ach, 0, mb + 0x320, 0, 0));
    const cred = std.mem.readInt(u64, g_mem[0x300..0x308], .little);
    try testing.expect(cred >= 0xC100);
    try testing.expectEqual(TLS_MAGIC, std.mem.readInt(u64, g_mem[0x308..0x310], .little));
}

test "sspi5: InitializeSecurityContext — ClientHello + ServerHello (SYNTHETIC-TLS)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_isc = reg.add("Secur32.dll", "InitializeSecurityContextA", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0);

    // pszTargetName = "example.com" на mb+0x40
    @memcpy(g_mem[0x40..0x40 + 11], "example.com");
    g_mem[0x4B] = 0;
    // pOutput: SecBufferDesc{version=0, cBuffers=1, pBuffers} @mb+0x100
    // SecBuffer{cb=256, type=TOKEN(2), pv=mb+0x200} @mb+0x180
    userD(mb + 0x100).* = 0; // version
    userD(mb + 0x104).* = 1; // cBuffers
    userQ(mb + 0x108).* = mb + 0x180;
    userD(mb + 0x180).* = 256;
    userD(mb + 0x184).* = 2; // SECBUFFER_TOKEN
    userQ(mb + 0x188).* = mb + 0x200;
    // phNewContext = mb+0x50 (стек-арг4), pInput=0, pOutput=стек-арг5(idx 4)
    t_stack_args[2] = 0; // pInput
    t_stack_args[3] = 0; // Reserved2
    t_stack_args[4] = mb + 0x50; // phNewContext
    t_stack_args[5] = mb + 0x100; // pOutput

    // Первый вызов: phContext = NULL
    const r1 = reg.call(id_isc, 0xC100, 0, mb + 0x40, 0);
    try testing.expectEqual(SEC_I_CONTINUE_NEEDED, r1);
    try testing.expect(logHas("ClientHello"));
    // phNewContext: {idx+1, magic}
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, g_mem[0x50..0x58], .little));
    try testing.expectEqual(TLS_MAGIC, std.mem.readInt(u64, g_mem[0x58..0x60], .little));
    // ClientHello в выходном буфере: record 0x16 03 03, handshake 01,
    // TLS1.2 (03 03), SNI-расширение с "example.com"
    const hello = g_mem[0x200..0x200 + 160];
    try testing.expectEqual(@as(u8, 0x16), hello[0]);
    try testing.expectEqual(@as(u8, 0x03), hello[1]);
    try testing.expectEqual(@as(u8, 0x01), hello[5]); // handshake ClientHello
    try testing.expectEqual(@as(u8, 0x03), hello[9]); // client_version 1.2
    // SNI: поиск "example.com" в теле hello
    try testing.expect(std.mem.indexOf(u8, hello[0..120], "example.com") != null);
    // cbBuffer выходного буфера = фактическая длина
    try testing.expect(userD(mb + 0x180).* > 100);

    // Второй вызов: phContext = handle, pInput = ServerHello-поток
    // (синтезируем серверный поток через наш же tlsBuildServerStream:
    // сессия уже создана — байты должны распарситься)
    const c = &(ctx orelse return error.NoCtx);
    const s = &c.tls_sessions[0];
    var srv: [512]u8 = undefined;
    const srv_len = win32crtTlsBuildServerStream(s, &srv);
    try testing.expect(srv_len > 90); // SH(47) + CCS(6) + Finished(41)
    // pInput: SecBufferDesc @mb+0x400, SecBuffer @mb+0x480, данные @mb+0x500
    userD(mb + 0x400).* = 0;
    userD(mb + 0x404).* = 1;
    userQ(mb + 0x408).* = mb + 0x480;
    userD(mb + 0x480).* = @intCast(srv_len);
    userD(mb + 0x484).* = 2; // TOKEN
    userQ(mb + 0x488).* = mb + 0x500;
    @memcpy(g_mem[0x500 .. 0x500 + srv_len], srv[0..srv_len]);
    t_stack_args[2] = mb + 0x400; // pInput
    t_stack_args[4] = mb + 0x50; // phNewContext (тот же)
    t_stack_args[5] = 0; // pOutput

    const r2 = reg.call(id_isc, 0xC100, mb + 0x50, 0, 0);
    try testing.expectEqual(@as(u64, 0), r2); // SEC_E_OK
    try testing.expect(s.established);
    try testing.expect(logHas("ServerHello принят"));
}

/// Обёртка для теста (tlsBuildServerStream — приватная):
const win32crtTlsBuildServerStream = tlsBuildServerStream;

test "sspi5: EncryptMessage/DecryptMessage — XOR-roundtrip STREAM" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_enc = reg.add("Secur32.dll", "EncryptMessage", 0);
    const id_dec = reg.add("Secur32.dll", "DecryptMessage", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0);

    // Сессия: создадим напрямую (установленная)
    const c = &(ctx orelse return error.NoCtx);
    const s = &c.tls_sessions[0];
    s.in_use = true;
    s.established = true;
    s.client_random = [_]u8{1} ** 32;
    s.server_random = [_]u8{2} ** 32;
    tlsDeriveKey(s);
    var key_copy = s.key;

    // Контекст-хэндл: mb+0x40 = {1, magic}
    userQ(mb + 0x40).* = 1;
    userQ(mb + 0x48).* = TLS_MAGIC;

    // Сообщение: 4 SecBuffer {STREAM_HEADER(5Б), DATA("GET /" 5Б), TRAILER(16Б), EMPTY}
    // desc @mb+0x100: {0, 4, pBuffers}
    userD(mb + 0x100).* = 0;
    userD(mb + 0x104).* = 4;
    userQ(mb + 0x108).* = mb + 0x180;
    // b0: header @mb+0x200 (5Б)
    userD(mb + 0x180).* = 5;
    userD(mb + 0x184).* = 7; // STREAM_HEADER
    userQ(mb + 0x188).* = mb + 0x200;
    // b1: data @mb+0x220 (16Б)
    userD(mb + 0x190).* = 16;
    userD(mb + 0x194).* = 1; // DATA
    userQ(mb + 0x198).* = mb + 0x220;
    @memcpy(g_mem[0x220..0x225], "GET /");
    // b2: trailer @mb+0x240 (16Б)
    userD(mb + 0x1A0).* = 16;
    userD(mb + 0x1A4).* = 6; // STREAM_TRAILER
    userQ(mb + 0x1A8).* = mb + 0x240;
    // b3: empty
    userD(mb + 0x1B0).* = 0;
    userD(mb + 0x1B4).* = 0;
    userQ(mb + 0x1B8).* = 0;

    try testing.expectEqual(@as(u64, 0), reg.call(id_enc, mb + 0x40, 0, mb + 0x100, 0));
    // header: 0x17 03 03 len=(16+16)
    try testing.expectEqual(@as(u8, 0x17), g_mem[0x200]);
    try testing.expectEqual(@as(u8, 0x03), g_mem[0x201]);
    const plen = (@as(u16, g_mem[0x203]) << 8) | g_mem[0x204];
    try testing.expectEqual(@as(u16, 32), plen); // 16 данных + 16 MAC
    // данные «зашифрованы» (XOR — отличаются от исходника)
    try testing.expect(!std.mem.eql(u8, g_mem[0x220..0x225], "GET /"));

    // Расшифровка: DecryptMessage с DATA-буфером = ПОЛНАЯ ЗАПИСЬ:
    // [header(5) + ciphertext(16) + MAC(16)] @mb+0x300
    @memcpy(g_mem[0x300..0x305], g_mem[0x200..0x205]);
    @memcpy(g_mem[0x305..0x305 + 16], g_mem[0x220..0x230]);
    @memcpy(g_mem[0x305 + 16 .. 0x305 + 32], g_mem[0x240..0x250]);
    // desc2 @mb+0x110: {0, 2, pBuffers} + буферы
    userD(mb + 0x110).* = 0;
    userD(mb + 0x114).* = 2;
    userQ(mb + 0x118).* = mb + 0x1C0;
    userD(mb + 0x1C0).* = 37; // вся запись
    userD(mb + 0x1C4).* = 1; // DATA
    userQ(mb + 0x1C8).* = mb + 0x300;
    userD(mb + 0x1D0).* = 0;
    userD(mb + 0x1D4).* = 5; // EXTRA
    userQ(mb + 0x1D8).* = 0;

    try testing.expectEqual(@as(u64, 0), reg.call(id_dec, mb + 0x40, mb + 0x110, 0, 0));
    // cbBuffer = plaintext_len = 16, pvBuffer = mb+0x305
    try testing.expectEqual(@as(u32, 16), userD(mb + 0x1C0).*);
    try testing.expectEqual(mb + 0x305, userQ(mb + 0x1C8).*);
    // plaintext восстановлен (первые 5Б из 16Б plaintext)
    try testing.expectEqualStrings("GET /", g_mem[0x305..0x30A]);
    // EXTRA обнулён
    try testing.expectEqual(@as(u32, 0), userD(mb + 0x1D0).*);
    // ключ не изменился
    try testing.expectEqualSlices(u8, &key_copy, &s.key);
}

test "sspi5: QueryContextAttributes STREAM_SIZES + Delete/Free" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_qca = reg.add("Secur32.dll", "QueryContextAttributesA", 0);
    const id_del = reg.add("Secur32.dll", "DeleteSecurityContext", 0);
    const id_fch = reg.add("Secur32.dll", "FreeCredentialsHandle", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0);

    const c = &(ctx orelse return error.NoCtx);
    const s = &c.tls_sessions[3];
    s.in_use = true;
    s.established = true;
    userQ(mb + 0x40).* = 4;
    userQ(mb + 0x48).* = TLS_MAGIC;

    // STREAM_SIZES (attr=4)
    try testing.expectEqual(@as(u64, 0), reg.call(id_qca, mb + 0x40, 4, mb + 0x200, 0));
    try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, g_mem[0x200..0x204], .little));
    try testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, g_mem[0x204..0x208], .little));
    try testing.expectEqual(@as(u32, 16384), std.mem.readInt(u32, g_mem[0x208..0x20C], .little));
    // прочий атрибут → SEC_E_UNSUPPORTED
    try testing.expectEqual(SEC_E_UNSUPPORTED_METHOD, reg.call(id_qca, mb + 0x40, 99, mb + 0x200, 0));

    // Delete: слот освобождён
    try testing.expectEqual(@as(u64, 0), reg.call(id_del, mb + 0x40, 0, 0, 0));
    try testing.expect(!s.in_use);
    // FreeCredentialsHandle
    try testing.expectEqual(@as(u64, 0), reg.call(id_fch, mb + 0x40, 0, 0, 0));
}

test "waveA5: CreateMutexA/WaitFor/Release + BCryptGenRandom + ctype + byteswap" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_mut = reg.add("KERNEL32.dll", "CreateMutexA", 0);
    const id_rel = reg.add("KERNEL32.dll", "ReleaseMutex", 0);
    const id_wait = reg.add("KERNEL32.dll", "WaitForSingleObject", 0);
    const id_bc = reg.add("bcrypt.dll", "BCryptGenRandom", 0);
    const id_isalnum = reg.add("api-ms-win-crt-string-l1-1-0.dll", "isalnum", 0);
    const id_bswap = reg.add("api-ms-win-crt-utility-l1-1-0.dll", "_byteswap_ulong", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0xEE);

    // CreateMutexA → хэндл 0x400+
    const h = reg.call(id_mut, 0, 0, 0, 0);
    try testing.expect(h >= 0x400);
    // WaitForSingleObject(mutex) → WAIT_OBJECT_0 (свободен)
    try testing.expectEqual(WAIT_OBJECT_0, reg.call(id_wait, h, 0xFFFFFFFF, 0, 0));
    // ReleaseMutex → TRUE
    try testing.expectEqual(@as(u64, 1), reg.call(id_rel, h, 0, 0, 0));

    // BCryptGenRandom: буфер mb+0x100, 16Б → STATUS_SUCCESS, байты ≠ 0xEE
    try testing.expectEqual(@as(u64, 0), reg.call(id_bc, 0, mb + 0x100, 16, 0));
    var changed = false;
    for (g_mem[0x100..0x110]) |b| {
        if (b != 0xEE) changed = true;
    }
    try testing.expect(changed);
    // невалидный буфер → STATUS_INVALID_HANDLE (не 0!)
    try testing.expectEqual(@as(u64, 0xC000_000D), reg.call(id_bc, 0, 0x9990, 16, 0));

    // ctype: 'e' (0x65) → 1, ' ' → 0
    try testing.expectEqual(@as(u64, 1), reg.call(id_isalnum, 0x65, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_isalnum, 0x20, 0, 0, 0));

    // byteswap: 0x12000000 → 0x12 (ntohl-семантика curl)
    try testing.expectEqual(@as(u64, 0x12), reg.call(id_bswap, 0x12000000, 0, 0, 0));
}

// ─── Тесты: v0.16.0 (CDD №7) — PUF-энтропия + VFS/FILE-API + окружение ──────

test "cdd7-entropy: BCryptGenRandom — ДВА вызова дают РАЗНЫЕ байты (ML-KEM-фикс)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_bc = reg.add("bcrypt.dll", "BCryptGenRandom", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(&g_mem, 0xEE);

    // вызов 1: 32Б в g_mem[0x100..0x120]
    try testing.expectEqual(@as(u64, 0), reg.call(id_bc, 0, mb + 0x100, 32, 0));
    // вызов 2: 32Б в g_mem[0x200..0x220]
    try testing.expectEqual(@as(u64, 0), reg.call(id_bc, 0, mb + 0x200, 32, 0));
    // ГЛАВНОЕ СВОЙСТВО (rot-козёл v0.15: статический сид 0x7E5CA01B):
    // два вызова НЕ равны — DRBG-экземпляры сидируются разным материалом
    var same = true;
    for (g_mem[0x100..0x120], g_mem[0x200..0x220]) |a, b| {
        if (a != b) {
            same = false;
            break;
        }
    }
    try testing.expect(!same);
    // энтропия реально запрашивалась (ops.entropy_fill, не tlsEntropy!)
    try testing.expectEqual(@as(usize, 2), t_entropy_calls);
    // оба буфера заполнены (не 0xEE)
    var filled1 = false;
    var filled2 = false;
    for (g_mem[0x100..0x120]) |b| {
        if (b != 0xEE) filled1 = true;
    }
    for (g_mem[0x200..0x220]) |b| {
        if (b != 0xEE) filled2 = true;
    }
    try testing.expect(filled1 and filled2);
    // cb=0 → SUCCESS без вызова энтропии; мусорный буфер → STATUS_INVALID_HANDLE
    const calls_before = t_entropy_calls;
    try testing.expectEqual(@as(u64, 0), reg.call(id_bc, 0, 0, 0, 0));
    try testing.expectEqual(calls_before, t_entropy_calls);
    try testing.expectEqual(@as(u64, 0xC000_000D), reg.call(id_bc, 0, 0x9990, 16, 0));
}

test "cdd7-file: CreateFileA/ReadFile/GetFileSize/SetFilePointer/CloseHandle — VFS" {
    ops = tOps();
    tReset();
    tCtx("");
    tVfsAdd("hello.txt", "Hello from POLER VFS!\n");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_cf = reg.add("KERNEL32.dll", "CreateFileA", 0);
    const id_rf = reg.add("KERNEL32.dll", "ReadFile", 0);
    const id_gs = reg.add("KERNEL32.dll", "GetFileSize", 0);
    const id_gx = reg.add("KERNEL32.dll", "GetFileSizeEx", 0);
    const id_sp = reg.add("KERNEL32.dll", "SetFilePointer", 0);
    const id_ch = reg.add("KERNEL32.dll", "CloseHandle", 0);
    const id_ga = reg.add("KERNEL32.dll", "GetFileAttributesA", 0);
    const id_gt = reg.add("KERNEL32.dll", "GetFileType", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // путь в user-памяти; CreateFileA: arg5(creation)=OPEN_EXISTING(3) — стек
    @memcpy(g_mem[0x100..0x109], "hello.txt");
    g_mem[0x109] = 0;
    t_stack_args[0] = 3; // OPEN_EXISTING
    const h = reg.call(id_cf, mb + 0x100, 0x8000_0000, 0, 0);
    try testing.expectEqual(@as(u64, FILE_HANDLE_BASE), h);
    try testing.expect(logHas("CreateFileA(\"hello.txt\")"));

    // GetFileSize → 22; GetFileSizeEx → u64 в буфере
    try testing.expectEqual(@as(u64, 22), reg.call(id_gs, h, 0, 0, 0));
    @memset(g_mem[0x400..0x410], 0xEE);
    try testing.expectEqual(@as(u64, 1), reg.call(id_gx, h, mb + 0x400, 0, 0));
    try testing.expectEqual(@as(u64, 22), std.mem.readInt(u64, g_mem[0x400..0x408], .little));

    // ReadFile: 8Б (lpRead — a4; lpOverlapped=стек[0]=NULL)
    t_stack_args[0] = 0;
    @memset(g_mem[0x500..0x600], 0xEE);
    try testing.expectEqual(@as(u64, 1), reg.call(id_rf, h, mb + 0x500, 8, mb + 0x410));
    try testing.expectEqualStrings("Hello fr", g_mem[0x500..0x508]);
    try testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, g_mem[0x410..0x414], .little));
    // остаток (14Б), затем EOF → TRUE + 0
    try testing.expectEqual(@as(u64, 1), reg.call(id_rf, h, mb + 0x500, 100, mb + 0x410));
    try testing.expectEqual(@as(u32, 14), std.mem.readInt(u32, g_mem[0x410..0x414], .little));
    try testing.expectEqual(@as(u64, 1), reg.call(id_rf, h, mb + 0x500, 10, mb + 0x410));
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, g_mem[0x410..0x414], .little));

    // SetFilePointer: BEGIN→6 (чтение 5Б «from »), END→22
    try testing.expectEqual(@as(u64, 6), reg.call(id_sp, h, 6, 0, 0));
    try testing.expectEqual(@as(u64, 1), reg.call(id_rf, h, mb + 0x500, 5, mb + 0x410));
    try testing.expectEqualStrings("from ", g_mem[0x500..0x505]);
    try testing.expectEqual(@as(u64, 22), reg.call(id_sp, h, 0, 0, 2));

    // не-файловый хэндл → FALSE + LastError 6
    ctx.?.last_error = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_rf, 0x9999, mb + 0x500, 5, mb + 0x410));
    try testing.expectEqual(@as(u32, 6), ctx.?.last_error);

    // CloseHandle → TRUE (слот освобождён); файл не найден → INVALID + 2
    try testing.expectEqual(@as(u64, 1), reg.call(id_ch, h, 0, 0, 0));
    @memcpy(g_mem[0x120..0x128], "nope.txt");
    g_mem[0x128] = 0;
    t_stack_args[0] = 3;
    try testing.expectEqual(INVALID_HANDLE_VALUE, reg.call(id_cf, mb + 0x120, 0x8000_0000, 0, 0));
    try testing.expectEqual(@as(u32, 2), ctx.?.last_error);

    // GetFileAttributesA: найден → 0x80; нет → 0xFFFFFFFF + 2
    try testing.expectEqual(@as(u64, 0x80), reg.call(id_ga, mb + 0x100, 0, 0, 0));
    ctx.?.last_error = 0;
    try testing.expectEqual(@as(u64, 0xFFFFFFFF), reg.call(id_ga, mb + 0x120, 0, 0, 0));
    try testing.expectEqual(@as(u32, 2), ctx.?.last_error);
    // GetFileType: файл → DISK(1); stdout-псевдохэндл → CHAR(2)
    const id_gsh = reg.add("KERNEL32.dll", "GetStdHandle", 0);
    const stdout_h = reg.call(id_gsh, @bitCast(@as(u64, 0xFFFF_FFF6)), 0, 0, 0);
    try testing.expectEqual(@as(u64, 2), reg.call(id_gt, stdout_h, 0, 0, 0));
}

test "cdd7-stdio: fopen/fread/fseek/ftell/feof/fgets/getc/ungetc/fclose — VFS" {
    ops = tOps();
    tReset();
    tCtx("");
    tVfsAdd("cacert.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_fo = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fopen", 0);
    const id_rd = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fread", 0);
    const id_sk = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fseek", 0);
    const id_tl = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "ftell", 0);
    const id_fe = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "feof", 0);
    const id_er = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "ferror", 0);
    const id_fc = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fclose", 0);
    const id_fg = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fgets", 0);
    const id_gc = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "getc", 0);
    const id_ug = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "ungetc", 0);
    const id_rw = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "rewind", 0);
    const id_fn = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_fileno", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x10A], "cacert.pem");
    g_mem[0x10A] = 0;
    @memcpy(g_mem[0x120..0x122], "rb");
    g_mem[0x122] = 0;

    // fopen("cacert.pem", "rb") → FILE* (блок 80Б из block-heap)
    const fp = reg.call(id_fo, mb + 0x100, mb + 0x120, 0, 0);
    try testing.expect(fp != 0);
    try testing.expect(logHas("fopen(\"cacert.pem\")"));
    // _fileno(FILE*) → 3 (первый VFS-fd после stdio 0/1/2)
    try testing.expectEqual(@as(u64, 3), reg.call(id_fn, fp, 0, 0, 0));

    // ftell=0, feof=0; fread 28Б (первая строка+перевод строки)
    try testing.expectEqual(@as(u64, 0), reg.call(id_tl, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_fe, fp, 0, 0, 0));
    @memset(g_mem[0x500..0x600], 0xEE);
    try testing.expectEqual(@as(u64, 28), reg.call(id_rd, mb + 0x500, 1, 28, fp));
    try testing.expectEqualStrings("-----BEGIN CERTIFICATE-----\n", g_mem[0x500..0x51C]);
    try testing.expectEqual(@as(u64, 28), reg.call(id_tl, fp, 0, 0, 0));
    // fread хвост (31Б из 59): 31 < want → eof-флаг поднят; ferror=0
    try testing.expectEqual(@as(u64, 31), reg.call(id_rd, mb + 0x500, 1, 100, fp));
    try testing.expectEqual(@as(u64, 1), reg.call(id_fe, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_er, fp, 0, 0, 0));
    // fread ЗА концом: 0 элементов, eof держится
    try testing.expectEqual(@as(u64, 0), reg.call(id_rd, mb + 0x500, 1, 28, fp));

    // fseek(SEEK_SET 0) снимает eof; fgets читает строку до '\n' включительно
    try testing.expectEqual(@as(u64, 0), reg.call(id_sk, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_fe, fp, 0, 0, 0));
    const fg = reg.call(id_fg, mb + 0x600, 100, fp, 0);
    try testing.expectEqual(mb + 0x600, fg);
    try testing.expectEqualStrings("-----BEGIN CERTIFICATE-----\n", g_mem[0x600..0x61C]);
    // getc: 'M'; ungetc('M') → снова 'M'
    try testing.expectEqual(@as(u64, 'M'), reg.call(id_gc, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 'M'), reg.call(id_ug, 'M', fp, 0, 0));
    try testing.expectEqual(@as(u64, 'M'), reg.call(id_gc, fp, 0, 0, 0));
    // rewind → позиция 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_rw, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_tl, fp, 0, 0, 0));

    // fclose → 0; после закрытия fread → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_fc, fp, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_rd, mb + 0x500, 1, 10, fp));

    // fopen несуществующего → NULL; режим 'w' → NULL (RO-VFS)
    @memcpy(g_mem[0x140..0x147], "nope.pm");
    g_mem[0x147] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_fo, mb + 0x140, mb + 0x120, 0, 0));
    @memcpy(g_mem[0x128..0x12A], "wb");
    g_mem[0x12A] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_fo, mb + 0x100, mb + 0x128, 0, 0));
}

test "cdd7-lowio: _sopen_s/_read/_lseeki64/_write/_close — lowio через VFS" {
    ops = tOps();
    tReset();
    tCtx("");
    tVfsAdd("data.bin", "0123456789");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_so = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_sopen_s", 0);
    const id_rd = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_read", 0);
    const id_lk = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_lseeki64", 0);
    const id_wr = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_write", 0);
    const id_cl = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "_close", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x108], "data.bin");
    g_mem[0x108] = 0;

    // _sopen_s(&fd, "data.bin", _O_RDONLY) → 0, fd=3
    try testing.expectEqual(@as(u64, 0), reg.call(id_so, mb + 0x200, mb + 0x100, 0, 0));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, g_mem[0x200..0x204], .little));
    // _read: 4Б
    @memset(g_mem[0x300..0x310], 0xEE);
    try testing.expectEqual(@as(u64, 4), reg.call(id_rd, 3, mb + 0x300, 4, 0));
    try testing.expectEqualStrings("0123", g_mem[0x300..0x304]);
    // _lseeki64(SEEK_SET 2) → 2; _read → «234»
    try testing.expectEqual(@as(u64, 2), reg.call(id_lk, 3, 2, 0, 0));
    try testing.expectEqual(@as(u64, 3), reg.call(id_rd, 3, mb + 0x300, 3, 0));
    try testing.expectEqualStrings("234", g_mem[0x300..0x303]);
    // _write в файл → -1 (RO-VFS); _write(1) → консоль
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_wr, 3, mb + 0x300, 3, 0));
    @memcpy(g_mem[0x400..0x403], "AB\n");
    try testing.expectEqual(@as(u64, 3), reg.call(id_wr, 1, mb + 0x400, 3, 0));
    try testing.expect(consoleHas("AB"));
    // _close → 0; чтение после закрытия → -1
    try testing.expectEqual(@as(u64, 0), reg.call(id_cl, 3, 0, 0, 0));
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_rd, 3, mb + 0x300, 3, 0));
}

test "cdd7-env: GetEnvironmentVariableA/W + getenv — env-таблица (CURL_CA_BUNDLE)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_a = reg.add("KERNEL32.dll", "GetEnvironmentVariableA", 0);
    const id_w = reg.add("KERNEL32.dll", "GetEnvironmentVariableW", 0);
    const id_g = reg.add("api-ms-win-crt-environment-l1-1-0.dll", "getenv", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // ядро-окружение: как main64 ставит перед peload
    var env = [_]EnvEntry{
        .{ .name = "CURL_CA_BUNDLE", .value = "cacert.pem" },
        .{ .name = "HOME", .value = "/" },
    };
    env_table = &env;

    // найдено: len=10 + копия в буфер
    @memcpy(g_mem[0x100..0x10E], "CURL_CA_BUNDLE");
    g_mem[0x10E] = 0;
    @memset(g_mem[0x200..0x210], 0xEE);
    try testing.expectEqual(@as(u64, 10), reg.call(id_a, mb + 0x100, mb + 0x200, 64, 0));
    try testing.expectEqualStrings("cacert.pem\x00", g_mem[0x200..0x20B]);
    try testing.expectEqual(@as(u32, 0), ctx.?.last_error);

    // буфер мал (5 < 11) → требуемый размер 11 + ERROR_INSUFFICIENT_BUFFER
    try testing.expectEqual(@as(u64, 11), reg.call(id_a, mb + 0x100, mb + 0x200, 5, 0));
    try testing.expectEqual(@as(u32, 122), ctx.?.last_error);

    // нет переменной → 0 + 203
    @memcpy(g_mem[0x120..0x126], "NOSUCH");
    g_mem[0x126] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_a, mb + 0x120, mb + 0x200, 64, 0));
    try testing.expectEqual(@as(u32, 203), ctx.?.last_error);

    // W-вариант: имя UTF-16, значение UTF-16LE
    const wname = "CURL_CA_BUNDLE";
    for (wname, 0..) |ch, i| userW(mb + 0x300 + i * 2).* = ch;
    userW(mb + 0x300 + wname.len * 2).* = 0;
    @memset(g_mem[0x400..0x430], 0xEE);
    try testing.expectEqual(@as(u64, 10), reg.call(id_w, mb + 0x300, mb + 0x400, 64, 0));
    var ok_w = true;
    for ("cacert.pem", 0..) |ch, i| {
        if (std.mem.readInt(u16, g_mem[0x400 + i * 2 ..][0..2], .little) != ch) ok_w = false;
    }
    try testing.expect(ok_w);

    // getenv (CRT): heap-блок с NUL
    const p = reg.call(id_g, mb + 0x100, 0, 0, 0);
    try testing.expect(p != 0);
    try testing.expectEqualStrings("cacert.pem", userPtr(p)[0..10]);
    try testing.expectEqual(@as(u8, 0), userPtr(p)[10]);
    // getenv отсутствующей → NULL
    try testing.expectEqual(@as(u64, 0), reg.call(id_g, mb + 0x120, 0, 0, 0));
    try testing.expect(logHas("getenv(\"CURL_CA_BUNDLE\")"));
}

// ═══════════════════════════════════════════════════════════════════════════
// v0.17.0 (CDD №8): тесты волны записи FAT32 + 7-Zip-функций
// ═══════════════════════════════════════════════════════════════════════════

test "cdd8-file: CreateFileW CREATE_ALWAYS + WriteFile + GetFileSize (RW-FAT32)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_cf = reg.add("KERNEL32.dll", "CreateFileW", 0);
    const id_wf = reg.add("KERNEL32.dll", "WriteFile", 0);
    const id_gs = reg.add("KERNEL32.dll", "GetFileSize", 0);
    const id_rf = reg.add("KERNEL32.dll", "ReadFile", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // Путь wide: «out.html»
    const name = "out.html";
    for (name, 0..) |ch, i| userW(mb + 0x100 + i * 2).* = ch;
    userW(mb + 0x100 + name.len * 2).* = 0;
    // GENERIC_WRITE + CREATE_ALWAYS(2): файла нет → создаётся (RW-фейк)
    t_stack_args[0] = 2; // диспозиция = CREATE_ALWAYS
    const h = reg.call(id_cf, mb + 0x100, 0x40000000, 0, 0);
    try testing.expect(h >= FILE_HANDLE_BASE);
    try testing.expect(logHas("out.html"));
    try testing.expect(logHas("RW"));

    // WriteFile 10Б → TRUE; *lpWritten = 10; GetFileSize = 10
    @memcpy(g_mem[0x300..0x30A], "POLER-RW!!");
    userD(mb + 0x400).* = 0; // lpWritten
    t_stack_args[0] = 0; // lpOverlapped = NULL
    try testing.expectEqual(@as(u64, 1), reg.call(id_wf, h, mb + 0x300, 10, mb + 0x400));
    try testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, g_mem[0x400..0x404], .little));
    try testing.expectEqual(@as(u64, 10), reg.call(id_gs, h, 0, 0, 0));

    // ПЕРЕчтение: CreateFileW OPEN_EXISTING(3) RO + ReadFile — данные с диска
    @memset(g_mem[0x500..0x50A], 0xEE);
    t_stack_args[0] = 3; // OPEN_EXISTING
    const h2 = reg.call(id_cf, mb + 0x100, 0x80000000, 0, 0); // GENERIC_READ
    try testing.expect(h2 >= FILE_HANDLE_BASE);
    userD(mb + 0x404).* = 0;
    t_stack_args[0] = 0;
    try testing.expectEqual(@as(u64, 1), reg.call(id_rf, h2, mb + 0x500, 10, mb + 0x404));
    try testing.expectEqualStrings("POLER-RW!!", g_mem[0x500..0x50A]);
}

test "cdd8-sysinfo: GetSystemInfo + GlobalMemoryStatusEx (7-Zip-волна)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_si = reg.add("KERNEL32.dll", "GetSystemInfo", 0);
    const id_gm = reg.add("KERNEL32.dll", "GlobalMemoryStatusEx", 0);
    const id_gt = reg.add("KERNEL32.dll", "GetTickCount", 0);
    const id_cp = reg.add("KERNEL32.dll", "GetCurrentProcess", 0);
    const id_pf = reg.add("KERNEL32.dll", "IsProcessorFeaturePresent", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memset(g_mem[0x100..0x200], 0xEE);

    // GetSystemInfo (Win64 = 48Б!): 4 CPU (t-модель), arch AMD64=9 (u16 @0)
    try testing.expectEqual(@as(u64, 0), reg.call(id_si, mb + 0x100, 0, 0, 0));
    try testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, g_mem[0x100 + 32 ..][0..4], .little));
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, g_mem[0x100 + 0 ..][0..2], .little));
    try testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, g_mem[0x100 + 4 ..][0..4], .little));
    // байты 48..64 НЕ тронуты (урок: первый вариант затирал слот возврата!)
    try testing.expectEqual(@as(u64, 0xEEEEEEEEEEEEEEEE), std.mem.readInt(u64, g_mem[0x100 + 48 ..][0..8], .little));
    try testing.expect(logHas("GetSystemInfo"));

    // GlobalMemoryStatusEx: Total=128МБ, TRUE
    @memset(g_mem[0x200..0x260], 0);
    try testing.expectEqual(@as(u64, 1), reg.call(id_gm, mb + 0x200, 0, 0, 0));
    try testing.expectEqual(@as(u64, 131072 * 1024), std.mem.readInt(u64, g_mem[0x200 + 8 ..][0..8], .little));
    try testing.expect(logHas("GlobalMemoryStatusEx"));

    // GetTickCount/GetCurrentProcess/IsProcessorFeaturePresent — семантика
    try testing.expect(reg.call(id_gt, 0, 0, 0, 0) != 0xFFFF_FFFF); // просто u32
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), reg.call(id_cp, 0, 0, 0, 0));
    try testing.expectEqual(@as(u64, 1), reg.call(id_pf, 10, 0, 0, 0));
}

test "cdd8-events: CreateEventW/SetEvent/ResetEvent/Wait (реальная сигнальность)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_ce = reg.add("KERNEL32.dll", "CreateEventW", 0);
    const id_se = reg.add("KERNEL32.dll", "SetEvent", 0);
    const id_re = reg.add("KERNEL32.dll", "ResetEvent", 0);
    const id_ws = reg.add("KERNEL32.dll", "WaitForSingleObject", 0);
    const id_cs = reg.add("KERNEL32.dll", "CreateSemaphoreW", 0);
    const id_rs = reg.add("KERNEL32.dll", "ReleaseSemaphore", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    // Несигнальный auto-reset: Wait(0) → TIMEOUT (не ждём!)
    const ev = reg.call(id_ce, 0, 0, 0, 0); // manual=0, initial=0
    try testing.expect(ev >= EVENT_HANDLE_BASE);
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, ev, 0, 0, 0));

    // SetEvent → Wait(0) захватывает (auto-reset сбрасывает сигнал)
    try testing.expectEqual(@as(u64, 1), reg.call(id_se, ev, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, ev, 0, 0, 0)); // WAIT_OBJECT_0
    // сигнал снят авто-ресетом → снова TIMEOUT
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, ev, 0, 0, 0));

    // manual-reset: сигнал держится после Wait
    const mev = reg.call(id_ce, 0, 1, 0, 0); // manual=1
    try testing.expectEqual(@as(u64, 1), reg.call(id_se, mev, 0, 0, 0));
    _ = reg.call(id_ws, mev, 0, 0, 0);
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, mev, 0, 0, 0)); // ещё сигнален
    try testing.expectEqual(@as(u64, 1), reg.call(id_re, mev, 0, 0, 0));
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, mev, 0, 0, 0));

    // Семафор: initial=2 → два захвата, третий — отказ
    const sem = reg.call(id_cs, 0, 2, 1, 0);
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, sem, 0, 0, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, sem, 0, 0, 0));
    try testing.expectEqual(@as(u64, 258), reg.call(id_ws, sem, 0, 0, 0));
    // ReleaseSemaphore(+1) → снова один захват
    userQ(mb + 0x500).* = 0; // lpPrev
    try testing.expectEqual(@as(u64, 1), reg.call(id_rs, sem, 1, mb + 0x500, 0));
    try testing.expectEqual(@as(u64, 0), reg.call(id_ws, sem, 0, 0, 0));
}

test "cdd8-msvcrt: dispatch msvcrt-ветки (strcmp/wcscmp/__getmainargs-семантика)" {
    ops = tOps();
    tReset();
    tCtx("");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_sc = reg.add("msvcrt.dll", "strcmp", 0);
    const id_wc = reg.add("msvcrt.dll", "wcscmp", 0);
    const id_xc = reg.add("msvcrt.dll", "_XcptFilter", 0);
    const id_sa = reg.add("msvcrt.dll", "__set_app_type", 0);
    const mb: u64 = @intFromPtr(&g_mem);

    @memcpy(g_mem[0x100..0x103], "abc");
    g_mem[0x104] = 0;
    @memcpy(g_mem[0x120..0x123], "abc");
    g_mem[0x124] = 0;
    @memcpy(g_mem[0x140..0x144], "abcd");
    g_mem[0x145] = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_sc, mb + 0x100, mb + 0x120, 0, 0));
    try testing.expect(reg.call(id_sc, mb + 0x100, mb + 0x140, 0, 0) != 0);

    // wcscmp: "ab" == "ab"
    userW(mb + 0x200).* = 'a';
    userW(mb + 0x202).* = 'b';
    userW(mb + 0x204).* = 0;
    userW(mb + 0x220).* = 'a';
    userW(mb + 0x222).* = 'b';
    userW(mb + 0x224).* = 0;
    try testing.expectEqual(@as(u64, 0), reg.call(id_wc, mb + 0x200, mb + 0x220, 0, 0));

    // _XcptFilter → EXCEPTION_CONTINUE_SEARCH (-1)
    try testing.expectEqual(@as(u64, @bitCast(@as(i64, -1))), reg.call(id_xc, 1, 0, 0, 0));
    // __set_app_type → 0
    try testing.expectEqual(@as(u64, 0), reg.call(id_sa, 1, 0, 0, 0));
}

test "cdd8-ro-boundary: fopen «w» на RO-initrd файле → NULL (граница v0.16)" {
    ops = tOps();
    tReset();
    tCtx("");
    tVfsAdd("ro.txt", "READONLY");
    var reg = FakeRegistry{ .entries = undefined, .disp = undefined };
    reg.init();
    const id_fo = reg.add("api-ms-win-crt-stdio-l1-1-0.dll", "fopen", 0);
    const mb: u64 = @intFromPtr(&g_mem);
    @memcpy(g_mem[0x100..0x106], "ro.txt");
    g_mem[0x106] = 0;
    @memcpy(g_mem[0x120..0x122], "wb");
    g_mem[0x122] = 0;

    // Файл есть в RO-t_vfs: truncate откажет → NULL + EACCES (как Windows)
    try testing.expectEqual(@as(u64, 0), reg.call(id_fo, mb + 0x100, mb + 0x120, 0, 0));
    try testing.expect(logHas("усечение запрещено"));
}
