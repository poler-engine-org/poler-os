// ============================================================================
// POLER-OS linux_syscalls.zig — фундамент Linux POSIX-слоя (v0.18.0, CDD №9)
// + ГРАФИЧЕСКАЯ ВОЛНА (v0.19.0, CDD №10 p3): fd-таблица, sys_ioctl (DRM/fb/
// evdev), sys_futex, sys_poll, epoll-троица, sys_mmap устройств, sys_munmap,
// sys_clone, sys_exit_group, sys_fcntl, sys_close.
// ============================================================================
//
// Модель Starnix: семантическое ядро syscall-таблицы ЧИСТОЕ (тестируется
// нативно через LinuxOps-инъекцию — прецедент LoaderOps/pe_loader.zig),
// платформенный доступ (валидация user-VA, копирование, fd-таблица,
// устройства, mmap, exit) — за ops-указателями. Ядро регистрирует реальный
// runtime из main64.zig (isr64.S: Linux-задачи идут RAX-ABI, Win32 — вектора
// #6/#7).
//
// Linux x86_64 ABI: номер syscall в RAX, аргументы RDI/RSI/RDX/R10/R8/R9,
// возврат в RAX; ошибки = -errno (маленькое отрицательное, u64-биткаст).
//
// ФИЛОСОФИЯ «Всё есть файл» (CDD №10): экран = /dev/fb0 + /dev/dri/card0,
// ввод = /dev/input/event0,1. Графический сервер (Mesa/Gamescope/Wayland из
// CachyOS) поднимается над ЭТИМИ файлами: ioctl для режимов, mmap для
// видеопамяти, poll/epoll для ввода, futex для потоков.
//
// Инвариант CDD №9/№10: НИКАКОЙ враждебный ввод (мусорные VA/len/fd/flags/
// cmd/nfds) не должен приводить к kernel-panic — только к -errno.
// ============================================================================

const std = @import("std");
const testing = std.testing;

pub const PAGE_SIZE: u64 = 4096;

// ─── Syscall numbers (linux x86_64 unistd_64.h) ────────────────────────────

pub const SYS_read: u64 = 0;
pub const SYS_write: u64 = 1;
pub const SYS_open: u64 = 2;
pub const SYS_close: u64 = 3;
pub const SYS_mmap: u64 = 9;
pub const SYS_brk: u64 = 12;
pub const SYS_munmap: u64 = 11;
pub const SYS_ioctl: u64 = 16;
pub const SYS_fstat: u64 = 5;
pub const SYS_lseek: u64 = 8;
pub const SYS_poll: u64 = 7;
pub const SYS_pread64: u64 = 17;
pub const SYS_writev: u64 = 20;
pub const SYS_access: u64 = 21;
pub const SYS_newfstatat: u64 = 262;
pub const SYS_mprotect: u64 = 10;
pub const SYS_arch_prctl: u64 = 158;
pub const SYS_set_tid_address: u64 = 218;
pub const SYS_clock_gettime: u64 = 228;
pub const SYS_set_robust_list: u64 = 273;
pub const SYS_rseq: u64 = 334; // 293 = pipe2 (!раньше коллизия: rseq-заглушка съедала pipe2 glibc)
pub const SYS_pipe2: u64 = 293;
pub const SYS_readlinkat: u64 = 267; // 298 = perf_event_open (!коллизия v0.19)
// ─── CDD №12 p2: канал-волна (номера сверены с syscall_64.tbl) ─────────────
pub const SYS_eventfd2: u64 = 290;
pub const SYS_signalfd4: u64 = 289;
pub const SYS_timerfd_create: u64 = 283;
pub const SYS_timerfd_settime: u64 = 286;
pub const SYS_epoll_pwait: u64 = 281;
pub const SYS_ppoll: u64 = 270;
pub const SYS_fstatfs: u64 = 138;
pub const SYS_getcwd: u64 = 79;
pub const SYS_prctl: u64 = 157;
pub const SYS_madvise: u64 = 28;
pub const SYS_rt_sigaction: u64 = 13;
pub const SYS_rt_sigprocmask: u64 = 14;
pub const SYS_socketpair: u64 = 53;
pub const SYS_memfd_create: u64 = 319;
pub const SYS_ftruncate: u64 = 77; // (!не 46 — это i386-номер; x86_64 = 77)
/// getdents64 (НЕ 220 — это старый getdents без d_type/d_ino-64)
pub const SYS_getdents64: u64 = 217;
/// CDD №12 p3: sched_getaffinity (glibc sysconf(_SC_NPROCESSORS_*) —
/// РАЗМЕР пула тредов llvmpipe! ENOSYS → мусорная нумерация CPU → падение)
pub const SYS_sched_getaffinity: u64 = 203;
pub const SYS_sched_setaffinity: u64 = 204;
/// CDD №12 p3: sysinfo (LLVM/Gallium оценка RAM для хипов) + mkdir (кэш Меса)
pub const SYS_sysinfo: u64 = 99;
pub const SYS_mkdir: u64 = 83;

// ─── CDD №12 p3: dev-номера (libdrm идентифицирует DRM-узлы) ──────────
/// Linux DRM_MAJOR (include/uapi/linux/major.h).
pub const DRM_MAJOR: u64 = 226;
/// new_encode_dev (Linux): major<256, minor<256 → (maj<<8)|min
/// (glibc makedev декодирует так же — stat st_rdev/rdev)
pub fn encodeDev(major: u64, minor: u64) u64 {
    return (major << 8) | (minor & 0xff);
}
/// minor devfs-узла по ПУТИ (fstat st_rdev: card0=0, renderD128=128 —
/// libdrm drmGetNodeTypeFromFd различает primary/render по minor!)
pub fn devMinor(path: []const u8) u32 {
    if (std.mem.eql(u8, path, "/dev/dri/renderD128")) return 128;
    if (std.mem.eql(u8, path, "/dev/input/event1")) return 65;
    if (std.mem.eql(u8, path, "/dev/input/event0")) return 64;
    return 0; // card0, fb0, console
}
/// major devfs-узла по fd-kind (DRM=226, fb=29, input=13, tty=5).
pub fn devMajorOf(kind: FdKind) u64 {
    return switch (kind) {
        .dri_card0 => DRM_MAJOR,
        .fb0 => 29,
        .input_event0, .input_event1 => 13,
        else => 5, // console_out (tty)
    };
}
/// d_type для linux_dirent64 (getdents64)
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;

/// O_CLOEXEC/O_NONBLOCK (pipe2/socketpair/eventfd2/timerfd/signalfd4).
pub const O_CLOEXEC: u64 = 0o2000000;
pub const EFD_SEMAPHORE: u64 = 1;
pub const EFD_NONBLOCK: u64 = 0o4000;
pub const EFD_CLOEXEC: u64 = 0o2000000;
pub const TFD_NONBLOCK: u64 = 0o4000;
pub const TFD_CLOEXEC: u64 = 0o2000000;
pub const SFD_NONBLOCK: u64 = 0o4000;
pub const SFD_CLOEXEC: u64 = 0o2000000;
/// prctl-опции (частичный набор).
pub const PR_CAPBSET_READ: u64 = 23;
pub const PR_SET_NAME: u64 = 15;
pub const PR_GET_NAME: u64 = 16;
pub const PR_SET_PDEATHSIG: u64 = 1;
/// Канал-типы (ops.channel_create kind).
pub const CHAN_PIPE: u32 = 0;
pub const CHAN_EVENTFD: u32 = 1;
pub const CHAN_SOCKETPAIR: u32 = 2;
pub const CHAN_TIMERFD: u32 = 3;
pub const SYS_readlink: u64 = 89; // 87 = unlink (!коллизия)
pub const SYS_prlimit64: u64 = 302;
pub const SYS_getrandom: u64 = 318;
pub const SYS_clone: u64 = 56;
pub const SYS_getpid: u64 = 39;
pub const SYS_fcntl: u64 = 72;
pub const SYS_exit: u64 = 60;
pub const SYS_futex: u64 = 202;
pub const SYS_getuid: u64 = 102;
pub const SYS_getgid: u64 = 104;
pub const SYS_geteuid: u64 = 107;
pub const SYS_getegid: u64 = 108;
pub const SYS_getppid: u64 = 110;
pub const SYS_gettid: u64 = 186;
pub const SYS_epoll_wait: u64 = 232;
pub const SYS_epoll_ctl: u64 = 233;
pub const SYS_exit_group: u64 = 231;
pub const SYS_epoll_create1: u64 = 291;
pub const SYS_uname: u64 = 63;
pub const SYS_openat: u64 = 257;

// ─── errno (linux asm-generic/errno-base.h + errno.h) ─────────────────────

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EFAULT: i64 = 14;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const ENODEV: i64 = 19;
pub const ENFILE: i64 = 23; // реестры каналов/файлов исчерпаны
pub const EINVAL: i64 = 22;
pub const EISDIR: i64 = 21; // read/write на dir-fd (CDD №12 p3)
pub const ENOTDIR: i64 = 20; // getdents64 не на dir-fd
pub const ELOOP: i64 = 40; // слишком много симлинков в цепи (readlink/resolve)
pub const EFBIG: i64 = 27; // ftruncate: сверх ANON_FILE_MAX (CDD №12 p3)
pub const EAFNOSUPPORT: i64 = 97; // socketpair: только AF_UNIX
pub const ESOCKTNOSUPPORT: i64 = 94; // только SOCK_STREAM
pub const EPROTONOSUPPORT: i64 = 93; // протокол 0
pub const ENOTSUP: i64 = 95; // TFD_TIMER_ABSTIME и пр.
pub const ENOTTY: i64 = 25;
pub const EPIPE: i64 = 32;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ETIMEDOUT: i64 = 110;
pub const ESPIPE: i64 = 29; // lseek на не-файл (pipe/device)

/// Кодирование ошибки в RAX: Linux возвращает -errno (u64-биткаст).
pub inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

/// Канонический потолок user-пространства x86_64 (57-бит LAPE не включаем).
pub const USER_VA_CEILING: u64 = 0x0000_7FFF_FFFF_FFFF;

/// AT_FDCWD (-100): openat относительно cwd процесса.
pub const AT_FDCWD: i64 = -100;

// ─── Utsname (asm/utsname.h: 6 полей × 65 байт) ────────────────────────────

pub const UTS_LEN: usize = 64; // +1 байт нуль-терминации = 65
pub const UTS_FIELDS: usize = 6;

/// struct utsname Linux: sysname, nodename, release, version, machine,
/// domainname (последнее поле — __NEW_UTS_LEN в glibc-совместимой раскладке).
pub const Utsname = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,

    /// Заполнить поле nul-терминированной строкой (обрезка по UTS_LEN).
    pub fn setField(self: *Utsname, comptime field: []const u8, value: []const u8) void {
        const dst = &@field(self, field);
        const n = @min(value.len, UTS_LEN);
        @memcpy(dst[0..n], value[0..n]);
        @memset(dst[n..], 0);
    }
};

/// comptime-заполнение поля utsname: строка + нули до 65Б (без ручных
/// счётчиков `[1]u8{0} ** N` — источника off-by-one).
fn utsField(comptime s: []const u8) [65]u8 {
    var buf: [65]u8 = .{0} ** 65;
    @memcpy(buf[0..s.len], s);
    return buf;
}

/// uname-данные POLER-OS Linux-слоя (ядро едино для всех задач).
pub const default_uts = Utsname{
    .sysname = utsField("POLER-OS"),
    .nodename = utsField("poler"),
    .release = utsField("0.19.0"),
    .version = utsField("POLER-OS CDD #10 Linux POSIX graphics layer"),
    .machine = utsField("x86_64"),
    .domainname = utsField("(none)"),
};

// ─── mmap-флаги/прот (linux mman.h) ────────────────────────────────────────

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const PROT_NONE: u64 = 0x0;

pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

// ─── open-флаги (fcntl.h) ─────────────────────────────────────────────────

pub const O_ACCMODE: u64 = 0x3;
pub const O_RDONLY: u64 = 0x0;
pub const O_WRONLY: u64 = 0x1;
pub const O_RDWR: u64 = 0x2;
pub const O_NONBLOCK: u64 = 0x800; // 0o4000

// ─── poll/epoll (poll.h + eventpoll.h) ────────────────────────────────────

pub const POLLIN: i16 = 0x001;
pub const POLLPRI: i16 = 0x002;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLL_CTL_ADD: u64 = 1;
pub const EPOLL_CTL_MOD: u64 = 2;
pub const EPOLL_CTL_DEL: u64 = 3;

/// struct pollfd (8Б): fd, events (in), revents (out).
pub const PollFd = extern struct {
    fd: i32 = -1,
    events: i16 = 0,
    revents: i16 = 0,
};

/// struct epoll_event (12Б, PACKED — uapi eventpoll.h):
/// events u32 @0 + data u64 @4 (без паддинга!).
pub const EpollEvent = extern struct {
    events: u32 = 0,
    data: u64 align(1) = 0,
};

// ─── futex (linux/futex.h) ────────────────────────────────────────────────

pub const FUTEX_WAIT: u64 = 0;
pub const FUTEX_WAKE: u64 = 1;
/// CDD №12 p3: glibc использует WAIT/WAKE_BITSET + CLOCK_REALTIME
/// (pthread-мьютексы: op 0x189 = WAIT_BITSET|PRIVATE|REALTIME — эмпирика
/// run8: EINVAL → потоки SPIN-или весь прогон)
pub const FUTEX_WAIT_BITSET: u64 = 9;
pub const FUTEX_WAKE_BITSET: u64 = 10;
pub const FUTEX_PRIVATE_FLAG: u64 = 128;
pub const FUTEX_CLOCK_REALTIME: u64 = 256; // бит-атрибут таймчасов

// ─── clone (linux/sched.h) ────────────────────────────────────────────────

pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_THREAD: u64 = 0x10000;
/// v0.20.0 (CDD №11): NPTL-контракты pthread_join
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_PARENT_SETTID: u64 = 0x100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;
pub const CLONE_CHILD_SETTID: u64 = 0x10000000;

/// Максимальная ёмкость poll-буфера фундамента (ядро копирует в статический
/// буфер — аллокаций в syscall-пути нет). Linux-лимит RLIMIT_NOFILE больше,
/// но WAIT-эпоха (реальные процессы) пересмотрит.
pub const MAX_POLL_FDS: usize = 64;
pub const MAX_EPOLL_EVENTS: usize = 1024; // CAsyncWaiter MaxEvents=1024 (gamescope)
pub const MAX_WATCHES: usize = 32;
pub const MAX_FDS: usize = 64;

// ─── fcntl-команды (fcntl.h) ──────────────────────────────────────────────

pub const F_DUPFD: u64 = 0;
pub const F_GETFD: u64 = 1;
pub const F_SETFD: u64 = 2;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;

// ============================================================================
//  FD-таблица: «Всё есть файл» — устройства как файлы
// ============================================================================

/// Тип файла fd. console_out — stdout/stderr (serial); устройства DRM/evdev
/// читаются/пишутся через dev-мосты ops; epoll — инстанс мультиплексора.
pub const FdKind = enum {
    free,
    console_out,
    fb0,
    dri_card0,
    input_event0,
    input_event1,
    epoll,
    /// Файл initrd (RO — Live-USB: чтение с USB).
    initrd_file,
    /// Файл tmpfs (RW — Live-USB: запись в RAM).
    tmpfs_file,
    // ─── CDD №12 p2: канал-объекты (pipe/eventfd/socketpair/timerfd/
    // signalfd) — file_id = индекс в реестре каналов runtime ─────
    /// Читательский конец pipe (FIFO; epoll POLLIN).
    pipe_read,
    /// Писательский конец pipe.
    pipe_write,
    /// eventfd (счётчик 8Б; POLLIN при ≠0).
    eventfd,
    /// Конец socketpair AF_UNIX/SOCK_STREAM (двунаправленный).
    socket,
    /// timerfd (дедлайн+интервал; POLLIN при истечении).
    timerfd,
    /// signalfd (маска хранится; готовность — нет сигналов = 0).
    signalfd,
    /// CDD №12 p3: поток каталога (opendir → getdents64; file_id = DirStream).
    dir,
};

pub const MAX_FILE_ID: u32 = 64; // реестр открытых файлов runtime (p2: 64 — е2е фд-фонтан)

/// Один наблюдаемый fd в epoll-инстансе.
pub const EpollWatch = struct {
    fd: i32 = -1,
    events: u32 = 0,
    data: u64 = 0,
};

pub const FdEntry = struct {
    kind: FdKind = .free,
    nonblock: bool = false,
    /// Файловый дескриптор: идентификатор в реестре runtime (VFS).
    file_id: u32 = 0,
    /// Текущее смещение чтения/записи (Linux: последовательный I/O,
    /// lseek — вне фундамента v0.19).
    file_off: u64 = 0,
    // epoll-инстанс: список наблюдений
    watches: [MAX_WATCHES]EpollWatch = [_]EpollWatch{.{}} ** MAX_WATCHES,
    watch_count: usize = 0,

    pub fn used(self: *const FdEntry) bool {
        return self.kind != .free;
    }

    pub fn isFile(self: *const FdEntry) bool {
        return self.kind == .initrd_file or self.kind == .tmpfs_file;
    }
};

/// Таблица fd процесса (0/1/2 = консоль — как Linux stdio).
pub const FdTable = struct {
    entries: [MAX_FDS]FdEntry = [_]FdEntry{.{}} ** MAX_FDS,

    pub fn init() FdTable {
        var t = FdTable{};
        t.entries[0] = .{ .kind = .console_out };
        t.entries[1] = .{ .kind = .console_out };
        t.entries[2] = .{ .kind = .console_out };
        return t;
    }

    pub fn get(self: *FdTable, fd: i64) ?*FdEntry {
        if (fd < 0 or fd >= MAX_FDS) return null;
        const e = &self.entries[@intCast(fd)];
        if (!e.used()) return null;
        return e;
    }

    fn allocFd(self: *FdTable, kind: FdKind, nonblock: bool) i64 {
        var i: usize = 0;
        while (i < MAX_FDS) : (i += 1) {
            if (!self.entries[i].used()) {
                self.entries[i] = .{ .kind = kind, .nonblock = nonblock };
                return @intCast(i);
            }
        }
        return -EMFILE; // таблица полна (Linux: EMFILE = 24)
    }
};

pub const EMFILE: i64 = 24;

/// Резолв devfs-пути → тип файла (префикс /dev/). Чужие пути → null
/// (runtime вернёт -ENOENT — файловый мост VFS вне фундамента v0.19).
pub fn resolveDevKind(path: []const u8) ?FdKind {
    if (std.mem.eql(u8, path, "/dev/fb0")) return .fb0;
    if (std.mem.eql(u8, path, "/dev/dri/card0")) return .dri_card0;
    if (std.mem.eql(u8, path, "/dev/dri/renderD128")) return .dri_card0;
    if (std.mem.eql(u8, path, "/dev/input/event0")) return .input_event0;
    if (std.mem.eql(u8, path, "/dev/input/event1")) return .input_event1;
    if (std.mem.eql(u8, path, "/dev/tty") or std.mem.eql(u8, path, "/dev/console")) return .console_out;
    return null;
}

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const LinuxOps = struct {
    /// Проверить user-диапазон [va, va+len) на доступ (want_write).
    /// Контракт зеркален win32_api.validateRange (постраничный walk PML4,
    /// canonical-потолок, @addWithOverflow — v0.18.0 hardening).
    validate: *const fn (va: u64, len: u64, want_write: bool) bool,
    /// Ядро → user: копия байтов (uname, poll-результаты). false = EFAULT.
    copy_out: *const fn (dst_va: u64, src: []const u8) bool,
    /// User → ядро: копия байтов (pollfd, epoll_event, futex-слово).
    copy_in: *const fn (dst: []u8, src_va: u64) bool,
    /// User C-строка (openat path) → kernel slice, не длиннее max_len.
    /// null = плохой указатель / нет терминатора в границах.
    copy_in_str: *const fn (src_va: u64, max_len: u64) ?[]const u8,
    /// write на консоль (stdout/stderr): байты или -errno.
    dev_write: *const fn (va: u64, count: u64) i64,
    /// read с устройства (event0/1): байты или -errno (-EAGAIN если пусто+NB).
    dev_read: *const fn (kind: FdKind, va: u64, count: u64, nonblock: bool) i64,
    /// ioctl-мост к drm_kms/evdev (kind идентифицирует устройство).
    dev_ioctl: *const fn (kind: FdKind, cmd: u32, arg: u64) i64,
    /// Готовность устройства: бит-маска POLLIN/POLLOUT (для poll/epoll).
    dev_ready: *const fn (kind: FdKind) u32,
    /// mmap устройства (fb0/card0+dumb-aperture): размещённый VA или -errno.
    dev_mmap: *const fn (kind: FdKind, off: u64, len: u64, prot: u64) i64,
    /// mmap анонимный: размещённый VA или -errno.
    do_mmap: *const fn (hint: u64, len: u64, prot: u64, flags: u64) i64,
    /// munmap: 0 или -errno.
    do_munmap: *const fn (va: u64, len: u64) i64,
    /// exit(code): завершение задачи (ядро — kill; тесты — запись кода).
    do_exit: *const fn (code: u64) void,
    /// exit_group(code): завершение процесса (все потоки).
    do_exit_group: *const fn (code: u64) void,
    /// clone-поток (CLONE_VM|CLONE_THREAD): tid или -errno. Ядро строит
    /// кадр ребёнка (RAX=0, RSP=stack, RIP=после-syscall) и регистрирует
    /// его стек в таблицах asm-владельца. parent_tid/child_tid — адреса
    /// слов SETTID-контрактов (пишет СЕМАНТИЧЕСКИЙ слой после успеха).
    do_clone: *const fn (flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) i64,
    /// futex-WAIT: значение уже сверено; парковка. 0/EAGAIN/ETIMEDOUT.
    futex_park: *const fn (uaddr: u64, timeout_ms: u64, infinite: bool) i64,
    /// futex-WAKE: число разбуженных.
    futex_wake: *const fn (uaddr: u64, n: u32) u32,
    /// v0.20.0 (CDD №11): PID текущего процесса (группа тредов).
    current_pid: *const fn () u64,
    /// v0.20.0 (CDD №11): TID текущей задачи (gettid; futex/NPTL).
    current_tid: *const fn () u64,
    /// v0.20.0 (CDD №11): brk(addr) — Linux-семантика (0 → текущий;
    /// рост/спад маппинга; отказ → старый brk).
    do_brk: *const fn (addr: u64) u64,
    /// glibc-волна (CDD №11 p1b): mprotect(va, len, prot) — обновление
    /// прав страниц (RELRO: RW→RO после загрузки). 0 / -errno.
    do_mprotect: *const fn (va: u64, len: u64, prot: u64) i64,
    /// arch_prctl(ARCH_SET_FS, addr): TLS-база задачи. 0 / -errno.
    arch_set_fs: *const fn (addr: u64) i64,
    /// arch_prctl(ARCH_GET_FS): текущая TLS-база.
    arch_get_fs: *const fn () u64,
    /// set_tid_address(addr): cleartid-слово ТЕКУЩЕГО треда (exit → 0+WAKE).
    /// Возвращает tid.
    set_tid_address: *const fn (addr: u64) u64,
    /// set_robust_list(addr, len): NPTL-реестр мьютексов. 0 / -errno.
    set_robust_list: *const fn (addr: u64, len: u64) i64,
    /// readlink("/proc/self/exe") в buf: длина или -errno (execfn из auxv).
    readlink_self: *const fn (buf_va: u64, bufsz: u64) i64,
    /// getrandom(va, count): энтропия в user-буфер. Байты или -errno.
    do_getrandom: *const fn (va: u64, count: u64) i64,
    /// clock_gettime-источник: монотонные наносекунды.
    time_ns: *const fn () u64,
    /// open_file: открыть файл VFS (initrd-RO/tmpfs-RW) по пути.
    /// Возвращает файл-id ≥ 0 или -errno; kind возвращает через out_kind.
    open_file: *const fn (path: []const u8, flags: u64, out_kind: *FdKind) i64,
    /// file_read: чтение файла по id+offset в user-VA (валидация уже
    /// сделана слоем). Возвращает байты или -errno.
    file_read: *const fn (id: u32, off: u64, va: u64, count: u64) i64,
    /// file_write: запись в файл (tmpfs) из user-VA.
    file_write: *const fn (id: u32, off: u64, va: u64, count: u64) i64,
    /// v0.20.0 (CDD №11 p3): FILE-BACKED mmap (MAP_PRIVATE): страницы с
    /// копией файловых байт [off, off+len) → размещённый VA или -errno.
    /// fixed_va != 0 — MAP_FIXED (ld.so: сегменты libc поверх первичного
    /// спана по точным адресам base+vaddr; замена существующих мапов).
    file_mmap: *const fn (id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64,
    /// v0.20.0 (CDD №11 p3): размер файла по id (lseek SEEK_END).
    file_size: *const fn (id: u32) u64,
    /// v0.20.0 (CDD №11 p3): УНИКАЛЬНЫЙ inode файла по id (fstat st_ino;
    /// glibc ld.so идентифицирует объекты по (st_dev, st_ino) — нулевой
    /// id = ложное «already loaded», библиотека не мапится!).
    file_ino: *const fn (id: u32) u64,
    /// v0.20.0 (CDD №11 p3): access(path) — существование (0/-errno).
    path_exists: *const fn (path: []const u8) i64,
    /// v0.20.0 (CDD №11 p3): newfstatat — stat по пути в user-VA (144Б
    /// struct stat: S_IFREG + st_size из VFS). 0/-errno.
    stat_by_path: *const fn (path: []const u8, buf_va: u64) i64,
    /// v0.20.0 (CDD №12 p1): readlink ОБЩЕГО пути (цель симлинка initrd)
    /// в user-буфер. Длина или -errno (-ENOENT/-EINVAL/-ELOOP).
    readlink_path: *const fn (path: []const u8, buf_va: u64, bufsz: u64) i64,
    /// v0.20.0 (CDD №12 p1): освобождение слота РЕЕСТРА файлов (close:
    /// реестр runtime VFS ≠ fd-таблица — иначе 16 либ = EMFILE, ld.so
    /// держит по одной открытой на каждую DT_NEEDED при обходе замыкания).
    release_file: *const fn (id: u32) void,
    // ─── CDD №12 p2: канал-объекты (pipe/eventfd/socketpair/timerfd) ──────
    /// Создать канал: kind 0=pipe, 1=eventfd, 2=socketpair, 3=timerfd;
    /// arg = initval(eventfd) / clockid(timerfd, игнорируется). id ≥ 0/-errno.
    channel_create: *const fn (kind: u32, arg: u64) i64,
    /// FIFO-чтение из канала (pipe_read/socket/eventfd-счётчик/timerfd-экспирации).
    channel_read: *const fn (id: u32, va: u64, count: u64) i64,
    /// Запись в канал (pipe_write/socket/eventfd-инкремент).
    channel_write: *const fn (id: u32, va: u64, count: u64) i64,
    /// Готовность канала: биты POLLIN/POLLOUT (для poll/epoll).
    channel_ready: *const fn (id: u32) u32,
    /// Снять ОДНУ ссылку канала (pipe/socketpair создаются с refs=2,
    /// eventfd/timerfd с refs=1); refs=0 → слот свободен.
    channel_unref: *const fn (id: u32) void,
    // ─── CDD №12 p2: сигнальное состояние glibc ───────────────────────────
    /// rt_sigaction: сохранить (sig, handler, flags, restorer); вернуть СТАРЫЙ
    /// handler или -errno (EINVAL: SIGKILL/SIGSTOP/диапазон).
    set_sigaction: *const fn (sig: u32, handler: u64, flags: u64, restorer: u64) i64,
    /// rt_sigaction: {handler, flags, restorer} текущего sig (для oldact).
    get_sigaction: *const fn (sig: u32) u64,
    /// rt_sigprocmask: установить маску (как 0=BLOCK/1=UNBLOCK/2=SETMASK);
    /// вернуть СТАРУЮ маску.
    set_sigmask: *const fn (how: u32, mask: u64) u64,
    /// memfd_create: анонимный RW-файл (Wayland-shm) → file_id или -errno.
    memfd_create: *const fn () i64,
    /// v0.20.0 (CDD №12 p3): ftruncate(id, len) — размер анонимного файла
    /// (PMM-блок, нули). 0/-errno. Только anon-файлы (memfd).
    truncate_file: *const fn (id: u32, len: u64) i64,
    /// v0.20.0 (CDD №12 p3): mmap MAP_SHARED anon-файла — ОБЩИЕ физ-
    /// страницы (Mesa lavapipe-heap, Wayland-shm). VA или -errno.
    shared_file_mmap: *const fn (id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64,
    /// CDD №12 p3: getdents64 — записи linux_dirent64 в user-буфер;
    /// поток каталога (libdrm opendir("/dev/dri") сканирует узлы).
    dir_read: *const fn (id: u32, buf_va: u64, count: u64) i64,
    /// CDD №12 p3: закрытие потока каталога.
    dir_close: *const fn (id: u32) void,
    /// CDD №12 p3: парковка ТЕКУЩЕЙ задачи на ms (блокирующий epoll_wait —
    /// анти-спин потоков композитора). Возврат — по тику/событию.
    task_park: *const fn (ms: u64) void,
    /// CDD №12 p3: mkdir в tmpfs (кэш-каталоги Меса: «дир» = слот-имя).
    mkdir_tmpfs: *const fn (path: []const u8) i64,
};

// ─── Аргументы syscall (единая структура для dispatch) ─────────────────────

pub const Args = struct {
    a1: u64 = 0, // RDI
    a2: u64 = 0, // RSI
    a3: u64 = 0, // RDX
    a4: u64 = 0, // R10
    a5: u64 = 0, // R8
    a6: u64 = 0, // R9
};

// ─── Обработчики (чистая логика + валидация → ops) ─────────────────────────

/// ssize_t write(fd, const void *buf, size_t count)
pub fn sysWrite(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    const e = fds.get(fd_i) orelse return err(EBADF);
    // tmpfs-файл: RW (Live-USB — «запись в RAM»)
    if (e.kind == .tmpfs_file) {
        // ядро ЧИТАЕТ user-буфер: want_write=false
        if (count > USER_VA_CEILING or !ops.validate(buf_va, count, false)) return err(EFAULT);
        const r = ops.file_write(e.file_id, e.file_off, buf_va, count);
        if (r < 0) return @bitCast(r);
        e.file_off += @intCast(r);
        return @intCast(r);
    }
    // CDD №12 p2: канальные виды (pipe-писец/socket/eventfd-инкремент)
    switch (e.kind) {
        .pipe_write, .socket, .eventfd => {
            if (count > USER_VA_CEILING or !ops.validate(buf_va, count, false)) return err(EFAULT);
            const r = ops.channel_write(e.file_id, buf_va, count);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        else => {},
    }
    if (e.kind != .console_out) return err(EBADF); // initrd: RO; файлы — только tmpfs
    // ядро ЧИТАЕТ user-буфер: want_write=false
    if (count > USER_VA_CEILING or !ops.validate(buf_va, count, false)) return err(EFAULT);
    const r = ops.dev_write(buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// ssize_t read(fd, void *buf, size_t count)
pub fn sysRead(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (e.kind) {
        .input_event0, .input_event1 => {
            // ядро ПИШЕТ в user-буфер: want_write=true
            if (count > USER_VA_CEILING or !ops.validate(buf_va, count, true)) return err(EFAULT);
            const r = ops.dev_read(e.kind, buf_va, count, e.nonblock);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        // CDD №12 p3: DRM-события (flip-complete/vblank) — read(card0)
        .dri_card0 => {
            if (count > USER_VA_CEILING or !ops.validate(buf_va, count, true)) return err(EFAULT);
            const r = ops.dev_read(e.kind, buf_va, count, e.nonblock);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        // каталог: read → EISDIR (Linux-семантика; glibc opendir не читает)
        .dir => return err(EISDIR),
        .pipe_read, .socket, .eventfd, .timerfd => {
            // канал: FIFO-чтение (pipe/socket), счётчик (eventfd), экспирации
            if (count > USER_VA_CEILING or !ops.validate(buf_va, count, true)) return err(EFAULT);
            const r = ops.channel_read(e.file_id, buf_va, count);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        .signalfd => return err(EAGAIN), // сигналов нет — пусто (NB-путь glibc)
        .initrd_file, .tmpfs_file => {
            // файл VFS: последовательное чтение (offset ведёт слой)
            if (count > USER_VA_CEILING or !ops.validate(buf_va, count, true)) return err(EFAULT);
            const r = ops.file_read(e.file_id, e.file_off, buf_va, count);
            if (r < 0) return @bitCast(r);
            e.file_off += @intCast(r);
            return @intCast(r);
        },
        else => return err(EBADF), // консоль: входного пути нет (stdin)
    }
}

/// int openat(int dirfd, const char *pathname, int flags, mode_t mode)
pub fn sysOpenat(ops: LinuxOps, fds: *FdTable, dirfd_i: i64, path_va: u64, flags: u64, mode: u64) u64 {
    _ = mode;
    _ = dirfd_i; // AT_FDCWD/абсолютные пути — cwd-слоя нет (фундамент)
    // путь — C-строка: 1..4096 байт (PATH_MAX с запасом на терминатор)
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 4096)) |path| {
            if (path.len == 0) return err(EINVAL);
            if (resolveDevKind(path)) |kind| {
                const fd = fds.allocFd(kind, (flags & O_NONBLOCK) != 0);
                if (fd < 0) return @bitCast(fd);
                // CDD №12 p3: minor узла — fstat st_rdev (libdrm
                // drmGetNodeTypeFromFd: renderD128 ↔ card0)
                fds.entries[@intCast(fd)].file_id = devMinor(path);
                return @intCast(fd);
            }
            // VFS-файл (initrd-RO / tmpfs-RW — Live-USB overlay)
            var kind: FdKind = .free;
            const file_id = ops.open_file(path, flags, &kind);
            if (file_id < 0) return @bitCast(file_id);
            const fd = fds.allocFd(kind, (flags & O_NONBLOCK) != 0);
            if (fd < 0) return @bitCast(fd);
            fds.entries[@intCast(fd)].file_id = @intCast(file_id);
            fds.entries[@intCast(fd)].file_off = 0;
            return @intCast(fd);
        }
    }
    return err(EFAULT);
}

/// int close(int fd)
pub fn sysClose(ops: LinuxOps, fds: *FdTable, fd_i: i64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    // v0.20.0 (CDD №12 p1): слот РЕЕСТРА файлов (fd→file_id: initrd/tmpfs)
    // освобождаем ДО затирания записи — иначе утечка (EMFILE после 16 либ).
    // p2: каналы (pipe/eventfd/socket/timerfd) — счётчик ссылок концов.
    switch (e.kind) {
        .initrd_file, .tmpfs_file => ops.release_file(e.file_id),
        .pipe_read, .pipe_write, .eventfd, .socket, .timerfd, .signalfd => ops.channel_unref(e.file_id),
        .dir => ops.dir_close(e.file_id), // CDD №12 p3: поток каталога
        else => {},
    }
    e.* = .{}; // освобождаем слот fd-таблицы (epoll-наблюдения тоже)
    return 0;
}

/// int fcntl(int fd, int cmd, ...): F_GETFL/F_SETFL (O_NONBLOCK) фундамент.
pub fn sysFcntl(ops: LinuxOps, fds: *FdTable, fd_i: i64, cmd: u64, arg: u64) u64 {
    _ = ops;
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (cmd) {
        F_GETFL => {
            var fl: u64 = O_RDWR; // устройства открыты RW
            if (e.nonblock) fl |= O_NONBLOCK;
            return fl;
        },
        F_SETFL => {
            // разрешаем менять ТОЛЬКО O_NONBLOCK (access-биты игнорируются)
            e.nonblock = (arg & O_NONBLOCK) != 0;
            return 0;
        },
        F_GETFD, F_SETFD => return 0, // FD_CLOEXEC — процессов-CLOEXEC нет
        else => return err(EINVAL),
    }
}

/// int ioctl(int fd, unsigned long cmd, ...) — мост к drm_kms/evdev.
pub fn sysIoctl(ops: LinuxOps, fds: *FdTable, fd_i: i64, cmd: u32, arg: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (e.kind) {
        .fb0, .dri_card0, .input_event0, .input_event1 => {
            const r = ops.dev_ioctl(e.kind, cmd, arg);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        else => return err(ENOTTY), // консоль/epoll: не ioctl-устройства
    }
}

/// void *mmap(addr, length, prot, flags, fd, off)
pub fn sysMmap(ops: LinuxOps, fds: *FdTable, hint: u64, length: u64, prot: u64, flags: u64, fd_i: i64, off: u64) u64 {
    if (length == 0) return err(EINVAL);
    if (length > USER_VA_CEILING) return err(ENOMEM);
    // Поле MAP_FIXED с хинтом вне canonical user — немедленный отказ
    if (flags & MAP_FIXED != 0) {
        if (hint > USER_VA_CEILING) return err(EINVAL);
    }
    if (flags & MAP_ANONYMOUS != 0) {
        // Анонимный маппинг: PRIVATE — приватные страницы; SHARED|ANON
        // разрешён Linux ≥3.17 (shmem) — v0.19 честно размещает те же
        // приватные страницы (разделяемость появится с real-threads).
        const r = ops.do_mmap(hint, length, prot, flags);
        if (r < 0) return @bitCast(r);
        return @intCast(r);
    }
    // Файловый/девайс-маппинг: fd обязан быть открыт
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (e.kind) {
        .fb0, .dri_card0 => {
            if (off % PAGE_SIZE != 0) return err(EINVAL); // offset кратен стр.
            const r = ops.dev_mmap(e.kind, off, length, prot);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        // v0.20.0 (CDD №11 p3, ld.so-волна): FILE-BACKED mmap (initrd/tmpfs):
        // MAP_PRIVATE = приватная копия (чтение с «USB», запись — своя).
        // Реализация: анонимные страницы + копия файловых байт (ld.so грузит
        // libc.so сегментами — эмпирика dyn-elf: ENODEV → exit_group(127)).
        .initrd_file, .tmpfs_file => {
            // CDD №12 p3: MAP_SHARED — только АНОН-файлы (memfd: lavapipe-heap,
            // wl_shm): общие физ-страницы между маппингами. initrd/heap-tmpfs
            // (RO/RAM-малые) — честный ENOSYS как раньше.
            if (flags & MAP_SHARED != 0) {
                const fixed_va: u64 = if (flags & MAP_FIXED != 0 and hint != 0) hint else 0;
                const r = ops.shared_file_mmap(e.file_id, off, length, prot, fixed_va);
                if (r < 0) return @bitCast(r);
                return @intCast(r);
            }
            // MAP_FIXED: ld.so ремапит сегменты по base+vaddr поверх спана
            const fixed_va: u64 = if (flags & MAP_FIXED != 0 and hint != 0) hint else 0;
            const r = ops.file_mmap(e.file_id, off, length, prot, fixed_va);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        else => return err(ENODEV), // event-файлы не мапятся (Linux: ENODEV)
    }
}

/// off_t lseek(int fd, off_t off, int whence): SEEK_SET=0/CUR=1/END=2.
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

pub fn sysLseek(ops: LinuxOps, fds: *FdTable, fd_i: i64, off: i64, whence: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    if (!e.isFile()) return err(ESPIPE); // консоль/devices: ESPIPE (Linux)
    var new_off: i64 = 0;
    switch (whence) {
        SEEK_SET => new_off = off,
        SEEK_CUR => {
            const sum = @addWithOverflow(@as(i64, @bitCast(e.file_off)), off);
            if (sum[1] != 0) return err(EINVAL);
            new_off = sum[0];
        },
        SEEK_END => {
            // конец файла — через file_size op (реестр runtime)
            const fsize: i64 = @intCast(ops.file_size(e.file_id));
            const sum = @addWithOverflow(fsize, off);
            if (sum[1] != 0) return err(EINVAL);
            new_off = sum[0];
        },
        else => return err(EINVAL),
    }
    if (new_off < 0) return err(EINVAL);
    e.file_off = @intCast(new_off);
    return @intCast(new_off);
}

/// ssize_t pread64(fd, buf, count, offset): чтение БЕЗ сдвига file_off.
pub fn sysPread64(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64, count: u64, off: u64) u64 {
    if (count == 0) return 0;
    if (count > USER_VA_CEILING) return err(EINVAL);
    const e = fds.get(fd_i) orelse return err(EBADF);
    if (!e.isFile()) return err(EBADF);
    if (!ops.validate(buf_va, count, true)) return err(EFAULT);
    const r = ops.file_read(e.file_id, off, buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// ssize_t writev(fd, iov, iovcnt): векторная запись (glibc: stderr/stdio!).
/// struct iovec { void *base; size_t len; } — 16Б.
pub const MAX_IOV: usize = 32;

pub fn sysWritev(ops: LinuxOps, fds: *FdTable, fd_i: i64, iov_va: u64, iovcnt: u64) u64 {
    if (iovcnt == 0) return 0;
    if (iovcnt > MAX_IOV) return err(EINVAL);
    if (!ops.validate(iov_va, iovcnt * 16, false)) return err(EFAULT);
    // пишем последовательно: каждая iovec = отдельный write (консоль/tmpfs)
    var total: u64 = 0;
    var i: u64 = 0;
    while (i < iovcnt) : (i += 1) {
        var iov: [16]u8 = undefined;
        if (!ops.copy_in(&iov, iov_va + i * 16)) return err(EFAULT);
        const base = std.mem.readInt(u64, iov[0..8], .little);
        const len = std.mem.readInt(u64, iov[8..16], .little);
        if (len == 0) continue;
        if (len > USER_VA_CEILING) return err(EINVAL);
        const w = sysWrite(ops, fds, fd_i, base, len);
        if (w != err(EFAULT) and w != err(EBADF)) {
            const bytes: i64 = @bitCast(w);
            if (bytes < 0) return w; // errno
            total += @intCast(bytes);
        } else {
            return w;
        }
    }
    return total;
}

/// int access(path, mode): существование файла (ld.so: конфиги/кэш).
pub fn sysAccess(ops: LinuxOps, path_va: u64, mode: u64) u64 {
    _ = mode; // R_OK/W_OK/X_OK/F_OK — база: существование
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 4096)) |path| {
            const r = ops.path_exists(path);
            if (r < 0) return @bitCast(r);
            return 0;
        }
    }
    return err(EFAULT);
}

/// int newfstatat(dirfd, path, statbuf, flags): stat по ПУТИ (ld.so:
/// размер библиотеки для mmap-планировки). struct stat x86_64 = 144Б.
pub fn sysNewfstatat(ops: LinuxOps, dirfd_i: i64, path_va: u64, buf_va: u64, flags: u64) u64 {
    _ = dirfd_i; // AT_FDCWD/абсолютные пути — cwd-слоя нет (фундамент)
    _ = flags; // AT_EMPTY_PATH-модель вне фундамента
    if (!ops.validate(buf_va, STAT_SIZE, true)) return err(EFAULT);
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 4096)) |path| {
            const r = ops.stat_by_path(path, buf_va);
            if (r < 0) return @bitCast(r);
            return 0;
        }
    }
    return err(EFAULT);
}

/// int munmap(void *addr, size_t length)
pub fn sysMunmap(ops: LinuxOps, va: u64, length: u64) u64 {
    if (length == 0) return err(EINVAL);
    if (va % PAGE_SIZE != 0) return err(EINVAL);
    if (va > USER_VA_CEILING) return err(EINVAL);
    const sum = @addWithOverflow(va, length);
    if (sum[1] != 0 or sum[0] > USER_VA_CEILING + 1) return err(EINVAL);
    const r = ops.do_munmap(va, length);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// long futex(u32 *uaddr, int op, u32 val, const timespec *timeout, ...)
pub fn sysFutex(ops: LinuxOps, uaddr: u64, op_in: u64, val: u64, timeout_va: u64) u64 {
    // CDD №12 p3: PRIVATE и CLOCK_REALTIME — АТРИБУТЫ (не операции);
    // BITSET-варианты ≈ обычные WAIT/WAKE (маска uaddr2/val3 — все-биты
    // в наших сценариях; игнорируем выборочно-битовые ожидания)
    const op = op_in & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    // Слово фьютекса обязано читаться (WAIT) — валидация ДО разыменования
    if (!ops.validate(uaddr, 4, false)) return err(EFAULT);
    switch (op) {
        FUTEX_WAIT, FUTEX_WAIT_BITSET => {
            var word_buf: [4]u8 = undefined;
            if (!ops.copy_in(&word_buf, uaddr)) return err(EFAULT);
            const word = std.mem.readInt(u32, &word_buf, .little);
            if (word != val) return err(EAGAIN); // классика: значение изменилось
            // таймаут: timespec { sec i64, nsec i64 } (16Б); 0 = бесконечно
            var timeout_ms: u64 = 0;
            var infinite = true;
            if (timeout_va != 0) {
                if (!ops.validate(timeout_va, 16, false)) return err(EFAULT);
                var ts_buf: [16]u8 = undefined;
                if (!ops.copy_in(&ts_buf, timeout_va)) return err(EFAULT);
                const sec = std.mem.readInt(i64, ts_buf[0..8], .little);
                const nsec = std.mem.readInt(i64, ts_buf[8..16], .little);
                if (sec == 0 and nsec == 0) {
                    infinite = false; // немедленный таймаут
                    timeout_ms = 0;
                } else {
                    // клампим в u64-мс (санити от мусора: ≤ суток)
                    const ms: u64 = @intCast(@max(sec, 0) * 1000 + @divTrunc(@max(nsec, 0), 1_000_000));
                    timeout_ms = @min(ms, 86_400_000);
                    infinite = false;
                }
            }
            const r = ops.futex_park(uaddr, timeout_ms, infinite);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        FUTEX_WAKE, FUTEX_WAKE_BITSET => {
            const n: u32 = std.math.cast(u32, val) orelse std.math.maxInt(u32);
            return ops.futex_wake(uaddr, n);
        },
        else => return err(EINVAL), // CMP_REPIQUE/PI-варианты — вне фундамента
    }
}

/// int poll(struct pollfd *fds, nfds_t nfds, int timeout)
pub fn sysPoll(ops: LinuxOps, fds: *FdTable, fds_va: u64, nfds: u64, timeout: i64) u64 {
    _ = timeout; // v0.19: НЕБЛОКИРУЮЩИЙ опрос (блокирующее ожидание —
    // epoll/wait-волна с реальными процессами; документировано)
    if (nfds > MAX_POLL_FDS) return err(EINVAL);
    if (nfds == 0) return 0;
    if (!ops.validate(fds_va, nfds * @sizeOf(PollFd), true)) return err(EFAULT);

    // копируем внутрь (pollfd — in/out), считаем готовность, копируем назад
    var kbuf: [MAX_POLL_FDS]PollFd = undefined;
    if (!ops.copy_in(std.mem.sliceAsBytes(kbuf[0..@intCast(nfds)]), fds_va)) return err(EFAULT);

    var ready_count: u64 = 0;
    for (kbuf[0..@intCast(nfds)]) |*p| {
        p.revents = 0;
        if (p.fd < 0) continue; // Linux: fd<0 → игнорируется
        const e = fds.get(p.fd) orelse {
            p.revents = POLLNVAL; // незакрытый/чужой fd
            ready_count += 1;
            continue;
        };
        var rdy: i16 = 0;
        switch (e.kind) {
            .console_out => rdy = POLLOUT, // консоль всегда готова писать
            .fb0, .dri_card0 => rdy = POLLOUT, // DRM-карта готова писать
            .input_event0, .input_event1 => {
                const mask = ops.dev_ready(e.kind);
                if (mask & EPOLLIN != 0) rdy |= POLLIN;
                if (mask & EPOLLOUT != 0) rdy |= POLLOUT;
                if (mask & EPOLLERR != 0) rdy |= POLLERR;
            },
            .epoll => rdy = POLLOUT, // epoll-инстанс «готов» (wait-able)
            .pipe_read => {
                if (ops.channel_ready(e.file_id) & EPOLLIN != 0) rdy |= POLLIN;
            },
            .pipe_write => rdy = POLLOUT, // запись в буфер канала — всегда
            .eventfd => {
                if (ops.channel_ready(e.file_id) & EPOLLIN != 0) rdy |= POLLIN;
                rdy |= POLLOUT;
            },
            .socket => {
                if (ops.channel_ready(e.file_id) & EPOLLIN != 0) rdy |= POLLIN;
                rdy |= POLLOUT;
            },
            .timerfd => {
                if (ops.channel_ready(e.file_id) & EPOLLIN != 0) rdy |= POLLIN;
            },
            .signalfd => {}, // сигналов нет — не готов
            .initrd_file => rdy = POLLIN, // RO-файл: читаем
            .tmpfs_file => rdy = POLLIN | POLLOUT, // RAM-файл: RW
            .dir => {}, // каталог: read недоступен (EISDIR) — не готов
            .free => unreachable,
        }
        p.revents = p.events & rdy;
        if (p.revents != 0) ready_count += 1;
    }

    if (!ops.copy_out(fds_va, std.mem.sliceAsBytes(kbuf[0..@intCast(nfds)]))) return err(EFAULT);
    return ready_count;
}

/// int epoll_create1(int flags)
pub fn sysEpollCreate1(ops: LinuxOps, fds: *FdTable, flags: u64) u64 {
    _ = flags; // EPOLL_CLOEXEC — без exec нет и close-on-exec
    _ = ops;
    const fd = fds.allocFd(.epoll, false);
    if (fd < 0) return @bitCast(fd);
    return @intCast(fd);
}

/// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
pub fn sysEpollCtl(ops: LinuxOps, fds: *FdTable, epfd: i64, op: u64, fd_i: i64, event_va: u64) u64 {
    const ep = fds.get(epfd) orelse return err(EBADF);
    if (ep.kind != .epoll) return err(EINVAL); // не epoll-инстанс
    // проверка существования целевого fd (валидация, значение ниже)
    if (fds.get(fd_i) == null) return err(EBADF);

    var ev = EpollEvent{};
    if (op != EPOLL_CTL_DEL) {
        if (!ops.validate(event_va, @sizeOf(EpollEvent), false)) return err(EFAULT);
        var ev_buf: [12]u8 = undefined;
        if (!ops.copy_in(&ev_buf, event_va)) return err(EFAULT);
        ev.events = std.mem.readInt(u32, ev_buf[0..4], .little);
        ev.data = std.mem.readInt(u64, ev_buf[4..12], .little);
    }

    switch (op) {
        EPOLL_CTL_ADD => {
            if (ep.watch_count >= MAX_WATCHES) return err(ENOMEM);
            // дубликат?
            for (ep.watches[0..ep.watch_count]) |w| {
                if (w.fd == fd_i) return err(EEXIST);
            }
            ep.watches[ep.watch_count] = .{ .fd = @intCast(fd_i), .events = ev.events, .data = ev.data };
            ep.watch_count += 1;
            return 0;
        },
        EPOLL_CTL_MOD => {
            for (ep.watches[0..ep.watch_count]) |*w| {
                if (w.fd == fd_i) {
                    w.events = ev.events;
                    w.data = ev.data;
                    return 0;
                }
            }
            return err(ENOENT);
        },
        EPOLL_CTL_DEL => {
            var i: usize = 0;
            while (i < ep.watch_count) : (i += 1) {
                if (ep.watches[i].fd == fd_i) {
                    // сдвигаем хвост (порядок наблюдений не гарантирован)
                    var j = i;
                    while (j + 1 < ep.watch_count) : (j += 1) {
                        ep.watches[j] = ep.watches[j + 1];
                    }
                    ep.watch_count -= 1;
                    return 0;
                }
            }
            return err(ENOENT);
        },
        else => return err(EINVAL),
    }
}

/// int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
/// (внутренний) одиночный скан готовности + копи-аут — неблокирующий.
fn epollScanOnce(ops: LinuxOps, fds: *FdTable, epfd: i64, events_va: u64, maxevents: u64) u64 {
    const ep = fds.get(epfd) orelse return err(EBADF);
    if (ep.kind != .epoll) return err(EINVAL);
    if (maxevents == 0 or maxevents > MAX_EPOLL_EVENTS) return err(EINVAL);
    if (!ops.validate(events_va, maxevents * @sizeOf(EpollEvent), true)) return err(EFAULT);

    // вычисляем готовые: watch.events & (готовность | EPOLLERR)
    var ev_buf: [MAX_EPOLL_EVENTS * 12]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < ep.watch_count and n < maxevents) : (i += 1) {
        const w = ep.watches[i];
        const e = fds.get(w.fd) orelse continue; // fd закрыли после ADD
        var rdy: u32 = 0;
        switch (e.kind) {
            .console_out, .fb0, .dri_card0, .epoll => rdy = EPOLLOUT,
            .input_event0, .input_event1 => rdy = ops.dev_ready(e.kind),
            .initrd_file => rdy = EPOLLIN,
            .tmpfs_file => rdy = EPOLLIN | EPOLLOUT,
            .pipe_read, .timerfd => rdy = ops.channel_ready(e.file_id),
            .dir => {}, // каталог: не готов (read → EISDIR)
            .pipe_write, .socket, .eventfd => rdy = ops.channel_ready(e.file_id) | EPOLLOUT,
            .signalfd => rdy = 0, // сигналов нет
            .free => unreachable,
        }
        // CDD №12 p3: HUP/ERR ТОЛЬКО из реальной готовности (channel_ready
        // вернёт EPOLLHUP когда закрыт peer-конец pipe/socketpair). Раньше
        // EPOLLHUP вводился в маску БЕЗУСЛОВНО → каждый watch немедленно
        // «hung up» → gamescope «IWaitable hung up. Aborting.» (мгновенный
        // abort на старте композитора).
        const combined = w.events & rdy;
        if (combined != 0) {
            var ev: EpollEvent = .{ .events = combined, .data = w.data };
            @memcpy(ev_buf[n * 12 ..][0..12], std.mem.asBytes(&ev));
            n += 1;
        }
    }
    if (n > 0) {
        if (!ops.copy_out(events_va, ev_buf[0 .. n * 12])) return err(EFAULT);
    }
    return n;
}

/// epoll_wait: БЛОКИРУЮЩИЙ (CDD №12 p3 — анти-СПИН: эмпирика run8-10 —
/// 2526 холостых вызовов: потоки gamescope жгли TCG на 100%). timeout=0 —
/// честный неблокирующий опрос; timeout>0 — до дедлайна; timeout<0 — до
/// события (парковка слайсами 20мс + перепроверка: готовность приходит от
/// тика таймера/канала — кооперативная модель диспетчера).
pub fn sysEpollWait(ops: LinuxOps, fds: *FdTable, epfd: i64, events_va: u64, maxevents: u64, timeout: i64) u64 {
    if (timeout == 0) return epollScanOnce(ops, fds, epfd, events_va, maxevents);
    // валидируем буфер ДЛЯ максимального события заранее (EFAULT до парка)
    {
        const ep = fds.get(epfd) orelse return err(EBADF);
        if (ep.kind != .epoll) return err(EINVAL);
        if (maxevents == 0 or maxevents > MAX_EPOLL_EVENTS) return err(EINVAL);
        if (!ops.validate(events_va, maxevents * @sizeOf(EpollEvent), true)) return err(EFAULT);
    }
    const t0_ns = ops.time_ns();
    while (true) {
        const n = epollScanOnce(ops, fds, epfd, events_va, maxevents);
        if (n != 0) return n;
        const elapsed_ms: u64 = (ops.time_ns() - t0_ns) / 1_000_000;
        if (timeout > 0) {
            const total_ms: u64 = @intCast(timeout);
            if (elapsed_ms >= total_ms) return 0; // таймаут (честные 0 событий)
        }
        // слайс парковки: конечный — не длиннее остатка; бесконечный — 20мс
        const slice_ms: u64 = if (timeout > 0)
            @min(@as(u64, @intCast(timeout)) -| elapsed_ms, 20)
        else
            20;
        ops.task_park(slice_ms);
    }
}

/// long clone(unsigned long flags, void *stack, int *parent_tid,
///             int *child_tid, unsigned long tls) — ПОТОКИ v0.20:
/// фактический запуск (RAX=0 у ребёнка — runtime-мост do_clone).
/// SETTID-контракты NPTL: после успеха ядро пишет tid ребёнка в
/// *parent_tid (CLONE_PARENT_SETTID) и/или *child_tid (CLONE_CHILD_SETTID);
/// CLONE_CHILD_CLEARTID-слово runtime обнуляет на exit треда + FUTEX_WAKE
/// (pthread_join). CLONE_SETTLS принимается — FS-base в arch_prctl-волне.
pub fn sysClone(ops: LinuxOps, flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) u64 {
    const need = CLONE_VM | CLONE_SIGHAND;
    if (flags & need != need) return err(EINVAL); // fork/COW — честный EINVAL
    if (flags & CLONE_SIGHAND != 0 and flags & CLONE_VM == 0) return err(EINVAL);
    // SETTID-указатели обязаны присутствовать (ядро пишет tid после успеха)
    if (flags & CLONE_PARENT_SETTID != 0 and parent_tid == 0) return err(EINVAL);
    if (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 and child_tid == 0)
        return err(EINVAL);
    const r = ops.do_clone(flags, stack, parent_tid, child_tid, tls);
    if (r < 0) return @bitCast(r);
    const tid: u32 = @truncate(@as(u64, @intCast(r)));
    if (flags & CLONE_PARENT_SETTID != 0) {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, tid, .little);
        if (!ops.copy_out(parent_tid, &b)) return err(EFAULT);
    }
    if (flags & CLONE_CHILD_SETTID != 0) {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, tid, .little);
        if (!ops.copy_out(child_tid, &b)) return err(EFAULT);
    }
    return @intCast(r);
}

/// void exit_group(int status) — завершение ВСЕХ потоков процесса.
pub fn sysExitGroup(ops: LinuxOps, code: u64) u64 {
    ops.do_exit_group(code);
    return 0; // ядро сюда не вернётся (kill + spin в runtime-ops)
}

/// int uname(struct utsname *buf)
pub fn sysUname(ops: LinuxOps, buf_va: u64) u64 {
    if (!ops.validate(buf_va, @sizeOf(Utsname), true)) return err(EFAULT);
    if (!ops.copy_out(buf_va, std.mem.asBytes(&default_uts))) return err(EFAULT);
    return 0;
}

// ─── v0.20.0 (CDD №11 p1): идентичность процесса + brk (glibc-static волна) ─

/// uid/gid нашего CachyOS-пользователя (не-root: безопасность).
pub const KUID: u64 = 1000;

/// pid_t gettid(void) — TID текущей задачи (NPTL: futex/robust-list).
pub fn sysGettid(ops: LinuxOps) u64 {
    return ops.current_tid();
}

/// pid_t getpid(void) — PID процесса (одинаков во всех тредах).
pub fn sysGetpid(ops: LinuxOps) u64 {
    return ops.current_pid();
}

/// pid_t getppid(void) — родитель = init (1).
pub fn sysGetppid(ops: LinuxOps) u64 {
    _ = ops;
    return 1;
}

/// unsigned long brk(unsigned long addr) — Linux-семантика:
///   addr=0 → текущий brk; рост/спад — runtime; отказ → старый brk.
/// glibc-static malloc стартует с sbrk(0) (получить базис).
pub fn sysBrk(ops: LinuxOps, addr: u64) u64 {
    return ops.do_brk(addr);
}

// ─── glibc-волна (CDD №11 p1b): ранний init статических бинарников ─────────

/// ARCH_SET_FS / ARCH_GET_FS (TLS glibc) + остальное → EINVAL.
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

pub fn sysArchPrctl(ops: LinuxOps, code: u64, addr: u64) u64 {
    switch (code) {
        ARCH_SET_FS => {
            if (addr > USER_VA_CEILING) return err(EPERM);
            const r = ops.arch_set_fs(addr);
            if (r < 0) return @bitCast(r);
            return 0;
        },
        ARCH_GET_FS => {
            if (!ops.validate(addr, 8, true)) return err(EFAULT);
            const v = ops.arch_get_fs();
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, v, .little);
            if (!ops.copy_out(addr, &b)) return err(EFAULT);
            return 0;
        },
        else => return err(EINVAL), // SET_GS/GET_GS — GS занят TEB Win32-задач
    }
}

/// set_tid_address(addr): слово, которое ядро обнуляет + FUTEX_WAKE на
/// exit ТЕКУЩЕГО треда (main-тред glibc — pthread_join с init).
pub fn sysSetTidAddress(ops: LinuxOps, addr: u64) u64 {
    if (addr != 0 and !ops.validate(addr, 4, true)) return err(EFAULT);
    return ops.set_tid_address(addr);
}

/// set_robust_list(head, len): реестр robust-мьютексов NPTL. v0.20 —
/// фиксируем адрес (futex-эпилог владельца мёртвого треда — будущие волны).
pub fn sysSetRobustList(ops: LinuxOps, addr: u64, len: u64) u64 {
    if (len != 24) return err(EINVAL); // sizeof(struct robust_list_head)
    if (!ops.validate(addr, 24, true)) return err(EFAULT);
    return 0;
}

/// rseq: честный -ENOSYS (glibc ≥ 2.35 переключается на сигнал-модель).
pub fn sysRseq() u64 {
    return err(ENOSYS);
}

/// prlimit64(0, res, NULL, &rlim): RLIMIT_STACK = 8МБ (glibc: стек-модель
/// stdio-буферов). Прочие ресурсы — EINVAL.
pub const RLIMIT_STACK: u64 = 3;
pub const STACK_LIMIT: u64 = 8 * 1024 * 1024;

pub fn sysPrlimit64(ops: LinuxOps, pid: u64, res: u64, new_va: u64, old_va: u64) u64 {
    if (pid != 0) return err(EPERM); // только о себе
    if (res != RLIMIT_STACK) return err(EINVAL);
    if (new_va != 0) return err(EPERM); // setter — не фундамент
    if (old_va == 0) return 0;
    if (!ops.validate(old_va, 16, true)) return err(EFAULT);
    var b: [16]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], STACK_LIMIT, .little); // rlim_cur
    std.mem.writeInt(u64, b[8..16], STACK_LIMIT, .little); // rlim_max
    if (!ops.copy_out(old_va, &b)) return err(EFAULT);
    return 0;
}

/// readlinkat(AT_FDCWD, "/proc/self/exe", buf, sz): execfn (argv[0]).
pub fn sysReadlinkat(ops: LinuxOps, dirfd: u64, path_va: u64, buf_va: u64, bufsz: u64) u64 {
    _ = dirfd;
    if (bufsz == 0) return err(EINVAL);
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 64)) |path| {
            // /proc/self/exe — спец-узел (execfn из proc-слота)
            if (std.mem.eql(u8, path, "/proc/self/exe")) {
                if (!ops.validate(buf_va, @min(bufsz, USER_VA_CEILING), true)) return err(EFAULT);
                const r = ops.readlink_self(buf_va, bufsz);
                if (r < 0) return @bitCast(r);
                return @intCast(r);
            }
            // общий путь: цель симлинка initrd (CDD №12 p1: rootfs CachyOS)
            if (!ops.validate(buf_va, @min(bufsz, USER_VA_CEILING), true)) return err(EFAULT);
            const r = ops.readlink_path(path, buf_va, bufsz);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        }
    }
    return err(EFAULT);
}

/// getrandom(buf, count, flags): энтропия (TSC-микс; PUF-апгрейд — P2).
pub fn sysGetrandom(ops: LinuxOps, buf_va: u64, count: u64, flags: u64) u64 {
    if (flags != 0 and flags != 1) return err(EINVAL); // GRND_NONBLOCK=1
    if (count == 0) return 0;
    if (count > 256) return err(EIO); // фундамент: cap 256Б/вызов
    if (!ops.validate(buf_va, count, true)) return err(EFAULT);
    const r = ops.do_getrandom(buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// clock_gettime(clk, tp): монотонное время (тик+TSC-микс).
pub const CLOCK_MONOTONIC: u64 = 1;
pub const CLOCK_REALTIME: u64 = 0;

pub fn sysClockGettime(ops: LinuxOps, clk: u64, tp_va: u64) u64 {
    if (clk != CLOCK_REALTIME and clk != CLOCK_MONOTONIC) return err(EINVAL);
    if (!ops.validate(tp_va, 16, true)) return err(EFAULT);
    const ns = ops.time_ns();
    var b: [16]u8 = undefined;
    std.mem.writeInt(u64, b[0..8], ns / 1_000_000_000, .little); // tv_sec
    std.mem.writeInt(u64, b[8..16], ns % 1_000_000_000, .little); // tv_nsec
    if (!ops.copy_out(tp_va, &b)) return err(EFAULT);
    return 0;
}

/// fstat(fd, …): файловые fd — S_IFREG + РЕАЛЬНЫЙ st_size (ld.so
/// верифицирует библиотеку по fstat: CHR/нулевой размер → отказ без
/// mmap → «undefined symbol: __libc_start_main» → exit(127); эмпирика
/// dyn-elf CDD №11 p3). Устройства/консоль — S_IFCHR-заглушка. 144Б.
pub const STAT_SIZE: usize = 144;
const S_IFCHR: u64 = 0x2000;
const S_IFDIR: u64 = 0x4000; // CDD №12 p3: opendir (fstat S_ISDIR-проверка glibc)
const S_IFREG: u64 = 0x8000;
/// v0.20.0 (CDD №11 p3): st_dev VFS-файлов — НЕнулевая константа.
/// ЭМПИРИКА dyn-elf (glibc dl-load.c:959-1006): ld.so ИДЕНТИФИЦИРУЕТ
/// библиотеки по (st_dev, st_ino) из fstat (_dl_get_file_id) и сверяет с
/// картами в _ns_loaded: все-нулевой id → ЛОЖНОЕ «already loaded» →
/// close(fd) БЕЗ mmap → «undefined symbol: __libc_start_main» → exit(127).
pub const POLER_VFS_DEV: u64 = 0x1998;

pub fn sysFstat(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    if (!ops.validate(buf_va, STAT_SIZE, true)) return err(EFAULT);
    var st: [STAT_SIZE]u8 = [_]u8{0} ** STAT_SIZE;
    if (e.isFile()) {
        // struct stat x86_64: st_dev@0, st_ino@8, st_nlink@16, st_mode@24,
        // st_rdev@40, st_size@48, st_blksize@56, st_blocks@64
        std.mem.writeInt(u64, st[0..8], POLER_VFS_DEV, .little);
        std.mem.writeInt(u64, st[8..16], ops.file_ino(e.file_id), .little); // УНИКАЛЬНЫЙ ino!
        std.mem.writeInt(u64, st[16..24], 1, .little); // st_nlink
        std.mem.writeInt(u32, st[24..28], @intCast(S_IFREG | 0x1A4), .little); // reg + 0644
        std.mem.writeInt(u64, st[48..56], ops.file_size(e.file_id), .little); // st_size
        std.mem.writeInt(u64, st[56..64], 4096, .little); // st_blksize
        const blocks = (ops.file_size(e.file_id) + 511) / 512;
        std.mem.writeInt(u64, st[64..72], blocks, .little); // st_blocks
    } else if (e.kind == .dir) {
        // CDD №12 p3: opendir → glibc ПРОВЕРЯЕТ S_ISDIR(fstat) — иначе lose!
        std.mem.writeInt(u64, st[0..8], POLER_VFS_DEV, .little);
        std.mem.writeInt(u64, st[8..16], 0xD1D0 + @as(u64, e.file_id), .little);
        std.mem.writeInt(u64, st[16..24], 2, .little); // nlink (dir-конвенция)
        std.mem.writeInt(u32, st[24..28], @intCast(S_IFDIR | 0x1ED), .little); // dir + 0755
        std.mem.writeInt(u64, st[48..56], 4096, .little); // st_size (конвенция)
        std.mem.writeInt(u64, st[56..64], 4096, .little);
    } else {
        // консоль/устройства — симв. устройство
        std.mem.writeInt(u32, st[24..28], @intCast(S_IFCHR | 0x1A0), .little); // chr + 0620
        // CDD №12 p3: st_rdev — (major<<8)|minor (libdrm drmGetNodeTypeFromFd:
        // minor ≥ 128 = render-узел; sysfs-путь /sys/dev/char/226:128 тоже)
        if (e.kind == .dri_card0 or e.kind == .fb0 or
            e.kind == .input_event0 or e.kind == .input_event1)
        {
            const rdev = encodeDev(devMajorOf(e.kind), e.file_id);
            std.mem.writeInt(u64, st[40..48], rdev, .little); // st_rdev
        }
        std.mem.writeInt(u64, st[56..64], 4096, .little);
    }
    if (!ops.copy_out(buf_va, &st)) return err(EFAULT);
    return 0;
}

/// mprotect(va, len, prot): RELRO-волна glibc (RW-страницы образа → RO).
pub fn sysMprotect(ops: LinuxOps, va: u64, len: u64, prot: u64) u64 {
    if (len == 0) return err(EINVAL);
    if (va % PAGE_SIZE != 0) return err(EINVAL);
    const sum = @addWithOverflow(va, len);
    if (sum[1] != 0 or sum[0] > USER_VA_CEILING) return err(EINVAL);
    if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return err(EINVAL);
    const r = ops.do_mprotect(va, len, prot);
    if (r < 0) return @bitCast(r);
    return 0;
}

/// void exit(int status) — noreturn по ABI; ядро убивает задачу.
pub fn sysExit(ops: LinuxOps, code: u64) u64 {
    ops.do_exit(code);
    return 0; // ядро сюда не вернётся (kill + spin в runtime-ops)
}

/// выравненного чтения НЕ нужно: std.mem.readInt на байтовых массивах не
/// требует выравнивания (packed epoll_event.data читается напрямую)

// ─── CDD №12 p3: ftruncate + MAP_SHARED (Mesa/Wayland-shm) ──────────────────

/// ftruncate(fd, len): размер анонимного файла (memfd). Mesa:
/// os_create_anonymous_file = memfd_create + ftruncate (без него lavapipe
/// «Failed to create anonymous file for memory allocations»).
pub fn sysFtruncate(ops: LinuxOps, fds: *FdTable, fd_i: i64, len: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (e.kind) {
        .tmpfs_file => {
            const r = ops.truncate_file(e.file_id, len);
            if (r < 0) return @bitCast(r);
            return 0;
        },
        .initrd_file => return err(EINVAL), // RO
        else => return err(EINVAL),
    }
}

/// getdents64(fd, buf, count): записи linux_dirent64 из потока каталога
/// (opendir glibc → getdents64; libdrm сканирует /dev/dri — базис
/// drmGetDeviceFromDevId). Одна запись: {u64 d_ino; s64 d_off; u16 d_reclen;
/// u8 d_type; char d_name[]}, выравнивание 8. 0 = EOF (glibc readdir).
pub fn sysGetdents64(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64, count: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    if (e.kind != .dir) return err(ENOTDIR);
    if (count == 0) return 0;
    if (count > 0x20_0000) return err(EINVAL); // 2МБ — предел здравого смысла
    if (!ops.validate(buf_va, count, true)) return err(EFAULT);
    const r = ops.dir_read(e.file_id, buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// sched_getaffinity(pid, len, mask): маска CPU — glibc sysconf →
/// NPROCESSORS → размер пула растеризации llvmpipe. Ядровая модель —
/// 1 CPU (e2e: -smp 1): маска {0x01, 0} (128Б-кап). Возврат = len (как Linux).
pub fn sysSchedGetaffinity(ops: LinuxOps, pid: u64, len: u64, mask_va: u64) u64 {
    _ = pid; // маска ТЕКУЩЕГО (pid=0-семантика; чужие неинтересны)
    if (len == 0 or len > 128) return err(EINVAL);
    if (!ops.validate(mask_va, len, true)) return err(EFAULT);
    var mask: [128]u8 = [_]u8{0} ** 128;
    mask[0] = 1; // CPU 0 доступен
    if (!ops.copy_out(mask_va, mask[0..@intCast(len)])) return err(EFAULT);
    return len;
}

/// sched_setaffinity: принимаем (модель 1-CPU — запись в маску ни на что
/// не влияет; glibc-pthreads зовут при создании тредов).
pub fn sysSchedSetaffinity(ops: LinuxOps, pid: u64, len: u64, mask_va: u64) u64 {
    _ = pid;
    if (len == 0 or len > 128) return err(EINVAL);
    if (!ops.validate(mask_va, len, false)) return err(EFAULT);
    return 0;
}

/// sysinfo(struct sysinfo*): 112Б x86_64 — totalram/freeram (LLVM/Gallium
/// оценивают хипы), procs, mem_unit. Ядровая модель: 2ГБ гостя.
pub fn sysSysinfo(ops: LinuxOps, info_va: u64) u64 {
    if (!ops.validate(info_va, 112, true)) return err(EFAULT);
    var si: [112]u8 = [_]u8{0} ** 112;
    std.mem.writeInt(u64, si[0..8], 100, .little); // uptime (с)
    // loads[3] (1/5/15-мин средние — масштаб 65536): 0.10/0.05/0.01
    std.mem.writeInt(u64, si[8..16], 6554, .little);
    std.mem.writeInt(u64, si[16..24], 3277, .little);
    std.mem.writeInt(u64, si[24..32], 655, .little);
    std.mem.writeInt(u64, si[32..40], 2 * 1024 * 1024 * 1024, .little); // totalram
    std.mem.writeInt(u64, si[40..48], 1 * 1024 * 1024 * 1024, .little); // freeram
    std.mem.writeInt(u64, si[48..56], 0, .little); // sharedram
    std.mem.writeInt(u64, si[56..64], 0, .little); // bufferram
    std.mem.writeInt(u64, si[64..72], 0, .little); // totalswap
    std.mem.writeInt(u64, si[72..80], 0, .little); // freeswap
    std.mem.writeInt(u16, si[80..82], 8, .little); // procs
    std.mem.writeInt(u16, si[82..84], 0, .little); // pad
    std.mem.writeInt(u64, si[84..92], 0, .little); // totalhigh
    std.mem.writeInt(u64, si[92..100], 0, .little); // freehigh
    std.mem.writeInt(u32, si[100..104], 1, .little); // mem_unit (Б)
    // _f[20-2*u64-u32] — нули (104..112 + хвост)
    if (!ops.copy_out(info_va, &si)) return err(EFAULT);
    return 0;
}

/// mkdir(path, mode): создаём в tmpfs (как open с записью) — кэш-каталоги
/// Меса (шейдеры) пишутся в /root/.cache/... — Live-модель: RAM.
pub fn sysMkdir(ops: LinuxOps, path_va: u64, mode: u64) u64 {
    _ = mode; // права-модель вне фундамента
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 4096)) |path| {
            // каталог в tmpfs = слот-имя «dir:...» (дети неявно — файлы)
            const r = ops.mkdir_tmpfs(path);
            if (r < 0) return @bitCast(r);
            return 0;
        }
    }
    return err(EFAULT);
}

// ─── CDD №12 p2: канал-объекты + сигналы + misc-волна ───────────────────────

/// pipe2(int fds[2], flags): wakeup-канал Wayland/reaper-потоков (glibc:
/// CAsyncWaiter gamescope; O_NONBLOCK наследуют оба конца).
pub fn sysPipe2(ops: LinuxOps, fds: *FdTable, fds_va: u64, flags: u64) u64 {
    if (flags & ~(O_CLOEXEC | O_NONBLOCK) != 0) return err(EINVAL);
    if (!ops.validate(fds_va, 8, true)) return err(EFAULT);
    const chan = ops.channel_create(CHAN_PIPE, 0);
    if (chan < 0) return @bitCast(chan);
    const cid: u32 = @intCast(chan);
    const nonblock = (flags & O_NONBLOCK) != 0;
    const rfd = fds.allocFd(.pipe_read, nonblock);
    if (rfd < 0) {
        _ = ops.channel_unref(cid); // вернуть ссылку (созданную каналом)
        _ = ops.channel_unref(cid);
        return @bitCast(rfd);
    }
    fds.entries[@intCast(rfd)].file_id = cid;
    const wfd = fds.allocFd(.pipe_write, nonblock);
    if (wfd < 0) {
        fds.entries[@intCast(rfd)] = .{};
        _ = ops.channel_unref(cid);
        _ = ops.channel_unref(cid);
        return @bitCast(wfd);
    }
    fds.entries[@intCast(wfd)].file_id = cid;
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], @intCast(rfd), .little);
    std.mem.writeInt(u32, b[4..8], @intCast(wfd), .little);
    if (!ops.copy_out(fds_va, &b)) return err(EFAULT);
    return 0;
}

/// socketpair(domain, type, protocol, sv[4]): AF_UNIX/SOCK_STREAM —
/// двунаправленный канал (Wayland client↔server). Оба конца RW.
pub fn sysSocketpair(ops: LinuxOps, fds: *FdTable, domain: u64, stype: u64, protocol: u64, sv_va: u64) u64 {
    if (domain != 1) return err(EAFNOSUPPORT); // AF_UNIX only (фундамент)
    if (protocol != 0) return err(EPROTONOSUPPORT);
    if (stype & 0xFF != 1) return err(ESOCKTNOSUPPORT); // SOCK_STREAM
    if (stype & ~(0xFF | O_CLOEXEC | O_NONBLOCK) != 0) return err(EINVAL);
    if (!ops.validate(sv_va, 8, true)) return err(EFAULT);
    const chan = ops.channel_create(CHAN_SOCKETPAIR, 0);
    if (chan < 0) return @bitCast(chan);
    const cid: u32 = @intCast(chan);
    const nonblock = (stype & O_NONBLOCK) != 0;
    const fd0 = fds.allocFd(.socket, nonblock);
    if (fd0 < 0) {
        _ = ops.channel_unref(cid);
        _ = ops.channel_unref(cid);
        return @bitCast(fd0);
    }
    fds.entries[@intCast(fd0)].file_id = cid;
    const fd1 = fds.allocFd(.socket, nonblock);
    if (fd1 < 0) {
        fds.entries[@intCast(fd0)] = .{};
        _ = ops.channel_unref(cid);
        _ = ops.channel_unref(cid);
        return @bitCast(fd1);
    }
    fds.entries[@intCast(fd1)].file_id = cid;
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], @intCast(fd0), .little);
    std.mem.writeInt(u32, b[4..8], @intCast(fd1), .little);
    if (!ops.copy_out(sv_va, &b)) return err(EFAULT);
    return 0;
}

/// eventfd2(initval, flags): счётчик-канал (wl_event_loop).
pub fn sysEventfd2(ops: LinuxOps, fds: *FdTable, initval: u64, flags: u64) u64 {
    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE) != 0) return err(EINVAL);
    if (initval > 0xFFFFFFFFFFFFFFFE) return err(EINVAL);
    const chan = ops.channel_create(CHAN_EVENTFD, initval);
    if (chan < 0) return @bitCast(chan);
    const fd = fds.allocFd(.eventfd, (flags & EFD_NONBLOCK) != 0);
    if (fd < 0) {
        _ = ops.channel_unref(@intCast(chan));
        return @bitCast(fd);
    }
    fds.entries[@intCast(fd)].file_id = @intCast(chan);
    return @intCast(fd);
}

/// signalfd4(fd, mask, sizset, flags): fd сигнальной очереди (маска
/// хранится; доставки сигналов нет → готовность 0; read → EAGAIN).
pub fn sysSignalfd4(ops: LinuxOps, fds: *FdTable, fd_i: i64, mask_va: u64, size: u64, flags: u64) u64 {
    if (size != 8) return err(EINVAL);
    if (flags & ~(SFD_CLOEXEC | SFD_NONBLOCK) != 0) return err(EINVAL);
    if (fd_i != -1) {
        const e = fds.get(fd_i) orelse return err(EBADF);
        if (e.kind != .signalfd) return err(EINVAL);
    }
    if (!ops.validate(mask_va, 8, false)) return err(EFAULT);
    var mb: [8]u8 = undefined;
    if (!ops.copy_in(&mb, mask_va)) return err(EFAULT);
    if (fd_i == -1) {
        const fd = fds.allocFd(.signalfd, (flags & SFD_NONBLOCK) != 0);
        if (fd < 0) return @bitCast(fd);
        return @intCast(fd);
    }
    return @intCast(fd_i);
}

/// timerfd_create(clockid, flags) → fd (wl таймеры; монотонный).
pub fn sysTimerfdCreate(ops: LinuxOps, fds: *FdTable, clockid: u64, flags: u64) u64 {
    _ = clockid; // CLOCK_MONOTONIC (1) / REALTIME (0) — один источник
    if (flags & ~(TFD_NONBLOCK | TFD_CLOEXEC) != 0) return err(EINVAL);
    const chan = ops.channel_create(CHAN_TIMERFD, 0);
    if (chan < 0) return @bitCast(chan);
    const fd = fds.allocFd(.timerfd, (flags & TFD_NONBLOCK) != 0);
    if (fd < 0) {
        _ = ops.channel_unref(@intCast(chan));
        return @bitCast(fd);
    }
    fds.entries[@intCast(fd)].file_id = @intCast(chan);
    return @intCast(fd);
}

/// timerfd_settime(fd, flags, new_itimerspec, old): tfd_args {value, interval}
/// (16Б: two timespec-like u64 нс). Абсолютный флаг не поддержан → EINVAL.
pub fn sysTimerfdSettime(ops: LinuxOps, fds: *FdTable, fd_i: i64, flags: u64, new_va: u64, old_va: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    if (e.kind != .timerfd) return err(EINVAL);
    if (flags & 1 != 0) return err(ENOTSUP); // TFD_TIMER_ABSTIME
    if (!ops.validate(new_va, 16, false)) return err(EFAULT);
    var nb: [16]u8 = undefined;
    if (!ops.copy_in(&nb, new_va)) return err(EFAULT);
    const value = std.mem.readInt(u64, nb[0..8], .little);
    const interval = std.mem.readInt(u64, nb[8..16], .little);
    if (old_va != 0) {
        if (!ops.validate(old_va, 16, true)) return err(EFAULT);
        var ob: [16]u8 = .{0} ** 16; // старое время — заглушка (нет хранилища prev в фундаменте)
        if (!ops.copy_out(old_va, &ob)) return err(EFAULT);
    }
    // установка дедлайна: channel_write с kernel-VA (контракт моста:
    // identity-map — ptr читается напрямую, как user-VA)
    var wb: [16]u8 = undefined;
    std.mem.writeInt(u64, wb[0..8], value, .little);
    std.mem.writeInt(u64, wb[8..16], interval, .little);
    _ = ops.channel_write(e.file_id, @intFromPtr(&wb), 16);
    return 0;
}

/// memfd_create(name, flags): анонимный RW-файл (Wayland-shm буферы).
pub fn sysMemfdCreate(ops: LinuxOps, fds: *FdTable, flags: u64) u64 {
    _ = flags; // MFD_CLOEXEC/MFD_ALLOW_SEALING — sealing не поддержан
    const id = ops.memfd_create();
    if (id < 0) return @bitCast(id);
    const fd = fds.allocFd(.tmpfs_file, false);
    if (fd < 0) {
        ops.release_file(@intCast(id));
        return @bitCast(fd);
    }
    fds.entries[@intCast(fd)].file_id = @intCast(id);
    return @intCast(fd);
}

/// rt_sigaction(sig, act, oldact, sigsetsize): ХРАНИЛИЩЕ обработчиков
/// (доставки сигналов нет — glibc требует успешную установку).
pub const KSIG_SIZE: u64 = 32; // {handler, flags, restorer, mask}

pub fn sysRtSigaction(ops: LinuxOps, sig: u64, act_va: u64, old_va: u64, sigsetsize: u64) u64 {
    if (sig == 0 or sig > 64) return err(EINVAL);
    if (sig == 9 or sig == 19) return err(EINVAL); // SIGKILL/SIGSTOP
    if (sigsetsize != 8) return err(EINVAL);
    // oldact: {handler, flags, restorer, mask} 32Б
    if (old_va != 0) {
        if (!ops.validate(old_va, 32, true)) return err(EFAULT);
        var ob: [32]u8 = .{0} ** 32;
        const old_h = ops.get_sigaction(@intCast(sig));
        if (old_h != 0) std.mem.writeInt(u64, ob[0..8], old_h, .little);
        if (!ops.copy_out(old_va, &ob)) return err(EFAULT);
    }
    if (act_va != 0) {
        if (!ops.validate(act_va, 32, false)) return err(EFAULT);
        var ab: [32]u8 = undefined;
        if (!ops.copy_in(&ab, act_va)) return err(EFAULT);
        const handler = std.mem.readInt(u64, ab[0..8], .little);
        const flags = std.mem.readInt(u64, ab[8..16], .little);
        const restorer = std.mem.readInt(u64, ab[16..24], .little);
        const r = ops.set_sigaction(@intCast(sig), handler, flags, restorer);
        if (r < 0) return @bitCast(r);
    }
    return 0;
}

/// rt_sigprocmask(how, set, oldset, size): маска сигналов (хранение).
pub fn sysRtSigprocmask(ops: LinuxOps, how: u64, set_va: u64, old_va: u64, size: u64) u64 {
    if (size != 8) return err(EINVAL);
    if (set_va != 0 and how > 2) return err(EINVAL); // SIG_BLOCK/UNBLOCK/SETMASK
    if (old_va != 0) {
        if (!ops.validate(old_va, 8, true)) return err(EFAULT);
        // how=3 (QUERY): контракт моста — вернуть СТАРУЮ без изменения
        const old = ops.set_sigmask(3, 0);
        var ob: [8]u8 = undefined;
        std.mem.writeInt(u64, &ob, old, .little);
        if (!ops.copy_out(old_va, &ob)) return err(EFAULT);
    }
    if (set_va != 0) {
        if (!ops.validate(set_va, 8, false)) return err(EFAULT);
        var sb: [8]u8 = undefined;
        if (!ops.copy_in(&sb, set_va)) return err(EFAULT);
        const mask = std.mem.readInt(u64, &sb, .little);
        _ = ops.set_sigmask(@intCast(how), mask);
    }
    return 0;
}

/// prctl(option, ...): CAPBSET_READ→0 (нет cap), SET_NAME→0, GET_NAME→имя.
pub fn sysPrctl(ops: LinuxOps, option: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) u64 {
    _ = arg3;
    _ = arg4;
    _ = arg5;
    switch (option) {
        PR_CAPBSET_READ => {
            if (arg2 > 40) return err(EINVAL); // CAP_LAST_CAP
            return 0; // вне bounding set (gamescope: привилегий нет — честно)
        },
        PR_SET_NAME, PR_SET_PDEATHSIG => return 0,
        PR_GET_NAME => {
            // имя процесса: копируем execfn-заглушку «gamescope»? — пусто
            var name: [16]u8 = .{0} ** 16;
            if (!ops.copy_out(arg2, &name)) return err(EFAULT);
            return 0;
        },
        else => return err(EINVAL), // SA_RESTORER-мир: неизвестные — EINVAL
    }
}

/// madvise(va, len, advice): DAMP-заглушка (RELRO/malloc-советы — успех).
pub fn sysMadvise(ops: LinuxOps, va: u64, len: u64, advice: u64) u64 {
    _ = advice; // MADV_NORMAL/DONTNEED/… — без VM-подсказок (анонимные страницы)
    if (len == 0) return 0;
    if (!ops.validate(va, len, false)) return err(EFAULT);
    return 0;
}

/// fstatfs(fd, buf): struct statfs 120Б — tmpfs-магия (glibc: /dev-проверки).
pub fn sysFstatfs(ops: LinuxOps, fds: *FdTable, fd_i: i64, buf_va: u64) u64 {
    const e = fds.get(fd_i) orelse return err(EBADF);
    _ = e;
    if (!ops.validate(buf_va, 120, true)) return err(EFAULT);
    var st: [120]u8 = .{0} ** 120;
    std.mem.writeInt(u64, st[0..8], 0x01021998, .little); // f_type: POLER-канал
    std.mem.writeInt(u64, st[8..16], 4096, .little); // f_bsize
    std.mem.writeInt(u64, st[16..24], 1 << 20, .little); // f_blocks (4ГБ)
    std.mem.writeInt(u64, st[24..32], 1 << 18, .little); // f_bfree
    std.mem.writeInt(u64, st[32..40], 1 << 18, .little); // f_bavail
    std.mem.writeInt(u64, st[40..48], 1 << 16, .little); // f_files
    std.mem.writeInt(u64, st[48..56], 1 << 15, .little); // f_ffree
    std.mem.writeInt(u64, st[56..64], 0x19981998, .little); // f_fsid
    std.mem.writeInt(u64, st[64..72], 255, .little); // f_namelen
    std.mem.writeInt(u64, st[72..80], 4096, .little); // f_frsize
    if (!ops.copy_out(buf_va, &st)) return err(EFAULT);
    return 0;
}

/// getcwd(buf, size): корень Live-сессии.
pub fn sysGetcwd(ops: LinuxOps, buf_va: u64, size: u64) u64 {
    if (size < 2) return err(ERANGE);
    if (!ops.validate(buf_va, 2, true)) return err(EFAULT);
    if (!ops.copy_out(buf_va, "/\x00")) return err(EFAULT);
    return 2; // записано байт: «/» + NUL
}

/// ppoll(fds, nfds, tmo, sigmask, size): poll + сигмаска (игнор) + timeout
/// (v0.19: неблокирующий — WAIT-эпоха добавит парковку).
pub fn sysPpoll(ops: LinuxOps, fds: *FdTable, fds_va: u64, nfds: u64, tmo_va: u64, sigmask_va: u64, size: u64) u64 {
    _ = tmo_va;
    _ = sigmask_va;
    _ = size;
    return sysPoll(ops, fds, fds_va, nfds, 0);
}

/// epoll_pwait(epfd, events, maxevents, timeout, sigmask): = epoll_wait
/// (сигмаску игнорируем — доставки сигналов нет).
pub fn sysEpollPwait(ops: LinuxOps, fds: *FdTable, epfd: i64, events_va: u64, maxevents: u64, timeout: i64, sigmask_va: u64) u64 {
    _ = sigmask_va;
    return sysEpollWait(ops, fds, epfd, events_va, maxevents, timeout);
}

// ─── Диспетчер (syscall-таблица) ───────────────────────────────────────────

/// Главная точка входа Linux POSIX-слоя: num — RAX, args — RDI/RSI/RDX/R10/R8.
/// Неизвестный номер → -ENOSYS. Возвращает RAX-значение.
pub fn dispatch(ops: LinuxOps, fds: *FdTable, num: u64, args: Args) u64 {
    switch (num) {
        SYS_read => return sysRead(ops, fds, @bitCast(args.a1), args.a2, args.a3),
        SYS_write => return sysWrite(ops, fds, @bitCast(args.a1), args.a2, args.a3),
        SYS_open => {
            // open(path, flags, mode) — легаси-синоним openat(AT_FDCWD, …)
            return sysOpenat(ops, fds, AT_FDCWD, args.a1, args.a2, args.a3);
        },
        SYS_openat => return sysOpenat(ops, fds, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_close => return sysClose(ops, fds, @bitCast(args.a1)),
        SYS_mmap => return sysMmap(ops, fds, args.a1, args.a2, args.a3, args.a4, @bitCast(args.a5), args.a6),
        SYS_lseek => return sysLseek(ops, fds, @bitCast(args.a1), @bitCast(args.a2), args.a3),
        SYS_pread64 => return sysPread64(ops, fds, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_writev => return sysWritev(ops, fds, @bitCast(args.a1), args.a2, args.a3),
        SYS_access => return sysAccess(ops, args.a1, args.a2),
        SYS_newfstatat => return sysNewfstatat(ops, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_munmap => return sysMunmap(ops, args.a1, args.a2),
        SYS_ioctl => return sysIoctl(ops, fds, @bitCast(args.a1), @truncate(args.a2), args.a3),
        SYS_fcntl => return sysFcntl(ops, fds, @bitCast(args.a1), args.a2, args.a3),
        SYS_poll => return sysPoll(ops, fds, args.a1, args.a2, @bitCast(args.a3)),
        SYS_clone => return sysClone(ops, args.a1, args.a2, args.a3, args.a4, args.a5),
        SYS_futex => return sysFutex(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_epoll_create1 => return sysEpollCreate1(ops, fds, args.a1),
        SYS_epoll_ctl => return sysEpollCtl(ops, fds, @bitCast(args.a1), args.a2, @bitCast(args.a3), args.a4),
        SYS_epoll_wait => return sysEpollWait(ops, fds, @bitCast(args.a1), args.a2, args.a3, @bitCast(args.a4)),
        SYS_exit => return sysExit(ops, args.a1),
        SYS_exit_group => return sysExitGroup(ops, args.a1),
        SYS_uname => return sysUname(ops, args.a1),
        SYS_gettid => return sysGettid(ops),
        SYS_getpid => return sysGetpid(ops),
        SYS_fstat => return sysFstat(ops, fds, @bitCast(args.a1), args.a2),
        SYS_mprotect => return sysMprotect(ops, args.a1, args.a2, args.a3),
        SYS_arch_prctl => return sysArchPrctl(ops, args.a1, args.a2),
        SYS_set_tid_address => return sysSetTidAddress(ops, args.a1),
        SYS_set_robust_list => return sysSetRobustList(ops, args.a1, args.a2),
        SYS_rseq => return sysRseq(),
        SYS_pipe2 => return sysPipe2(ops, fds, args.a1, args.a2),
        SYS_socketpair => return sysSocketpair(ops, fds, args.a1, args.a2, args.a3, args.a4),
        SYS_eventfd2 => return sysEventfd2(ops, fds, args.a1, args.a2),
        SYS_signalfd4 => return sysSignalfd4(ops, fds, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_timerfd_create => return sysTimerfdCreate(ops, fds, args.a1, args.a2),
        SYS_timerfd_settime => return sysTimerfdSettime(ops, fds, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_memfd_create => return sysMemfdCreate(ops, fds, args.a2),
        SYS_ftruncate => return sysFtruncate(ops, fds, @bitCast(args.a1), args.a2),
        SYS_getdents64 => return sysGetdents64(ops, fds, @bitCast(args.a1), args.a2, args.a3),
        SYS_sched_getaffinity => return sysSchedGetaffinity(ops, @bitCast(args.a1), args.a2, args.a3),
        SYS_sched_setaffinity => return sysSchedSetaffinity(ops, @bitCast(args.a1), args.a2, args.a3),
        SYS_sysinfo => return sysSysinfo(ops, args.a1),
        SYS_mkdir => return sysMkdir(ops, args.a1, args.a2),
        SYS_rt_sigaction => return sysRtSigaction(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_rt_sigprocmask => return sysRtSigprocmask(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_prctl => return sysPrctl(ops, args.a1, args.a2, args.a3, args.a4, args.a5),
        SYS_madvise => return sysMadvise(ops, args.a1, args.a2, args.a3),
        SYS_fstatfs => return sysFstatfs(ops, fds, @bitCast(args.a1), args.a2),
        SYS_getcwd => return sysGetcwd(ops, args.a1, args.a2),
        SYS_ppoll => return sysPpoll(ops, fds, args.a1, args.a2, args.a3, args.a4, args.a5),
        SYS_epoll_pwait => return sysEpollPwait(ops, fds, @bitCast(args.a1), args.a2, args.a3, @bitCast(args.a4), args.a5),
        SYS_readlinkat => return sysReadlinkat(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_readlink => return sysReadlinkat(ops, @bitCast(@as(i64, -100)), args.a1, args.a2, args.a3),
        SYS_prlimit64 => return sysPrlimit64(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_getrandom => return sysGetrandom(ops, args.a1, args.a2, args.a3),
        SYS_clock_gettime => return sysClockGettime(ops, args.a1, args.a2),
        SYS_getppid => return sysGetppid(ops),
        SYS_getuid => return @intCast(KUID),
        SYS_geteuid => return @intCast(KUID),
        SYS_getgid => return @intCast(KUID),
        SYS_getegid => return @intCast(KUID),
        SYS_brk => return sysBrk(ops, args.a1),
        else => return err(ENOSYS),
    }
}

// ============================================================================
//  Нативные тесты (linux x86_64 gnu — Zig test runner)
// ============================================================================

/// Фейковое user-пространство: буфер 32КБ по VA 0x20000_0000 (выше 4ГБ —
/// как реальные PE/ELF-образы POLER-OS), fd-таблица, mmap-бамп.
const FakeEnv = struct {
    const USER_BASE: u64 = 0x20000_0000;
    const USER_LEN: u64 = 32 * 1024;

    mem: []u8,
    write_calls: u64 = 0,
    write_bytes: u64 = 0,
    read_calls: u64 = 0,
    exit_code: ?u64 = null,
    exit_group_code: ?u64 = null,
    mmap_calls: u64 = 0,
    last_mmap_len: u64 = 0,
    munmap_calls: u64 = 0,
    open_path: ?[]const u8 = null,
    ioctl_calls: u64 = 0,
    last_ioctl_cmd: u32 = 0,
    last_ioctl_kind: FdKind = .free,
    dev_mmap_calls: u64 = 0,
    last_dev_mmap_off: u64 = 0,
    clone_calls: u64 = 0,
    last_clone_flags: u64 = 0,
    brk_calls: u64 = 0,
    last_brk_addr: u64 = 0,
    brk_value: u64 = 0x1000,
    mprotect_calls: u64 = 0,
    last_mprotect_prot: u64 = 0,
    fs_base: u64 = 0,
    tid_address: u64 = 0,
    robust_head: u64 = 0,
    getrandom_calls: u64 = 0,
    execfn: []const u8 = "hello-static",
    truncate_calls: u64 = 0,
    last_truncate_len: u64 = 0,
    shared_mmap_calls: u64 = 0,
    last_shared_len: u64 = 0,
    last_shared_prot: u64 = 0,
    getdents_calls: u64 = 0,
    last_park_ms: u64 = 0,
    mkdir_calls: u64 = 0,
    last_mkdir_path: ?[]const u8 = null,
    file_mmap_calls: u64 = 0,
    last_file_mmap_off: u64 = 0,
    last_file_mmap_len: u64 = 0,
    last_file_mmap_prot: u64 = 0,
    last_file_mmap_fixed: u64 = 0,
    access_calls: u64 = 0,
    stat_calls: u64 = 0,
    park_calls: u64 = 0,
    wake_calls: u64 = 0,
    last_wake_n: u32 = 0,
    last_mmap_flags: u64 = 0,
    last_mmap_fixed: u64 = 0,
    ready_kbd: u32 = 0, // управляемая тестом готовность event0
    ready_mouse: u32 = 0,
    /// fd-таблица: 0/1/2 открыты (stdin/stdout/stderr), 42 закрыт.
    open_fds: [8]i64 = .{ 0, 1, 2, -1, -1, -1, -1, -1 },
    mmap_cursor: u64 = USER_BASE + USER_LEN,

    fn init() !FakeEnv {
        return .{ .mem = try testing.allocator.alloc(u8, @intCast(USER_LEN)) };
    }
    fn deinit(self: *FakeEnv) void {
        testing.allocator.free(self.mem);
    }
    /// Валидация user-VA: свободная функция (не метод — self не нужен,
    /// границы региона — константы FakeEnv).
    fn vaOk(va: u64, len: u64, want_write: bool) bool {
        _ = want_write; // fake-регион не разделяет R/W (реальный PML4 — разделяет)
        if (len == 0) return true;
        const sum = @addWithOverflow(va, len);
        if (sum[1] != 0) return false;
        if (sum[0] > USER_VA_CEILING) return false;
        return va >= USER_BASE and sum[0] <= USER_BASE + USER_LEN;
    }
    fn vaPtr(self: *FakeEnv, va: u64) ?[*]u8 {
        if (va < USER_BASE or va >= USER_BASE + USER_LEN) return null;
        return self.mem.ptr + @as(usize, @intCast(va - USER_BASE));
    }
    fn fdOpen(self: *FakeEnv, fd: i64) bool {
        if (fd < 0 or fd >= 8) return false;
        return self.open_fds[@intCast(fd)] >= 0;
    }
};

var g_env: ?*FakeEnv = null;

fn fakeValidate(va: u64, len: u64, want_write: bool) bool {
    return FakeEnv.vaOk(va, len, want_write);
}
fn fakeCopyOut(dst_va: u64, src: []const u8) bool {
    const e = g_env.?;
    if (!FakeEnv.vaOk(dst_va, src.len, true)) return false;
    const p = e.vaPtr(dst_va) orelse return false;
    @memcpy(p[0..src.len], src);
    return true;
}
fn fakeCopyIn(dst: []u8, src_va: u64) bool {
    const e = g_env.?;
    if (!FakeEnv.vaOk(src_va, dst.len, false)) return false;
    const p = e.vaPtr(src_va) orelse return false;
    @memcpy(dst, p[0..dst.len]);
    return true;
}
fn fakeCopyInStr(src_va: u64, max_len: u64) ?[]const u8 {
    const e = g_env.?;
    if (!FakeEnv.vaOk(src_va, 1, false)) return null;
    const p = e.vaPtr(src_va).?;
    var n: u64 = 0;
    while (n < max_len) : (n += 1) {
        const va = src_va + n;
        if (va >= FakeEnv.USER_BASE + FakeEnv.USER_LEN) break;
        if (p[@intCast(n)] == 0) return p[0..@intCast(n)];
    }
    return null; // нет терминатора в границах max_len
}
fn fakeDevWrite(va: u64, count: u64) i64 {
    const e = g_env.?;
    e.write_calls += 1;
    e.write_bytes += count;
    _ = va;
    return @intCast(count);
}
fn fakeDevRead(kind: FdKind, va: u64, count: u64, nonblock: bool) i64 {
    const e = g_env.?;
    e.read_calls += 1;
    e.last_ioctl_kind = kind;
    if (kind == .input_event0 and e.ready_kbd == 0) {
        return if (nonblock) -EAGAIN else 0;
    }
    if (kind == .input_event1 and e.ready_mouse == 0) {
        return if (nonblock) -EAGAIN else 0;
    }
    _ = va;
    return @intCast(count);
}
fn fakeDevIoctl(kind: FdKind, cmd: u32, arg: u64) i64 {
    const e = g_env.?;
    e.ioctl_calls += 1;
    e.last_ioctl_cmd = cmd;
    e.last_ioctl_kind = kind;
    _ = arg;
    return 0;
}
fn fakeDevReady(kind: FdKind) u32 {
    const e = g_env.?;
    return switch (kind) {
        .input_event0 => e.ready_kbd,
        .input_event1 => e.ready_mouse,
        else => EPOLLOUT,
    };
}
fn fakeDevMmap(kind: FdKind, off: u64, len: u64, prot: u64) i64 {
    const e = g_env.?;
    e.dev_mmap_calls += 1;
    e.last_dev_mmap_off = off;
    e.last_ioctl_kind = kind;
    _ = len;
    _ = prot;
    const r: i64 = @intCast(e.mmap_cursor);
    e.mmap_cursor += PAGE_SIZE;
    return r;
}
fn fakeDoMmap(hint: u64, len: u64, prot: u64, flags: u64) i64 {
    _ = prot;
    const e = g_env.?;
    e.mmap_calls += 1;
    e.last_mmap_len = len;
    e.last_mmap_flags = flags;
    // MAP_FIXED: точный адрес (ld.so bss-хвост libc поверх спана)
    if (flags & MAP_FIXED != 0 and hint != 0) {
        e.last_mmap_fixed = hint;
        return @intCast(hint);
    }
    e.last_mmap_fixed = 0;
    const r: i64 = @intCast(e.mmap_cursor);
    e.mmap_cursor += (len + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    return r;
}
fn fakeDoMunmap(va: u64, len: u64) i64 {
    const e = g_env.?;
    e.munmap_calls += 1;
    _ = va;
    _ = len;
    return 0;
}
fn fakeDoExit(code: u64) void {
    g_env.?.exit_code = code;
}
fn fakeDoExitGroup(code: u64) void {
    g_env.?.exit_group_code = code;
}
fn fakeDoClone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) i64 {
    const e = g_env.?;
    e.clone_calls += 1;
    e.last_clone_flags = flags;
    _ = stack;
    _ = parent_tid;
    _ = child_tid;
    _ = tls;
    return 77; // tid ребёнка
}
fn fakeFutexPark(uaddr: u64, timeout_ms: u64, infinite: bool) i64 {
    const e = g_env.?;
    e.park_calls += 1;
    _ = uaddr;
    _ = timeout_ms;
    if (infinite) return 0; // «разбудили» (тест-модель)
    return -ETIMEDOUT; // тест-модель таймаута
}
fn fakeFutexWake(uaddr: u64, n: u32) u32 {
    const e = g_env.?;
    e.wake_calls += 1;
    e.last_wake_n = n;
    _ = uaddr;
    return @min(n, 2); // «разбудили» двоих (тест-модель)
}

/// Fake-реестр файлов VFS: 4 слота (tmpfs RW / initrd RO); ПОВТОРНОЕ
/// открытие того же пути возвращает ТОТ ЖЕ файл (как настоящий VFS).
const FakeFile = struct {
    used: bool = false,
    kind: FdKind = .free,
    anon: bool = false, // CDD №12 p3: memfd (ftruncate/MAP_SHARED)
    name: [64]u8 = .{0} ** 64,
    name_len: usize = 0,
    data: [128]u8 = .{0} ** 128,
    size: usize = 0,
};
var g_files: [4]FakeFile = [_]FakeFile{.{}} ** 4;

// ─── CDD №12 p3: фейк getdents64 (поток каталога) ─────────────────────

const FakeDir = struct {
    used: bool = false,
    entries: [6]DirEnt = [_]DirEnt{.{}} ** 6,
    count: u32 = 0,
    pos: u32 = 0,
};
const DirEnt = struct {
    name: [24]u8 = .{0} ** 24,
    name_len: u8 = 0,
    dtype: u8 = 0,
};
var g_dirs: [4]FakeDir = [_]FakeDir{.{}} ** 4;

/// fake-open КАТАЛОГА: /dev/dri (card0, renderD128 — libdrm-скан).
fn fakeDirOpen(path: []const u8) i64 {
    if (!std.mem.eql(u8, path, "/dev/dri")) return -ENODEV; // не каталог
    for (&g_dirs, 0..) |*d, i| {
        if (!d.used) {
            d.* = .{ .used = true };
            pushEnt(d, ".", DT_DIR);
            pushEnt(d, "..", DT_DIR);
            pushEnt(d, "card0", DT_CHR);
            pushEnt(d, "renderD128", DT_CHR);
            return @intCast(i);
        }
    }
    return -ENFILE;
}

fn pushEnt(d: *FakeDir, name: []const u8, dtype: u8) void {
    if (d.count >= d.entries.len or name.len >= 24) return;
    @memcpy(d.entries[d.count].name[0..name.len], name);
    d.entries[d.count].name_len = @intCast(name.len);
    d.entries[d.count].dtype = dtype;
    d.count += 1;
}

/// fake getdents64: записи dirent64 в user-буфер (счётчик вызовов в env).
fn fakeDirRead(id: u32, buf_va: u64, count: u64) i64 {
    const e = g_env.?;
    e.getdents_calls += 1;
    if (id >= g_dirs.len or !g_dirs[id].used) return -EBADF;
    const d = &g_dirs[id];
    const mem = e.vaPtr(buf_va).?;
    var written: u64 = 0;
    while (d.pos < d.count) {
        const i: usize = @intCast(d.pos);
        const nl: u64 = d.entries[i].name_len;
        const reclen: u64 = 19 + nl + 1;
        const padded: u64 = (reclen + 7) & ~@as(u64, 7);
        if (written + padded > count) break;
        const base: usize = @intCast(written);
        std.mem.writeInt(u64, mem[base..][0..8], 9000 + i, .little);
        std.mem.writeInt(u64, mem[base + 8 ..][0..8], @as(u64, i) + 1, .little);
        std.mem.writeInt(u16, mem[base + 16 ..][0..2], @intCast(padded), .little);
        mem[base + 18] = d.entries[i].dtype;
        @memcpy(mem[base + 19 ..][0..@intCast(nl)], d.entries[i].name[0..@intCast(nl)]);
        written += padded;
        d.pos += 1;
    }
    return @intCast(written);
}

fn fakeDirClose(id: u32) void {
    if (id < g_dirs.len) g_dirs[id] = .{};
}

/// fake-парковка: без сна — немедленный возврат (тест-модель времени).
fn fakeTaskPark(ms: u64) void {
    const e = g_env.?;
    e.park_calls += 1;
    e.last_park_ms = ms;
}

/// fake-mkdir: tmpfs-слот (fake-реестр — счётчик вызовов).
fn fakeMkdirTmpfs(path: []const u8) i64 {
    const e = g_env.?;
    e.mkdir_calls += 1;
    e.last_mkdir_path = path;
    if (!std.mem.startsWith(u8, path, "/tmp") and !std.mem.startsWith(u8, path, "/root"))
        return -EPERM;
    return 0;
}

fn fakeOpenFile(path: []const u8, flags: u64, out_kind: *FdKind) i64 {
    _ = flags;
    const e = g_env.?;
    e.open_path = path;
    // CDD №12 p3: КАТАЛОГ первым (как ядро — isDirPath до VFS-резолва)
    const d = fakeDirOpen(path);
    if (d >= 0) {
        out_kind.* = .dir;
        return d;
    }
    // повторное открытие → тот же файл (offset-состояние у fd-слоя своё)
    for (&g_files, 0..) |*f, i| {
        if (f.used and std.mem.eql(u8, f.name[0..f.name_len], path)) {
            out_kind.* = f.kind;
            return @intCast(i);
        }
    }
    var slot: ?usize = null;
    for (&g_files, 0..) |*f, i| {
        if (!f.used) {
            slot = i;
            break;
        }
    }
    const s = slot orelse return -EMFILE;
    if (path.len > 64) return -EINVAL;
    g_files[s].used = true;
    if (std.mem.startsWith(u8, path, "/tmp/")) {
        g_files[s].kind = .tmpfs_file;
        out_kind.* = .tmpfs_file;
    } else if (std.mem.eql(u8, path, "/etc/hostname")) {
        g_files[s].kind = .initrd_file;
        const content = "poler-live-host";
        @memcpy(g_files[s].data[0..content.len], content);
        g_files[s].size = content.len;
        out_kind.* = .initrd_file;
    } else if (std.mem.eql(u8, path, "/usr/bin/gamescope") or std.mem.eql(u8, path, "/README.txt")) {
        g_files[s].kind = .initrd_file;
        const content = "BINARY-PLACEHOLDER";
        @memcpy(g_files[s].data[0..content.len], content);
        g_files[s].size = content.len;
        out_kind.* = .initrd_file;
    } else if (std.mem.startsWith(u8, path, "/usr/lib/") and path.len > 9) {
        // CDD #12 p1: CachyOS-rootfs — библиотеки лежат в /usr/lib (usr-merge)
        g_files[s].kind = .initrd_file;
        const content = "SO-LIB-PLACEHOLDER";
        @memcpy(g_files[s].data[0..content.len], content);
        g_files[s].size = content.len;
        out_kind.* = .initrd_file;
    } else {
        g_files[s].used = false;
        return -ENOENT;
    }
    @memcpy(g_files[s].name[0..path.len], path);
    g_files[s].name_len = path.len;
    return @intCast(s);
}
fn fakeFileRead(id: u32, off: u64, va: u64, count: u64) i64 {
    if (id >= g_files.len or !g_files[id].used) return -EBADF;
    const f = &g_files[id];
    if (off >= f.size) return 0; // EOF
    const n = @min(@as(usize, @intCast(count)), f.size - @as(usize, @intCast(off)));
    if (!fakeCopyOut(va, f.data[@intCast(off)..][0..n])) return -EFAULT;
    return @intCast(n);
}
fn fakeFileMmap(id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64 {
    const e = g_env.?;
    e.file_mmap_calls += 1;
    e.last_file_mmap_off = off;
    e.last_file_mmap_len = len;
    e.last_file_mmap_prot = prot;
    e.last_file_mmap_fixed = fixed_va;
    _ = id;
    // MAP_FIXED: точный адрес (ld.so: сегменты поверх спана)
    if (fixed_va != 0) return @intCast(fixed_va);
    return @intCast(e.mmap_cursor); // «разместили»
}

fn fakeFileSize(id: u32) u64 {
    _ = id;
    return 8192; // тестовый размер
}

fn fakeFileIno(id: u32) u64 {
    // уникальный НЕнулевой inode (glibc: (st_dev, st_ino) — идентификация)
    return 100 + @as(u64, id);
}

fn fakePathExists(path: []const u8) i64 {
    const e = g_env.?;
    e.access_calls += 1;
    if (std.mem.eql(u8, path, "/etc/ld.so.cache")) return -ENOENT; // нет кэша
    return 0;
}

fn fakeStatByPath(path: []const u8, buf_va: u64) i64 {
    const e = g_env.?;
    e.stat_calls += 1;
    if (std.mem.eql(u8, path, "/etc/ld.so.cache")) return -ENOENT; // нет кэша
    var st: [144]u8 = [_]u8{0} ** 144;
    std.mem.writeInt(u64, st[0..8], POLER_VFS_DEV, .little); // st_dev
    std.mem.writeInt(u64, st[8..16], 42, .little); // st_ino (уникальный)
    std.mem.writeInt(u64, st[16..24], 1, .little); // st_nlink
    std.mem.writeInt(u32, st[24..28], @intCast(0x8000 | 0x124), .little); // S_IFREG|0444
    std.mem.writeInt(u64, st[48..56], fakeFileSize(0), .little); // st_size
    std.mem.writeInt(u64, st[56..64], 4096, .little); // st_blksize
    std.mem.writeInt(u64, st[64..72], (fakeFileSize(0) + 511) / 512, .little); // st_blocks
    if (!fakeCopyOut(buf_va, &st)) return -EFAULT;
    return 0;
}

fn fakeReadlinkPath(path: []const u8, buf_va: u64, bufsz: u64) i64 {
    // fake-симлинк: /lib64/ld-linux-x86-64.so.2 → /usr/lib/ld-linux-x86-64.so.2
    if (std.mem.eql(u8, path, "/lib64/ld-linux-x86-64.so.2")) {
        const target = "/usr/lib/ld-linux-x86-64.so.2";
        const n: usize = @intCast(@min(target.len, bufsz));
        if (!fakeCopyOut(buf_va, target[0..n])) return -EFAULT;
        return @intCast(n);
    }
    return -ENOENT;
}

/// CDD №12 p1: close — освобождение слота реестра (fake: 4 слота)
fn fakeReleaseFile(id: u32) void {
    if (id >= g_files.len) return;
    g_files[id].used = false;
}

// ─── CDD №12 p2: фейк-каналы (pipe/eventfd/socketpair/timerfd) ──────────────
const FakeChan = struct {
    used: bool = false,
    refs: u8 = 0,
    kind: u32 = 0, // 0=pipe 1=eventfd 2=socketpair 3=timerfd
    buf: [64]u8 = .{0} ** 64,
    len: usize = 0,
    counter: u64 = 0,
    deadline_ns: u64 = 0,
    interval_ns: u64 = 0,
};
var g_chans: [8]FakeChan = [_]FakeChan{.{}} ** 8;

fn fakeChannelCreate(kind: u32, arg: u64) i64 {
    for (&g_chans, 0..) |*c, i| {
        if (c.used) continue;
        c.* = .{ .used = true, .refs = if (kind == 0 or kind == 2) 2 else 1, .kind = kind, .counter = arg };
        if (g_env) |e| e.mmap_calls += 0; // наблюдаемость при необходимости
        return @intCast(i);
    }
    return -ENFILE;
}
fn fakeChannelRead(id: u32, va: u64, count: u64) i64 {
    if (id >= g_chans.len or !g_chans[id].used) return -EBADF;
    const c = &g_chans[id];
    switch (c.kind) {
        1 => { // eventfd: 8Б счётчик
            if (count < 8) return -EINVAL;
            if (c.counter == 0) return -EAGAIN;
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, c.counter, .little);
            if (!fakeCopyOut(va, &b)) return -EFAULT;
            c.counter = 0;
            return 8;
        },
        3 => { // timerfd
            if (count < 8) return -EINVAL;
            if (c.counter == 0) return -EAGAIN;
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, c.counter, .little);
            if (!fakeCopyOut(va, &b)) return -EFAULT;
            c.counter = 0;
            return 8;
        },
        else => { // pipe/socketpair: FIFO
            if (c.len == 0) return -EAGAIN;
            const n: usize = @intCast(@min(count, c.len));
            if (!fakeCopyOut(va, c.buf[0..n])) return -EFAULT;
            std.mem.copyForwards(u8, c.buf[0 .. c.len - n], c.buf[n..c.len]);
            c.len -= n;
            return @intCast(n);
        },
    }
}
fn fakeChannelWrite(id: u32, va: u64, count: u64) i64 {
    if (id >= g_chans.len or !g_chans[id].used) return -EBADF;
    const c = &g_chans[id];
    switch (c.kind) {
        1 => { // eventfd: += 8Б value
            if (count < 8) return -EINVAL;
            var b: [8]u8 = undefined;
            if (!fakeCopyIn(&b, va)) return -EFAULT;
            c.counter += std.mem.readInt(u64, &b, .little);
            return 8;
        },
        3 => { // timerfd: arm [value, interval] из kernel-VA
            if (count < 16) return -EINVAL;
            var b: [16]u8 = undefined;
            const s: [*]const u8 = @ptrFromInt(va);
            @memcpy(&b, s[0..16]);
            c.interval_ns = std.mem.readInt(u64, b[8..16], .little);
            const value = std.mem.readInt(u64, b[0..8], .little);
            c.deadline_ns = if (value == 0) 0 else 1; // fake-время: value>0 → «взведён»
            c.counter = 0;
            return 16;
        },
        else => { // pipe/socketpair: FIFO append
            const n: usize = @intCast(count);
            if (c.len + n > c.buf.len) return -EAGAIN;
            if (!fakeCopyIn(c.buf[c.len .. c.len + n], va)) return -EFAULT;
            c.len += n;
            return @intCast(n);
        },
    }
}
fn fakeChannelReady(id: u32) u32 {
    if (id >= g_chans.len or !g_chans[id].used) return 0;
    const c = &g_chans[id];
    return switch (c.kind) {
        1, 3 => if (c.counter > 0) EPOLLIN else 0,
        else => if (c.len > 0) EPOLLIN else 0,
    };
}
fn fakeChannelUnref(id: u32) void {
    if (id >= g_chans.len) return;
    if (g_chans[id].refs > 0) g_chans[id].refs -= 1;
    if (g_chans[id].refs == 0) g_chans[id].used = false;
}

// ─── CDD №12 p2: фейк-сигналы + memfd ──────────────────────────────────────
var g_sig_handlers: [65]u64 = .{0} ** 65;
var g_sig_mask: u64 = 0;

fn fakeSetSigaction(sig: u32, handler: u64, flags: u64, restorer: u64) i64 {
    _ = flags;
    _ = restorer;
    if (sig == 0 or sig > 64 or sig == 9 or sig == 19) return -EINVAL;
    const old: i64 = @bitCast(g_sig_handlers[sig]);
    g_sig_handlers[sig] = handler;
    return old;
}
fn fakeGetSigaction(sig: u32) u64 {
    if (sig == 0 or sig > 64) return 0;
    return g_sig_handlers[sig];
}
fn fakeSetSigmask(how: u32, mask: u64) u64 {
    const old = g_sig_mask;
    switch (how) {
        0 => g_sig_mask |= mask,
        1 => g_sig_mask &= ~mask,
        2 => g_sig_mask = mask,
        else => {},
    }
    return old;
}
fn fakeMemfdCreate() i64 {
    // fake: файл реестра «memfd»
    for (&g_files, 0..) |*f, i| {
        if (!f.used) {
            f.* = .{ .used = true, .kind = .tmpfs_file, .anon = true };
            const name = "/tmp/.memfd"; // путь-имя КАК в openat (фейк-сравнение)
            @memcpy(f.name[0..name.len], name);
            f.name_len = name.len;
            f.size = 0;
            return @intCast(i);
        }
    }
    return -ENFILE;
}

// ─── CDD №12 p3: фейк ftruncate + MAP_SHARED (Mesa lavapipe-контракт) ────

/// ftruncate: размер anon-файла (fake: слот реестра; блок 128Б).
fn fakeTruncateFile(id: u32, len: u64) i64 {
    const e = g_env.?;
    e.truncate_calls += 1;
    e.last_truncate_len = len;
    if (id >= g_files.len or !g_files[id].used) return -EBADF;
    if (!g_files[id].anon) return -EINVAL; // heap-tmpfs/initrd — не растим
    if (len > 128) return -EFBIG; // fake-блок 128Б (ядро: ANON_FILE_MAX 512МБ)
    g_files[id].size = @intCast(len);
    if (len == 0) @memset(g_files[id].data[0..], 0);
    return 0;
}

/// mmap MAP_SHARED anon-файла: fake-валидации (ftruncate-обязателен,
/// off кратен странице, диапазон в блоке) + «размещение» курсором.
fn fakeSharedFileMmap(id: u32, off: u64, len: u64, prot: u64, fixed_va: u64) i64 {
    const e = g_env.?;
    e.shared_mmap_calls += 1;
    e.last_shared_len = len;
    e.last_shared_prot = prot;
    if (id >= g_files.len or !g_files[id].used) return -EBADF;
    const f = &g_files[id];
    if (f.kind != .tmpfs_file or !f.anon) return -ENODEV; // initrd/heap — не разделяем
    if (f.size == 0) return -ENOMEM; // ftruncate не был вызван
    if (off % 4096 != 0) return -EINVAL;
    const blk_len = (f.size + 4095) / 4096 * 4096;
    if (off >= blk_len) return -EINVAL;
    if (off + len > blk_len) return -ENOMEM; // хвост за блоком
    _ = fixed_va;
    return @intCast(e.mmap_cursor);
}

fn fakeFileWrite(id: u32, off: u64, va: u64, count: u64) i64 {
    if (id >= g_files.len or !g_files[id].used) return -EBADF;
    const f = &g_files[id];
    if (f.kind != .tmpfs_file) return -EBADF; // initrd: RO
    const n: usize = @intCast(@min(count, 128));
    var tmp: [128]u8 = undefined;
    if (!fakeCopyIn(tmp[0..n], va)) return -EFAULT;
    const end = @as(usize, @intCast(off)) + n;
    if (end > 128) return -ENOMEM;
    @memcpy(f.data[@intCast(off)..end], tmp[0..n]);
    if (end > f.size) f.size = end;
    return @intCast(n);
}

fn fakeOps() LinuxOps {
    return .{
        .validate = fakeValidate,
        .copy_out = fakeCopyOut,
        .copy_in = fakeCopyIn,
        .copy_in_str = fakeCopyInStr,
        .dev_write = fakeDevWrite,
        .dev_read = fakeDevRead,
        .dev_ioctl = fakeDevIoctl,
        .dev_ready = fakeDevReady,
        .dev_mmap = fakeDevMmap,
        .do_mmap = fakeDoMmap,
        .do_munmap = fakeDoMunmap,
        .do_exit = fakeDoExit,
        .do_exit_group = fakeDoExitGroup,
        .do_clone = fakeDoClone,
        .futex_park = fakeFutexPark,
        .futex_wake = fakeFutexWake,
        .current_pid = fakeCurrentPid,
        .current_tid = fakeCurrentTid,
        .do_brk = fakeDoBrk,
        .do_mprotect = fakeDoMprotect,
        .arch_set_fs = fakeArchSetFs,
        .arch_get_fs = fakeArchGetFs,
        .set_tid_address = fakeSetTidAddress,
        .set_robust_list = fakeSetRobustList,
        .readlink_self = fakeReadlinkSelf,
        .do_getrandom = fakeGetrandom,
        .time_ns = fakeTimeNs,
        .open_file = fakeOpenFile,
        .file_read = fakeFileRead,
        .file_write = fakeFileWrite,
        .file_mmap = fakeFileMmap,
        .file_size = fakeFileSize,
        .file_ino = fakeFileIno,
        .path_exists = fakePathExists,
        .stat_by_path = fakeStatByPath,
        .readlink_path = fakeReadlinkPath,
        .release_file = fakeReleaseFile,
        .channel_create = fakeChannelCreate,
        .channel_read = fakeChannelRead,
        .channel_write = fakeChannelWrite,
        .channel_ready = fakeChannelReady,
        .channel_unref = fakeChannelUnref,
        .set_sigaction = fakeSetSigaction,
        .get_sigaction = fakeGetSigaction,
        .set_sigmask = fakeSetSigmask,
        .memfd_create = fakeMemfdCreate,
        .truncate_file = fakeTruncateFile,
        .shared_file_mmap = fakeSharedFileMmap,
        .dir_read = fakeDirRead,
        .dir_close = fakeDirClose,
        .task_park = fakeTaskPark,
        .mkdir_tmpfs = fakeMkdirTmpfs,
    };
}

fn fakeCurrentPid() u64 {
    return 100; // слот-модель ядра: pid = 100 + slot
}

fn fakeCurrentTid() u64 {
    return 77;
}

fn fakeDoBrk(addr: u64) u64 {
    const e = g_env.?;
    e.brk_calls += 1;
    e.last_brk_addr = addr;
    if (addr == 0) return e.brk_value;
    if (addr < 0x1000) return e.brk_value; // ниже базиса — отказ
    e.brk_value = addr;
    return addr;
}

fn fakeDoMprotect(va: u64, len: u64, prot: u64) i64 {
    const e = g_env.?;
    e.mprotect_calls += 1;
    e.last_mprotect_prot = prot;
    _ = va;
    _ = len;
    return 0;
}

fn fakeArchSetFs(addr: u64) i64 {
    const e = g_env.?;
    e.fs_base = addr;
    return 0;
}

fn fakeArchGetFs() u64 {
    return g_env.?.fs_base;
}

fn fakeSetTidAddress(addr: u64) u64 {
    const e = g_env.?;
    e.tid_address = addr;
    return 77;
}

fn fakeSetRobustList(addr: u64, len: u64) i64 {
    const e = g_env.?;
    e.robust_head = addr;
    _ = len;
    return 0;
}

fn fakeReadlinkSelf(buf_va: u64, bufsz: u64) i64 {
    const e = g_env.?;
    const s = e.execfn;
    const n = @min(bufsz, s.len);
    if (!fakeCopyOut(buf_va, s[0..@intCast(n)])) return -EFAULT;
    return @intCast(n);
}

fn fakeGetrandom(va: u64, count: u64) i64 {
    const e = g_env.?;
    e.getrandom_calls += 1;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        e.mem[@intCast(va - FakeEnv.USER_BASE + i)] = @truncate(0x5A ^ i);
    }
    return @intCast(count);
}

fn fakeTimeNs() u64 {
    return 123_456_789;
}

fn envSetup() !*FakeEnv {
    const e = try testing.allocator.create(FakeEnv);
    e.* = try FakeEnv.init();
    @memset(e.mem, 0);
    g_env = e;
    g_files = [_]FakeFile{.{}} ** 4; // чистый реестр файлов на каждый тест
    g_dirs = [_]FakeDir{.{}} ** 4; // чистые потоки каталогов
    return e;
}
fn envTeardown(e: *FakeEnv) void {
    g_env = null;
    e.deinit();
    testing.allocator.destroy(e);
}

/// Кладём строку в fake-user, возвращаем VA.
fn putStr(e: *FakeEnv, off: u64, s: []const u8) u64 {
    const va = FakeEnv.USER_BASE + off;
    const p = e.vaPtr(va).?;
    @memcpy(p[0..s.len], s);
    p[s.len] = 0;
    return va;
}

/// Пишем u32 в fake-user.
fn putU32(e: *FakeEnv, off: u64, v: u32) u64 {
    const va = FakeEnv.USER_BASE + off;
    std.mem.writeInt(u32, e.vaPtr(va).?[0..4], v, .little);
    return va;
}

// ─── Тесты: базовая волна (v0.18.0, адаптация под fd-таблицу) ──────────────

test "linux: syscall-числа x86_64 — ABI-контракты таблицы" {
    try testing.expectEqual(@as(u64, 0), SYS_read);
    try testing.expectEqual(@as(u64, 9), SYS_mmap);
    try testing.expectEqual(@as(u64, 11), SYS_munmap);
    try testing.expectEqual(@as(u64, 16), SYS_ioctl);
    try testing.expectEqual(@as(u64, 56), SYS_clone);
    try testing.expectEqual(@as(u64, 60), SYS_exit);
    try testing.expectEqual(@as(u64, 63), SYS_uname);
    try testing.expectEqual(@as(u64, 72), SYS_fcntl);
    try testing.expectEqual(@as(u64, 202), SYS_futex);
    try testing.expectEqual(@as(u64, 231), SYS_exit_group);
    try testing.expectEqual(@as(u64, 232), SYS_epoll_wait);
    try testing.expectEqual(@as(u64, 233), SYS_epoll_ctl);
    try testing.expectEqual(@as(u64, 291), SYS_epoll_create1);
    try testing.expectEqual(@as(u64, 257), SYS_openat);
    try testing.expectEqual(@as(i64, -100), AT_FDCWD);
}

test "linux: errno-кодирование — -errno в RAX как u64-биткаст" {
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFF2), err(EFAULT)); // -14
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFEA), err(EINVAL)); // -22
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFF7), err(EBADF)); // -9
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFDA), err(ENOSYS)); // -38
}

test "linux: dispatch — маршрутизация таблицы; неизвестный номер → -ENOSYS" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // write(1, valid, 16) → обработчик write вызван
    const buf = FakeEnv.USER_BASE;
    const r = dispatch(ops, &fds, SYS_write, .{ .a1 = 1, .a2 = buf, .a3 = 16 });
    try testing.expectEqual(@as(u64, 16), r);
    try testing.expectEqual(@as(u64, 1), e.write_calls);

    // exit_group(3) → do_exit_group вызван с кодом
    _ = dispatch(ops, &fds, SYS_exit_group, .{ .a1 = 3 });
    try testing.expectEqual(@as(u64, 3), e.exit_group_code.?);

    // неизвестный номер → -ENOSYS
    try testing.expectEqual(err(ENOSYS), dispatch(ops, &fds, 999, .{}));
    try testing.expectEqual(err(ENOSYS), dispatch(ops, &fds, 0xDEAD, .{}));
}

test "linux: sys_uname — заполнение Utsname, поля и нуль-терминация" {
    const e = try envSetup();
    defer envTeardown(e);

    const dst = FakeEnv.USER_BASE + 0x100;
    const r = sysUname(fakeOps(), dst);
    try testing.expectEqual(@as(u64, 0), r);

    // Читаем записанное из fake-памяти
    const p = e.vaPtr(dst).?;
    const uts: *const Utsname = @ptrCast(@alignCast(p));
    try testing.expectEqualStrings("POLER-OS", uts.sysname[0..std.mem.indexOfScalar(u8, &uts.sysname, 0).?]);
    try testing.expectEqualStrings("x86_64", uts.machine[0..std.mem.indexOfScalar(u8, &uts.machine, 0).?]);
    try testing.expectEqualStrings("0.19.0", uts.release[0..std.mem.indexOfScalar(u8, &uts.release, 0).?]);
    // размер структуры = 6×65 = 390 (glibc-совместимая раскладка)
    try testing.expectEqual(@as(usize, 390), @sizeOf(Utsname));
}

test "linux: sys_uname — плохой указатель → -EFAULT (никаких паник)" {
    const e = try envSetup();
    defer envTeardown(e);
    // NULL
    try testing.expectEqual(err(EFAULT), sysUname(fakeOps(), 0));
    // kernel-половина
    try testing.expectEqual(err(EFAULT), sysUname(fakeOps(), 0xFFFF_8000_0000_0000));
    // вне fake-региона
    try testing.expectEqual(err(EFAULT), sysUname(fakeOps(), 0x30000_0000));
    // частичный заход за границу региона
    try testing.expectEqual(err(EFAULT), sysUname(fakeOps(), FakeEnv.USER_BASE + FakeEnv.USER_LEN - 8));
}

test "linux: sys_write — счёт байтов; закрытый fd → -EBADF" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf = FakeEnv.USER_BASE;

    try testing.expectEqual(@as(u64, 32), sysWrite(ops, &fds, 1, buf, 32)); // stdout
    try testing.expectEqual(@as(u64, 32), sysWrite(ops, &fds, 2, buf, 32)); // stderr
    try testing.expectEqual(@as(u64, 0), sysWrite(ops, &fds, 1, buf, 0)); // count=0 — Linux-семантика
    try testing.expectEqual(@as(u64, 2), e.write_calls);
    try testing.expectEqual(@as(u64, 64), e.write_bytes);

    // fd=42 закрыт
    try testing.expectEqual(err(EBADF), sysWrite(ops, &fds, 42, buf, 8));
    // fd=-1
    try testing.expectEqual(err(EBADF), sysWrite(ops, &fds, -1, buf, 8));
}

test "linux: sys_write — враждебный буфер → -EFAULT (ядро читает user)" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // NULL-страница
    try testing.expectEqual(err(EFAULT), sysWrite(ops, &fds, 1, 0x0, 16));
    // kernel-VA
    try testing.expectEqual(err(EFAULT), sysWrite(ops, &fds, 1, 0xFFFF_8888_0000_0000, 16));
    // va+len перенос u64 — отказ ДО walk (hardening v0.18.0)
    try testing.expectEqual(err(EFAULT), sysWrite(ops, &fds, 1, 0xFFFF_FFFF_FFFF_FFF0, 32));
    // count не лезет в canonical user
    try testing.expectEqual(err(EFAULT), sysWrite(ops, &fds, 1, FakeEnv.USER_BASE, 0x8000_0000_0000_0000));
    // заход за границу fake-региона
    try testing.expectEqual(err(EFAULT), sysWrite(ops, &fds, 1, FakeEnv.USER_BASE + FakeEnv.USER_LEN - 4, 16));
    try testing.expectEqual(@as(u64, 0), e.write_calls); // ops не дергались
}

test "linux: sys_openat — AT_FDCWD, путь существует/нет; пустой путь → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // Устройство /dev/fb0 открывается (низший свободный fd = 3)
    const path_va = putStr(e, 0, "/dev/fb0");
    try testing.expectEqual(@as(u64, 3), sysOpenat(ops, &fds, AT_FDCWD, path_va, 0, 0));

    // Устройство /dev/dri/card0 → fd 4
    const path2 = putStr(e, 0x40, "/dev/dri/card0");
    try testing.expectEqual(@as(u64, 4), sysOpenat(ops, &fds, AT_FDCWD, path2, 0, 0));

    // /dev/input/event1 → fd 5
    const path3 = putStr(e, 0x80, "/dev/input/event1");
    try testing.expectEqual(@as(u64, 5), sysOpenat(ops, &fds, AT_FDCWD, path3, O_NONBLOCK, 0));
    try testing.expect(fds.entries[5].nonblock);

    // Обычный файл БЕЗ VFS-записи (initrd-слой не монтирован в тесте) →
    // VFS-мост вернёт -ENOENT — используем заведомо отсутствующий путь
    const path4 = putStr(e, 0xC0, "/var/log/nothing");
    try testing.expectEqual(err(ENOENT), sysOpenat(ops, &fds, AT_FDCWD, path4, 0, 0));

    // Пустой путь → -EINVAL
    const empty = putStr(e, 0x100, "");
    try testing.expectEqual(err(EINVAL), sysOpenat(ops, &fds, AT_FDCWD, empty, 0, 0));
}

test "linux: sys_openat — битые указатели пути → -EFAULT без паник" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    // Весь регион — не-нулевые байты: терминатора в 4096 точно нет
    @memset(e.mem, 'A');

    try testing.expectEqual(err(EFAULT), sysOpenat(ops, &fds, AT_FDCWD, 0, 0, 0)); // NULL
    try testing.expectEqual(err(EFAULT), sysOpenat(ops, &fds, AT_FDCWD, 0xFFFF_9000_0000_0000, 0, 0)); // kernel
    // путь без терминатора в 4096 → EFAULT (copy_in_str → null)
    try testing.expectEqual(err(EFAULT), sysOpenat(ops, &fds, AT_FDCWD, FakeEnv.USER_BASE, 0, 0));
}

// ─── Тесты: графическая волна v0.19.0 (fd/ioctl/mmap-dev/poll/epoll/futex) ──

test "linux: close/fcntl — жизненный цикл fd, O_NONBLOCK через F_SETFL" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    const path_va = putStr(e, 0, "/dev/input/event0");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path_va, 0, 0);
    try testing.expectEqual(@as(u64, 3), fd);

    // F_GETFL: O_RDWR без O_NONBLOCK
    const fl = sysFcntl(ops, &fds, 3, F_GETFL, 0);
    try testing.expectEqual(O_RDWR, fl & O_ACCMODE);
    try testing.expectEqual(@as(u64, 0), fl & O_NONBLOCK);

    // F_SETFL O_NONBLOCK → чтение пустой очереди → -EAGAIN
    try testing.expectEqual(@as(u64, 0), sysFcntl(ops, &fds, 3, F_SETFL, O_NONBLOCK));
    try testing.expectEqual(err(EAGAIN), sysRead(ops, &fds, 3, FakeEnv.USER_BASE, 24));
    // сброс → блокирующее чтение пусто → 0 (нет данных)
    try testing.expectEqual(@as(u64, 0), sysFcntl(ops, &fds, 3, F_SETFL, 0));
    try testing.expectEqual(@as(u64, 0), sysRead(ops, &fds, 3, FakeEnv.USER_BASE, 24));

    // close → слот свободен: read/write → EBADF
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 3));
    try testing.expectEqual(err(EBADF), sysRead(ops, &fds, 3, FakeEnv.USER_BASE, 24));
    try testing.expectEqual(err(EBADF), sysClose(ops, &fds, 3)); // повторный close
    try testing.expectEqual(err(EBADF), sysFcntl(ops, &fds, 3, F_GETFL, 0));

    // чужая fcntl-команда → -EINVAL (fb0 переоткрылся в слот 3 — низший)
    const path2 = putStr(e, 0x40, "/dev/fb0");
    const fb_fd = sysOpenat(ops, &fds, AT_FDCWD, path2, 0, 0);
    try testing.expectEqual(@as(u64, 3), fb_fd);
    try testing.expectEqual(err(EINVAL), sysFcntl(ops, &fds, @intCast(fb_fd), 99, 0));
}

test "linux: sys_ioctl — мост к устройствам; консоль/epoll → -ENOTTY" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const arg = FakeEnv.USER_BASE + 0x200;

    // открыли card0 → ioctl передаётся в dev_ioctl (мост к drm_kms)
    const path = putStr(e, 0, "/dev/dri/card0");
    _ = sysOpenat(ops, &fds, AT_FDCWD, path, 0, 0);
    const r = sysIoctl(ops, &fds, 3, 0xC040_64A0, arg); // GETRESOURCES
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqual(@as(u64, 1), e.ioctl_calls);
    try testing.expectEqual(@as(u32, 0xC040_64A0), e.last_ioctl_cmd);
    try testing.expectEqual(FdKind.dri_card0, e.last_ioctl_kind);

    // закрытый fd → EBADF; консоль → ENOTTY
    try testing.expectEqual(err(EBADF), sysIoctl(ops, &fds, 77, 0xC040_64A0, arg));
    try testing.expectEqual(err(ENOTTY), sysIoctl(ops, &fds, 1, 0xC040_64A0, arg));
}

test "linux: sys_mmap — файловый путь к fb0/card0; event-fd → -ENODEV" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // анонимный (как в v0.18.0)
    const r = sysMmap(ops, &fds, 0, 0x1234, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    try testing.expect(r != err(EINVAL));
    try testing.expectEqual(@as(u64, 1), e.mmap_calls);
    try testing.expectEqual(@as(u64, 0x1234), e.last_mmap_len);

    // MAP_SHARED|ANONYMOUS — разрешён (Linux ≥3.17 семантика)
    const r2 = sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    try testing.expect(r2 != err(EINVAL));

    // fb0 + offset=0 → dev_mmap (WC-видеопамять)
    const path = putStr(e, 0, "/dev/fb0");
    _ = sysOpenat(ops, &fds, AT_FDCWD, path, 0, 0);
    const r3 = sysMmap(ops, &fds, 0, 0x3000, PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0);
    try testing.expect(r3 != err(ENODEV));
    try testing.expectEqual(@as(u64, 1), e.dev_mmap_calls);
    try testing.expectEqual(FdKind.fb0, e.last_ioctl_kind);
    try testing.expectEqual(@as(u64, 0), e.last_dev_mmap_off);

    // card0 + unaligned offset → -EINVAL
    const path2 = putStr(e, 0x40, "/dev/dri/card0");
    _ = sysOpenat(ops, &fds, AT_FDCWD, path2, 0, 0);
    try testing.expectEqual(err(EINVAL), sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_SHARED, 4, 123));

    // event-fd (не мапится) → -ENODEV
    const path3 = putStr(e, 0x80, "/dev/input/event0");
    _ = sysOpenat(ops, &fds, AT_FDCWD, path3, 0, 0);
    try testing.expectEqual(err(ENODEV), sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_SHARED, 5, 0));

    // файловый маппинг без fd → -EBADF
    try testing.expectEqual(err(EBADF), sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_SHARED, 42, 0));

    // length=0 → -EINVAL
    try testing.expectEqual(err(EINVAL), sysMmap(ops, &fds, 0, 0, PROT_READ, MAP_SHARED, 3, 0));
}

test "linux: sys_mmap — length=0 → -EINVAL; MAP_FIXED вне user → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    try testing.expectEqual(err(EINVAL), sysMmap(ops, &fds, 0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    // MAP_FIXED с kernel-хинтом — отказ
    try testing.expectEqual(err(EINVAL), sysMmap(ops, &fds, 0xFFFF_8000_0000_0000, 4096, PROT_READ, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    // length за canonical-потолок
    try testing.expectEqual(err(ENOMEM), sysMmap(ops, &fds, 0, USER_VA_CEILING + 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
}

test "linux: sys_munmap — валидация диапазона → ops" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // валидный: страница + 8КБ
    try testing.expectEqual(@as(u64, 0), sysMunmap(ops, 0x4000_0000_0000, 8192));
    try testing.expectEqual(@as(u64, 1), e.munmap_calls);
    // нулевая длина
    try testing.expectEqual(err(EINVAL), sysMunmap(ops, 0x4000_0000_0000, 0));
    // невыгнанная страница
    try testing.expectEqual(err(EINVAL), sysMunmap(ops, 0x4000_0000_0001, 4096));
    // kernel-VA
    try testing.expectEqual(err(EINVAL), sysMunmap(ops, 0xFFFF_8000_0000_0000, 4096));
    // перенос u64
    try testing.expectEqual(err(EINVAL), sysMunmap(ops, 0x7FFF_FFFF_FFFF_F000, 0x2000));
}

test "linux: sys_futex — WAIT сверяет слово, WAKE проходит, таймаут парсится" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // futex-слово = 5 в user
    const fva = putU32(e, 0x10, 5);

    // CDD №12 p3: BITSET+CLOCK_REALTIME-варианты — атрибуты, не операции
    // (эмпирика run8: op 0x189 → EINVAL → pthread-потоки SPIN-или)
    try testing.expectEqual(@as(u64, 0),
        sysFutex(ops, fva, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME, 5, 0));
    try testing.expectEqual(@as(u64, 2), sysFutex(ops, fva, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 3, 0));
    try testing.expectEqual(@as(u32, 3), e.last_wake_n);

    // WAIT с ожидаемым 5 → паркинг (тест-модель: разбудили → 0);
    // park_calls=2: один уже сделан BITSET-WAIT'ом выше
    try testing.expectEqual(@as(u64, 0), sysFutex(ops, fva, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 5, 0));
    try testing.expectEqual(@as(u64, 2), e.park_calls);

    // WAIT с ожидаемым 4 (слово=5): значение изменилось → -EAGAIN
    try testing.expectEqual(err(EAGAIN), sysFutex(ops, fva, FUTEX_WAIT, 4, 0));
    try testing.expectEqual(@as(u64, 2), e.park_calls); // не доехал до паркинга

    // WAKE 3 → до 2 разбуженных
    try testing.expectEqual(@as(u64, 2), sysFutex(ops, fva, FUTEX_WAKE, 3, 0));
    try testing.expectEqual(@as(u32, 3), e.last_wake_n);

    // таймаут {1.5с} → паркинг с 1500мс
    const ts_va = FakeEnv.USER_BASE + 0x40;
    std.mem.writeInt(i64, e.vaPtr(ts_va).?[0..8], 1, .little);
    std.mem.writeInt(i64, e.vaPtr(ts_va).?[8..16], 500_000_000, .little);
    // (бесконечный таймаут-путь паркинга уже проверен; таймаут-модель → ETIMEDOUT)
    try testing.expectEqual(err(ETIMEDOUT), sysFutex(ops, fva, FUTEX_WAIT, 5, ts_va));

    // мусорный uaddr → -EFAULT; неизвестный op → -EINVAL
    try testing.expectEqual(err(EFAULT), sysFutex(ops, 0x30000_0000, FUTEX_WAIT, 0, 0));
    try testing.expectEqual(err(EINVAL), sysFutex(ops, fva, 13, 0, 0));
}

test "linux: sys_poll — POLLIN/POLLOUT/POLLNVAL; готовность устройств" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const poll_va = FakeEnv.USER_BASE + 0x200;

    // открываем event0/event1; kbd готов, мышь нет
    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0, "/dev/input/event0"), 0, 0); // fd 3
    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x40, "/dev/input/event1"), 0, 0); // fd 4
    e.ready_kbd = EPOLLIN;
    e.ready_mouse = 0;

    // 3 pollfd: event0 (POLLIN интерес), event1 (POLLIN), stdout (POLLOUT)
    var pfds = [_]PollFd{
        .{ .fd = 3, .events = POLLIN },
        .{ .fd = 4, .events = POLLIN },
        .{ .fd = 1, .events = POLLOUT },
        .{ .fd = 99, .events = POLLIN }, // незакрытый → POLLNVAL
        .{ .fd = -1, .events = POLLIN }, // fd<0 → игнор
    };
    @memcpy(e.vaPtr(poll_va).?[0 .. 5 * 8], std.mem.sliceAsBytes(pfds[0..5]));
    const r = sysPoll(ops, &fds, poll_va, 5, -1);
    try testing.expectEqual(@as(u64, 3), r); // kbd + stdout + NVAL

    const out: [*]const PollFd = @ptrCast(@alignCast(e.vaPtr(poll_va).?));
    try testing.expectEqual(POLLIN, out[0].revents);
    try testing.expectEqual(@as(i16, 0), out[1].revents); // мышь молчит
    try testing.expectEqual(POLLOUT, out[2].revents);
    try testing.expectEqual(POLLNVAL, out[3].revents);
    try testing.expectEqual(@as(i16, 0), out[4].revents); // fd<0 игнор

    // nfds > MAX → -EINVAL; мусорный указатель → -EFAULT
    try testing.expectEqual(err(EINVAL), sysPoll(ops, &fds, poll_va, 999, 0));
    try testing.expectEqual(err(EFAULT), sysPoll(ops, &fds, 0x30000_0000, 2, 0));
    // nfds=0 → 0
    try testing.expectEqual(@as(u64, 0), sysPoll(ops, &fds, poll_va, 0, 0));
}

test "linux: epoll-троица — create/ctl(ADD/MOD/DEL)/wait + ошибки" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const ev_va = FakeEnv.USER_BASE + 0x300;

    // epoll_create1 → fd 3
    const epfd = sysEpollCreate1(ops, &fds, 0);
    try testing.expectEqual(@as(u64, 3), epfd);

    // открываем event0 (fd 4): kbd ГОТОВ
    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0, "/dev/input/event0"), 0, 0);
    e.ready_kbd = EPOLLIN;

    // epoll_ctl ADD event0 с EPOLLIN + data=0xBEEF
    var evb: [12]u8 = .{0} ** 12;
    std.mem.writeInt(u32, evb[0..4], EPOLLIN, .little);
    std.mem.writeInt(u64, evb[4..12], 0xBEEF, .little);
    @memcpy(e.vaPtr(ev_va).?[0..12], &evb);
    try testing.expectEqual(@as(u64, 0), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_ADD, 4, ev_va));

    // повторный ADD → -EEXIST; MOD несуществующего fd → -EBADF (target-фд
    // проверяется РАНЬШЕ наблюдений — Linux-семантика)
    try testing.expectEqual(err(EEXIST), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_ADD, 4, ev_va));
    try testing.expectEqual(err(EBADF), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_MOD, 5, ev_va));

    // epoll_wait: kbd готов → 1 событие (events=EPOLLIN, data=0xBEEF)
    const wait_va = FakeEnv.USER_BASE + 0x340;
    const n = sysEpollWait(ops, &fds, 3, wait_va, 4, 0);
    try testing.expectEqual(@as(u64, 1), n);
    const out = e.vaPtr(wait_va).?;
    try testing.expectEqual(EPOLLIN, std.mem.readInt(u32, out[0..4], .little));
    try testing.expectEqual(@as(u64, 0xBEEF), std.mem.readInt(u64, out[4..12], .little));

    // kbd опустел → 0 событий
    e.ready_kbd = 0;
    try testing.expectEqual(@as(u64, 0), sysEpollWait(ops, &fds, 3, wait_va, 4, 0));

    // закрыли event0 (fd 4) → наблюдение «фантом», wait его пропускает
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 4));
    try testing.expectEqual(@as(u64, 0), sysEpollWait(ops, &fds, 3, wait_va, 4, 0));

    // переоткроем: наблюдение fd 4 всё ещё ВИСИТ (close НЕ снимает его —
    // Linux-семантика «фантома») → ADD → -EEXIST; MOD обновляет → готов
    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x80, "/dev/input/event0"), 0, 0);
    e.ready_kbd = EPOLLIN;
    try testing.expectEqual(err(EEXIST), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_ADD, 4, ev_va));
    try testing.expectEqual(@as(u64, 0), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_MOD, 4, ev_va));
    try testing.expectEqual(@as(u64, 1), sysEpollWait(ops, &fds, 3, wait_va, 4, 0));

    // DEL наблюдения
    try testing.expectEqual(@as(u64, 0), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_DEL, 4, 0));
    try testing.expectEqual(@as(u64, 0), sysEpollWait(ops, &fds, 3, wait_va, 4, 0));
    // повторный DEL → -ENOENT
    try testing.expectEqual(err(ENOENT), sysEpollCtl(ops, &fds, 3, EPOLL_CTL_DEL, 4, 0));

    // ошибки: epoll-операции на НЕ-epoll fd → EINVAL; мусорный epfd → EBADF
    try testing.expectEqual(err(EINVAL), sysEpollCtl(ops, &fds, 1, EPOLL_CTL_ADD, 4, ev_va));
    try testing.expectEqual(err(EINVAL), sysEpollWait(ops, &fds, 1, wait_va, 4, 0));
    try testing.expectEqual(err(EBADF), sysEpollWait(ops, &fds, 77, wait_va, 4, 0));
    // maxevents=0/65 → EINVAL; мусорный events-VA → EFAULT
    try testing.expectEqual(err(EINVAL), sysEpollWait(ops, &fds, 3, wait_va, 0, 0));
    try testing.expectEqual(err(EFAULT), sysEpollWait(ops, &fds, 3, 0x30000_0000, 4, 0));
}

test "linux: sys_clone — потоковые флаги; fork (без CLONE_VM) → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // поток: CLONE_VM|CLONE_SIGHAND|CLONE_THREAD|CLONE_FS|CLONE_FILES
    const thr = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FS | CLONE_FILES;
    const r = sysClone(ops, thr, 0x2000_0000_0000, 0, 0, 0);
    try testing.expectEqual(@as(u64, 77), r); // tid ребёнка
    try testing.expectEqual(@as(u64, 1), e.clone_calls);
    try testing.expectEqual(thr, e.last_clone_flags);

    // fork (SIGCHLD, без CLONE_VM) → -EINVAL (COW вне фундамента v0.19)
    try testing.expectEqual(err(EINVAL), sysClone(ops, 17, 0, 0, 0, 0));
    // CLONE_VM без CLONE_SIGHAND → Linux требует пару → -EINVAL
    try testing.expectEqual(err(EINVAL), sysClone(ops, CLONE_VM, 0, 0, 0, 0));
}

test "linux: sys_clone SETTID — NPTL-контракты parent/child_tid" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // слова tid в «user»-памяти фейка (USER_BASE — валидная зона fakeValidate)
    const ctid_va = FakeEnv.USER_BASE + 0x60;
    const ptid_va = FakeEnv.USER_BASE + 0x70;
    std.mem.writeInt(u32, e.mem[0x60..0x64], 0xDEAD, .little);
    std.mem.writeInt(u32, e.mem[0x70..0x74], 0xBEEF, .little);

    const thr = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FS | CLONE_FILES |
        CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    const r = sysClone(ops, thr, 0x2000_0000_0000, ptid_va, ctid_va, 0);
    try testing.expectEqual(@as(u64, 77), r);

    // tid (77) записан в ОБА слова
    try testing.expectEqual(@as(u32, 77), std.mem.readInt(u32, e.mem[0x60..0x64], .little));
    try testing.expectEqual(@as(u32, 77), std.mem.readInt(u32, e.mem[0x70..0x74], .little));

    // CLONE_PARENT_SETTID без указателя → EINVAL
    try testing.expectEqual(err(EINVAL), sysClone(
        ops,
        CLONE_VM | CLONE_SIGHAND | CLONE_PARENT_SETTID,
        0x2000_0000_0000,
        0,
        0,
        0,
    ));
    // CLONE_CHILD_CLEARTID без указателя → EINVAL
    try testing.expectEqual(err(EINVAL), sysClone(
        ops,
        CLONE_VM | CLONE_SIGHAND | CLONE_CHILD_CLEARTID,
        0x2000_0000_0000,
        0,
        0,
        0,
    ));
}

test "linux: sys_read — event-устройства, EAGAIN/EOF-семантика; консоль → EBADF" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0, "/dev/input/event0"), O_NONBLOCK, 0);
    _ = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x40, "/dev/input/event1"), 0, 0);

    // event0 пуст + NB → -EAGAIN
    try testing.expectEqual(err(EAGAIN), sysRead(ops, &fds, 3, FakeEnv.USER_BASE, 24));
    // event1 пуст блокирующе → 0 (нет данных)
    try testing.expectEqual(@as(u64, 0), sysRead(ops, &fds, 4, FakeEnv.USER_BASE, 24));
    // данные есть → счёт (итого 3 вызова dev_read: NB-пусто, блок-пусто, данные)
    e.ready_kbd = EPOLLIN;
    try testing.expectEqual(@as(u64, 48), sysRead(ops, &fds, 3, FakeEnv.USER_BASE, 48));
    try testing.expectEqual(@as(u64, 3), e.read_calls);

    // stdin/stdout (консоль) → -EBADF: входного пути нет
    try testing.expectEqual(err(EBADF), sysRead(ops, &fds, 0, FakeEnv.USER_BASE, 24));
    try testing.expectEqual(err(EBADF), sysRead(ops, &fds, 1, FakeEnv.USER_BASE, 24));
    // мусорный буфер → EFAULT
    try testing.expectEqual(err(EFAULT), sysRead(ops, &fds, 3, 0x30000_0000, 24));
}

test "linux: FdTable — EMFILE при заполнении; resolveDevKind" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // заполняем все слоты (3..MAX_FDS-1 = 61 открытие; p2: 16→64)
    var i: u64 = 0;
    while (i < MAX_FDS - 3) : (i += 1) {
        const r = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x100, "/dev/fb0"), 0, 0);
        try testing.expectEqual(3 + i, r);
    }
    // таблица полна → -EMFILE
    try testing.expectEqual(err(EMFILE), sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x140, "/dev/fb0"), 0, 0));
    // close освобождает → следующий open получает слот 3
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 3));
    try testing.expectEqual(@as(u64, 3), sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x180, "/dev/fb0"), 0, 0));

    // devfs-резолв
    try testing.expectEqual(FdKind.fb0, resolveDevKind("/dev/fb0"));
    try testing.expectEqual(FdKind.dri_card0, resolveDevKind("/dev/dri/card0"));
    try testing.expectEqual(FdKind.dri_card0, resolveDevKind("/dev/dri/renderD128"));
    try testing.expectEqual(FdKind.input_event0, resolveDevKind("/dev/input/event0"));
    try testing.expectEqual(FdKind.input_event1, resolveDevKind("/dev/input/event1"));
    try testing.expectEqual(FdKind.console_out, resolveDevKind("/dev/tty"));
    try testing.expect(resolveDevKind("/etc/passwd") == null);
    try testing.expect(resolveDevKind("/dev/fb1") == null);
}

test "linux: UAPI-якоря волны — pollfd 8Б, epoll_event 12Б (packed)" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(PollFd));
    try testing.expectEqual(@as(usize, 12), @sizeOf(EpollEvent)); // PACKED: u32 + u64 без паддинга
    try testing.expectEqual(@as(usize, 4), @offsetOf(PollFd, "events"));
    try testing.expectEqual(@as(usize, 6), @offsetOf(PollFd, "revents"));
    // флаги Linux
    try testing.expectEqual(@as(u64, 0x800), O_NONBLOCK); // 0o4000
    try testing.expectEqual(@as(u64, 128), FUTEX_PRIVATE_FLAG);
    try testing.expectEqual(@as(u64, 0x10000), CLONE_THREAD);
}

// ─── Тесты: VFS-файлы (Live-USB overlay — CDD №10 p4) ──────────────────────

test "linux: openat /tmp-файл → write → read roundtrip + смещение" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    // открыли tmpfs-файл (создаётся открытием — O_CREAT-стиль);
    // путь — в отдалённом буфере (записи теста идут по offset 0)
    const path = putStr(e, 0x100, "/tmp/session.conf");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.tmpfs_file, fds.entries[3].kind);

    // write «POLER» + «-LIVE» — offset движется
    @memcpy(e.vaPtr(buf_va).?[0..5], "POLER");
    try testing.expectEqual(@as(u64, 5), sysWrite(ops, &fds, 3, buf_va, 5));
    @memcpy(e.vaPtr(buf_va).?[0..5], "-LIVE");
    try testing.expectEqual(@as(u64, 5), sysWrite(ops, &fds, 3, buf_va, 5));
    try testing.expectEqual(@as(u64, 10), fds.entries[3].file_off);

    // переоткрытие НЕ разделяет offset (новый file_id — новое состояние)
    const fd2 = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 4), fd2);
    try testing.expectEqual(@as(u64, 0), fds.entries[4].file_off);

    // полное содержимое — через ВТОРОЕ открытие (его offset = 0);
    // чистим ТОЛЬКО читаемый буфер (путь живёт в 0x100)
    @memset(e.vaPtr(buf_va).?[0..64], 0);
    try testing.expectEqual(@as(u64, 10), sysRead(ops, &fds, 4, buf_va, 64));
    try testing.expectEqualStrings("POLER-LIVE", e.vaPtr(buf_va).?[0..10]);
    // fd4 дошёл до конца → EOF (0)
    try testing.expectEqual(@as(u64, 0), sysRead(ops, &fds, 4, buf_va, 64));
    // fd3 тоже в конце (offset = 10 после записей)
    try testing.expectEqual(@as(u64, 0), sysRead(ops, &fds, 3, buf_va, 64));
    // частичное чтение со смещением — третье открытие
    const fd5 = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 5), fd5);
    try testing.expectEqual(@as(u64, 4), sysRead(ops, &fds, 5, buf_va, 4));
    try testing.expectEqualStrings("POL", e.vaPtr(buf_va).?[0..3]);
}

test "linux: initrd-файл — RO-чтение с «USB»; запись → -EBADF" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    const path = putStr(e, 0, "/etc/hostname");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDONLY, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.initrd_file, fds.entries[3].kind);

    // чтение RO-файла (initrd-CPIO контент)
    try testing.expectEqual(@as(u64, 15), sysRead(ops, &fds, 3, buf_va, 64));
    try testing.expectEqualStrings("poler-live-host", e.vaPtr(buf_va).?[0..15]);

    // ЗАПИСЬ в initrd → -EBADF (RO-fd: Linux-семантика)
    @memcpy(e.vaPtr(buf_va).?[0..3], "XYZ");
    try testing.expectEqual(err(EBADF), sysWrite(ops, &fds, 3, buf_va, 3));

    // несуществующий файл → -ENOENT
    const p404 = putStr(e, 0x40, "/var/log/nope");
    try testing.expectEqual(err(ENOENT), sysOpenat(ops, &fds, AT_FDCWD, p404, 0, 0));

    // poll: initrd-файл читаем (POLLIN), tmpfs — RW
    var pfds = [_]PollFd{.{ .fd = 3, .events = POLLIN | POLLOUT }};
    const pva = FakeEnv.USER_BASE + 0x200;
    @memcpy(e.vaPtr(pva).?[0..8], std.mem.sliceAsBytes(pfds[0..1]));
    _ = sysPoll(ops, &fds, pva, 1, 0);
    const out: *const PollFd = @ptrCast(@alignCast(e.vaPtr(pva).?));
    try testing.expectEqual(POLLIN, out.revents & POLLIN);
    try testing.expectEqual(@as(i16, 0), out.revents & POLLOUT); // RO — писать нельзя

    // v0.20.0 (CDD №11 p3): fstat на ФАЙЛОВОМ fd — S_IFREG + st_size +
    // УНИКАЛЬНЫЙ (st_dev, st_ino): ld.so идентифицирует библиотеки по паре —
    // нулевой id = ложное «already loaded» (dl-load.c:994) → без mmap → 127
    const st_va = FakeEnv.USER_BASE + 0x280;
    try testing.expectEqual(@as(u64, 0), sysFstat(ops, &fds, 3, st_va));
    const q = e.vaPtr(st_va).?;
    try testing.expectEqual(POLER_VFS_DEV, std.mem.readInt(u64, q[0..8], .little));
    try testing.expectEqual(@as(u64, 100), std.mem.readInt(u64, q[8..16], .little)); // ino = 100+id
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, q[16..24], .little)); // nlink
    try testing.expectEqual(@as(u32, S_IFREG | 0x1A4), std.mem.readInt(u32, q[24..28], .little));
    try testing.expectEqual(@as(u64, 8192), std.mem.readInt(u64, q[48..56], .little)); // size (fake)
    try testing.expectEqual(@as(u64, 16), std.mem.readInt(u64, q[64..72], .little)); // blocks
    // консоль — по-прежнему S_IFCHR
    try testing.expectEqual(@as(u64, 0), sysFstat(ops, &fds, 1, st_va));
    try testing.expectEqual(@as(u32, S_IFCHR | 0x1A0), std.mem.readInt(u32, q[24..28], .little));
}

test "linux: v0.20 identity/brk — gettid/getpid/getppid/uid/brk-семантика" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();
    var fds = FdTable.init();

    // якоря номеров (unistd_64.h)
    try testing.expectEqual(@as(u64, 12), SYS_brk);
    try testing.expectEqual(@as(u64, 39), SYS_getpid);
    try testing.expectEqual(@as(u64, 102), SYS_getuid);
    try testing.expectEqual(@as(u64, 104), SYS_getgid);
    try testing.expectEqual(@as(u64, 107), SYS_geteuid);
    try testing.expectEqual(@as(u64, 108), SYS_getegid);
    try testing.expectEqual(@as(u64, 110), SYS_getppid);
    try testing.expectEqual(@as(u64, 186), SYS_gettid);

    // dispatch: identity-волна
    try testing.expectEqual(@as(u64, 77), dispatch(ops, &fds, SYS_gettid, .{}));
    try testing.expectEqual(@as(u64, 100), dispatch(ops, &fds, SYS_getpid, .{}));
    try testing.expectEqual(@as(u64, 1), dispatch(ops, &fds, SYS_getppid, .{}));
    try testing.expectEqual(@as(u64, 1000), dispatch(ops, &fds, SYS_getuid, .{}));
    try testing.expectEqual(@as(u64, 1000), dispatch(ops, &fds, SYS_geteuid, .{}));
    try testing.expectEqual(@as(u64, 1000), dispatch(ops, &fds, SYS_getgid, .{}));
    try testing.expectEqual(@as(u64, 1000), dispatch(ops, &fds, SYS_getegid, .{}));

    // brk: sbrk(0) → базис; рост → новый; отказ (ниже базиса) → старый
    try testing.expectEqual(@as(u64, 0x1000), dispatch(ops, &fds, SYS_brk, .{ .a1 = 0 }));
    try testing.expectEqual(@as(u64, 0x3000), dispatch(ops, &fds, SYS_brk, .{ .a1 = 0x3000 }));
    try testing.expectEqual(@as(u64, 0x3000), dispatch(ops, &fds, SYS_brk, .{ .a1 = 0x800 })); // отказ
    try testing.expectEqual(@as(u64, 3), e.brk_calls);
    try testing.expectEqual(@as(u64, 0x3000), e.brk_value);
}

// ─── v0.20.0 (CDD №11 p3): ld.so-волна — lseek/pread64/writev/access/newfstatat/file-mmap ──

test "linux: lseek — SEEK_SET/CUR/END на tmpfs; ESPIPE на консоли; EINVAL-края" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    // tmpfs-файл с 10 байтами контента
    const path = putStr(e, 0x100, "/tmp/seek.bin");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    @memcpy(e.vaPtr(buf_va).?[0..10], "0123456789");
    try testing.expectEqual(@as(u64, 10), sysWrite(ops, &fds, 3, buf_va, 10));

    // SEEK_SET: абсолют
    try testing.expectEqual(@as(u64, 4), sysLseek(ops, &fds, 3, 4, SEEK_SET));
    try testing.expectEqual(@as(u64, 4), fds.entries[3].file_off);
    // SEEK_CUR: относительный сдвиг (+2)
    try testing.expectEqual(@as(u64, 6), sysLseek(ops, &fds, 3, 2, SEEK_CUR));
    // SEEK_END: хвост (fake file_size = 8192): 8192-10 = 8182
    try testing.expectEqual(@as(u64, 8182), sysLseek(ops, &fds, 3, -10, SEEK_END));
    // чтение с позиции 6: «6789»
    try testing.expectEqual(@as(u64, 6), sysLseek(ops, &fds, 3, 6, SEEK_SET));
    @memset(e.vaPtr(buf_va).?[0..16], 0);
    try testing.expectEqual(@as(u64, 4), sysRead(ops, &fds, 3, buf_va, 16));
    try testing.expectEqualStrings("6789", e.vaPtr(buf_va).?[0..4]);

    // консоль (fd 1) — не файл: ESPIPE (Linux: lseek на tty)
    try testing.expectEqual(err(ESPIPE), sysLseek(ops, &fds, 1, 0, SEEK_SET));
    // неизвестный whence → EINVAL
    try testing.expectEqual(err(EINVAL), sysLseek(ops, &fds, 3, 0, 99));
    // отрицательный результат → EINVAL
    try testing.expectEqual(err(EINVAL), sysLseek(ops, &fds, 3, -5, SEEK_SET));
    // закрытый fd → EBADF
    try testing.expectEqual(err(EBADF), sysLseek(ops, &fds, 9, 0, SEEK_SET));

    // якорь номера
    try testing.expectEqual(@as(u64, 8), SYS_lseek);
}

test "linux: pread64 — чтение БЕЗ сдвига file_off; EBADF/EFAULT" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    const path = putStr(e, 0x100, "/tmp/pread.bin");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    @memcpy(e.vaPtr(buf_va).?[0..10], "ABCDEFGHIJ");
    try testing.expectEqual(@as(u64, 10), sysWrite(ops, &fds, 3, buf_va, 10));
    // подводим file_off в конец
    _ = sysLseek(ops, &fds, 3, 10, SEEK_SET);

    // pread64 с offset 2: «CDE» — file_off НЕ двигается (остался 10)
    @memset(e.vaPtr(buf_va).?[0..16], 0);
    try testing.expectEqual(@as(u64, 3), sysPread64(ops, &fds, 3, buf_va, 3, 2));
    try testing.expectEqualStrings("CDE", e.vaPtr(buf_va).?[0..3]);
    try testing.expectEqual(@as(u64, 10), fds.entries[3].file_off);

    // offset за концом → EOF (0)
    try testing.expectEqual(@as(u64, 0), sysPread64(ops, &fds, 3, buf_va, 3, 8192));
    // консоль → EBADF (не файл)
    try testing.expectEqual(err(EBADF), sysPread64(ops, &fds, 1, buf_va, 3, 0));
    // битый буфер → EFAULT
    try testing.expectEqual(err(EFAULT), sysPread64(ops, &fds, 3, 0x10_0000, 3, 0));
    // якорь номера
    try testing.expectEqual(@as(u64, 17), SYS_pread64);
}

test "linux: writev — векторная запись (tmpfs + консоль); EINVAL/EFAULT-края" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    // iovec[2] в fake-user: {base=buf, len=5} и {base=buf+5, len=5}
    const iov_va = FakeEnv.USER_BASE + 0x300;
    const p = e.vaPtr(iov_va).?;
    @memcpy(e.vaPtr(buf_va).?[0..10], "POLER-DYNA");
    std.mem.writeInt(u64, p[0..8], buf_va, .little);
    std.mem.writeInt(u64, p[8..16], 5, .little);
    std.mem.writeInt(u64, p[16..24], buf_va + 5, .little);
    std.mem.writeInt(u64, p[24..32], 5, .little);

    // консоль: writev(1, iov, 2) = 10 байт (две записи write)
    try testing.expectEqual(@as(u64, 10), sysWritev(ops, &fds, 1, iov_va, 2));

    // tmpfs-файл: файловый writev — offset движется, контент склеен
    const path = putStr(e, 0x100, "/tmp/wv.bin");
    _ = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDWR, 0);
    try testing.expectEqual(@as(u64, 10), sysWritev(ops, &fds, 3, iov_va, 2));
    try testing.expectEqual(@as(u64, 10), fds.entries[3].file_off);
    // перечитали с нуля (новый fd)
    const fd2 = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDONLY, 0);
    @memset(e.vaPtr(buf_va).?[0..16], 0);
    try testing.expectEqual(@as(u64, 10), sysRead(ops, &fds, @intCast(fd2), buf_va, 16));
    try testing.expectEqualStrings("POLER-DYNA", e.vaPtr(buf_va).?[0..10]);

    // iovcnt=0 → 0; iovcnt > MAX_IOV → EINVAL
    try testing.expectEqual(@as(u64, 0), sysWritev(ops, &fds, 3, iov_va, 0));
    try testing.expectEqual(err(EINVAL), sysWritev(ops, &fds, 3, iov_va, MAX_IOV + 1));
    // битый iov-указатель → EFAULT; битая base внутри → EFAULT
    try testing.expectEqual(err(EFAULT), sysWritev(ops, &fds, 1, 0x10_0000, 2));
    std.mem.writeInt(u64, p[0..8], 0x10_0000, .little);
    try testing.expectEqual(err(EFAULT), sysWritev(ops, &fds, 1, iov_va, 1));
    // пустая iovec (len=0) — просто скип
    std.mem.writeInt(u64, p[0..8], buf_va, .little);
    std.mem.writeInt(u64, p[8..16], 0, .little);
    try testing.expectEqual(@as(u64, 0), sysWritev(ops, &fds, 1, iov_va, 1));

    // якорь номера
    try testing.expectEqual(@as(u64, 20), SYS_writev);
}

test "linux: access — существование пути (ld.so: ld.so.cache ENOENT)" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // /etc/hostname есть (fake: всё кроме ld.so.cache)
    const p_ok = putStr(e, 0, "/etc/hostname");
    try testing.expectEqual(@as(u64, 0), sysAccess(ops, p_ok, 4)); // R_OK
    // кэша динамического линковщика нет → ENOENT (ld.so идёт по каталогам)
    const p_cache = putStr(e, 0x40, "/etc/ld.so.cache");
    try testing.expectEqual(err(ENOENT), sysAccess(ops, p_cache, 4));
    // битый указатель → EFAULT
    try testing.expectEqual(err(EFAULT), sysAccess(ops, 0x10_0000, 4));
    // счётчик вызовов
    try testing.expectEqual(@as(u64, 2), g_env.?.access_calls);
    // якорь номера (access=21 — legacy, но glibc вызывает)
    try testing.expectEqual(@as(u64, 21), SYS_access);
}

test "linux: newfstatat — stat-раскладка 144Б: S_IFREG/st_size/st_blksize" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    const p = putStr(e, 0, "/lib/x86_64-linux-gnu/libc.so.6");
    try testing.expectEqual(@as(u64, 0), sysNewfstatat(ops, AT_FDCWD, p, buf_va, 0));
    // раскладка struct stat x86_64: st_dev@0, st_ino@8, st_nlink@16,
    // st_mode@24 (S_IFREG|0444=0x8124), st_size@48 (fake 8192), st_blksize@56
    const q = e.vaPtr(buf_va).?;
    try testing.expectEqual(POLER_VFS_DEV, std.mem.readInt(u64, q[0..8], .little));
    try testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, q[8..16], .little)); // ino ≠ 0!
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, q[16..24], .little));
    try testing.expectEqual(@as(u32, 0x8124), std.mem.readInt(u32, q[24..28], .little));
    try testing.expectEqual(@as(u64, 8192), std.mem.readInt(u64, q[48..56], .little));
    try testing.expectEqual(@as(u64, 4096), std.mem.readInt(u64, q[56..64], .little));
    try testing.expectEqual(@as(u64, 16), std.mem.readInt(u64, q[64..72], .little)); // blocks

    // несуществующий путь → ENOENT (fake: ld.so.cache)
    const p404 = putStr(e, 0x80, "/etc/ld.so.cache");
    try testing.expectEqual(err(ENOENT), sysNewfstatat(ops, AT_FDCWD, p404, buf_va, 0));
    // битый statbuf → EFAULT; битый путь → EFAULT
    try testing.expectEqual(err(EFAULT), sysNewfstatat(ops, AT_FDCWD, p, 0x10_0000, 0));
    try testing.expectEqual(err(EFAULT), sysNewfstatat(ops, AT_FDCWD, 0x10_0000, buf_va, 0));
    // dispatch-маршрут + якорь номера (262)
    try testing.expectEqual(@as(u64, 262), SYS_newfstatat);
    try testing.expectEqual(err(ENOENT), dispatch(ops, &fds, SYS_newfstatat, .{
        .a1 = @bitCast(AT_FDCWD), .a2 = p404, .a3 = buf_va, .a4 = 0,
    }));
    // libc(1) + ld.so.cache(2) + dispatch-повтор(3); EFAULT-ветки НЕ считаются
    try testing.expectEqual(@as(u64, 3), g_env.?.stat_calls);
}

test "linux: mmap file-backed (MAP_PRIVATE) — initrd-файл; MAP_SHARED (non-anon) → ENODEV" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    const buf_va = FakeEnv.USER_BASE;

    const path = putStr(e, 0, "/etc/hostname");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, path, O_RDONLY, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.initrd_file, fds.entries[3].kind);

    // MAP_PRIVATE: ld.so грузит libc сегментами — file_mmap-оп вызван
    const want_va: u64 = e.mmap_cursor;
    const r = sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_PRIVATE, 3, 0);
    try testing.expectEqual(want_va, r);
    try testing.expectEqual(@as(u64, 1), e.file_mmap_calls);
    try testing.expectEqual(@as(u64, 0), e.last_file_mmap_off);
    try testing.expectEqual(@as(u64, 4096), e.last_file_mmap_len);
    try testing.expectEqual(PROT_READ, e.last_file_mmap_prot);

    // MAP_SHARED на RO-файле → ENOSYS (осознанно: только приватные копии)
    // CDD №12 p3: initrd не разделяем — ENODEV (было ENOSYS до memfd-волны)
    try testing.expectEqual(err(ENODEV), sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_SHARED, 3, 0));
    // event-fd по-прежнему ENODEV
    try testing.expectEqual(err(ENODEV), sysMmap(ops, &fds, 0, 4096, PROT_READ, MAP_PRIVATE, 0, 0));

    // MAP_FIXED: ld.so-семантика — сегмент по ТОЧНОМУ адресу base+vaddr
    // поверх первичного спана (возвращаем заданный VA, fixed передан в оп)
    const want_fixed: u64 = 0x0000_0040_0100_2000;
    const rf = sysMmap(ops, &fds, want_fixed, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, 3, 0x1000);
    try testing.expectEqual(want_fixed, rf);
    try testing.expectEqual(want_fixed, e.last_file_mmap_fixed);
    try testing.expectEqual(@as(u64, 0x1000), e.last_file_mmap_off);
    // hint БЕЗ MAP_FIXED — игнорируется (ядро размещает само)
    _ = sysMmap(ops, &fds, want_fixed, 4096, PROT_READ, MAP_PRIVATE, 3, 0);
    try testing.expectEqual(@as(u64, 0), e.last_file_mmap_fixed);

    // АНОНИМНЫЙ MAP_FIXED (ld.so: bss-хвост libc поверх спана,
    // dl-map-segments.h:163): hint+flags уходят в do_mmap op
    const ra = sysMmap(ops, &fds, want_fixed, 0x1000, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    try testing.expectEqual(want_fixed, ra);
    try testing.expectEqual(want_fixed, e.last_mmap_fixed);
    try testing.expectEqual(MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, e.last_mmap_flags);
    // анонимный БЕЗ FIXED — курсор (fake), fixed-запись сброшена
    _ = sysMmap(ops, &fds, 0, 0x1000, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    try testing.expectEqual(@as(u64, 0), e.last_mmap_fixed);

    // dispatch-маршрут: mmap(9) с fd → file_mmap (итог: приватный+fixed+hint+dispatch)
    _ = dispatch(ops, &fds, SYS_mmap, .{ .a1 = 0, .a2 = 8192, .a3 = PROT_READ, .a4 = MAP_PRIVATE, .a5 = 3, .a6 = 0x1000 });
    try testing.expectEqual(@as(u64, 4), e.file_mmap_calls);
    try testing.expectEqual(@as(u64, 0x1000), e.last_file_mmap_off);
    try testing.expectEqual(@as(u64, 8192), e.last_file_mmap_len);

    _ = buf_va;
}

// ─── Тесты CDD №12 p1: readlink/readlinkat общего пути ─────────────────────

test "linux: readlink — цель симлинка initrd; /proc/self/exe сохранён" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();
    g_env.?.execfn = "gamescope";

    // readlink("/lib64/ld-linux-x86-64.so.2") → абсолютная цель симлинка
    const p_link = putStr(e, 0, "/lib64/ld-linux-x86-64.so.2");
    const buf_va = putStr(e, 0x100, ""); // пустой буфер в fake-user
    const r1 = sysReadlinkat(ops, 0, p_link, buf_va, 64);
    try testing.expectEqual(@as(u64, 29), r1); // len("/usr/lib/ld-linux-x86-64.so.2")
    var out: [64]u8 = undefined;
    try testing.expect(fakeCopyIn(&out, buf_va));
    try testing.expectEqualStrings("/usr/lib/ld-linux-x86-64.so.2", out[0..29]);

    // /proc/self/exe — прежний путь (execfn)
    const p_exe = putStr(e, 0, "/proc/self/exe");
    const r2 = sysReadlinkat(ops, 0, p_exe, buf_va, 64);
    try testing.expectEqual(@as(u64, "gamescope".len), r2);
    try testing.expect(fakeCopyIn(&out, buf_va));
    try testing.expectEqualStrings("gamescope", out[0..9]);

    // bufsz=0 → EINVAL
    try testing.expectEqual(err(EINVAL), sysReadlinkat(ops, 0, p_link, buf_va, 0));
    // битый path-указатель → EFAULT
    try testing.expectEqual(err(EFAULT), sysReadlinkat(ops, 0, 0x10_0000, buf_va, 64));
}

test "linux: readlink (leg #87) — маршрутизация dispatch" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();
    g_env.?.execfn = "gs";

    // SYS_readlink(path, buf, sz) → sysReadlinkat(AT_FDCWD, …)
    const p_exe = putStr(e, 0, "/proc/self/exe");
    const buf_va = FakeEnv.USER_BASE + 0x100;
    const args = Args{ .a1 = p_exe, .a2 = buf_va, .a3 = 32 };
    const r = dispatch(ops, &fds, SYS_readlink, args);
    try testing.expectEqual(@as(u64, 2), r); // "gs"
    // якорь номера (сверено с arch/x86/entry/syscalls/syscall_64.tbl:
    // readlink=89 [87=unlink!], readlinkat=267 [298=perf_event_open!])
    try testing.expectEqual(@as(u64, 89), SYS_readlink);
    try testing.expectEqual(@as(u64, 267), SYS_readlinkat);
}

// ─── Тесты CDD №12 p1: close — жизненный цикл реестра файлов ────────────────

test "linux: close — освобождение слота РЕЕСТРА (EMFILE-утечка вылечена)" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // цикл ld.so: open → close × 5 (реестр 4 слота — раньше 5-й open
    // дал бы EMFILE из-за утечки слотов реестра)
    for (0..5) |i| {
        var name_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&name_buf, "/usr/lib/lib{d}.so.1", .{i}) catch unreachable;
        const p = putStr(e, 0, path);
        const fd = sysOpenat(ops, &fds, 0, p, 0, 0);
        try testing.expect(fd >= 3 and fd < 256); // успех (ошибки — huge u64)
        // close → слот РЕЕСТРА освобождён вместе с fd
        try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, @intCast(fd)));
        try testing.expectEqual(err(EBADF), sysClose(ops, &fds, @intCast(fd))); // повтор
    }

    // одновременно 4 файла — ок; 5-й без close → EMFILE (лимит реестра)
    var opened: [6]u64 = undefined;
    for (0..6) |i| {
        var name_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&name_buf, "/usr/lib/libX{d}.so.1", .{i}) catch unreachable;
        const p = putStr(e, 0, path);
        opened[i] = sysOpenat(ops, &fds, 0, p, 0, 0);
    }
    try testing.expect(opened[3] >= 3 and opened[3] < 256); // 4 слота реестра
    try testing.expectEqual(err(EMFILE), opened[4]); // 5-й — EMFILE

    // close одного → open снова работает (слот реестра вернулся в пул)
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, @intCast(opened[0])));
    var name_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&name_buf, "/usr/lib/libY.so.1", .{}) catch unreachable;
    const p = putStr(e, 0, path);
    const fd2 = sysOpenat(ops, &fds, 0, p, 0, 0);
    try testing.expect(fd2 >= 3 and fd2 < 256);
}

// ─── Тесты CDD №12 p2: канал-волна + сигналы + misc ─────────────────────────

test "linux: pipe2 — пара fd, FIFO write/read, EINVAL/EFAULT-края" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    const pair_va = FakeEnv.USER_BASE + 0x200;
    const r = sysPipe2(ops, &fds, pair_va, 0);
    try testing.expectEqual(@as(u64, 0), r);
    var pb: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&pb, pair_va));
    const rfd: i64 = std.mem.readInt(u32, pb[0..4], .little);
    const wfd: i64 = std.mem.readInt(u32, pb[4..8], .little);
    try testing.expect(rfd == 3 and wfd == 4);
    try testing.expectEqual(FdKind.pipe_read, fds.entries[3].kind);
    try testing.expectEqual(FdKind.pipe_write, fds.entries[4].kind);

    // FIFO: write 4Б в писца → read 4Б из читателя
    const msg = putStr(e, 0x40, "PING");
    try testing.expectEqual(@as(u64, 4), sysWrite(ops, &fds, wfd, msg, 4));
    const out_va = FakeEnv.USER_BASE + 0x300;
    try testing.expectEqual(@as(u64, 4), sysRead(ops, &fds, rfd, out_va, 8));
    var out: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&out, out_va));
    try testing.expectEqualStrings("PING", out[0..4]);
    // пустой pipe + NB → EAGAIN
    fds.entries[@intCast(rfd)].nonblock = true;
    try testing.expectEqual(err(EAGAIN), sysRead(ops, &fds, rfd, out_va, 8));

    // краи: битые флаги → EINVAL; битый указатель → EFAULT
    try testing.expectEqual(err(EINVAL), sysPipe2(ops, &fds, pair_va, 0x4));
    try testing.expectEqual(err(EFAULT), sysPipe2(ops, &fds, 0x10_0000, 0));
}

test "linux: eventfd2 — счётчик write→read; ready-биты; close→unref" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    const fd = sysEventfd2(ops, &fds, 0, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.eventfd, fds.entries[3].kind);
    // инкремент (write 8Б value=5)
    const val_va = putStr(e, 0x40, "\x05\x00\x00\x00\x00\x00\x00\x00");
    try testing.expectEqual(@as(u64, 8), sysWrite(ops, &fds, 3, val_va, 8));
    // read → счётчик 5, сброс
    const out_va = FakeEnv.USER_BASE + 0x300;
    try testing.expectEqual(@as(u64, 8), sysRead(ops, &fds, 3, out_va, 8));
    var out: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&out, out_va));
    try testing.expectEqual(@as(u64, 5), std.mem.readInt(u64, &out, .little));
    // после сброса → EAGAIN
    try testing.expectEqual(err(EAGAIN), sysRead(ops, &fds, 3, out_va, 8));
    // флаги-край
    try testing.expectEqual(err(EINVAL), sysEventfd2(ops, &fds, 0, 0x100));
    // close → слот канала освободился (переиспользование id)
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 3));
}

test "linux: socketpair — AF_UNIX пара; wrong domain → EAFNOSUPPORT" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    const sv_va = FakeEnv.USER_BASE + 0x200;
    try testing.expectEqual(@as(u64, 0), sysSocketpair(ops, &fds, 1, 1, 0, sv_va));
    var pb: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&pb, sv_va));
    try testing.expect(std.mem.readInt(u32, pb[0..4], .little) == 3);
    try testing.expect(std.mem.readInt(u32, pb[4..8], .little) == 4);
    try testing.expectEqual(FdKind.socket, fds.entries[3].kind);
    // двунаправленность: write fd3 → read fd4
    const msg = putStr(e, 0x40, "WL");
    try testing.expectEqual(@as(u64, 2), sysWrite(ops, &fds, 3, msg, 2));
    const out_va = FakeEnv.USER_BASE + 0x300;
    try testing.expectEqual(@as(u64, 2), sysRead(ops, &fds, 4, out_va, 8));
    // не-AF_UNIX
    try testing.expectEqual(err(EAFNOSUPPORT), sysSocketpair(ops, &fds, 2, 1, 0, sv_va));
}

test "linux: rt_sigaction/rt_sigprocmask — хранилище; SIGKILL → EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // установить SIGUSR1(10) = 0xDEAD
    var act: [32]u8 = .{0} ** 32;
    std.mem.writeInt(u64, act[0..8], 0xDEAD, .little);
    const act_va = putStr(e, 0, "/proc/self/exe"); // перезапишем ниже сырыми байтами
    try testing.expect(fakeCopyOut(act_va, &act));
    try testing.expectEqual(@as(u64, 0), sysRtSigaction(ops, 10, act_va, 0, 8));
    try testing.expectEqual(@as(u64, 0xDEAD), g_sig_handlers[10]);

    // oldact возвращает прежний handler
    const old_va = FakeEnv.USER_BASE + 0x100;
    std.mem.writeInt(u64, act[0..8], 0xBEEF, .little);
    try testing.expect(fakeCopyOut(act_va, &act));
    try testing.expectEqual(@as(u64, 0), sysRtSigaction(ops, 10, act_va, old_va, 8));
    var ob: [32]u8 = undefined;
    try testing.expect(fakeCopyIn(&ob, old_va));
    try testing.expectEqual(@as(u64, 0xDEAD), std.mem.readInt(u64, ob[0..8], .little));

    // SIGKILL(9)/SIGSTOP(19) → EINVAL; sig=0/65 → EINVAL
    try testing.expectEqual(err(EINVAL), sysRtSigaction(ops, 9, act_va, 0, 8));
    try testing.expectEqual(err(EINVAL), sysRtSigaction(ops, 0, act_va, 0, 8));

    // sigprocmask: SETMASK 0xFF → old 0; QUERY возвращает 0xFF
    const set_va = putStr(e, 0x40, "\xFF\x00\x00\x00\x00\x00\x00\x00");
    const oldm_va = FakeEnv.USER_BASE + 0x140;
    try testing.expectEqual(@as(u64, 0), sysRtSigprocmask(ops, 2, set_va, oldm_va, 8));
    var mb: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&mb, oldm_va));
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, &mb, .little));
    try testing.expectEqual(@as(u64, 0xFF), g_sig_mask);
}

test "linux: prctl — CAPBSET_READ→0; madvise; getcwd; fstatfs" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN=21) → 0 (нет cap)
    try testing.expectEqual(@as(u64, 0), sysPrctl(ops, PR_CAPBSET_READ, 21, 0, 0, 0));
    try testing.expectEqual(err(EINVAL), sysPrctl(ops, PR_CAPBSET_READ, 64, 0, 0, 0));
    // madvise: корректный VA → 0
    const buf = FakeEnv.USER_BASE;
    try testing.expectEqual(@as(u64, 0), sysMadvise(ops, buf, 16, 3));
    try testing.expectEqual(err(EFAULT), sysMadvise(ops, 0x10_0000, 16, 3));
    // getcwd: «/» + NUL = 2 байта
    const cwd_va = FakeEnv.USER_BASE + 0x80;
    try testing.expectEqual(@as(u64, 2), sysGetcwd(ops, cwd_va, 64));
    var cb: [4]u8 = undefined;
    try testing.expect(fakeCopyIn(&cb, cwd_va));
    try testing.expectEqual(@as(u8, '/'), cb[0]);
    try testing.expectEqual(@as(u8, 0), cb[1]);
    try testing.expectEqual(err(ERANGE), sysGetcwd(ops, cwd_va, 1));
    // fstatfs: 120Б, f_bsize=4096
    const p_fb = putStr(e, 0, "/dev/fb0");
    const fb = sysOpenat(ops, &fds, AT_FDCWD, p_fb, 0, 0);
    const stfs_va = FakeEnv.USER_BASE + 0x100;
    try testing.expectEqual(@as(u64, 0), sysFstatfs(ops, &fds, @intCast(fb), stfs_va));
    var sb: [120]u8 = undefined;
    try testing.expect(fakeCopyIn(&sb, stfs_va));
    try testing.expectEqual(@as(u64, 4096), std.mem.readInt(u64, sb[8..16], .little));
}

test "linux: timerfd — create/arm/read-цикл; memfd — anon RW-файл" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // timerfd: create + arm (kernel-VA 16Б) + read (fake: value>0 → счётчик
    // вручную — проверяем контракт read)
    const fd = sysTimerfdCreate(ops, &fds, 1, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.timerfd, fds.entries[3].kind);
    // arm через settime: new_itimerspec {value=5мс, interval=0} (fake: взвод)
    var it: [16]u8 = .{0} ** 16;
    std.mem.writeInt(u64, it[0..8], 5_000_000, .little);
    const it_va = FakeEnv.USER_BASE + 0x60;
    try testing.expect(fakeCopyOut(it_va, &it));
    try testing.expectEqual(@as(u64, 0), sysTimerfdSettime(ops, &fds, 3, 0, it_va, 0));
    // чтение до экспирации → EAGAIN (fake-время не тикает)
    const out_va = FakeEnv.USER_BASE + 0x300;
    try testing.expectEqual(err(EAGAIN), sysRead(ops, &fds, 3, out_va, 8));
    // ABSTIME-флаг → ENOTSUP
    try testing.expectEqual(err(ENOTSUP), sysTimerfdSettime(ops, &fds, 3, 1, it_va, 0));

    // memfd: anon tmpfs RW
    const mfd = sysMemfdCreate(ops, &fds, 0);
    try testing.expectEqual(@as(u64, 4), mfd);
    try testing.expectEqual(FdKind.tmpfs_file, fds.entries[4].kind);
    var fds2 = FdTable.init();
    _ = &fds2;
    const w = putStr(e, 0x40, "SHM-DATA");
    try testing.expectEqual(@as(u64, 8), sysWrite(ops, &fds, 4, w, 8));
    // чтение С 0: ВТОРОЕ открытие того же файла (offset=0) — как mmap-клиент
    const p_memfd = putStr(e, 0x20, "/tmp/.memfd");
    const mfd2 = sysOpenat(ops, &fds, AT_FDCWD, p_memfd, 0, 0);
    try testing.expect(mfd2 >= 5);
    const out2 = FakeEnv.USER_BASE + 0x310;
    try testing.expectEqual(@as(u64, 8), sysRead(ops, &fds, @intCast(mfd2), out2, 8));
    var rb: [8]u8 = undefined;
    try testing.expect(fakeCopyIn(&rb, out2));
    try testing.expectEqualStrings("SHM-DATA", rb[0..8]);
}

test "linux: ftruncate + MAP_SHARED — контракт Mesa lavapipe (memfd-хип)" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // 1. memfd → ftruncate(128) → блок выделен (os_create_anonymous_file)
    const mfd = sysMemfdCreate(ops, &fds, 0);
    try testing.expectEqual(@as(u64, 3), mfd);
    try testing.expectEqual(@as(u64, 0), sysFtruncate(ops, &fds, 3, 128));

    // 2. mmap MAP_SHARED — ОБЩИЕ страницы (lavapipe-heap / wl_shm-буферы)
    const va = sysMmap(ops, &fds, 0, 128, PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0);
    try testing.expectEqual(@as(u64, FakeEnv.USER_BASE + FakeEnv.USER_LEN), va);
    try testing.expectEqual(@as(u64, 1), e.shared_mmap_calls);
    try testing.expectEqual(@as(u64, 128), e.last_shared_len);
    try testing.expectEqual(PROT_READ | PROT_WRITE, e.last_shared_prot);

    // 3. края: БЕЗ ftruncate → ENOMEM; off не кратен странице → EINVAL;
    //    хвост за блоком → ENOMEM
    const mfd2 = sysMemfdCreate(ops, &fds, 0); // fd 4 — нет ftruncate
    try testing.expectEqual(@as(u64, 4), mfd2);
    try testing.expectEqual(err(ENOMEM), sysMmap(ops, &fds, 0, 128, PROT_READ | PROT_WRITE, MAP_SHARED, 4, 0));
    try testing.expectEqual(err(EINVAL), sysMmap(ops, &fds, 0, 64, PROT_READ | PROT_WRITE, MAP_SHARED, 3, 1));
    try testing.expectEqual(err(ENOMEM), sysMmap(ops, &fds, 0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0));

    // 4. initrd (RO) — не truncate-ится и не разделяется (ENODEV);
    //    дырявый fd → EBADF; сверх-блока → EFBIG
    const p_host = putStr(e, 0x20, "/etc/hostname");
    const hfd = sysOpenat(ops, &fds, AT_FDCWD, p_host, 0, 0);
    try testing.expect(hfd >= 0);
    try testing.expectEqual(err(EINVAL), sysFtruncate(ops, &fds, @intCast(hfd), 8));
    try testing.expectEqual(err(ENODEV), sysMmap(ops, &fds, 0, 8, PROT_READ, MAP_SHARED, @intCast(hfd), 0));
    try testing.expectEqual(err(EBADF), sysFtruncate(ops, &fds, 42, 8));
    try testing.expectEqual(err(EFBIG), sysFtruncate(ops, &fds, 3, 1 << 20));

    // 5. якорь номера: ftruncate = 77 (НЕ 46 — это i386-номер!); dispatch-
    //    маршрутизация; ftruncate(0) — размер снят → повторный shared-мап ENOMEM
    try testing.expectEqual(@as(u64, 77), SYS_ftruncate);
    try testing.expectEqual(@as(u64, 0), dispatch(ops, &fds, SYS_ftruncate, .{ .a1 = 3, .a2 = 0 }));
    try testing.expectEqual(err(ENOMEM), sysMmap(ops, &fds, 0, 128, PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0));

    // 6. close memfd → реестр освобождён (физблок — в ядре; fake: слот)
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 4));
    try testing.expectEqual(err(EBADF), sysFtruncate(ops, &fds, 4, 8));
}

test "linux: getdents64 — opendir /dev/dri (libdrm-скан drmGetDeviceFromDevId)" {
    const e = try envSetup();
    defer envTeardown(e);
    var fds = FdTable.init();
    const ops = fakeOps();

    // 1. open("/dev/dri") → dir-fd (fake: поток каталога)
    const p = putStr(e, 0x20, "/dev/dri");
    const fd = sysOpenat(ops, &fds, AT_FDCWD, p, 0, 0);
    try testing.expectEqual(@as(u64, 3), fd);
    try testing.expectEqual(FdKind.dir, fds.entries[3].kind);

    // 2. fstat dir-fd: S_ISDIR (glibc opendir ПРОВЕРЯЕТ — иначе lose!)
    const st_va = FakeEnv.USER_BASE + 0x400;
    try testing.expectEqual(@as(u64, 0), sysFstat(ops, &fds, 3, st_va));
    const stp = e.vaPtr(st_va).?;
    const mode = std.mem.readInt(u32, stp[24..28], .little);
    try testing.expectEqual(@as(u32, 0x4000 | 0x1ED), mode); // S_IFDIR|0755
    try testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, stp[16..24], .little)); // nlink

    // 3. getdents64: все 4 записи (".", "..", card0, renderD128)
    const buf_va = FakeEnv.USER_BASE + 0x500;
    const n = sysGetdents64(ops, &fds, 3, buf_va, 4096);
    try testing.expect(n > 0);
    var off: usize = 0;
    var names: [8][]const u8 = undefined;
    var dts: [8]u8 = .{0} ** 8;
    var nrec: usize = 0;
    while (off < @as(usize, @intCast(n))) {
        const base = e.vaPtr(buf_va).? + off;
        const reclen = std.mem.readInt(u16, base[16..18], .little);
        try testing.expect(reclen >= 24 and reclen % 8 == 0); // валидная запись
        names[nrec] = base[19..][0..@intCast(std.mem.indexOfScalar(u8, base[19..@intCast(off + reclen)], 0) orelse 0)];
        dts[nrec] = base[18];
        nrec += 1;
        off += reclen;
    }
    try testing.expectEqual(@as(usize, 4), nrec);
    try testing.expectEqualStrings("card0", names[2]);
    try testing.expectEqualStrings("renderD128", names[3]);
    try testing.expectEqual(DT_CHR, dts[2]);
    try testing.expectEqual(DT_CHR, dts[3]);
    try testing.expectEqual(DT_DIR, dts[0]); // "."
    try testing.expectEqual(@as(u64, 1), e.getdents_calls);

    // 4. EOF: повторный вызов → 0 (glibc readdir завершает цикл)
    try testing.expectEqual(@as(u64, 0), sysGetdents64(ops, &fds, 3, buf_va, 4096));

    // 5. края: не-dir fd → ENOTDIR; дырявый → EBADF; count=0 → 0
    try testing.expectEqual(err(ENOTDIR), sysGetdents64(ops, &fds, 0, buf_va, 64));
    try testing.expectEqual(err(EBADF), sysGetdents64(ops, &fds, 42, buf_va, 64));
    try testing.expectEqual(@as(u64, 0), sysGetdents64(ops, &fds, 3, buf_va, 0));

    // 6. read на каталоге → EISDIR; close освобождает поток
    try testing.expectEqual(err(EISDIR), sysRead(ops, &fds, 3, buf_va, 8));
    try testing.expectEqual(@as(u64, 0), sysClose(ops, &fds, 3));

    // 7. якорь номера: getdents64 = 217 (220 — старый getdents без d_type);
    //    dev-номера: libdrm-контракт makedev(226, 128)
    try testing.expectEqual(@as(u64, 217), SYS_getdents64);
    try testing.expectEqual(@as(u32, 128), devMinor("/dev/dri/renderD128"));
    try testing.expectEqual(@as(u32, 0), devMinor("/dev/dri/card0"));
    try testing.expectEqual(@as(u64, (226 << 8) | 128), encodeDev(DRM_MAJOR, 128));
    try testing.expectEqual(@as(u64, 226), devMajorOf(.dri_card0));
}

test "linux: ppoll/epoll_pwait — маршрутизация dispatch (якоря номеров)" {
    // сверка номеров с arch/x86/entry/syscalls/syscall_64.tbl
    try testing.expectEqual(@as(u64, 293), SYS_pipe2);
    try testing.expectEqual(@as(u64, 290), SYS_eventfd2);
    try testing.expectEqual(@as(u64, 289), SYS_signalfd4);
    try testing.expectEqual(@as(u64, 283), SYS_timerfd_create);
    try testing.expectEqual(@as(u64, 286), SYS_timerfd_settime);
    try testing.expectEqual(@as(u64, 281), SYS_epoll_pwait);
    try testing.expectEqual(@as(u64, 270), SYS_ppoll);
    try testing.expectEqual(@as(u64, 138), SYS_fstatfs);
    try testing.expectEqual(@as(u64, 79), SYS_getcwd);
    try testing.expectEqual(@as(u64, 157), SYS_prctl);
    try testing.expectEqual(@as(u64, 28), SYS_madvise);
    try testing.expectEqual(@as(u64, 13), SYS_rt_sigaction);
    try testing.expectEqual(@as(u64, 14), SYS_rt_sigprocmask);
    try testing.expectEqual(@as(u64, 53), SYS_socketpair);
    try testing.expectEqual(@as(u64, 319), SYS_memfd_create);
    try testing.expectEqual(@as(u64, 334), SYS_rseq);
}

test "linux: p3 — sched_getaffinity/sysinfo/mkdir (CPU-маска llvmpipe)" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // 1. sched_getaffinity: маска CPU0 (ядро — 1 CPU), len копируется
    const mask_va = FakeEnv.USER_BASE + 0x600;
    try testing.expectEqual(@as(u64, 128), sysSchedGetaffinity(ops, 0, 128, mask_va));
    const mp = e.vaPtr(mask_va).?;
    try testing.expectEqual(@as(u8, 1), mp[0]); // CPU 0
    try testing.expectEqual(@as(u8, 0), mp[1]);
    // края: len=0 → EINVAL; len>128 → EINVAL; мусорный указ → EFAULT
    try testing.expectEqual(err(EINVAL), sysSchedGetaffinity(ops, 0, 0, mask_va));
    try testing.expectEqual(err(EINVAL), sysSchedGetaffinity(ops, 0, 256, mask_va));
    try testing.expectEqual(err(EFAULT), sysSchedGetaffinity(ops, 0, 8, 0x0));

    // 2. sched_setaffinity: 0 (принято); валидация маски
    try testing.expectEqual(@as(u64, 0), sysSchedSetaffinity(ops, 0, 8, mask_va));
    try testing.expectEqual(err(EFAULT), sysSchedSetaffinity(ops, 0, 8, 0x0));

    // 3. sysinfo: 112Б, totalram 2ГБ, mem_unit=1
    const si_va = FakeEnv.USER_BASE + 0x700;
    try testing.expectEqual(@as(u64, 0), sysSysinfo(ops, si_va));
    const sp = e.vaPtr(si_va).?;
    try testing.expectEqual(@as(u64, 2 * 1024 * 1024 * 1024), std.mem.readInt(u64, sp[32..40], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, sp[100..104], .little));
    try testing.expectEqual(err(EFAULT), sysSysinfo(ops, 0x0));

    // 4. mkdir: RAM-пути принимаются, /usr — EPERM; мусорный VA → EFAULT
    const p_cache = putStr(e, 0x20, "/root/.cache/mesa_shader_cache");
    try testing.expectEqual(@as(u64, 0), sysMkdir(ops, p_cache, 0o755));
    try testing.expectEqual(@as(u64, 1), e.mkdir_calls);
    const p_usr = putStr(e, 0x120, "/usr/share/gamescope");
    try testing.expectEqual(err(EPERM), sysMkdir(ops, p_usr, 0o755));
    try testing.expectEqual(err(EFAULT), sysMkdir(ops, 0x0, 0o755));

    // 5. якоря: 203/204/99/83
    try testing.expectEqual(@as(u64, 203), SYS_sched_getaffinity);
    try testing.expectEqual(@as(u64, 204), SYS_sched_setaffinity);
    try testing.expectEqual(@as(u64, 99), SYS_sysinfo);
    try testing.expectEqual(@as(u64, 83), SYS_mkdir);
}
