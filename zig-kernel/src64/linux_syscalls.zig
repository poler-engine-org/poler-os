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
pub const SYS_poll: u64 = 7;
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
pub const EINVAL: i64 = 22;
pub const ENOTTY: i64 = 25;
pub const EPIPE: i64 = 32;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ETIMEDOUT: i64 = 110;

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
pub const FUTEX_PRIVATE_FLAG: u64 = 128;

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
pub const MAX_EPOLL_EVENTS: usize = 64;

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
};

pub const MAX_FILE_ID: u32 = 16; // реестр открытых файлов runtime

/// Один наблюдаемый fd в epoll-инстансе.
pub const EpollWatch = struct {
    fd: i32 = -1,
    events: u32 = 0,
    data: u64 = 0,
};

pub const MAX_FDS: usize = 16;
pub const MAX_WATCHES: usize = 12;

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
    /// open_file: открыть файл VFS (initrd-RO/tmpfs-RW) по пути.
    /// Возвращает файл-id ≥ 0 или -errno; kind возвращает через out_kind.
    open_file: *const fn (path: []const u8, flags: u64, out_kind: *FdKind) i64,
    /// file_read: чтение файла по id+offset в user-VA (валидация уже
    /// сделана слоем). Возвращает байты или -errno.
    file_read: *const fn (id: u32, off: u64, va: u64, count: u64) i64,
    /// file_write: запись в файл (tmpfs) из user-VA.
    file_write: *const fn (id: u32, off: u64, va: u64, count: u64) i64,
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
    _ = ops;
    const e = fds.get(fd_i) orelse return err(EBADF);
    e.* = .{}; // освобождаем слот (epoll-наблюдения тоже)
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
    // Файловый/девайс-маппинг: fd обязан быть открыт и быть устройством
    const e = fds.get(fd_i) orelse return err(EBADF);
    switch (e.kind) {
        .fb0, .dri_card0 => {
            if (off % PAGE_SIZE != 0) return err(EINVAL); // offset кратен стр.
            const r = ops.dev_mmap(e.kind, off, length, prot);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        },
        else => return err(ENODEV), // event-файлы не мапятся (Linux: ENODEV)
    }
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
    const op = op_in & ~FUTEX_PRIVATE_FLAG; // приватность — атрибут, не операция
    // Слово фьютекса обязано читаться (WAIT) — валидация ДО разыменования
    if (!ops.validate(uaddr, 4, false)) return err(EFAULT);
    switch (op) {
        FUTEX_WAIT => {
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
        FUTEX_WAKE => {
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
            .initrd_file => rdy = POLLIN, // RO-файл: читаем
            .tmpfs_file => rdy = POLLIN | POLLOUT, // RAM-файл: RW
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
pub fn sysEpollWait(ops: LinuxOps, fds: *FdTable, epfd: i64, events_va: u64, maxevents: u64, timeout: i64) u64 {
    _ = timeout; // v0.19: неблокирующий опрос (см. sysPoll)
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
            .free => unreachable,
        }
        const combined = w.events & (rdy | EPOLLERR | EPOLLHUP);
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

/// void exit(int status) — noreturn по ABI; ядро убивает задачу.
pub fn sysExit(ops: LinuxOps, code: u64) u64 {
    ops.do_exit(code);
    return 0; // ядро сюда не вернётся (kill + spin в runtime-ops)
}

/// выравненного чтения НЕ нужно: std.mem.readInt на байтовых массивах не
/// требует выравнивания (packed epoll_event.data читается напрямую)

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
    park_calls: u64 = 0,
    wake_calls: u64 = 0,
    last_wake_n: u32 = 0,
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
    _ = hint;
    _ = prot;
    _ = flags;
    const e = g_env.?;
    e.mmap_calls += 1;
    e.last_mmap_len = len;
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
    name: [64]u8 = .{0} ** 64,
    name_len: usize = 0,
    data: [128]u8 = .{0} ** 128,
    size: usize = 0,
};
var g_files: [4]FakeFile = [_]FakeFile{.{}} ** 4;

fn fakeOpenFile(path: []const u8, flags: u64, out_kind: *FdKind) i64 {
    _ = flags;
    const e = g_env.?;
    e.open_path = path;
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
        .open_file = fakeOpenFile,
        .file_read = fakeFileRead,
        .file_write = fakeFileWrite,
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

fn envSetup() !*FakeEnv {
    const e = try testing.allocator.create(FakeEnv);
    e.* = try FakeEnv.init();
    @memset(e.mem, 0);
    g_env = e;
    g_files = [_]FakeFile{.{}} ** 4; // чистый реестр файлов на каждый тест
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

    // WAIT с ожидаемым 5 → паркинг (тест-модель: разбудили → 0)
    try testing.expectEqual(@as(u64, 0), sysFutex(ops, fva, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 5, 0));
    try testing.expectEqual(@as(u64, 1), e.park_calls);

    // WAIT с ожидаемым 4 (слово=5): значение изменилось → -EAGAIN
    try testing.expectEqual(err(EAGAIN), sysFutex(ops, fva, FUTEX_WAIT, 4, 0));
    try testing.expectEqual(@as(u64, 1), e.park_calls); // не доехал до паркинга

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

    // заполняем все слоты (3..15 = 13 открытий)
    var i: u64 = 0;
    while (i < 13) : (i += 1) {
        const r = sysOpenat(ops, &fds, AT_FDCWD, putStr(e, 0x100, "/dev/fb0"), 0, 0);
        try testing.expectEqual(@as(u64, 3 + i), r);
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
