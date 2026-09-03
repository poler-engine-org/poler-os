// ============================================================================
// POLER-OS linux_syscalls.zig — фундамент Linux POSIX-слоя (v0.18.0, CDD №9)
// ============================================================================
//
// Модель Starnix: семантическое ядро syscall-таблицы ЧИСТОЕ (тестируется
// нативно через LinuxOps-инъекцию — прецедент LoaderOps/pe_loader.zig),
// платформенный доступ (валидация user-VA, копирование, fd-таблица,
// mmap, exit) — за ops-указателями. Ядро регистрирует реальный runtime
// из main64.zig (isr64.S: Linux-задачи идут RAX-ABI, Win32 — вектора #6/#7).
//
// Linux x86_64 ABI: номер syscall в RAX, аргументы RDI/RSI/RDX/R10/R8/R9,
// возврат в RAX; ошибки = -errno (маленькое отрицательное, u64-биткаст).
//
// Инвариант CDD №9: НИКАКОЙ враждебный ввод (мусорные VA/len/fd/flags)
// не должен приводить к kernel-panic — только к -errno.
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
pub const SYS_exit: u64 = 60;
pub const SYS_uname: u64 = 63;
pub const SYS_openat: u64 = 257;

// ─── errno (linux asm-generic/errno-base.h) ────────────────────────────────

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EBADF: i64 = 9;
pub const ENOMEM: i64 = 12;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;

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
    .release = utsField("0.18.0"),
    .version = utsField("POLER-OS CDD #9 Linux POSIX layer"),
    .machine = utsField("x86_64"),
    .domainname = utsField("(none)"),
};

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const LinuxOps = struct {
    /// Проверить user-диапазон [va, va+len) на доступ (want_write).
    /// Контракт зеркален win32_api.validateRange (постраничный walk PML4,
    /// canonical-потолок, @addWithOverflow — v0.18.0 hardening).
    validate: *const fn (va: u64, len: u64, want_write: bool) bool,
    /// Ядро → user: копия байтов (uname). false = EFAULT.
    copy_out: *const fn (dst_va: u64, src: []const u8) bool,
    /// User C-строка (openat path) → kernel slice, не длиннее max_len.
    /// null = плохой указатель / нет терминатора в границах.
    copy_in_str: *const fn (src_va: u64, max_len: u64) ?[]const u8,
    /// write(fd, va, count): возвращает записанное или -errno.
    fd_write: *const fn (fd: i64, va: u64, count: u64) i64,
    /// read(fd, va, count): возвращает прочитанное или -errno.
    fd_read: *const fn (fd: i64, va: u64, count: u64) i64,
    /// openat(dirfd, path, flags): fd или -errno. Путь уже валидирован.
    fd_openat: *const fn (dirfd: i64, path: []const u8, flags: u64) i64,
    /// mmap(hint, len, prot, flags): размещённый VA или -errno.
    do_mmap: *const fn (hint: u64, len: u64, prot: u64, flags: u64) i64,
    /// exit(code): завершение задачи (ядро — kill; тесты — запись кода).
    do_exit: *const fn (code: u64) void,
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
pub fn sysWrite(ops: LinuxOps, fd_i: i64, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    // ядро ЧИТАЕТ user-буфер: want_write=false
    if (count > USER_VA_CEILING or !ops.validate(buf_va, count, false)) return err(EFAULT);
    const r = ops.fd_write(fd_i, buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// ssize_t read(fd, void *buf, size_t count)
pub fn sysRead(ops: LinuxOps, fd_i: i64, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    // ядро ПИШЕТ в user-буфер: want_write=true
    if (count > USER_VA_CEILING or !ops.validate(buf_va, count, true)) return err(EFAULT);
    const r = ops.fd_read(fd_i, buf_va, count);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// int openat(int dirfd, const char *pathname, int flags, mode_t mode)
pub fn sysOpenat(ops: LinuxOps, dirfd_i: i64, path_va: u64, flags: u64, mode: u64) u64 {
    _ = mode;
    // путь — C-строка: 1..4096 байт (PATH_MAX с запасом на терминатор)
    if (ops.validate(path_va, 1, false)) {
        if (ops.copy_in_str(path_va, 4096)) |path| {
            if (path.len == 0) return err(EINVAL);
            const r = ops.fd_openat(dirfd_i, path, flags);
            if (r < 0) return @bitCast(r);
            return @intCast(r);
        }
    }
    return err(EFAULT);
}

/// void *mmap(addr, length, prot, flags, fd, off)
pub fn sysMmap(ops: LinuxOps, hint: u64, length: u64, prot: u64, flags: u64) u64 {
    if (length == 0) return err(EINVAL);
    if (length > USER_VA_CEILING) return err(ENOMEM);
    // Поле MAP_FIXED с хинтом вне canonical user — немедленный отказ
    if (flags & MAP_FIXED != 0) {
        if (hint > USER_VA_CEILING) return err(EINVAL);
    }
    // Фундамент v0.18.0 поддерживает ТОЛЬКО MAP_PRIVATE|MAP_ANONYMOUS:
    // файловый маппинг — v0.19+ (VFS-мост), SHARED-без-бэкинга — честный
    // отказ (POSIX: MAP_SHARED|MAP_ANONYMOUS = undefined behavior).
    if (flags & MAP_ANONYMOUS == 0) return err(EINVAL);
    if (flags & MAP_SHARED != 0) return err(EINVAL);
    const r = ops.do_mmap(hint, length, prot, flags);
    if (r < 0) return @bitCast(r);
    return @intCast(r);
}

/// int uname(struct utsname *buf)
pub fn sysUname(ops: LinuxOps, buf_va: u64) u64 {
    if (!ops.validate(buf_va, @sizeOf(Utsname), true)) return err(EFAULT);
    if (!ops.copy_out(buf_va, std.mem.asBytes(&default_uts))) return err(EFAULT);
    return 0;
}

/// void exit(int status) — noreturn по ABI; ядро убивает задачу.
pub fn sysExit(ops: LinuxOps, code: u64) u64 {
    ops.do_exit(code);
    return 0; // ядро сюда не вернётся (kill + spin в runtime-ops)
}

// ─── Диспетчер (syscall-таблица) ───────────────────────────────────────────

/// Главная точка входа Linux POSIX-слоя: num — RAX, args — RDI/RSI/RDX/R10/R8.
/// Неизвестный номер → -ENOSYS. Возвращает RAX-значение.
pub fn dispatch(ops: LinuxOps, num: u64, args: Args) u64 {
    switch (num) {
        SYS_read => return sysRead(ops, @bitCast(args.a1), args.a2, args.a3),
        SYS_write => return sysWrite(ops, @bitCast(args.a1), args.a2, args.a3),
        SYS_open => {
            // open(path, flags, mode) — легаси-синоним openat(AT_FDCWD, …)
            return sysOpenat(ops, AT_FDCWD, args.a1, args.a2, args.a3);
        },
        SYS_openat => return sysOpenat(ops, @bitCast(args.a1), args.a2, args.a3, args.a4),
        SYS_mmap => return sysMmap(ops, args.a1, args.a2, args.a3, args.a4),
        SYS_exit => return sysExit(ops, args.a1),
        SYS_uname => return sysUname(ops, args.a1),
        else => return err(ENOSYS),
    }
}

// ============================================================================
//  Нативные тесты (linux x86_64 gnu — Zig test runner)
// ============================================================================

/// Фейковое user-пространство: буфер 16КБ по VA 0x20000_0000 (выше 4ГБ —
/// как реальные PE/ELF-образы POLER-OS), fd-таблица, mmap-бамп.
const FakeEnv = struct {
    const USER_BASE: u64 = 0x20000_0000;
    const USER_LEN: u64 = 16 * 1024;

    mem: []u8,
    write_calls: u64 = 0,
    write_bytes: u64 = 0,
    read_calls: u64 = 0,
    exit_code: ?u64 = null,
    mmap_calls: u64 = 0,
    last_mmap_len: u64 = 0,
    open_path: ?[]const u8 = null,
    /// fd-таблица: 0/1/2 открыты (stdin/stdout/stderr), 42 закрыт.
    open_fds: [8]i64 = .{ 0, 1, 2, -1, -1, -1, -1, -1 },
    mmap_cursor: u64 = USER_BASE + USER_LEN, // mmap поверх fake-региона

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
    const p = g_env.?.vaPtr(dst_va) orelse return false;
    const end = @addWithOverflow(dst_va, src.len);
    if (end[1] != 0) return false;
    if (!FakeEnv.vaOk(dst_va, src.len, true)) return false;
    @memcpy(p[0..src.len], src);
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
fn fakeFdWrite(fd: i64, va: u64, count: u64) i64 {
    const e = g_env.?;
    if (!e.fdOpen(fd)) return -EBADF;
    e.write_calls += 1;
    e.write_bytes += count;
    _ = va;
    return @intCast(count);
}
fn fakeFdRead(fd: i64, va: u64, count: u64) i64 {
    const e = g_env.?;
    if (!e.fdOpen(fd)) return -EBADF;
    e.read_calls += 1;
    _ = va;
    return @intCast(count);
}
fn fakeFdOpenat(dirfd: i64, path: []const u8, flags: u64) i64 {
    _ = dirfd;
    _ = flags;
    const e = g_env.?;
    e.open_path = path;
    if (std.mem.eql(u8, path, "/etc/hostname")) return 7; // «существует»
    return -ENOENT;
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
fn fakeDoExit(code: u64) void {
    g_env.?.exit_code = code;
}

fn fakeOps() LinuxOps {
    return .{
        .validate = fakeValidate,
        .copy_out = fakeCopyOut,
        .copy_in_str = fakeCopyInStr,
        .fd_write = fakeFdWrite,
        .fd_read = fakeFdRead,
        .fd_openat = fakeFdOpenat,
        .do_mmap = fakeDoMmap,
        .do_exit = fakeDoExit,
    };
}

fn envSetup() !*FakeEnv {
    const e = try testing.allocator.create(FakeEnv);
    e.* = try FakeEnv.init();
    g_env = e;
    return e;
}
fn envTeardown(e: *FakeEnv) void {
    g_env = null;
    e.deinit();
    testing.allocator.destroy(e);
}

// ─── Тесты ─────────────────────────────────────────────────────────────────

test "linux: syscall-числа x86_64 — ABI-контракты таблицы" {
    try testing.expectEqual(@as(u64, 0), SYS_read);
    try testing.expectEqual(@as(u64, 1), SYS_write);
    try testing.expectEqual(@as(u64, 9), SYS_mmap);
    try testing.expectEqual(@as(u64, 60), SYS_exit);
    try testing.expectEqual(@as(u64, 63), SYS_uname);
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
    const ops = fakeOps();

    // write(1, valid, 16) → обработчик write вызван
    const buf = FakeEnv.USER_BASE;
    @memset(e.mem, 0); // детерминированные строки ниже
    const r = dispatch(ops, SYS_write, .{ .a1 = 1, .a2 = buf, .a3 = 16 });
    try testing.expectEqual(@as(u64, 16), r);
    try testing.expectEqual(@as(u64, 1), e.write_calls);

    // exit(3) → do_exit вызван с кодом
    _ = dispatch(ops, SYS_exit, .{ .a1 = 3 });
    try testing.expectEqual(@as(u64, 3), e.exit_code.?);

    // open(path, 0) — легаси-синоним openat(AT_FDCWD): детерминированный путь
    const p = e.vaPtr(buf).?;
    @memcpy(p[0..2], "/x");
    p[2] = 0;
    _ = dispatch(ops, SYS_open, .{ .a1 = buf, .a2 = 0 });
    try testing.expectEqualStrings("/x", e.open_path.?);

    // неизвестный номер → -ENOSYS
    try testing.expectEqual(err(ENOSYS), dispatch(ops, 999, .{}));
    try testing.expectEqual(err(ENOSYS), dispatch(ops, 0xDEAD, .{}));
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
    try testing.expectEqualStrings("0.18.0", uts.release[0..std.mem.indexOfScalar(u8, &uts.release, 0).?]);
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
    const ops = fakeOps();
    const buf = FakeEnv.USER_BASE;

    try testing.expectEqual(@as(u64, 32), sysWrite(ops, 1, buf, 32)); // stdout
    try testing.expectEqual(@as(u64, 32), sysWrite(ops, 2, buf, 32)); // stderr
    try testing.expectEqual(@as(u64, 0), sysWrite(ops, 1, buf, 0)); // count=0 — Linux-семантика
    try testing.expectEqual(@as(u64, 2), e.write_calls);
    try testing.expectEqual(@as(u64, 64), e.write_bytes);

    // fd=42 закрыт
    try testing.expectEqual(err(EBADF), sysWrite(ops, 42, buf, 8));
    // fd=-1
    try testing.expectEqual(err(EBADF), sysWrite(ops, -1, buf, 8));
}

test "linux: sys_write — враждебный буфер → -EFAULT (ядро читает user)" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // NULL-страница
    try testing.expectEqual(err(EFAULT), sysWrite(ops, 1, 0x0, 16));
    // kernel-VA
    try testing.expectEqual(err(EFAULT), sysWrite(ops, 1, 0xFFFF_8888_0000_0000, 16));
    // va+len перенос u64 — отказ ДО walk (hardening v0.18.0)
    try testing.expectEqual(err(EFAULT), sysWrite(ops, 1, 0xFFFF_FFFF_FFFF_FFF0, 32));
    // count не лезет в canonical user
    try testing.expectEqual(err(EFAULT), sysWrite(ops, 1, FakeEnv.USER_BASE, 0x8000_0000_0000_0000));
    // заход за границу fake-региона
    try testing.expectEqual(err(EFAULT), sysWrite(ops, 1, FakeEnv.USER_BASE + FakeEnv.USER_LEN - 4, 16));
    try testing.expectEqual(@as(u64, 0), e.write_calls); // ops не дергались
}

test "linux: sys_read — счёт; буфер только на запись (want_write)" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();
    const buf = FakeEnv.USER_BASE;

    try testing.expectEqual(@as(u64, 64), sysRead(ops, 0, buf, 64)); // stdin
    try testing.expectEqual(@as(u64, 1), e.read_calls);
    // закрытый fd
    try testing.expectEqual(err(EBADF), sysRead(ops, 5, buf, 8));
    // буфер ядру НЕ принадлежит → EFAULT (проверка want_write=true)
    try testing.expectEqual(err(EFAULT), sysRead(ops, 0, 0x30000_0000, 8));
}

test "linux: sys_openat — AT_FDCWD, путь существует/нет; пустой путь → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    // Кладём путь "/etc/hostname" в fake-user (13 символов + терминатор)
    const path_va = FakeEnv.USER_BASE;
    const p = e.vaPtr(path_va).?;
    @memcpy(p[0..13], "/etc/hostname");
    p[13] = 0;

    try testing.expectEqual(@as(u64, 7), sysOpenat(ops, AT_FDCWD, path_va, 0, 0));
    try testing.expectEqualStrings("/etc/hostname", e.open_path.?);

    // Несуществующий путь (12 символов + терминатор)
    @memcpy(p[0..12], "/no/such/dir");
    p[12] = 0;
    try testing.expectEqual(err(ENOENT), sysOpenat(ops, AT_FDCWD, path_va, 0, 0));

    // Пустой путь (сразу терминатор) → -EINVAL
    p[0] = 0;
    try testing.expectEqual(err(EINVAL), sysOpenat(ops, AT_FDCWD, path_va, 0, 0));
}

test "linux: sys_openat — битые указатели пути → -EFAULT без паник" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();
    // Весь регион — не-нулевые байты: терминатора в 4096 точно нет
    @memset(e.mem, 'A');

    try testing.expectEqual(err(EFAULT), sysOpenat(ops, AT_FDCWD, 0, 0, 0)); // NULL
    try testing.expectEqual(err(EFAULT), sysOpenat(ops, AT_FDCWD, 0xFFFF_9000_0000_0000, 0, 0)); // kernel
    // путь без терминатора в 4096 → EFAULT (copy_in_str → null)
    try testing.expectEqual(err(EFAULT), sysOpenat(ops, AT_FDCWD, FakeEnv.USER_BASE, 0, 0));
}

test "linux: sys_mmap — length=0 → -EINVAL; не-ANONYMOUS → -EINVAL (фундамент)" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    try testing.expectEqual(err(EINVAL), sysMmap(ops, 0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS));
    // Файловый маппинг (без ANONYMOUS) — вне фундамента v0.18.0
    try testing.expectEqual(err(EINVAL), sysMmap(ops, 0, 4096, PROT_READ, MAP_PRIVATE));
    // SHARED|ANONYMOUS без бэкинга — тоже не поддержан фундаментом
    try testing.expectEqual(err(EINVAL), sysMmap(ops, 0, 4096, PROT_READ, MAP_SHARED | MAP_ANONYMOUS));
    try testing.expectEqual(@as(u64, 0), e.mmap_calls);
}

test "linux: sys_mmap — ANONYMOUS|PRIVATE размещение; MAP_FIXED вне user → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    const ops = fakeOps();

    const r = sysMmap(ops, 0, 0x1234, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    try testing.expect(r != err(EINVAL));
    try testing.expectEqual(@as(u64, 1), e.mmap_calls);
    try testing.expectEqual(@as(u64, 0x1234), e.last_mmap_len); // длина до ops как есть

    // MAP_FIXED с kernel-хинтом — отказ
    try testing.expectEqual(err(EINVAL), sysMmap(ops, 0xFFFF_8000_0000_0000, 4096, PROT_READ, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE));
    // length за canonical-потолок
    try testing.expectEqual(err(ENOMEM), sysMmap(ops, 0, USER_VA_CEILING + 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS));
}
