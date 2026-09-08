// ============================================================================
// POLER-OS vfs.zig — виртуальная файловая система Live-режима (v0.19.0, CDD №10 p4)
// ============================================================================
//
// «Всё есть файл» + Live-USB overlay:
//   /dev/**   → devfs: устройства (fb0, dri/card0, input/event0,1) —
//               открытие через fd-слой linux_syscalls (kind-резолв);
//   /tmp/**   → tmpfs: ЗАПИСЬ В RAM (Live-режим: «запись в RAM, чтение с USB»);
//   остальное → initrd-RO (CPIO: пакеты CachyOS, конфиги) — чтение только.
//
// МОДЕЛЬ (Starnix-прецедент): tmpfs/нормализация/резолв — ЧИСТЫЕ (нативные
// тесты через VfsOps-инъекцию: heap-аллокатор + fake-initrd), платформенный
// доступ — за ops. Runtime (main64) подключает heap64 + cpio-архив.
//
// Live-USB СТРАТЕГИЯ (CDD №10): тяжёлый юзерспейс (Mesa/Gamescope/Wayland/
// Plasma) приезжает ГОТОВЫМ в initrd-CPIO/FAT32-USB (сборщик
// scripts/build-live-iso.sh); ядро предоставляет файловый фасад поверх.
// tmpfs — RW-слой: конфиги сессии, сокеты Wayland (/tmp/...), логи.
//
// Инвариант CDD №10: враждебные пути (пустые, мусорные имена, гигантские
// файлы) → VfsError/errno, НЕ паника ядра.
// ============================================================================

const std = @import("std");
const testing = std.testing;
const linux = @import("linux_syscalls.zig");

// ─── Ошибки VFS (→ errno в fd-слое) ────────────────────────────────────────

pub const VfsError = error{
    NotFound, // ENOENT
    ReadOnly, // EBADF/EACCES в зависимости от контекста
    NoSpace, // ENOSPC (лимит tmpfs)
    TooManyFiles, // ENFILE (лимит записей)
    NameTooLong, // ENAMETOOLONG
    BadPath, // EINVAL
    TooManyLinks, // ELOOP (цикл/глубина симлинков)
    NotASymlink, // EINVAL (readlink не на симлинке)
};

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const VfsOps = struct {
    /// Выделить n байт (heap) — backing tmpfs-файла. null = ENOSPC.
    alloc: *const fn (n: usize) ?[*]u8,
    /// Освободить (delete/перезапись).
    free: *const fn (ptr: [*]u8, n: usize) void,
    /// Поиск УЗЛА initrd-CPIO по одиночному ключу (БЕЗ алиасов/симлинков —
    /// их резолвит VFS). null = нет.
    initrd_find: *const fn (name: []const u8) ?InitrdNode,
};

/// Узел initrd: данные + режим (S_IFLNK — симлинк, data = цель).
pub const InitrdNode = struct {
    data: []const u8,
    /// режим CPIO-записи: 0o100644 файл, 0o120777 симлинк.
    mode: u32 = 0o100644,

    pub fn isSymlink(self: InitrdNode) bool {
        return self.mode & 0o170000 == 0o120000;
    }
};

// ─── Tmpfs: RAM-файлы Live-сессии ──────────────────────────────────────────

pub const MAX_NAME: usize = 96; // p14: mesa-кэш-пути длиннее 48Б
pub const MAX_TMP_FILES: usize = 256; // p14: wlserver+кэш+locks (32 мало!)
/// Бюджет tmpfs: 2МБ RAM (Live-сессия: конфиги, сокеты, логи — не медиа).
pub const MAX_TMP_TOTAL: usize = 16 * 1024 * 1024; // p14: кэш-записи
/// Максимальный размер одного файла (1МБ).
pub const MAX_TMP_FILE: usize = 1024 * 1024;

pub const TmpFile = struct {
    used: bool = false,
    name: [MAX_NAME]u8 = .{0} ** MAX_NAME,
    name_len: usize = 0,
    data: ?[]u8 = null,
    size: u64 = 0,

    pub fn nameSlice(self: *const TmpFile) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const TmpFs = struct {
    files: [MAX_TMP_FILES]TmpFile = [_]TmpFile{.{}} ** MAX_TMP_FILES,
    total: usize = 0, // занято байт (сумма cap)
    ops: VfsOps,

    /// Найти файл по имени.
    pub fn find(self: *TmpFs, name: []const u8) ?*TmpFile {
        if (name.len == 0 or name.len > MAX_NAME) return null;
        for (&self.files) |*f| {
            if (f.used and std.mem.eql(u8, f.nameSlice(), name)) return f;
        }
        return null;
    }

    /// Создать пустой файл (или вернуть существующий — open(O_CREAT)-стиль).
    pub fn create(self: *TmpFs, name: []const u8) VfsError!*TmpFile {
        if (name.len == 0 or name.len > MAX_NAME) return VfsError.NameTooLong;
        if (self.find(name)) |f| return f;
        for (&self.files) |*f| {
            if (f.used) continue;
            f.used = true;
            @memcpy(f.name[0..name.len], name);
            f.name_len = name.len;
            f.size = 0;
            f.data = null;
            return f;
        }
        return VfsError.TooManyFiles;
    }

    /// p14: освободить буфер данных файла (через ops.free аллокатора VFS).
    fn freeData(self: *TmpFs, d: []u8) void {
        self.ops.free(d.ptr, d.len);
    }

    /// p14: удалить файл tmpfs (unlink устаревших lock/socket-файлов
    /// wlserver'а). true = удалён, false = не найден.
    pub fn remove(self: *TmpFs, name: []const u8) bool {
        for (&self.files) |*f| {
            if (f.used and std.mem.eql(u8, f.nameSlice(), name)) {
                if (f.data) |d| self.freeData(d);
                f.* = .{};
                return true;
            }
        }
        return false;
    }

    /// Записать data по смещению off (расширение файла; O_APPEND-стиль —
    /// вызывающий ведёт offset). Возвращает записанное число байт.
    pub fn write(self: *TmpFs, f: *TmpFile, off: u64, data: []const u8) VfsError!usize {
        const end = off + data.len;
        if (end > MAX_TMP_FILE) return VfsError.NoSpace;
        // рост файла → перевыделение (простая модель: cap = max(need, growth))
        const need: usize = @intCast(end);
        const old_len: usize = if (f.data) |d| d.len else 0;
        if (f.data == null or old_len < need) {
            const cap = @max(need, @min(MAX_TMP_FILE, (old_len +| need + 255) & ~@as(usize, 255)));
            const buf = self.ops.alloc(cap) orelse return VfsError.NoSpace;
            if (f.data) |old| {
                @memcpy(buf[0..old.len], old);
                self.ops.free(old.ptr, old.len);
            }
            f.data = buf[0..cap];
        }
        @memcpy(f.data.?[off..end], data);
        if (end > f.size) f.size = end;
        return data.len;
    }

    /// Прочитать до out.len байт по смещению off. Возвращает прочитанное.
    pub fn read(self: *TmpFs, f: *TmpFile, off: u64, out: []u8) usize {
        _ = self;
        if (f.data == null) return 0;
        if (off >= f.size) return 0;
        const avail: usize = @intCast(f.size - off);
        const n = @min(out.len, avail);
        @memcpy(out[0..n], f.data.?[off..][0..n]);
        return n;
    }

    /// Удалить файл (free backing).
    pub fn delete(self: *TmpFs, name: []const u8) bool {
        const f = self.find(name) orelse return false;
        if (f.data) |d| {
            self.ops.free(d.ptr, d.len);
            self.total -|= d.len;
        }
        f.* = .{};
        return true;
    }

    /// Список файлов (имя + размер) — для ls Live-сессии.
    pub const Stat = struct { name: []const u8, size: u64 };

    pub fn statAll(self: *TmpFs, out: []Stat) usize {
        var n: usize = 0;
        for (&self.files) |*f| {
            if (n >= out.len) break;
            if (!f.used) continue;
            out[n] = .{ .name = f.nameSlice(), .size = f.size };
            n += 1;
        }
        return n;
    }
};

// ─── Нормализация путей (лексическая, без симлинков) ──────────────────────

/// Нормализовать путь: ведущий '/'+лексический резолв './' и '../',
/// схлопывание '//' и хвостовых '/'. Буфер out — результат (nul-free).
/// Возвращает срез нормализованного пути или null (путь «выпал» из корня).
pub fn normalizePath(path: []const u8, out: []u8) ?[]const u8 {
    if (path.len == 0 or path[0] != '/') return null;
    var len: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue; // «//» и хвостовой '/'
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            // откатываем последний сегмент
            while (len > 0 and out[len - 1] != '/') len -= 1;
            if (len > 0) len -= 1; // съесть '/'
            continue;
        }
        if (len + 1 + seg.len > out.len) return null; // BadPath (слишком длинно)
        out[len] = '/';
        len += 1;
        @memcpy(out[len .. len + seg.len], seg);
        len += seg.len;
    }
    // «/..» = «/» (Linux-семантика: кламп к корню, НЕ ошибка)
    if (len == 0) {
        out[0] = '/';
        return out[0..1];
    }
    return out[0..len];
}

// ─── usr-merge алиасы библиотечных путей (CDD #12 p1) ───────────────────

/// CachyOS/Arch-лэйаут (usr-merge): физически библиотеки лежат в /usr/lib;
/// /lib, /lib64, /usr/lib64 — симлинки на usr/lib. Вместо реальных
/// каталогов-симлинков ядро пробует ПСЕВДО-АЛИАСЫ ключей при промахе:
///   "lib/…"     → "usr/lib/…"
///   "lib64/…"   → "usr/lib/…"
///   "usr/lib64/…" → "usr/lib/…"
/// (порядок: сперва точный ключ — Debian-диалект "lib/x86_64-linux-gnu/…"
/// из dyn-elf-e2e продолжает работать как есть).
pub const MAX_ALIASES: usize = 4;
pub const ALIAS_SCRATCH: usize = 192;

pub fn libPathAliases(key: []const u8, out: *[MAX_ALIASES][]const u8, scratch: *[ALIAS_SCRATCH]u8) usize {
    var n: usize = 0;
    out[n] = key;
    n += 1;
    var used: usize = 0; // байтов scratch занято
    const prefixes = [_][]const u8{ "lib/", "lib64/", "usr/lib64/" };
    const plens = [_]usize{ 4, 6, 10 };
    for (prefixes, 0..) |pre, pi| {
        if (std.mem.startsWith(u8, key, pre)) {
            const tail = key[plens[pi]..];
            if (used + 8 + tail.len > scratch.len) continue;
            @memcpy(scratch[used..][0..8], "usr/lib/");
            @memcpy(scratch[used + 8 ..][0..tail.len], tail);
            out[n] = scratch[used ..][0 .. 8 + tail.len];
            n += 1;
            used += 8 + tail.len;
            break; // один ключ — один usr-merge вариант
        }
    }
    return n;
}

// ─── VFS: монтирование слоёв Live-режима ───────────────────────────────────

/// Узел результата резолва: чем является путь.
pub const NodeKind = enum {
    dev, // устройство devfs (kind в linux-слое)
    initrd_file, // файл initrd-CPIO (RO)
    tmpfs_file, // файл tmpfs (RW, RAM)
};

pub const Node = struct {
    kind: NodeKind,
    dev: linux.FdKind = .free, // для .dev
    tmp: ?*TmpFile = null, // для .tmpfs_file
    initrd_data: ?[]const u8 = null, // для .initrd_file
};

pub const Vfs = struct {
    tmp: TmpFs,
    ops: VfsOps,

    pub fn init(ops: VfsOps) Vfs {
        return .{ .tmp = .{ .ops = ops }, .ops = ops };
    }

    /// Резолв пути для ОТКРЫТИЯ: devfs → tmpfs → initrd (RO, симлинки
    /// разыменовываются — Linux-семантика open()).
    /// write=true: путь обязан лежать в tmpfs (Live-модель: запись в RAM).
    pub fn resolve(self: *Vfs, path: []const u8, write: bool) VfsError!Node {
        var buf: [128]u8 = undefined;
        const norm = normalizePath(path, &buf) orelse return VfsError.BadPath;
        return self.resolveNorm(norm, write, 0);
    }

    fn resolveNorm(self: *Vfs, norm: []const u8, write: bool, depth: u32) VfsError!Node {
        // /dev/** → devfs (устройства fd-слоя)
        if (std.mem.startsWith(u8, norm, "/dev/")) {
            const dev_path = norm[1..]; // "dev/fb0" — совместимо с linux-резолвом
            const kind = linux.resolveDevKind(norm) orelse linux.resolveDevKind(dev_path) orelse
                return VfsError.NotFound;
            return .{ .kind = .dev, .dev = kind };
        }

        // запись: ТОЛЬКО tmpfs (Live-модель «запись в RAM»)
        if (write) {
            if (!std.mem.startsWith(u8, norm, "/tmp")) return VfsError.ReadOnly;
            const name = norm[1..]; // "tmp/имя" — плоское tmpfs-пространство
            // CDD №12 p13: overlay-write БЕЗ тени: путь существует ТОЛЬКО в
            // initrd-слое → возвращаем RO-ноду (fstat/чтение/mmap-COW живут;
            // запись в RO — честный отказ). Тень в tmpfs создаётся только
            // для НОВЫХ путей (кэш-записи mesa поверх пустого tmpfs-слоя).
            // Эмпирика: open(index, O_RDWR|O_CREAT) создавал ПУСТУЮ тень,
            // затеняющую 2МБ-индекс → шейдер-кэш всегда мажет → TCG-медленная
            // перекомпиляция на каждом прогоне.
            if (self.tmp.find(name) == null) {
                if (self.resolveInitrd(norm, depth)) |node| return node
                else |_| {} // нет и в initrd → тень ниже
            }
            const f = try self.tmp.create(name);
            return .{ .kind = .tmpfs_file, .tmp = f };
        }

        // чтение: tmpfs-файл ЕСТЬ? → он (overlay: RAM поверх initrd)
        {
            const name = norm[1..];
            if (self.tmp.find(name)) |f| return .{ .kind = .tmpfs_file, .tmp = f };
        }
        // затем initrd (RO) — с usr-merge алиасами и симлинками
        return self.resolveInitrd(norm, depth);
    }

    /// initrd-резолв: точный ключ → usr-merge алиасы; симлинк → пересчёт
    /// пути (абсолютная цель или относительная к каталогу ссылки).
    fn resolveInitrd(self: *Vfs, norm: []const u8, depth: u32) VfsError!Node {
        var aliases: [MAX_ALIASES][]const u8 = undefined;
        var scratch: [ALIAS_SCRATCH]u8 = undefined;
        const key = norm[1..]; // без ведущего '/'
        const n = libPathAliases(key, &aliases, &scratch);
        for (aliases[0..n]) |cand| {
            const node = self.ops.initrd_find(cand) orelse continue;
            if (!node.isSymlink()) {
                return .{ .kind = .initrd_file, .initrd_data = node.data };
            }
            // симлинк: data = цель. Глубина — защита от циклов (ELOOP).
            if (depth >= MAX_SYMLINK_DEPTH) return VfsError.TooManyLinks;
            const target = node.data;
            var tbuf: [128]u8 = undefined;
            var joined: []const u8 = undefined;
            if (target.len > 0 and target[0] == '/') {
                joined = normalizePath(target, &tbuf) orelse
                    return VfsError.BadPath;
            } else {
                // относительная цель: join(каталог(cand), target) — норм
                // ждёт АБСОЛЮТНЫЙ путь → ведущий '/'
                const dir = dirnameOf(cand);
                var jbuf: [160]u8 = undefined;
                const full = std.fmt.bufPrint(&jbuf, "/{s}/{s}", .{ dir, target }) catch
                    return VfsError.NameTooLong;
                joined = normalizePath(full, &tbuf) orelse return VfsError.BadPath;
            }
            // только файлы (не /dev и не tmpfs-запись) в симлинк-цепи
            return self.resolveNorm(joined, false, depth + 1);
        }
        return VfsError.NotFound;
    }

    /// readlink(2): цель симлинка БЕЗ разыменования. NotFound — пути нет;
    /// NotASymlink — путь есть, но не симлинк (→ EINVAL).
    pub fn readlink(self: *Vfs, path: []const u8) VfsError![]const u8 {
        var buf: [128]u8 = undefined;
        const norm = normalizePath(path, &buf) orelse return VfsError.BadPath;
        if (std.mem.startsWith(u8, norm, "/dev/")) return VfsError.NotASymlink;
        // tmpfs-файл симлинком быть не может (flat-модель)
        if (self.tmp.find(norm[1..]) != null) return VfsError.NotASymlink;
        var aliases: [MAX_ALIASES][]const u8 = undefined;
        var scratch: [ALIAS_SCRATCH]u8 = undefined;
        const key = norm[1..];
        const n = libPathAliases(key, &aliases, &scratch);
        for (aliases[0..n]) |cand| {
            const node = self.ops.initrd_find(cand) orelse continue;
            if (node.isSymlink()) return node.data;
            return VfsError.NotASymlink;
        }
        return VfsError.NotFound;
    }

    /// Список tmpfs-файлов (ls /tmp).
    pub fn listTmp(self: *Vfs, out: []TmpFs.Stat) usize {
        return self.tmp.statAll(out);
    }
};

/// Максимальная глубина симлинк-цепи (Linux: 40; для rootfs хватает 8).
pub const MAX_SYMLINK_DEPTH: u32 = 8;

/// Каталог пути "usr/lib/libX.so" → "usr/lib" (без '/' на конце).
fn dirnameOf(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| {
        return path[0..i];
    }
    return "";
}

// ============================================================================
//  Нативные тесты
// ============================================================================

/// Fake-окружение: heap-аллокатор + initrd-файлы в тестовой памяти.
const FakeVfs = struct {
    mem: []u8,
    allocs: usize = 0,
    frees: usize = 0,

    fn init() !FakeVfs {
        return .{ .mem = try testing.allocator.alloc(u8, 256 * 1024) };
    }
    fn deinit(self: *FakeVfs) void {
        testing.allocator.free(self.mem);
    }
};

var g_vfs_env: ?*FakeVfs = null;
/// fake initrd: файлы + симлинки (CDD #12 p1: rootfs CachyOS-лэйаут)
const InitrdEntry = struct { name: []const u8, mode: u32 };
const INITRD_ENTRIES = [_]InitrdEntry{
    .{ .name = "etc/hostname", .mode = 0o100644 },
    .{ .name = "usr/bin/gamescope", .mode = 0o100755 },
    .{ .name = "README.txt", .mode = 0o100644 },
    .{ .name = "usr/lib/libdrm.so.2.134.0", .mode = 0o100644 },
    .{ .name = "usr/lib/libdrm.so.2", .mode = 0o120777 },        // симлинк → файл
    .{ .name = "usr/lib/ld-linux-x86-64.so.2", .mode = 0o100755 },
    .{ .name = "lib64/ld-linux-x86-64.so.2", .mode = 0o120777 }, // абс. цель
    .{ .name = "usr/lib/libX11.so.6.4.0", .mode = 0o100644 },
    .{ .name = "usr/lib/libX11.so.6", .mode = 0o120777 },         // отн. цель
    .{ .name = "usr/lib/loop-a", .mode = 0o120777 },
};
const INITRD_CONTENT = "poler-live-content";

/// Цели симлинков (data в CPIO — целевая строка).
fn fakeInitrdTarget(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "usr/lib/libdrm.so.2")) return "libdrm.so.2.134.0";
    if (std.mem.eql(u8, name, "lib64/ld-linux-x86-64.so.2")) return "/usr/lib/ld-linux-x86-64.so.2";
    if (std.mem.eql(u8, name, "usr/lib/libX11.so.6")) return "libX11.so.6.4.0";
    if (std.mem.eql(u8, name, "usr/lib/loop-a")) return "loop-a"; // цикл!
    return "";
}

fn fakeAlloc(n: usize) ?[*]u8 {
    const e = g_vfs_env.?;
    e.allocs += 1;
    if (n > e.mem.len) return null;
    return e.mem.ptr;
}
fn fakeFree(ptr: [*]u8, n: usize) void {
    _ = ptr;
    _ = n;
    g_vfs_env.?.frees += 1;
}
fn fakeInitrdFind(name: []const u8) ?InitrdNode {
    for (INITRD_ENTRIES) |e| {
        if (std.mem.eql(u8, e.name, name)) {
            if (e.mode & 0o170000 == 0o120000) {
                return .{ .data = fakeInitrdTarget(e.name), .mode = e.mode };
            }
            return .{ .data = INITRD_CONTENT, .mode = e.mode };
        }
    }
    return null;
}

fn vfsSetup() !*FakeVfs {
    const e = try testing.allocator.create(FakeVfs);
    e.* = try FakeVfs.init();
    g_vfs_env = e;
    return e;
}
fn vfsTeardown(e: *FakeVfs) void {
    g_vfs_env = null;
    e.deinit();
    testing.allocator.destroy(e);
}
fn vfsOps() VfsOps {
    return .{ .alloc = fakeAlloc, .free = fakeFree, .initrd_find = fakeInitrdFind };
}

// ─── Тесты: нормализация путей ─────────────────────────────────────────────

test "vfs: normalizePath — '//', './', '../', хвостовые слэши" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("/usr/bin", normalizePath("/usr/bin", &buf).?);
    try testing.expectEqualStrings("/usr/bin", normalizePath("//usr//bin/", &buf).?);
    try testing.expectEqualStrings("/usr/bin", normalizePath("/usr/./bin", &buf).?);
    try testing.expectEqualStrings("/usr", normalizePath("/usr/bin/../", &buf).?);
    try testing.expectEqualStrings("/etc", normalizePath("/usr/../etc/./x/../", &buf).?);
    // «/..» = «/» — кламп к корню (Linux-семантика), НЕ ошибка
    try testing.expectEqualStrings("/", normalizePath("/../..", &buf).?);
    try testing.expectEqualStrings("/", normalizePath("/", &buf).?);
    // относительный путь → null (ядро ждёт абсолютные)
    try testing.expect(normalizePath("usr/bin", &buf) == null);
    try testing.expect(normalizePath("", &buf) == null);
}

// ─── Тесты: tmpfs CRUD ─────────────────────────────────────────────────────

test "vfs: tmpfs — create/write/read roundtrip, размер, повторный open" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var fs = TmpFs{ .ops = vfsOps() };

    const f = try fs.create("tmp/hello.txt");
    try testing.expectEqual(@as(usize, 0), f.size);
    const wn = try fs.write(f, 0, "POLER");
    try testing.expectEqual(@as(usize, 5), wn);
    const wn2 = try fs.write(f, 5, "-LIVE");
    try testing.expectEqual(@as(usize, 5), wn2);
    try testing.expectEqual(@as(u64, 10), f.size);

    var out: [16]u8 = undefined;
    const rn = fs.read(f, 0, &out);
    try testing.expectEqual(@as(usize, 10), rn);
    try testing.expectEqualStrings("POLER-LIVE", out[0..10]);
    // частичное чтение с offset
    const rn2 = fs.read(f, 6, &out);
    try testing.expectEqual(@as(usize, 4), rn2);
    try testing.expectEqualStrings("LIVE", out[0..4]);
    // за концом → 0
    try testing.expectEqual(@as(usize, 0), fs.read(f, 10, &out));

    // повторный create того же имени → тот же файл (O_CREAT-стиль)
    const f2 = try fs.create("tmp/hello.txt");
    try testing.expectEqual(f, f2);
}

test "vfs: tmpfs — лимиты: ENFILE ×33, имя > 48 → ENAMETOOLONG" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var fs = TmpFs{ .ops = vfsOps() };

    var i: usize = 0;
    while (i < MAX_TMP_FILES) : (i += 1) {
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "tmp/f{d}", .{i}) catch unreachable;
        _ = try fs.create(name);
    }
    // 33-й → TooManyFiles
    try testing.expectError(VfsError.TooManyFiles, fs.create("tmp/overflow"));
    // длинное имя (p14: MAX_NAME=96 → тестовое имя удлинено)
    const long = "tmp/" ++ "a" ** 100;
    try testing.expectError(VfsError.NameTooLong, fs.create(long));
    // find длинного → null (не паника)
    try testing.expect(fs.find(long) == null);
}

test "vfs: tmpfs — statAll + delete (free backing)" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var fs = TmpFs{ .ops = vfsOps() };

    const f = try fs.create("tmp/session.conf");
    _ = try fs.write(f, 0, "seat0");
    const f2 = try fs.create("tmp/wayland-0.lock");
    _ = try fs.write(f2, 0, "wl");

    var stats: [8]TmpFs.Stat = undefined;
    const n = fs.statAll(&stats);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("tmp/session.conf", stats[0].name);
    try testing.expectEqual(@as(u64, 5), stats[0].size);
    try testing.expectEqual(@as(u64, 2), stats[1].size);

    try testing.expect(fs.delete("tmp/session.conf"));
    try testing.expect(!fs.delete("tmp/session.conf")); // повторно — нет
    try testing.expect(fs.find("tmp/session.conf") == null);
    const n2 = fs.statAll(&stats);
    try testing.expectEqual(@as(usize, 1), n2);
}

// ─── Тесты: VFS-резолв (overlay) ──────────────────────────────────────────

test "vfs: resolve — /dev → devfs; /tmp RW; initrd RO; overlay tmpfs-поверх" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // устройство
    const d = try v.resolve("/dev/fb0", false);
    try testing.expectEqual(NodeKind.dev, d.kind);
    try testing.expectEqual(linux.FdKind.fb0, d.dev);
    const d2 = try v.resolve("/dev/input/event0", false);
    try testing.expectEqual(linux.FdKind.input_event0, d2.dev);

    // initrd-файл (RO)
    const r = try v.resolve("/etc/hostname", false);
    try testing.expectEqual(NodeKind.initrd_file, r.kind);
    try testing.expectEqualStrings(INITRD_CONTENT, r.initrd_data.?);
    try testing.expectEqualStrings(INITRD_CONTENT, (try v.resolve("/usr/bin/gamescope", false)).initrd_data.?);

    // initrd-файла нет
    try testing.expectError(VfsError.NotFound, v.resolve("/etc/passwd", false));

    // запись в initrd-зону → ReadOnly (Live-модель: запись ТОЛЬКО в RAM)
    try testing.expectError(VfsError.ReadOnly, v.resolve("/etc/hostname", true));
    try testing.expectError(VfsError.ReadOnly, v.resolve("/usr/bin/gamescope", true));

    // запись в /tmp → tmpfs
    const w = try v.resolve("/tmp/session.conf", true);
    try testing.expectEqual(NodeKind.tmpfs_file, w.kind);
    _ = try v.tmp.write(w.tmp.?, 0, "rw");
    // теперь ЧТЕНИЕ того же пути → tmpfs (overlay поверх несуществующего)
    const r2 = try v.resolve("/tmp/session.conf", false);
    try testing.expectEqual(NodeKind.tmpfs_file, r2.kind);
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), v.tmp.read(r2.tmp.?, 0, &out));
    try testing.expectEqualStrings("rw", out[0..2]);

    // несуществующее устройство → NotFound
    try testing.expectError(VfsError.NotFound, v.resolve("/dev/fb9", false));
    // мусорный путь → BadPath
    try testing.expectError(VfsError.BadPath, v.resolve("no-slash", false));
}

test "vfs: Live-структура initrd — /dev /proc /sys /usr /tmp манифест" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // build-live-iso.sh кладёт в initrd LIVE-MANIFEST + структуру:
    // чтение манифеста через VFS (initrd-RO)
    const m = try v.resolve("/README.txt", false);
    try testing.expectEqual(NodeKind.initrd_file, m.kind);
}

// ─── Тесты CDD #12 p1: usr-merge алиасы + симлинки ─────────────────────────

test "vfs: libPathAliases — usr-merge: lib/… lib64/… usr/lib64/… → usr/lib/…" {
    var out: [MAX_ALIASES][]const u8 = undefined;
    var scratch: [ALIAS_SCRATCH]u8 = undefined;

    // lib/x86_64-linux-gnu/libc.so.6 (Debian-диалект dyn-elf): точный ключ
    // ПЕРВЫЙ (back-compat), алиас — «usr/lib/x86_64-linux-gnu/libc.so.6»
    var n = libPathAliases("lib/x86_64-linux-gnu/libc.so.6", &out, &scratch);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("lib/x86_64-linux-gnu/libc.so.6", out[0]);
    try testing.expectEqualStrings("usr/lib/x86_64-linux-gnu/libc.so.6", out[1]);

    // lib64/ld-linux…
    n = libPathAliases("lib64/ld-linux-x86-64.so.2", &out, &scratch);
    try testing.expectEqualStrings("usr/lib/ld-linux-x86-64.so.2", out[1]);

    // usr/lib64/libdrm.so.2
    n = libPathAliases("usr/lib64/libdrm.so.2", &out, &scratch);
    try testing.expectEqualStrings("usr/lib/libdrm.so.2", out[1]);

    // usr/lib/… — один кандидат (сам ключ; usr-merge уже на месте)
    n = libPathAliases("usr/lib/libdrm.so.2", &out, &scratch);
    try testing.expectEqual(@as(usize, 1), n);

    // не-библиотечный путь — один кандидат
    n = libPathAliases("etc/ld.so.cache", &out, &scratch);
    try testing.expectEqual(@as(usize, 1), n);
}

test "vfs: resolve — usr-merge: /lib/libdrm.so.2 находит usr/lib/…" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // /lib/libdrm.so.2 → точного «lib/…» нет → алиас «usr/lib/libdrm.so.2»
    // → симлинк → «libdrm.so.2.134.0» (относительная цель) → файл
    const r = try v.resolve("/lib/libdrm.so.2", false);
    try testing.expectEqual(NodeKind.initrd_file, r.kind);
    try testing.expectEqualStrings(INITRD_CONTENT, r.initrd_data.?);

    // /usr/lib64/libdrm.so.2 → алиас usr/lib → симлинк → файл
    const r2 = try v.resolve("/usr/lib64/libdrm.so.2", false);
    try testing.expectEqual(NodeKind.initrd_file, r2.kind);

    // прямой путь — работает как раньше
    const r3 = try v.resolve("/usr/lib/libX11.so.6", false);
    try testing.expectEqual(NodeKind.initrd_file, r3.kind);
}

test "vfs: resolve — симлинки: абсолютная цель (PT_INTERP /lib64/ld-linux…)" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // классика usr-merge: /lib64/ld-linux-x86-64.so.2 → симлинк с АБСОЛЮТНОЙ
    // целью /usr/lib/ld-linux-x86-64.so.2 → файл ld.so
    const r = try v.resolve("/lib64/ld-linux-x86-64.so.2", false);
    try testing.expectEqual(NodeKind.initrd_file, r.kind);
    try testing.expectEqualStrings(INITRD_CONTENT, r.initrd_data.?);
}

test "vfs: resolve — ELOOP на цикле симлинков" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // loop-a → loop-a → … (8 глубина) → TooManyLinks
    try testing.expectError(VfsError.TooManyLinks, v.resolve("/usr/lib/loop-a", false));
}

test "vfs: readlink — цель симлинка (абс/отн), NotASymlink, NotFound" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // readlink("/usr/lib/libX11.so.6") → относительная цель
    try testing.expectEqualStrings("libX11.so.6.4.0", try v.readlink("/usr/lib/libX11.so.6"));
    // readlink("/lib64/ld-linux-x86-64.so.2") — точный ключ-симлинк есть
    try testing.expectEqualStrings("/usr/lib/ld-linux-x86-64.so.2", try v.readlink("/lib64/ld-linux-x86-64.so.2"));

    // не симлинк → NotASymlink (→ EINVAL)
    try testing.expectError(VfsError.NotASymlink, v.readlink("/etc/hostname"));
    // нет пути → NotFound
    try testing.expectError(VfsError.NotFound, v.readlink("/usr/lib/libNOPE.so"));
}
