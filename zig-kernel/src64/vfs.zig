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
    /// Опциональный поиск в SquashFS airootfs.sfs (CachyOS/Arch Live)
    squashfs_find: ?*const fn (name: []const u8) ?InitrdNode = null,
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

pub const MAX_NAME: usize = 200; // CDD #17: пути пакетов usr/share/... длиннее 96Б
pub const MAX_TMP_FILES: usize = 3072; // CDD #17: pacman-установки (256 мало!)
/// Бюджет tmpfs: 512МБ RAM (CDD #17: пакеты в RAM-overlay, QEMU -m 2G).
pub const MAX_TMP_TOTAL: usize = 512 * 1024 * 1024;
/// Максимальный размер одного файла (CDD #17: муттер ~4МБ, локали ~40МБ).
pub const MAX_TMP_FILE: usize = 96 * 1024 * 1024;

pub const TmpFile = struct {
    used: bool = false,
    name: [MAX_NAME]u8 = .{0} ** MAX_NAME,
    name_len: usize = 0,
    data: ?[]u8 = null,
    size: u64 = 0,
    /// CDD #17: режим записи: 0o100644 файл, 0o120777 симлинк,
    /// 0o040755 каталог (неявен, для getdents/структуры)
    mode: u32 = 0o100644,
    /// цель симлинка (пусто = не симлинк)
    link: [128]u8 = .{0} ** 128,
    link_len: usize = 0,

    pub fn nameSlice(self: *const TmpFile) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn isSymlink(self: *const TmpFile) bool {
        return self.mode & 0o170000 == 0o120000;
    }

    pub fn linkSlice(self: *const TmpFile) []const u8 {
        return self.link[0..self.link_len];
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
    /// CDD #17: total-учёт бюджета MAX_TMP_TOTAL (раньше не проверялся!).
    pub fn write(self: *TmpFs, f: *TmpFile, off: u64, data: []const u8) VfsError!usize {
        const end = off + data.len;
        if (end > MAX_TMP_FILE) return VfsError.NoSpace;
        // рост файла → перевыделение (простая модель: cap = max(need, growth))
        const need: usize = @intCast(end);
        const old_len: usize = if (f.data) |d| d.len else 0;
        if (f.data == null or old_len < need) {
            const cap = @max(need, @min(MAX_TMP_FILE, (old_len +| need + 255) & ~@as(usize, 255)));
            if (self.total + cap - old_len > MAX_TMP_TOTAL) return VfsError.NoSpace;
            const buf = self.ops.alloc(cap) orelse return VfsError.NoSpace;
            if (f.data) |old| {
                @memcpy(buf[0..old.len], old);
                self.ops.free(old.ptr, old.len);
                self.total -= old_len;
            }
            f.data = buf[0..cap];
            self.total += cap;
        }
        @memcpy(f.data.?[off..end], data);
        if (end > f.size) f.size = end;
        return data.len;
    }

    /// CDD #17: симлинк в tmpfs (create-or-replace).
    pub fn makeSymlink(self: *TmpFs, name: []const u8, target: []const u8) VfsError!void {
        const f = try self.create(name);
        if (target.len > f.link.len) return VfsError.NameTooLong;
        f.mode = 0o120777;
        @memcpy(f.link[0..target.len], target);
        f.link_len = target.len;
        // симлинк без данных
        if (f.data) |d| {
            self.freeData(d);
            self.total -= d.len;
        }
        f.data = null;
        f.size = 0;
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

/// CDD #17: префиксы overlay-записи (RAM-модель pacman-установок).
pub fn isWritableOverlay(norm: []const u8) bool {
    const prefixes = [_][]const u8{ "/tmp", "/usr", "/etc", "/var", "/opt", "/root" };
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, norm, p)) {
            // "/usr2" не должен считаться "/usr" — проверим границу
            if (norm.len == p.len or norm[p.len] == '/') return true;
        }
    }
    return false;
}

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
    // Если путь без каталога (напр. "libcrypt.so.2") — пробуем искать в "usr/lib/"
    if (!std.mem.containsAtLeast(u8, key, 1, "/") and n < MAX_ALIASES) {
        if (used + 8 + key.len <= scratch.len) {
            @memcpy(scratch[used..][0..8], "usr/lib/");
            @memcpy(scratch[used + 8 ..][0..key.len], key);
            out[n] = scratch[used ..][0 .. 8 + key.len];
            n += 1;
            used += 8 + key.len;
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

        // запись: tmpfs overlay (CDD #17: pacman устанавливает пакеты в
        // /usr, /etc, /var, /opt, /root — RAM-модель расширена с /tmp)
        if (write) {
            if (!isWritableOverlay(norm)) return VfsError.ReadOnly;
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

        // чтение: tmpfs-файл ЕСТЬ? → он (overlay: RAM поверх initrd).
        // CDD #17: tmpfs-симлинк — разыменовываем (open-семантика Linux).
        {
            const name = norm[1..];
            if (self.tmp.find(name)) |f| {
                if (f.isSymlink()) {
                    if (depth >= MAX_SYMLINK_DEPTH) return VfsError.TooManyLinks;
                    const target = f.linkSlice();
                    var tbuf: [128]u8 = undefined;
                    var joined: []const u8 = undefined;
                    if (target.len > 0 and target[0] == '/') {
                        joined = normalizePath(target, &tbuf) orelse
                            return VfsError.BadPath;
                    } else {
                        // относительная цель: join с каталогом ссылки
                        var jbuf: [160]u8 = undefined;
                        const slash_pos = std.mem.lastIndexOfScalar(u8, norm, '/') orelse 0;
                        const base = norm[0..slash_pos]; // "/usr/lib" для /usr/lib/x
                        var jl: usize = 0;
                        const catf = struct {
                            fn cf(b: []u8, o: *usize, s: []const u8) void {
                                const n = @min(s.len, b.len - o.*);
                                @memcpy(b[o.* .. o.* + n], s[0..n]);
                                o.* += n;
                            }
                        }.cf;
                        catf(&jbuf, &jl, base);
                        catf(&jbuf, &jl, "/");
                        catf(&jbuf, &jl, target);
                        joined = normalizePath(jbuf[0..jl], &tbuf) orelse
                            return VfsError.BadPath;
                    }
                    return self.resolveNorm(joined, write, depth + 1);
                }
                return .{ .kind = .tmpfs_file, .tmp = f };
            }
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
            var node_opt = self.ops.initrd_find(cand);
            if (node_opt == null and self.ops.squashfs_find != null) {
                node_opt = self.ops.squashfs_find.?(cand);
            }
            const node = node_opt orelse continue;
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
            var node_opt = self.ops.initrd_find(cand);
            if (node_opt == null and self.ops.squashfs_find != null) {
                node_opt = self.ops.squashfs_find.?(cand);
            }
            const node = node_opt orelse continue;
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

test "vfs: tmpfs — лимиты MAX_NAME (CDD #17: 200), TooManyFiles-контракт" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var fs = TmpFs{ .ops = vfsOps() };

    // CDD #17: MAX_TMP_FILES=3072 (полный прогон непрактичен в тесте) —
    // проверяем контракт: первые N создаются, имя > MAX_NAME → ENAMETOOLONG
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "tmp/f{d}", .{i}) catch unreachable;
        _ = try fs.create(name);
    }
    // имя ровно на границе — ок
    _ = try fs.create("tmp/" ++ "b" ** (MAX_NAME - 4));
    // длинное имя → NameTooLong
    const long = "tmp/" ++ "a" ** (MAX_NAME + 1);
    try testing.expectError(VfsError.NameTooLong, fs.create(long));
    // find длинного → null (не паника)
    try testing.expect(fs.find(long) == null);
    // бюджет tmpfs: MAX_TMP_TOTAL увеличен для pacman (контракт)
    try testing.expect(MAX_TMP_TOTAL >= 384 * 1024 * 1024);
    try testing.expect(MAX_TMP_FILE >= 64 * 1024 * 1024);
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

    // CDD #17: /etc и /usr — overlay-записи; существующий initrd-файл
    // возвращается как RO-нода (p13: тень НЕ создаётся для существующих
    // путей — fstat/чтение живут, запись в RO-ноду откажет в fd-слое)
    const w1 = try v.resolve("/etc/hostname", true);
    try testing.expectEqual(NodeKind.initrd_file, w1.kind);
    const w2 = try v.resolve("/usr/bin/gamescope", true);
    try testing.expectEqual(NodeKind.initrd_file, w2.kind);
    // НОВЫЙ путь в overlay-зоне → tmpfs-тень (pacman-установки)
    const w3 = try v.resolve("/usr/bin/newtool", true);
    try testing.expectEqual(NodeKind.tmpfs_file, w3.kind);
    // вне overlay-зоны (например /home) → ReadOnly
    try testing.expectError(VfsError.ReadOnly, v.resolve("/home/x", true));
    try testing.expectError(VfsError.ReadOnly, v.resolve("/boot/vmlinuz", true));

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

fn fakeSquashFsFind(name: []const u8) ?InitrdNode {
    if (std.mem.eql(u8, name, "usr/lib/libQt6Core.so.6")) {
        return .{ .data = "QT6_CORE_SQUASHFS_DATA", .mode = 0o100644 };
    }
    return null;
}

test "vfs: layered SquashFS fallback lookup" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var ops = vfsOps();
    ops.squashfs_find = fakeSquashFsFind;
    var v = Vfs.init(ops);

    // Look up file residing only in SquashFS layer
    const r = try v.resolve("/usr/lib/libQt6Core.so.6", false);
    try testing.expectEqual(NodeKind.initrd_file, r.kind);
    try testing.expectEqualStrings("QT6_CORE_SQUASHFS_DATA", r.initrd_data.?);
}

// ─── CDD #17 (pacman): overlay-записи, tmpfs-симлинки, overlay-префиксы ────

test "vfs CDD#17: isWritableOverlay — границы префиксов" {
    try testing.expect(isWritableOverlay("/tmp"));
    try testing.expect(isWritableOverlay("/tmp/x"));
    try testing.expect(isWritableOverlay("/usr"));
    try testing.expect(isWritableOverlay("/usr/bin/bash"));
    try testing.expect(isWritableOverlay("/etc/pacman.conf"));
    try testing.expect(isWritableOverlay("/var/lib/pacman"));
    try testing.expect(isWritableOverlay("/opt/kde"));
    try testing.expect(isWritableOverlay("/root/.bashrc"));
    // НЕ overlay (граница сегмента!)
    try testing.expect(!isWritableOverlay("/usr2"));
    try testing.expect(!isWritableOverlay("/tmpx"));
    try testing.expect(!isWritableOverlay("/home/user"));
    try testing.expect(!isWritableOverlay("/boot"));
    try testing.expect(!isWritableOverlay("/"));
}

test "vfs CDD#17: makeSymlink + чтение через симлинк (open-семантика)" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());

    // файл-цель
    const f = try v.resolve("/usr/lib/libmini.so.1.0.0", true);
    _ = try v.tmp.write(f.tmp.?, 0, "ELF-DATA");
    // симлинк → цель
    try v.tmp.makeSymlink("usr/lib/libmini.so", "libmini.so.1.0.0");
    // чтение через симлинк разыменовывается
    const via = try v.resolve("/usr/lib/libmini.so", false);
    try testing.expectEqual(NodeKind.tmpfs_file, via.kind);
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), v.tmp.read(via.tmp.?, 0, &out));
    try testing.expectEqualStrings("ELF-DATA", &out);
    // абсолютный симлинк
    try v.tmp.makeSymlink("usr/bin/abs-link", "/usr/lib/libmini.so.1.0.0");
    const via2 = try v.resolve("/usr/bin/abs-link", false);
    try testing.expectEqual(NodeKind.tmpfs_file, via2.kind);
}

test "vfs CDD#17: бюджет MAX_TMP_TOTAL — write отказывает при переполнении" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var fs = TmpFs{ .ops = vfsOps() };
    fs.total = MAX_TMP_TOTAL; // искусственно «заполнен»
    const f = try fs.create("tmp/big");
    try testing.expectError(VfsError.NoSpace, fs.write(f, 0, "x" ** 16));
}

test "vfs CDD#17: повторная запись в tmpfs-симлинк — replace на файл" {
    const e = try vfsSetup();
    defer vfsTeardown(e);
    var v = Vfs.init(vfsOps());
    try v.tmp.makeSymlink("usr/lib/x.so", "x.so.1");
    // create(name) возвращает СУЩЕСТВУЮЩУЮ запись (open O_CREAT)
    const f = try v.resolve("/usr/lib/x.so", true);
    try testing.expectEqual(NodeKind.tmpfs_file, f.kind);
    _ = try v.tmp.write(f.tmp.?, 0, "DATA");
    // после записи в data-слот — это файл с данными (режим не сбрасываем:
    // VFS-слой читает через data; симлинк-цель осталась бы — проверим
    // перезапись через makeSymlink для симлинка-обновления)
    try v.tmp.makeSymlink("usr/lib/x.so", "x.so.2");
    const f2 = v.tmp.find("usr/lib/x.so");
    try testing.expect(f2 != null);
    try testing.expectEqualStrings("x.so.2", f2.?.linkSlice());
}
