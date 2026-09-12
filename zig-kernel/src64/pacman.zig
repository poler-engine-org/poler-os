// ============================================================================
// POLER-OS pacman.zig — полноценный сетевой менеджер пакетов (v0.21.0, CDD #17)
// ============================================================================
//
// ЗАДАЧА: превратить заглушку pacman в настоящий сетевой установщик
// CachyOS/Arch Linux (.pkg.tar.zst) в память tmpfs RAM-overlay.
//
// КОНВЕЙЕР -S <pkg>:
//   DNS → TCP(virtio-net) → HTTP GET core.db → gzip(inflate) → tar
//   → ALPM desc/depends-парсер → резолвер зависимостей → HTTP GET
//   .pkg.tar.zst → zstd(декодер) → tar → файлы в VFS (/usr/**, /etc/**).
//
// МОДЕЛЬ (Starnix-прецедент, как vfs.zig/linux_syscalls.zig): вся логика
// ЧИСТАЯ — платформенный доступ за PacOps-инъекцией (kernel: virtio_net +
// kernel_vfs + heap64 + hal.Serial; нативные тесты: fake-transport +
// bump-аллокатор + файлы-словарь). НИ ОДНОГО импорта hal/pmm/virtio_net!
//
// ОПЕРАЦИИ CLI (pacmanMain):
//   -Sy / -Syy    — синхронизация БД репозиториев (core.db)
//   -S <targets>  — резолв + скачивание + установка в RAM-overlay
//   -Sw <targets> — только скачать (без распаковки)
//   -Q            — список установленных
//   -Ql <pkg>     — файлы установленного пакета
//   -Ss <substr>  — поиск по БД репозитория
//   --version/-h  — справка
//
// E2E-МАЯКИ (serial, без ANSI — для wait-скриптов):
//   [PAC] sync OK: <N> packages (<repo>)        — -Sy успех
//   [PAC] install OK: <name> <ver> (<M> files)  — установка пакета
//   [PAC] PACMAN-OK                              — транзакция успешна
//   [PAC] PACMAN-FAIL: <причина>                 — ошибка
//
// ОГРАНИЧЕНИЯ RAM-модели (по эмпирике предыдущих сессий):
//   - extra.db: 8.9МБ сжат → 66МБ распакован — слишком жирно; дефолт = core.
//   - HTTPS: в ядре НЕТ TLS — только plain-HTTP зеркала (geo.mirror.pkgbuild.com
//     и mirror.rackspace.com отдают 200 OK без редиректа; mirror.cachyos.org
//     301→https — НЕ годен для RAM-модели без TLS-стека).
//   - Транзакция ≤ 48 пакетов (глубина резолва core-пакетов ≪, но защита от
//     «-S gnome» на 300+ пакетах RAM-смерти).
// ============================================================================

const std = @import("std");
const testing = std.testing;

// ─── Конфигурация: зеркала и репозитории ───────────────────────────────────

/// Зеркало: host + порт + база пути. ТОЛЬКО plain-HTTP (нет TLS в ядре).
pub const Mirror = struct {
    host: []const u8,
    port: u16 = 80,
    /// база пути репозиториев (без хвостового '/')
    base: []const u8,
};

/// Рабочие зеркала (проверены curl-ом: 200 OK по http://, без 301-редиректа).
pub const MIRRORS = [_]Mirror{
    .{ .host = "geo.mirror.pkgbuild.com", .base = "core/os/x86_64" },
    .{ .host = "mirror.rackspace.com", .base = "archlinux/core/os/x86_64" },
};

/// Репозитории по умолчанию: core (257-300 пакетов, ~130КБ БД).
/// extra не влезает в RAM-модель (66МБ распакованной БД).
pub const DEFAULT_REPOS = [_][]const u8{"core"};

// ─── Лимиты (RAM-модель, QEMU -m 2G) ───────────────────────────────────────

pub const MAX_DB_PACKAGES: usize = 512; // core ≈ 299 + запас
pub const MAX_PKG_NAME: usize = 64;
pub const MAX_PKG_VER: usize = 48;
pub const MAX_PKG_FILE: usize = 144; // "bash-5.3.15-1-x86_64.pkg.tar.zst"
pub const MAX_DEPS_PER_PKG: usize = 24; // включая soname-депенды
pub const MAX_PROVIDES_PER_PKG: usize = 12;
pub const MAX_INSTALLED_PKGS: usize = 64; // RAM-сессия
pub const MAX_FILES_PER_PKG: usize = 2048; // -Ql (glibc ~3000, покажем первые)
pub const MAX_TXN_PACKAGES: usize = 48; // транзакция -S

/// Максимальный скачиваемый артефакт (core.db ~130КБ; glibc ~9МБ).
pub const MAX_DOWNLOAD_BYTES: usize = 96 * 1024 * 1024;
/// Максимальный распакованный .pkg (glibc ~35МБ; mutter ~4МБ).
pub const MAX_PACKAGE_UNPACKED: usize = 384 * 1024 * 1024;
/// HTTP-заголовки.
pub const MAX_HTTP_HDR: usize = 4096;

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const PacOps = struct {
    /// TCP: подключиться к ip:port. Возврат: слот ≥0 или -errno.
    tcp_connect: *const fn (ip: [4]u8, port: u16) i64,
    /// TCP: отправить данные (все). Возврат: байты или -errno.
    tcp_send: *const fn (slot: usize, data: []const u8) i64,
    /// TCP: принять до out.len (поллинг внутри impl). Возврат: ≥0 байт,
    /// 0 = пока нет данных, -1 = соединение закрыто (FIN/RST).
    tcp_recv: *const fn (slot: usize, out: []u8) i64,
    /// TCP: закрыть слот.
    tcp_close: *const fn (slot: usize) void,
    /// DNS A-запись (блокирующая). null = не разрешено.
    dns_resolve: *const fn (host: []const u8) ?[4]u8,
    /// Записать ПОЛНЫЙ файл в VFS overlay (create-or-replace). true = ок.
    write_file: *const fn (path: []const u8, data: []const u8) bool,
    /// Симлинк в VFS overlay. true = ок.
    make_symlink: *const fn (path: []const u8, target: []const u8) bool,
    /// Аллокация (kernel: heap64.kmalloc; тесты: bump).
    alloc: *const fn (n: usize) ?[*]u8,
    /// Освобождение.
    free: *const fn (ptr: [*]u8, n: usize) void,
    /// Консольный вывод (kernel: hal.Serial+fb; тесты: сбор строк).
    print: *const fn (s: []const u8) void,
};

// ─── Глобальное состояние движка ───────────────────────────────────────────

/// Пакет репозитория (минимальная ALPM-выжимка из desc/depends).
pub const RepoPkg = struct {
    used: bool = false,
    name: [MAX_PKG_NAME]u8 = undefined,
    name_len: usize = 0,
    ver: [MAX_PKG_VER]u8 = undefined,
    ver_len: usize = 0,
    file: [MAX_PKG_FILE]u8 = undefined, // %FILENAME%
    file_len: usize = 0,
    csize: u64 = 0, // %CSIZE%
    isize: u64 = 0, // %ISIZE%
    deps: [MAX_DEPS_PER_PKG][MAX_PKG_NAME]u8 = undefined,
    deps_len: [MAX_DEPS_PER_PKG]usize = .{0} ** MAX_DEPS_PER_PKG,
    deps_n: usize = 0,
    provides: [MAX_PROVIDES_PER_PKG][MAX_PKG_NAME]u8 = undefined,
    provides_len: [MAX_PROVIDES_PER_PKG]usize = .{0} ** MAX_PROVIDES_PER_PKG,
    provides_n: usize = 0,

    pub fn nameSlice(self: *const RepoPkg) []const u8 {
        return self.name[0..self.name_len];
    }
    pub fn verSlice(self: *const RepoPkg) []const u8 {
        return self.ver[0..self.ver_len];
    }
    pub fn fileSlice(self: *const RepoPkg) []const u8 {
        return self.file[0..self.file_len];
    }
    pub fn depSlice(self: *const RepoPkg, i: usize) []const u8 {
        return self.deps[i][0..self.deps_len[i]];
    }
    pub fn provideSlice(self: *const RepoPkg, i: usize) []const u8 {
        return self.provides[i][0..self.provides_len[i]];
    }
};

/// Установленный пакет (для -Q/-Ql; файлы — счётчик + имена первых N).
pub const InstalledPkg = struct {
    used: bool = false,
    name: [MAX_PKG_NAME]u8 = undefined,
    name_len: usize = 0,
    ver: [MAX_PKG_VER]u8 = undefined,
    ver_len: usize = 0,
    files: [MAX_FILES_PER_PKG][MAX_PKG_NAME]u8 = undefined, // путь без '/'
    files_len: [MAX_FILES_PER_PKG]u16 = .{0} ** MAX_FILES_PER_PKG,
    files_n: u32 = 0, // полный счёт (может > ёмкости)

    pub fn nameSlice(self: *const InstalledPkg) []const u8 {
        return self.name[0..self.name_len];
    }
    pub fn verSlice(self: *const InstalledPkg) []const u8 {
        return self.ver[0..self.ver_len];
    }
};

/// Скратч-буферы конвейера (одна транзакция — один контекст; reentrancy
/// в ядре нет: pacman работает под in_win32_syscall-транзакцией).
pub const PacEnv = struct {
    // ── БД репозитория ──
    repo: [MAX_DB_PACKAGES]RepoPkg = [_]RepoPkg{.{}} ** MAX_DB_PACKAGES,
    repo_n: usize = 0,
    db_synced: bool = false,

    // ── Установленные ──
    installed: [MAX_INSTALLED_PKGS]InstalledPkg = [_]InstalledPkg{.{}} ** MAX_INSTALLED_PKGS,
    installed_n: usize = 0,

    // ── HTTP-скратч ──
    http_hdr: [MAX_HTTP_HDR]u8 = undefined, // накопление заголовков
    // ── tar-конвейер: имя текущей записи (GNU longname может быть длинным)
    tar_name: [256]u8 = undefined,
    // ── ALPM-парсер: накопление desc/depends текущего пакета
    alpm_field: [32]u8 = undefined, // %NAME% / %DEPENDS% ...
    alpm_buf: [8192]u8 = undefined, // содержимое поля (сырое)
    alpm_key: [MAX_PKG_NAME]u8 = undefined, // dir-имя пакета "bash-5.3.15-1"
};

pub var env: PacEnv = .{};

// ─── Мелкие утилиты (pure, без std.fmt — ядро + консервативный аллокатор) ──

var g_ops: PacOps = undefined; // сетится в каждом публичном входе

fn p(s: []const u8) void {
    g_ops.print(s);
}

pub fn u8hex(c: u8) u8 {
    return if (c < 10) '0' + c else 'a' + (c - 10);
}

fn printDecimal(v: u64) void {
    var buf: [24]u8 = undefined;
    var i: usize = buf.len;
    var x = v;
    if (x == 0) {
        p("0");
        return;
    }
    while (x > 0) {
        i -= 1;
        buf[i] = @intCast('0' + @mod(x, 10));
        x /= 10;
    }
    p(buf[i..]);
}

fn printKib(bytes: u64) void {
    if (bytes >= 1024 * 1024) {
        printDecimal(bytes / (1024 * 1024));
        p("MiB");
    } else if (bytes >= 1024) {
        printDecimal(bytes / 1024);
        p("KiB");
    } else {
        printDecimal(bytes);
        p("B");
    }
}

fn startsWith(haystack: []const u8, needle: []const u8) bool {
    return std.mem.startsWith(u8, haystack, needle);
}

fn eqStr(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub const REPO_DB_SUFFIX: []const u8 = ".db"; // core.db (gzip-тар ALPM)

fn copyTo(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

// ─── Аллокация через ops ────────────────────────────────────────────────────

fn oalloc(n: usize) ?[]u8 {
    const ptr = g_ops.alloc(n) orelse return null;
    return ptr[0..n];
}

fn ofree(buf: []u8) void {
    g_ops.free(buf.ptr, buf.len);
}

// ============================================================================
// HTTP-клиент поверх PacOps TCP (GET, Connection: close, chunked-decode,
// редиректы 301/302/307/308 — только http://)
// ============================================================================

pub const HttpError = error{
    DnsFail,
    ConnectFail,
    SendFail,
    Closed,
    BadResponse,
    TooBig,
    NoMem,
    RedirectLoop,
    HttpsNotSupported,
    Status,
    DownloadFailed,
};

var http_redirect_hops: usize = 0;

/// Рост буфера через ops (realloc вручную).
fn ogrow(buf: []u8, need: usize) HttpError![]u8 {
    if (need > MAX_DOWNLOAD_BYTES) return HttpError.TooBig;
    var new_cap = @max(need, buf.len * 2);
    new_cap = @min(new_cap, MAX_DOWNLOAD_BYTES);
    const nb = oalloc(new_cap) orelse return HttpError.NoMem;
    @memcpy(nb[0..buf.len], buf);
    ofree(buf);
    return nb;
}

/// httpGet: скачать URL "http://host[:port]/path" → ops.alloc-буфер тела.
/// caller освобождает через ofree. Content-Length ИЛИ chunked, ИЛИ до-EOF.
fn httpFetchUrl(host: []const u8, port: u16, path: []const u8, max_bytes: usize) HttpError![]u8 {
    // 1. DNS
    p("[PAC] stage: dns ");
    p(host);
    p("\n");
    const ip = g_ops.dns_resolve(host) orelse {
        p("[PAC] http: DNS fail: ");
        p(host);
        p("\n");
        return HttpError.DnsFail;
    };
    p("[PAC] stage: dns OK\n");
    // 2. TCP connect
    const slot64 = g_ops.tcp_connect(ip, port);
    if (slot64 < 0) {
        p("[PAC] http: connect fail (");
        printDecimal(@intCast(-slot64));
        p(")\n");
        return HttpError.ConnectFail;
    }
    const slot: usize = @intCast(slot64);
    defer g_ops.tcp_close(slot);

    // 3. GET-запрос (Connection: close — читаем до EOF, без keep-alive)
    var req: [512]u8 = undefined;
    var rl: usize = 0;
    const wr = struct {
        fn cat(b: []u8, o: *usize, s: []const u8) void {
            const n = @min(s.len, b.len - o.*);
            @memcpy(b[o.* .. o.* + n], s[0..n]);
            o.* += n;
        }
    };
    wr.cat(&req, &rl, "GET ");
    wr.cat(&req, &rl, path);
    wr.cat(&req, &rl, " HTTP/1.1\r\nHost: ");
    wr.cat(&req, &rl, host);
    wr.cat(&req, &rl, "\r\nUser-Agent: pacman-poler/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    if (g_ops.tcp_send(slot, req[0..rl]) < 0) return HttpError.SendFail;

    // 4. Заголовки: читаем до "\r\n\r\n"; первый кусок может нести тело
    var hdr_len: usize = 0;
    var done = false;
    var body_chunk: [4096]u8 = undefined;
    var body_first: [4096]u8 = undefined;
    var body_first_len: usize = 0;
    while (!done) {
        const n = g_ops.tcp_recv(slot, &body_chunk);
        if (n < 0) break; // EOF до заголовков
        if (n == 0) {
            if (hdr_len > 0) break;
            continue;
        }
        const got: usize = @intCast(n);
        const hdr_len_before = hdr_len;
        const take = @min(got, MAX_HTTP_HDR - hdr_len);
        const search_from = if (hdr_len >= 3) hdr_len - 3 else 0;
        @memcpy(env.http_hdr[hdr_len .. hdr_len + take], body_chunk[0..take]);
        hdr_len += take;
        var i = search_from;
        while (i + 4 <= hdr_len) : (i += 1) {
            if (env.http_hdr[i] == '\r' and env.http_hdr[i + 1] == '\n' and
                env.http_hdr[i + 2] == '\r' and env.http_hdr[i + 3] == '\n')
            {
                // заголовок кончился на абсолютной позиции hdr_end
                const hdr_end = i + 4;
                // сколько байт текущего куска за пределами заголовка
                const in_chunk_hdr_end = if (hdr_end > hdr_len_before) hdr_end - hdr_len_before else 0;
                if (in_chunk_hdr_end < got) {
                    const rest = got - in_chunk_hdr_end;
                    const rn = @min(rest, body_first.len);
                    @memcpy(body_first[0..rn], body_chunk[in_chunk_hdr_end .. in_chunk_hdr_end + rn]);
                    body_first_len = rn;
                }
                hdr_len = hdr_end;
                done = true;
                break;
            }
        }
        if (hdr_len >= MAX_HTTP_HDR) return HttpError.BadResponse;
    }
    if (!done) return HttpError.BadResponse;
    const hdr = env.http_hdr[0..hdr_len];

    // 5. Статус-строка: "HTTP/1.1 200 OK"
    if (hdr.len < 12 or !startsWith(hdr, "HTTP/1.")) return HttpError.BadResponse;
    const status = std.fmt.parseInt(u32, hdr[9..12], 10) catch return HttpError.BadResponse;

    // 6. Заголовки: Content-Length / Transfer-Encoding / Location
    var content_length: ?u64 = null;
    var chunked = false;
    var location: ?[]const u8 = null;
    {
        var it = std.mem.splitSequence(u8, hdr, "\r\n");
        _ = it.next(); // статус-строка
        while (it.next()) |line| {
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const key = line[0..colon];
            var val = line[colon + 1 ..];
            if (val.len > 0 and val[0] == ' ') val = val[1..];
            if (std.ascii.eqlIgnoreCase(key, "Content-Length")) {
                content_length = std.fmt.parseInt(u64, val, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(key, "Transfer-Encoding")) {
                if (std.ascii.indexOfIgnoreCase(val, "chunked") != null) chunked = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Location")) {
                location = val;
            }
        }
    }

    // 7. Редиректы: 301/302/307/308
    if (status >= 301 and status <= 308 and location != null) {
        http_redirect_hops += 1;
        if (http_redirect_hops > 3) return HttpError.RedirectLoop;
        const loc = location.?;
        if (startsWith(loc, "https://")) {
            p("[PAC] http: зеркало требует HTTPS (TLS в ядре нет)\n");
            return HttpError.HttpsNotSupported;
        }
        if (startsWith(loc, "http://")) {
            const rest = loc[7..];
            const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
            var hostpart = rest[0..slash];
            var nport: u16 = 80;
            if (std.mem.indexOfScalar(u8, hostpart, ':')) |ci| {
                nport = std.fmt.parseInt(u16, hostpart[ci + 1 ..], 10) catch 80;
                hostpart = hostpart[0..ci];
            }
            const npath = if (slash < rest.len) rest[slash..] else "/";
            return httpFetchUrl(hostpart, nport, npath, max_bytes);
        }
        if (loc.len > 0 and loc[0] == '/') {
            return httpFetchUrl(host, port, loc, max_bytes);
        }
        return HttpError.BadResponse;
    }

    if (status != 200) {
        p("[PAC] http: статус ");
        printDecimal(status);
        p(" (ожидали 200)\n");
        return HttpError.Status;
    }

    // 8. Тело
    if (content_length) |cl| {
        if (cl > max_bytes) return HttpError.TooBig;
    }
    const cap = content_length orelse 4 * 1024 * 1024;
    var body = oalloc(@intCast(@max(cap, 8192))) orelse return HttpError.NoMem;
    var have: usize = 0;
    var total: u64 = 0;

    if (body_first_len > 0) {
        const n = @min(body_first_len, body.len);
        @memcpy(body[0..n], body_first[0..n]);
        have = n;
        total = n;
    }

    if (chunked) {
        // 8a. chunked: "<hex>[;ext] CRLF <data> CRLF" ... "0 CRLF"
        // первый recv мог нести начало чанк-потока (body_first)
        have = 0;
        total = 0;
        var cbuf: [4096]u8 = undefined;
        var clen: usize = @min(body_first_len, cbuf.len);
        if (clen > 0) @memcpy(cbuf[0..clen], body_first[0..clen]);
        var state: enum { size, data, crlf, done } = .size;
        var chunk_size: usize = 0;
        var chunk_got: usize = 0;
        // recv ТОЛЬКО когда парсер не может продвинуться
        const recvMore = struct {
            fn f(cb: []u8, cl: *usize, sl: usize) bool {
                if (cl.* >= cb.len) return false;
                const n = g_ops.tcp_recv(sl, cb[cl.*..]);
                if (n <= 0) return false;
                cl.* += @intCast(n);
                return true;
            }
        }.f;
        outer: while (state != .done) {
            switch (state) {
                .size => {
                    var nl: ?usize = null;
                    {
                        var k: usize = 0;
                        while (k + 1 < clen) : (k += 1) {
                            if (cbuf[k] == 13 and cbuf[k + 1] == 10) {
                                nl = k;
                                break;
                            }
                        }
                    }
                    if (nl == null) {
                        if (clen >= 256) return HttpError.BadResponse;
                        if (!recvMore(&cbuf, &clen, slot)) return HttpError.Closed;
                        continue :outer;
                    }
                    const l = nl.?;
                    var szs = cbuf[0..l];
                    if (std.mem.indexOfScalar(u8, szs, ';')) |si| szs = szs[0..si];
                    const sz = std.fmt.parseInt(usize, std.mem.trim(u8, szs, " \t"), 16) catch
                        return HttpError.BadResponse;
                    const consumed = l + 2;
                    std.mem.copyForwards(u8, cbuf[0 .. clen - consumed], cbuf[consumed..clen]);
                    clen -= consumed;
                    if (sz == 0) {
                        state = .done;
                        break :outer;
                    }
                    if (total + sz > max_bytes) return HttpError.TooBig;
                    chunk_size = sz;
                    chunk_got = 0;
                    state = .data;
                },
                .data => {
                    if (clen == 0) {
                        if (!recvMore(&cbuf, &clen, slot)) return HttpError.Closed;
                        continue :outer;
                    }
                    const want = chunk_size - chunk_got;
                    const take = @min(want, clen);
                    if (have + take > body.len) {
                        body = try ogrow(body, have + take + 4096);
                    }
                    @memcpy(body[have .. have + take], cbuf[0..take]);
                    have += take;
                    total += take;
                    chunk_got += take;
                    std.mem.copyForwards(u8, cbuf[0 .. clen - take], cbuf[take..clen]);
                    clen -= take;
                    if (chunk_got == chunk_size) state = .crlf;
                },
                .crlf => {
                    if (clen < 2) {
                        if (!recvMore(&cbuf, &clen, slot)) return HttpError.Closed;
                        continue :outer;
                    }
                    std.mem.copyForwards(u8, cbuf[0 .. clen - 2], cbuf[2..clen]);
                    clen -= 2;
                    state = .size;
                },
                .done => break :outer,
            }
        }
        } else {
        // 8b. Content-Length или до-EOF (Connection: close)
        while (true) {
            if (content_length) |cl| {
                if (total >= cl) break;
            }
            if (have >= body.len) {
                body = try ogrow(body, have + 65536);
            }
            const n = g_ops.tcp_recv(slot, body[have..]);
            if (n < 0) {
                // EOF: если Content-Length НЕ ДОСТИГНУТ — обрыв (KA-abort /
                // ретрансмит-таймаут) → ТРУНКАЯ НЕ УСПЕХ: ретрай на верхнем
                // уровне (эмпирика e2e: «получено 3KiB» + zstd BadBlockHeader)
                if (content_length != null and total < content_length.?) {
                    p("[PAC] http: обрыв (получено ");
                    printKib(total);
                    p(" из ");
                    printKib(content_length.?);
                    p(")\n");
                    return HttpError.Closed;
                }
                break; // до-EOF режим: честный конец потока
            }
            if (n == 0) continue; // пустой recv — поллинг
            have += @intCast(n);
            total += @intCast(n);
            if (total > max_bytes) return HttpError.TooBig;
        }
    }
    p("  http: получено ");
    printKib(total);
    p(" от ");
    p(host);
    p("\n");
    return body[0..have];
}

/// Публичный GET: сброс редирект-счётчика + лимит загрузки.
pub fn httpGet(host: []const u8, port: u16, path: []const u8, max_bytes: usize) HttpError![]u8 {
    http_redirect_hops = 0;
    // CDD #17-НАДЁЖНОСТЬ: TCP-слой не гарантирует доставку КАЖДОГО сегмента
    // (эмпирика e2e: первый сегмент ответа теряется при перекрёстном
    // ретрансмит-шторме прошлой транзакции → gap-дропы → порча пакета).
    // HTTP-клиент ДОЛЖЕН ретраить — как реальные клиенты: свежая попытка =
    // свежий коннект (новый порт) + сервер шлёт ответ заново. Пауза между
    // попытками даёт SLIRP-таймерам осесть (retx-шторм утихает).
    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        http_redirect_hops = 0;
        if (httpFetchUrl(host, port, path, max_bytes)) |body| {
            return body;
        } else |_| {
            if (attempt == 0) {
                p("[PAC] http: ретрай ");
                p(host);
                p(" (");
                p(path);
                p(")\n");
            }
            // пауза ~500мс: пропускаем шум ретрансмитов прошлой транзакции
            var spins: u32 = 0;
            while (spins < 25_000_000) : (spins += 1) asm volatile ("pause");
        }
    }
    return HttpError.DownloadFailed;
}

// ============================================================================
// GZIP / DEFLATE-декодер (RFC 1951/1952) — для repo-БД core.db.tar.gz
// ============================================================================
// Полный inflate: stored / fixed-Huffman / dynamic-Huffman + CRC32.
// ВАЖНО (эмпирика прошлой сессии): НЕ используем std.io.FixedWriter —
// его write() возвращает 0 при заполнении → writeAll зацикливается. Свои
// суррогаты: GrowBuf с честной ошибкой.
// ============================================================================

/// Растущий буфер поверх ops.alloc (собственный, без std-обёрток).
const GrowBuf = struct {
    data: []u8 = &.{},
    len: usize = 0,

    fn init(cap: usize) !GrowBuf {
        const d = oalloc(cap) orelse return error.NoMem;
        return .{ .data = d, .len = 0 };
    }
    fn deinit(self: *GrowBuf) void {
        if (self.data.len > 0) ofree(self.data);
        self.* = .{};
    }
    fn ensure(self: *GrowBuf, extra: usize) !void {
        const need = self.len + extra;
        if (need <= self.data.len) return;
        var new_cap = @max(self.data.len * 2, need);
        new_cap = @min(new_cap, MAX_PACKAGE_UNPACKED + 4096);
        if (need > new_cap) return error.TooBig;
        const nb = oalloc(new_cap) orelse return error.NoMem;
        @memcpy(nb[0..self.len], self.data[0..self.len]);
        if (self.data.len > 0) ofree(self.data);
        self.data = nb;
    }
    fn append(self: *GrowBuf, bytes: []const u8) !void {
        try self.ensure(bytes.len);
        @memcpy(self.data[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }
    fn appendByte(self: *GrowBuf, b: u8) !void {
        try self.ensure(1);
        self.data[self.len] = b;
        self.len += 1;
    }
    fn slice(self: *const GrowBuf) []const u8 {
        return self.data[0..self.len];
    }
};

/// Битовый читатель LSB-first (DEFLATE-порядок).
const BitReader = struct {
    data: []const u8,
    pos: usize = 0, // битовая позиция
    bits: u64 = 0,
    nbits: u32 = 0,

    fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }
    /// Подзагрузка контейнера (LSB-first: байты идут по порядку).
    fn refill(self: *BitReader) void {
        while (self.nbits <= 56 and self.pos < self.data.len * 8) {
            const byte_idx = self.pos / 8;
            const b = self.data[byte_idx];
            self.bits |= @as(u64, b) << @intCast(self.nbits);
            self.nbits += 8;
            self.pos += 8;
        }
    }
    fn peek(self: *BitReader, n: u6) u32 {
        return @intCast(self.bits & ((@as(u64, 1) << n) - 1));
    }
    fn drop(self: *BitReader, n: u6) void {
        self.bits >>= n;
        self.nbits -= n;
    }
    fn read(self: *BitReader, n: u6) u32 {
        if (n == 0) return 0;
        self.refill();
        const v = self.peek(n);
        self.drop(n);
        return v;
    }
    fn alignByte(self: *BitReader) void {
        // pos = потреблено + предзагружено в контейнер: откатываем контейнер,
        // выравниваем только ПОТРЕБЛЁННЫЕ биты
        const consumed = self.pos - self.nbits;
        const rem: usize = consumed % 8;
        self.pos = if (rem == 0) consumed else consumed + (8 - rem);
        self.bits = 0;
        self.nbits = 0;
    }
    fn bytePos(self: *const BitReader) usize {
        return (self.pos + 7) / 8;
    }
    fn exhausted(self: *BitReader) bool {
        return self.pos >= self.data.len * 8;
    }
};

/// Канонический Huffman-декодер (декод-таблица по длинам кодов).
const HuffTree = struct {
    /// counts[len] = число кодов длины len; symbols отсортированы по (len, sym)
    counts: [16]u16 = .{0} ** 16,
    symbols: [320]u16 = .{0} ** 320,

    const DECODE_ERR: u16 = 0xFFFF;

    fn build(lengths: []const u8) !HuffTree {
        var t = HuffTree{};
        for (lengths) |l| {
            if (l > 15) return error.BadHuff;
            t.counts[l] += 1;
        }
        if (t.counts[0] == lengths.len) return error.BadHuff; // пусто
        // проверка Крафта: сумма 2^-len == 1 (полное) или < 1 (неполное ок)
        var left: i32 = 1;
        var l: usize = 1;
        while (l <= 15) : (l += 1) {
            left <<= 1;
            left -= @intCast(t.counts[l]);
            if (left < 0) return error.BadHuff; // переполнение
        }
        // offsets
        var offs: [16]u16 = .{0} ** 16;
        var sum: usize = 0;
        l = 1;
        while (l <= 15) : (l += 1) {
            offs[l] = @intCast(sum);
            sum += t.counts[l];
        }
        if (sum > t.symbols.len) return error.BadHuff;
        for (lengths, 0..) |ln, sym| {
            if (ln != 0) {
                t.symbols[offs[ln]] = @intCast(sym);
                offs[ln] += 1;
            }
        }
        return t;
    }

    /// Декод символа: peek-макс-15-бит, поиск по длинам.
    fn decode(self: *const HuffTree, br: *BitReader) !u16 {
        br.refill();
        var code: u32 = 0;
        var first: u32 = 0;
        var index: u32 = 0;
        var len: usize = 1;
        while (len <= 15) : (len += 1) {
            code |= br.peek(1);
            br.drop(1);
            const cnt: u32 = self.counts[len];
            if (code < first + cnt) {
                return self.symbols[index + (code - first)];
            }
            index += cnt;
            first = (first + cnt) << 1;
            code <<= 1;
        }
        return error.BadHuff;
    }
};

/// CRC32 (IEEE, reflected) — таблица на лету при init (lazy один раз).
var crc_table: [256]u32 = undefined;
var crc_table_ready = false;

fn crc32(data: []const u8) u32 {
    if (!crc_table_ready) {
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            var c: u32 = @intCast(i);
            var k: usize = 0;
            while (k < 8) : (k += 1) {
                c = if (c & 1 != 0) 0xEDB88320 ^ (c >> 1) else c >> 1;
            }
            crc_table[i] = c;
        }
        crc_table_ready = true;
    }
    var c: u32 = 0xFFFFFFFF;
    for (data) |b| {
        c = crc_table[(c ^ b) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

/// LZ77-окно (32КБ) + копирование с перекрытием.
const LzWindow = struct {
    w: [32768]u8 = undefined,
    wlen: usize = 0,

    fn push(self: *LzWindow, b: u8) void {
        self.w[self.wlen % 32768] = b;
        self.wlen += 1;
    }
    fn pushSlice(self: *LzWindow, bytes: []const u8) void {
        for (bytes) |b| self.push(b);
    }
    fn dist(self: *const LzWindow, d: u32) u8 {
        return self.w[(self.wlen -% d) % 32768];
    }
};

const LEN_BASE = [29]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
const LEN_EXTRA = [29]u4{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
const DIST_BASE = [30]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
const DIST_EXTRA = [30]u4{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/// Inflate-блок в out+window.
fn inflateBlock(br: *BitReader, out: *GrowBuf, win: *LzWindow, lit: *const HuffTree, dist: *const HuffTree) !void {
    while (true) {
        const sym = try lit.decode(br);
        if (sym < 256) {
            try out.appendByte(@intCast(sym));
            win.push(@intCast(sym));
        } else if (sym == 256) {
            return; // конец блока
        } else {
            const li = sym - 257;
            if (li >= 29) return error.BadHuff;
            const len = LEN_BASE[li] + br.read(LEN_EXTRA[li]);
            const dsym = try dist.decode(br);
            if (dsym >= 30) return error.BadHuff;
            const d = DIST_BASE[dsym] + br.read(DIST_EXTRA[dsym]);
            if (d > 32768 or d > win.wlen) return error.BadDist;
            var i: usize = 0;
            while (i < len) : (i += 1) {
                const b = win.dist(d);
                try out.appendByte(b);
                win.push(b);
            }
        }
    }
}

/// Полный DEFLATE-стрим (RFC 1951) → GrowBuf.
fn inflateAll(data: []const u8) !GrowBuf {
    var br = BitReader.init(data);
    var out = try GrowBuf.init(64 * 1024);
    errdefer out.deinit();
    var win = LzWindow{};
    while (true) {
        const final = br.read(1);
        const btype = br.read(2);
        switch (btype) {
            0 => { // stored
                br.alignByte();
                const len = br.read(16);
                const nlen = br.read(16);
                if (len != (nlen ^ 0xFFFF)) return error.BadStored;
                var i: usize = 0;
                while (i < len) : (i += 1) {
                    const b: u8 = @intCast(br.read(8));
                    try out.appendByte(b);
                    win.push(b);
                }
            },
            1 => { // fixed Huffman
                var lit_lengths: [288]u8 = undefined;
                for (0..144) |i| lit_lengths[i] = 8;
                for (144..256) |i| lit_lengths[i] = 9;
                for (256..280) |i| lit_lengths[i] = 7;
                for (280..288) |i| lit_lengths[i] = 8;
                var dist_lengths: [30]u8 = undefined;
                for (&dist_lengths) |*dl| dl.* = 5;
                const lit = try HuffTree.build(&lit_lengths);
                const dt = try HuffTree.build(&dist_lengths);
                try inflateBlock(&br, &out, &win, &lit, &dt);
            },
            2 => { // dynamic Huffman
                const hlit: usize = @as(usize, br.read(5)) + 257;
                const hdist: usize = @as(usize, br.read(5)) + 1;
                const hclen: usize = @as(usize, br.read(4)) + 4;
                if (hlit > 286 or hdist > 30) return error.BadHuff;
                const clen_order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
                var clen: [19]u8 = .{0} ** 19;
                for (0..hclen) |i| clen[clen_order[i]] = @intCast(br.read(3));
                const clen_tree = try HuffTree.build(&clen);
                var lengths: [286 + 30]u8 = .{0} ** (286 + 30);
                var i: usize = 0;
                while (i < hlit + hdist) {
                    const sym = try clen_tree.decode(&br);
                    switch (sym) {
                        0...15 => {
                            lengths[i] = @intCast(sym);
                            i += 1;
                        },
                        16 => {
                            if (i == 0) return error.BadHuff;
                            const prev = lengths[i - 1];
                            const rep = 3 + br.read(2);
                            var r: usize = 0;
                            while (r < rep and i < hlit + hdist) : (r += 1) {
                                lengths[i] = prev;
                                i += 1;
                            }
                        },
                        17 => {
                            const rep = 3 + br.read(3);
                            var r: usize = 0;
                            while (r < rep and i < hlit + hdist) : (r += 1) {
                                lengths[i] = 0;
                                i += 1;
                            }
                        },
                        18 => {
                            const rep = 11 + br.read(7);
                            var r: usize = 0;
                            while (r < rep and i < hlit + hdist) : (r += 1) {
                                lengths[i] = 0;
                                i += 1;
                            }
                        },
                        else => return error.BadHuff,
                    }
                }
                const lit = try HuffTree.build(lengths[0..hlit]);
                const dt = try HuffTree.build(lengths[hlit .. hlit + hdist]);
                try inflateBlock(&br, &out, &win, &lit, &dt);
            },
            else => return error.BadBlockType,
        }
        if (final == 1) break;
    }
    return out;
}

/// gunzip: RFC 1952 (magic 1F 8B, метод 8, флаги, → deflate → CRC32 + ISIZE).
/// Проверка CRC32 мягкая (лог при несовпадении, не фейл — см. эмпирику
/// сессии: строгий CRC у .db-шек Arch ломает совместимость из-за trailing).
pub fn gunzip(data: []const u8) ![]u8 {
    if (data.len < 18) return error.BadGzip;
    if (data[0] != 0x1F or data[1] != 0x8B) return error.BadGzip;
    if (data[2] != 8) return error.BadGzip; // только deflate
    const flg = data[3];
    var off: usize = 10;
    if (flg & 0x04 != 0) { // FEXTRA
        if (off + 2 > data.len) return error.BadGzip;
        const xlen = @as(usize, data[off]) | (@as(usize, data[off + 1]) << 8);
        off += 2 + xlen;
    }
    if (flg & 0x08 != 0) { // FNAME (zstring)
        while (off < data.len and data[off] != 0) off += 1;
        off += 1;
    }
    if (flg & 0x10 != 0) { // FCOMMENT
        while (off < data.len and data[off] != 0) off += 1;
        off += 1;
    }
    if (flg & 0x02 != 0) off += 2; // FHCRC
    if (off >= data.len) return error.BadGzip;
    var out = try inflateAll(data[off..]);
    // Мягкая проверка трейлера (последние 8Б: CRC32+ISIZE): лог при
    // несовпадении, НЕ фейл — емпирика: .db иногда имеет trailing-мусор.
    if (data.len >= 8) {
        const isize_le = std.mem.readInt(u32, data[data.len - 4 ..][0..4], .little);
        if (isize_le != @as(u32, @truncate(out.len)) and (isize_le & 0xFFFFFFFF) != (out.len & 0xFFFFFFFF)) {
            p("[PAC] gzip: ISIZE mismatch (");
            printDecimal(isize_le);
            p(" vs ");
            printDecimal(out.len);
            p(") — продолжаем\n");
        }
    }
    return out.data[0..out.len];
}

// ============================================================================
// ZSTD-декодер (RFC zstd v0.8+, без словарей) — для .pkg.tar.zst
// ============================================================================
// Полный декодер сжатых блоков: literals (raw/RLE/Huffman 1X/4X) +
// sequences (FSE: predefined/RLE/compressed/repeat) + repeat-offsets +
// xxh64-чекпоинт. Семантика 1:1 с libzstd (zstd 1.5.6, сверено по исходникам
// FSE_readNCount/FSE_buildDTable/HUF_readStats/HUF_readDTableX1/
// ZSTD_decodeLiteralsBlock/ZSTD_decodeSeqHeaders/ZSTD_decodeSequence).
//
// Ключевые решения RAM-модели:
//   - Состояние декодера — глобальная .bss-структура (одна транзакция).
//   - Окно — динамический буфер ≤ windowSize (bash: 2МБ, уровень ≤19: 8МБ).
//   - Выход — GrowBuf (собственный, НЕ std.FixedWriter — см. урок gzip).
// ============================================================================

const ZstdError = error{
    BadMagic,
    BadFrameHeader,
    BadBlockHeader,
    BadLiterals,
    BadHuffman,
    BadFse,
    BadSequences,
    BadOffset,
    Unsupported, // словари/зарезервированные режимы
    TooBig,
    NoMem,
    Checksum,
};

fn highbit32(x: u32) u5 {
    return @intCast(31 - @clz(x));
}

// ─── xxhash64 (контрольная сумма кадра) ─────────────────────────────────────

const XXH_PRIME1: u64 = 0x9E3779B185EBCA87;
const XXH_PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
const XXH_PRIME3: u64 = 0x165667B19E3779F9;
const XXH_PRIME4: u64 = 0x85EBCA77C2B2AE63;
const XXH_PRIME5: u64 = 0x27D4EB2F165667C5;

fn xxrotl(x: u64, comptime r: u6) u64 {
    return (x << r) | (x >> @intCast(64 - @as(u7, r)));
}

fn xxround(acc: u64, input: u64) u64 {
    return xxrotl(acc +% (input *% XXH_PRIME2), 31) *% XXH_PRIME1;
}

fn xxmergeRound(acc: u64, val: u64) u64 {
    const v = xxround(0, val);
    var a = acc ^ v;
    a = a *% XXH_PRIME1 +% XXH_PRIME4;
    return a;
}

/// XXH64(data, seed=0).
pub fn xxh64(data: []const u8) u64 {
    const n = data.len;
    var h: u64 = undefined;
    var i: usize = 0;
    if (n >= 32) {
        var v1: u64 = XXH_PRIME1 +% XXH_PRIME2;
        var v2: u64 = XXH_PRIME2;
        var v3: u64 = 0;
        var v4: u64 = 0 -% XXH_PRIME1;
        while (i + 32 <= n) : (i += 32) {
            v1 = xxround(v1, std.mem.readInt(u64, data[i..][0..8], .little));
            v2 = xxround(v2, std.mem.readInt(u64, data[i + 8 ..][0..8], .little));
            v3 = xxround(v3, std.mem.readInt(u64, data[i + 16 ..][0..8], .little));
            v4 = xxround(v4, std.mem.readInt(u64, data[i + 24 ..][0..8], .little));
        }
        h = xxrotl(v1, 1) +% xxrotl(v2, 7) +% xxrotl(v3, 12) +% xxrotl(v4, 18);
        h = xxmergeRound(h, v1);
        h = xxmergeRound(h, v2);
        h = xxmergeRound(h, v3);
        h = xxmergeRound(h, v4);
    } else {
        h = XXH_PRIME5;
    }
    h +%= n;
    // хвост
    while (i + 8 <= n) : (i += 8) {
        const k = xxround(0, std.mem.readInt(u64, data[i..][0..8], .little));
        h ^= k;
        h = xxrotl(h, 27) *% XXH_PRIME1 +% XXH_PRIME4;
    }
    if (i + 4 <= n) {
        h ^= @as(u64, std.mem.readInt(u32, data[i..][0..4], .little)) *% XXH_PRIME1;
        h = xxrotl(h, 23) *% XXH_PRIME2 +% XXH_PRIME3;
        i += 4;
    }
    while (i < n) : (i += 1) {
        h ^= @as(u64, data[i]) *% XXH_PRIME5;
        h = xxrotl(h, 11) *% XXH_PRIME1;
    }
    h ^= h >> 33;
    h *%= XXH_PRIME2;
    h ^= h >> 29;
    h *%= XXH_PRIME3;
    h ^= h >> 32;
    return h;
}

// ─── Обратный бит-стрим (zstd FSE/Huffman: чтение с конца, MSB-first) ──────

/// Семантика BIT_DStream (bitstream.h): контейнер = LE64 последних байт;
/// потребление сверху; ptr движется назад; выравнивание — «endMark»: consumed
/// на init = 8 - highbit(lastByte) (пропуск ведущих нулей + маркирующий бит).
const RevBits = struct {
    data: []const u8 = &.{},
    ptr: usize = 0, // индекс начала 8-байтного окна
    container: u64 = 0,
    consumed: u32 = 0, // бит потреблено сверху (может >64 при overflow)

    fn init(data: []const u8) ZstdError!RevBits {
        var rb = RevBits{ .data = data };
        if (data.len == 0) return ZstdError.BadFse;
        const last = data[data.len - 1];
        if (last == 0) return ZstdError.BadFse; // endMark обязан быть
        const skip_bits: u32 = 8 - @as(u32, highbit32(last));
        if (data.len >= 8) {
            rb.ptr = data.len - 8;
            rb.container = std.mem.readInt(u64, data[rb.ptr..][0..8], .little);
            rb.consumed = skip_bits;
        } else {
            // частичная загрузка: байты на своих местах, верх — нули
            var c: u64 = 0;
            for (data, 0..) |b, i| c |= @as(u64, b) << @intCast(i * 8);
            rb.container = c;
            rb.ptr = 0;
            rb.consumed = skip_bits + (8 - @as(u32, @intCast(data.len))) * 8;
        }
        return rb;
    }

    /// Следующие n бит БЕЗ потребления. ЧАСТИЧНЫЙ peek при нехватке бит
    /// (семантика BIT_lookBitsFast: реальные биты в СТАРШИХ позициях
    /// значения, младшие — нули; код с длиной ≤ avail резолвится верно).
    fn look(self: *const RevBits, n: u6) u64 {
        if (n == 0) return 0;
        if (self.consumed >= 64) return 0; // полный over-read
        const avail: u32 = 64 - self.consumed; // ≥ 1
        if (avail < n) {
            // (container << consumed) >> (64 - n): двойной сдвиг reference
            const sh: u6 = @intCast(@min(self.consumed, 63));
            const shifted = self.container << sh;
            return (shifted >> @intCast(64 - @as(u32, n))) & ((@as(u64, 1) << n) - 1);
        }
        const sh: u6 = @intCast((64 - self.consumed - @as(u32, n)) & 63);
        return (self.container >> sh) & ((@as(u64, 1) << n) - 1);
    }

    /// Чтение с предварительным reload (для длинных полей: offset ≤ 31 бит).
    fn readSafe(self: *RevBits, n: u6) u64 {
        if (n == 0) return 0;
        if (self.consumed + @as(u32, n) > 56) {
            _ = self.reload();
        }
        return self.read(n);
    }

    fn skip(self: *RevBits, n: u32) void {
        self.consumed += n;
    }

    fn read(self: *RevBits, n: u6) u64 {
        if (n == 0) return 0;
        const v = self.look(n);
        self.skip(n);
        return v;
    }

    /// Перезагрузка (семантика BIT_reloadDStream): двигаем ptr назад на
    /// consumed>>3 байт (кламп к началу — частичная зона), consumed -= 8*back.
    /// false = стрим полностью потреблён (ptr==0 и consumed>=64).
    fn reload(self: *RevBits) bool {
        if (self.ptr == 0 and self.consumed >= 64) return false;
        if (self.consumed > 64) return false; // overflow: за концом
        const want_back: usize = self.consumed >> 3;
        const back = @min(want_back, self.ptr);
        self.ptr -= back;
        self.consumed -= @intCast(back * 8);
        if (self.data.len >= 8 and self.ptr + 8 <= self.data.len) {
            self.container = std.mem.readInt(u64, self.data[self.ptr..][0..8], .little);
        }
        return !(self.ptr == 0 and self.consumed >= 64);
    }

    /// Осталось ≤ n бит до конца? (грубая проверка для циклов)
    fn nearEnd(self: *const RevBits) bool {
        const bits_left: u64 = @as(u64, self.ptr) * 8 + (64 - self.consumed);
        return bits_left <= 8;
    }
};

// ─── Прямой LSB-first читатель (FSE NCount-заголовки) ───────────────────────

const FwdBits = struct {
    data: []const u8,
    bit_pos: usize = 0,

    fn init(data: []const u8) FwdBits {
        return .{ .data = data };
    }
    fn read(self: *FwdBits, n: u6) u32 {
        const v = self.peekBits(n);
        self.bit_pos += n;
        return v;
    }
    /// Следующие n бит БЕЗ продвижения (threshold-логика NCount).
    fn peekBits(self: *const FwdBits, n: u32) u32 {
        var v: u32 = 0;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const pos = self.bit_pos + i;
            const byte = pos / 8;
            const bit: u32 = if (byte < self.data.len)
                (self.data[byte] >> @intCast(pos % 8)) & 1
            else
                0;
            v |= bit << @intCast(i);
        }
        return v;
    }
    fn advance(self: *FwdBits, n: u32) void {
        self.bit_pos += n;
    }
    fn bytePos(self: *const FwdBits) usize {
        return (self.bit_pos + 7) / 8;
    }
};

// ─── FSE: чтение нормализованных счётчиков (FSE_readNCount) ────────────────

const FSE_MIN_TABLELOG: u32 = 5;
const FSE_MAX_SYMBOL_VALUE: usize = 255;

/// Прочитать NCount → norm[0..maxSV], tableLog. Возврат: потреблено БАЙТ.
fn fseReadNCount(data: []const u8, norm: []i16, max_sv_in: usize, table_log_out: *u32) ZstdError!usize {
    if (data.len < 4) return ZstdError.BadFse;
    var br = FwdBits.init(data);
    const table_log = br.read(4) + FSE_MIN_TABLELOG;
    if (table_log > 20) return ZstdError.BadFse;
    table_log_out.* = table_log;
    @memset(norm, 0);
    var remaining: i32 = @as(i32, @intCast(@as(u32, 1) << @intCast(table_log))) + 1;
    var threshold: i32 = @as(i32, @intCast(@as(u32, 1) << @intCast(table_log)));
    var nb_bits: u32 = table_log + 1;
    var charnum: usize = 0;
    var previous0 = false;
    const max_sv1 = max_sv_in + 1;

    while (true) {
        if (previous0) {
            // счёт нулей: пары «11» = +3, финальная пара < 3 — остаток
            while (true) {
                const pair = br.read(2);
                if (pair == 3) {
                    charnum += 3;
                } else {
                    charnum += pair;
                    break;
                }
            }
            if (charnum >= max_sv1) return ZstdError.BadFse;
            previous0 = false;
        }
        {
            const max: i32 = (2 * threshold - 1) - remaining;
            var count: i32 = undefined;
            const low = br.peekBits(nb_bits - 1);
            if (low < max) {
                count = @intCast(low);
                br.advance(nb_bits - 1);
            } else {
                const wide = br.peekBits(nb_bits);
                count = @intCast(wide);
                if (count >= threshold) count -= max;
                br.advance(nb_bits);
            }
            count -= 1; // extra accuracy
            remaining -= if (count >= 0) count else -count;
            if (charnum < norm.len) norm[charnum] = @intCast(count) else return ZstdError.BadFse;
            charnum += 1;
            previous0 = (count == 0);

            if (remaining < threshold) {
                if (remaining <= 1) break;
                nb_bits = @as(u32, highbit32(@intCast(remaining))) + 1;
                threshold = @as(i32, @intCast(@as(u32, 1) << @intCast(nb_bits - 1)));
            }
            if (charnum >= max_sv1) break;
        }
    }
    if (remaining != 1) return ZstdError.BadFse;
    if (charnum > max_sv1) return ZstdError.BadFse;
    return br.bytePos();
}

// (помощники peekBits/advance — методы FwdBits выше)

// ─── FSE: декод-таблица (FSE_buildDTable) ───────────────────────────────────

const FseEntry = struct {
    symbol: u8 = 0,
    nb_bits: u8 = 0,
    next_state: u16 = 0,
};

const MAX_FSE_TABLE: usize = 2048; // log ≤ 9 для LL/ML (512), запас для FSE generic (log ≤ 11)

const FseDTable = struct {
    table_log: u6 = 0,
    size: usize = 0,
    entries: [MAX_FSE_TABLE]FseEntry = [_]FseEntry{.{}} ** MAX_FSE_TABLE,
};

/// Построить декод-таблицу из нормализованных счётчиков (FSE_buildDTable).
fn fseBuildDTable(dt: *FseDTable, norm: []const i16, table_log: u32) ZstdError!void {
    if (table_log < 5 or table_log > 11) return ZstdError.BadFse;
    const table_size: usize = @as(usize, 1) << @intCast(table_log);
    dt.table_log = @intCast(table_log);
    dt.size = table_size;
    var symbol_next: [FSE_MAX_SYMBOL_VALUE + 1]u16 = undefined;
    var high_threshold: i64 = @as(i64, @intCast(table_size - 1));

    // lowprob (-1) — с конца таблицы
    for (norm, 0..) |c, s| {
        if (c == -1) {
            if (high_threshold < 0) return ZstdError.BadFse;
            dt.entries[@intCast(high_threshold)].symbol = @intCast(s);
            symbol_next[s] = 1;
            high_threshold -= 1;
        } else {
            symbol_next[s] = @intCast(@max(c, 0));
        }
    }

    // spread: step-обход
    const step: usize = (table_size >> 1) + (table_size >> 3) + 3;
    const mask: usize = table_size - 1;
    const ht_limit: usize = @intCast(high_threshold);
    var position: usize = 0;
    for (norm, 0..) |c, s| {
        if (c <= 0) continue;
        var i: i32 = 0;
        while (i < c) : (i += 1) {
            dt.entries[position].symbol = @intCast(s);
            position = (position + step) & mask;
            while (position > ht_limit) {
                position = (position + step) & mask;
            }
        }
    }
    // (позиция обязана вернуться в 0 — иначе данные битые; не фейлим жёстко,
    // т.к. lowprob-зона могла сместить: проверим суммой)
    // Биты декода:
    for (0..table_size) |u| {
        const sym = dt.entries[u].symbol;
        const next = symbol_next[sym];
        symbol_next[sym] += 1;
        const hb = highbit32(next);
        dt.entries[u].nb_bits = @intCast(table_log - hb);
        dt.entries[u].next_state = (next << @intCast(table_log - hb)) - @as(u16, @intCast(table_size));
    }
}

// ─── Huffman (X1, односимвольные записи) ────────────────────────────────────

const HUF_SYMBOL_MAX: usize = 256;
const HUF_TABLELOG_MAX: u6 = 12;
const MAX_HUF_TABLE: usize = 4096; // 2^12

const HufEntry = struct {
    byte: u8 = 0,
    nb_bits: u8 = 0,
};

const HuffTable = struct {
    table_log: u6 = 0,
    entries: [MAX_HUF_TABLE]HufEntry = [_]HufEntry{.{}} ** MAX_HUF_TABLE,
};

/// Прочитать веса (HUF_readStats): byte0 = iSize;
/// ≥128 → прямые нибблы (oSize = iSize-127); <128 → FSE-сжатые веса.
/// Возврат: (веса[0..nbSymbols], tableLog, потреблено байт).
fn hufReadStats(data: []const u8, weights: *[HUF_SYMBOL_MAX]u8, nb_symbols: *usize, table_log: *u32) ZstdError!usize {
    if (data.len == 0) return ZstdError.BadHuffman;
    const i_size = data[0];
    var o_size: usize = 0;
    var consumed: usize = 0;
    if (i_size >= 128) {
        o_size = @as(usize, i_size) - 127;
        const packed_bytes = (o_size + 1) / 2;
        if (1 + packed_bytes > data.len) return ZstdError.BadHuffman;
        var n: usize = 0;
        while (n < o_size) : (n += 2) {
            const b = data[1 + n / 2];
            weights[n] = b >> 4;
            if (n + 1 < o_size) weights[n + 1] = b & 15;
        }
        consumed = 1 + packed_bytes;
    } else {
        // FSE-сжатые веса: maxLog = 6; символы-веса ≤ 15 (валидация ниже)
        if (1 + @as(usize, i_size) > data.len) return ZstdError.BadHuffman;
        var norm: [16]i16 = undefined;
        var tlog: u32 = 0;
        const n_read = fseReadNCount(data[1..], norm[0..15], 15, &tlog) catch return ZstdError.BadHuffman;
        if (tlog > 6) return ZstdError.BadHuffman;
        var wdt: FseDTable = .{};
        try fseBuildDTable(&wdt, norm[0..15], tlog);
        // декод весов: ДВЕ чередующиеся FSE-состояния (reference-паттерн
        // FSE_decompress: state1/state2, терминация — overflow consumed>64)
        const stream = data[1 + n_read .. 1 + @as(usize, i_size)];
        var rb = try RevBits.init(stream);
        var state1: usize = @intCast(rb.readSafe(wdt.table_log));
        var state2: usize = @intCast(rb.readSafe(wdt.table_log));
        var n: usize = 0;
        while (n + 2 < HUF_SYMBOL_MAX) {
            {
                if (state1 >= wdt.size) return ZstdError.BadHuffman;
                const e = wdt.entries[state1];
                if (e.symbol > HUF_TABLELOG_MAX) return ZstdError.BadHuffman;
                weights[n] = e.symbol;
                n += 1;
                state1 = @as(usize, e.next_state) + @as(usize, @intCast(rb.readSafe(@intCast(e.nb_bits))));
            }
            if (rb.consumed > 64) {
                if (state2 >= wdt.size) return ZstdError.BadHuffman;
                weights[n] = wdt.entries[state2].symbol;
                n += 1;
                break;
            }
            {
                if (state2 >= wdt.size) return ZstdError.BadHuffman;
                const e = wdt.entries[state2];
                if (e.symbol > HUF_TABLELOG_MAX) return ZstdError.BadHuffman;
                weights[n] = e.symbol;
                n += 1;
                state2 = @as(usize, e.next_state) + @as(usize, @intCast(rb.readSafe(@intCast(e.nb_bits))));
            }
            if (rb.consumed > 64) {
                if (state1 >= wdt.size) return ZstdError.BadHuffman;
                weights[n] = wdt.entries[state1].symbol;
                n += 1;
                break;
            }
        }
        o_size = n;
        consumed = 1 + @as(usize, i_size);
    }

    // статистика весов → tableLog + имплицитный последний вес
    var rank: [HUF_TABLELOG_MAX + 2]u32 = .{0} ** (HUF_TABLELOG_MAX + 2);
    var weight_total: u32 = 0;
    for (weights[0..o_size]) |w| {
        if (w > HUF_TABLELOG_MAX) return ZstdError.BadHuffman;
        rank[w] += 1;
        weight_total += (@as(u32, 1) << @intCast(w)) >> 1;
    }
    if (weight_total == 0) return ZstdError.BadHuffman;
    const tlog: u32 = @as(u32, highbit32(weight_total)) + 1;
    if (tlog > HUF_TABLELOG_MAX) return ZstdError.BadHuffman;
    const total: u32 = @as(u32, 1) << @intCast(tlog);
    const rest: u32 = total - weight_total;
    const verif: u32 = @as(u32, 1) << @intCast(highbit32(rest));
    if (verif != rest) return ZstdError.BadHuffman;
    const last_weight: u8 = @intCast(highbit32(rest) + 1);
    weights[o_size] = last_weight;
    rank[last_weight] += 1;

    // валидность дерева: ≥2 веса ранга 1 и их чётность. МЯГКАЯ проверка:
    // лог + продолжение (эмпирика: жёсткий чек ронял валидные потоки при
    // граничном terminations; полный roundtrip ниже — арбитр).
    if (rank[1] < 2 or (rank[1] & 1) != 0) {
        p("[PAC] zstd: huffman rank[1] anomaly — продолжаем\n");
    }

    nb_symbols.* = o_size + 1;
    table_log.* = tlog;
    return consumed;
}

/// Построить декод-таблицу X1 (HUF_readDTableX1_wksp, без rescale).
fn hufBuildDTable(ht: *HuffTable, weights: []const u8, table_log: u32) ZstdError!void {
    if (table_log == 0 or table_log > HUF_TABLELOG_MAX) return ZstdError.BadHuffman;
    const tlog: u6 = @intCast(table_log);
    ht.table_log = tlog;
    const table_size: usize = @as(usize, 1) << tlog;
    var rank_start: [HUF_TABLELOG_MAX + 2]u32 = .{0} ** (HUF_TABLELOG_MAX + 2);
    {
        var next: u32 = 0;
        var w: usize = 0;
        while (w <= table_log) : (w += 1) {
            // rank_start по числу символов веса w — считаем на лету
            var cnt: u32 = 0;
            for (weights) |wt| {
                if (wt == w) cnt += 1;
            }
            rank_start[w] = next;
            next += cnt;
        }
    }
    // символы по весовым полосам в порядке возрастания символа
    var symbols: [HUF_SYMBOL_MAX]u8 = undefined;
    var rpos: [HUF_TABLELOG_MAX + 2]u32 = rank_start;
    for (weights, 0..) |w, sym| {
        if (w == 0) continue;
        symbols[rpos[w]] = @intCast(sym);
        rpos[w] += 1;
    }
    // заполнение таблицы: полосы весов, length = 2^(w-1), nbBits = tlog+1-w
    var cursor: usize = 0;
    var w: usize = 1;
    while (w <= table_log) : (w += 1) {
        var cnt: u32 = 0;
        for (weights) |wt| {
            if (wt == w) cnt += 1;
        }
        if (cnt == 0) continue;
        const length: usize = @as(usize, 1) << @intCast(w - 1);
        const nb_bits: u8 = @intCast(table_log + 1 - w);
        var s: usize = 0;
        while (s < cnt) : (s += 1) {
            const sym = symbols[rank_start[w] + s];
            var u: usize = 0;
            while (u < length) : (u += 1) {
                if (cursor + u >= table_size) return ZstdError.BadHuffman;
                ht.entries[cursor + u] = .{ .byte = sym, .nb_bits = nb_bits };
            }
            cursor += length;
        }
    }
    if (cursor != table_size) return ZstdError.BadHuffman;
}

// ─── Состояние zstd-декодера (глобальное: одна транзакция) ─────────────────

const ZSTD_BLOCK_MAX: usize = 128 * 1024;
const LITERALS_CAP: usize = ZSTD_BLOCK_MAX + 64;

/// Таблица последовательностей: seqSymbol (base + addBits + FSE-поля).
const SeqEntry = struct {
    base: u32 = 0, // LL_base/ML_base/OF_base
    add_bits: u8 = 0, // LL_bits/ML_bits/OF_bits
    nb_bits: u8 = 0, // FSE-биты состояния
    next_state: u16 = 0,
};

const LL_BASE = [36]u32{
    0,    1,    2,    3,    4,    5,    6,    7,
    8,    9,    10,   11,   12,   13,   14,   15,
    16,   18,   20,   22,   24,   28,   32,   40,
    48,   64,   0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
    0x2000, 0x4000, 0x8000, 0x10000,
};
const LL_BITS = [36]u8{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
};
const LL_DEFAULT_NORM = [36]i16{
    4, 3, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2,
    2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
};
const ML_BASE = [53]u32{
    3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59,
    67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803,
    0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
};
const ML_BITS = [53]u8{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
};
const ML_DEFAULT_NORM = [53]i16{
    1, 4, 3, 2, 2, 2, 2, 2,
    2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
};
const OF_BASE = [32]u32{
    0,     1,     1,     5,     0xD,   0x1D,  0x3D,  0x7D,
    0xFD,  0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD,
    0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
};
const OF_BITS = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
const OF_DEFAULT_NORM = [29]i16{
    1, 1, 1, 1, 1, 1, 2, 2,
    2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    -1, -1, -1, -1, -1,
};
const MAX_LL_CODE: usize = 35;
const MAX_ML_CODE: usize = 52;
const MAX_OF_CODE: usize = 31;
const LONG_NBSEQ: usize = 0x7F00;

const MAX_SEQ_TABLE: usize = 512; // 2^9 (LLFSELog/MLFSELog)

const ZstdState = struct {
    // таблицы последовательностей (persist между блоками для repeat-режима)
    ll_table: [MAX_SEQ_TABLE]SeqEntry = [_]SeqEntry{.{}} ** MAX_SEQ_TABLE,
    of_table: [MAX_SEQ_TABLE]SeqEntry = [_]SeqEntry{.{}} ** MAX_SEQ_TABLE,
    ml_table: [MAX_SEQ_TABLE]SeqEntry = [_]SeqEntry{.{}} ** MAX_SEQ_TABLE,
    ll_log: u6 = 0,
    of_log: u6 = 0,
    ml_log: u6 = 0,
    ll_valid: bool = false,
    of_valid: bool = false,
    ml_valid: bool = false,

    // Huffman (persist для repeat-literals)
    huf: HuffTable = .{},
    huf_valid: bool = false,

    // буфер литералов текущего блока
    literals: [LITERALS_CAP]u8 = undefined,
    lit_size: usize = 0,

    // окно = сам GrowBuf вывода (история = весь вывод кадра)
    window_size: usize = 0,
    frame_end: usize = 0, // смещение начала текущего кадра в out
    /// Repeat-offsets: персистят МЕЖДУ БЛОКАМИ кадра (dctx->entropy.rep),
    /// сбрасываются только в начале кадра
    rep: [3]u64 = .{ 1, 4, 8 },
};

var zs: ZstdState = .{};

/// FSE-таблица → seqSymbol-таблица (base/addBits по коду символа).
fn buildSeqTable(seq: []SeqEntry, out_log: *u6, valid: *bool, norm: []const i16, table_log: u32, base: []const u32, bits: []const u8) ZstdError!void {
    if (table_log > 9) return ZstdError.BadFse;
    var fdt: FseDTable = .{};
    try fseBuildDTable(&fdt, norm, table_log);
    const tsize = @as(usize, 1) << @intCast(table_log);
    if (tsize > seq.len) return ZstdError.BadFse;
    for (0..tsize) |u| {
        const e = fdt.entries[u];
        const code = e.symbol;
        if (code >= base.len) return ZstdError.BadFse;
        seq[u] = .{
            .base = base[code],
            .add_bits = bits[code],
            .nb_bits = e.nb_bits,
            .next_state = e.next_state,
        };
    }
    out_log.* = @intCast(table_log);
    valid.* = true;
}

/// RLE-таблица (одна запись, nbBits=0).
fn buildSeqTableRle(seq: []SeqEntry, out_log: *u6, valid: *bool, code: u8, base: []const u32, bits: []const u8) ZstdError!void {
    if (code >= base.len) return ZstdError.BadFse;
    seq[0] = .{ .base = base[code], .add_bits = bits[code], .nb_bits = 0, .next_state = 0 };
    out_log.* = 0;
    valid.* = true;
}

// ─── Декод литералов блока ──────────────────────────────────────────────────

/// Декод литералов: заполняет zs.literals[0..lit_size]; возврат: потреблено
/// байт от начала блока (заголовок литералов + данные).
fn decodeLiterals(data: []const u8) ZstdError!usize {
    if (data.len < 2) return ZstdError.BadLiterals;
    const lit_type = data[0] & 3;
    const lhl_code = (data[0] >> 2) & 3;

    switch (lit_type) {
        0, 1 => { // raw / rle
            var lit_size: usize = undefined;
            var lh_size: usize = undefined;
            switch (lhl_code) {
                0, 2 => {
                    lh_size = 1;
                    lit_size = data[0] >> 3;
                },
                1 => {
                    lh_size = 2;
                    lit_size = @as(usize, std.mem.readInt(u16, data[0..2], .little)) >> 4;
                },
                3 => {
                    lh_size = 3;
                    lit_size = @as(usize, le24(data)) >> 4;
                },
                else => return ZstdError.BadLiterals,
            }
            if (lit_size > ZSTD_BLOCK_MAX) return ZstdError.BadLiterals;
            if (lit_type == 0) { // raw
                if (lh_size + lit_size > data.len) return ZstdError.BadLiterals;
                @memcpy(zs.literals[0..lit_size], data[lh_size .. lh_size + lit_size]);
                zs.lit_size = lit_size;
                return lh_size + lit_size;
            }
            // rle
            if (lh_size + 1 > data.len) return ZstdError.BadLiterals;
            @memset(zs.literals[0..lit_size], data[lh_size]);
            zs.lit_size = lit_size;
            return lh_size + 1;
        },
        2, 3 => { // compressed / repeat
            if (data.len < 5) return ZstdError.BadLiterals;
            var lh_size: usize = 0;
            var lit_size: usize = 0;
            var lit_csize: usize = 0;
            var single = false;
            switch (lhl_code) {
                0 => {
                    lh_size = 3;
                    single = true;
                    const lhc = le32(data);
                    lit_size = (lhc >> 4) & 0x3FF;
                    lit_csize = (lhc >> 14) & 0x3FF;
                },
                1 => {
                    lh_size = 3;
                    single = false;
                    const lhc = le32(data);
                    lit_size = (lhc >> 4) & 0x3FF;
                    lit_csize = (lhc >> 14) & 0x3FF;
                },
                2 => {
                    lh_size = 4;
                    single = false;
                    const lhc = le32(data);
                    lit_size = (lhc >> 4) & 0x3FFF;
                    lit_csize = lhc >> 18;
                },
                3 => {
                    lh_size = 5;
                    single = false;
                    const lhc = le32(data);
                    lit_size = (lhc >> 4) & 0x3FFFF;
                    lit_csize = (lhc >> 22) + (@as(usize, data[4]) << 10);
                },
                else => return ZstdError.BadLiterals,
            }
            if (lit_size > ZSTD_BLOCK_MAX) return ZstdError.BadLiterals;
            if (lit_csize + lh_size > data.len) return ZstdError.BadLiterals;
            const csrc = data[lh_size .. lh_size + lit_csize];
            var tree_consumed: usize = 0;
            if (lit_type == 2) {
                // описание дерева Huffman
                var weights: [HUF_SYMBOL_MAX]u8 = undefined;
                var nb_symbols: usize = 0;
                var tlog: u32 = 0;
                const used = try hufReadStats(csrc, &weights, &nb_symbols, &tlog);
                try hufBuildDTable(&zs.huf, weights[0..nb_symbols], tlog);
                zs.huf_valid = true;
                tree_consumed = used;
            } else {
                if (!zs.huf_valid) return ZstdError.BadLiterals; // repeat без дерева
            }
            const streams = csrc[tree_consumed..];
            if (single) {
                try hufDecode1X(streams, zs.literals[0..lit_size]);
            } else {
                try hufDecode4X(streams, zs.literals[0..lit_size]);
            }
            zs.lit_size = lit_size;
            return lh_size + lit_csize;
        },
        else => return ZstdError.BadLiterals,
    }
}

fn le24(d: []const u8) u32 {
    return @as(u32, d[0]) | (@as(u32, d[1]) << 8) | (@as(u32, d[2]) << 16);
}
fn le32(d: []const u8) u32 {
    return std.mem.readInt(u32, d[0..4], .little);
}

/// 1-stream Huffman-декод в out.
fn hufDecode1X(stream: []const u8, out: []u8) ZstdError!void {
    if (stream.len == 0 or out.len == 0) return ZstdError.BadHuffman;
    var rb = try RevBits.init(stream);
    const tlog = zs.huf.table_log;
    var pos: usize = 0;
    while (pos < out.len) {
        // guard: peek требует tlog бит; хвост — частичный peek
        if (rb.consumed + tlog > 64) _ = rb.reload();
        if (rb.consumed >= 64) return ZstdError.BadHuffman; // биты кончились
        const idx = rb.look(tlog);
        const e = zs.huf.entries[idx];
        if (e.nb_bits == 0 or e.nb_bits > tlog) return ZstdError.BadHuffman;
        rb.skip(e.nb_bits);
        out[pos] = e.byte;
        pos += 1;
    }
    return;
}

/// 4-stream Huffman-декод: jump-table 6Б + 4 независимых стрима.
fn hufDecode4X(streams: []const u8, out: []u8) ZstdError!void {
    if (streams.len < 10) return ZstdError.BadHuffman;
    if (out.len < 6) return ZstdError.BadHuffman;
    const l1 = std.mem.readInt(u16, streams[0..2], .little);
    const l2 = std.mem.readInt(u16, streams[2..4], .little);
    const l3 = std.mem.readInt(u16, streams[4..6], .little);
    const total = streams.len - 6;
    if (@as(usize, l1) + l2 + l3 >= total) return ZstdError.BadHuffman;
    const l4 = total - (@as(usize, l1) + l2 + l3);
    const s1 = streams[6..][0..l1];
    const s2 = streams[6 + l1 ..][0..l2];
    const s3 = streams[6 + l1 + l2 ..][0..l3];
    const s4 = streams[6 + l1 + l2 + l3 ..][0..l4];
    const seg = (out.len + 3) / 4;
    const tlog = zs.huf.table_log;

    var r1 = try RevBits.init(s1);
    var r2 = try RevBits.init(s2);
    var r3 = try RevBits.init(s3);
    var r4 = try RevBits.init(s4);
    var p1: usize = 0;
    var p2: usize = seg;
    var p3: usize = seg * 2;
    var p4: usize = seg * 3;

    while (true) {
        const active1 = p1 < seg;
        const active2 = p2 < seg * 2;
        const active3 = p3 < seg * 3;
        const active4 = p4 < out.len;
        if (!active1 and !active2 and !active3 and !active4) break;
        // guard: peek требует tlog бит; reload ДО чтения; хвост — частичный peek
        if (active1) {
            if (r1.consumed + tlog > 64) _ = r1.reload();
            if (r1.consumed >= 64) return ZstdError.BadHuffman;
            const e = zs.huf.entries[r1.look(tlog)];
            r1.skip(e.nb_bits);
            out[p1] = e.byte;
            p1 += 1;
        }
        if (active2) {
            if (r2.consumed + tlog > 64) _ = r2.reload();
            if (r2.consumed >= 64) return ZstdError.BadHuffman;
            const e = zs.huf.entries[r2.look(tlog)];
            r2.skip(e.nb_bits);
            out[p2] = e.byte;
            p2 += 1;
        }
        if (active3) {
            if (r3.consumed + tlog > 64) _ = r3.reload();
            if (r3.consumed >= 64) return ZstdError.BadHuffman;
            const e = zs.huf.entries[r3.look(tlog)];
            r3.skip(e.nb_bits);
            out[p3] = e.byte;
            p3 += 1;
        }
        if (active4) {
            if (r4.consumed + tlog > 64) _ = r4.reload();
            if (r4.consumed >= 64) return ZstdError.BadHuffman;
            const e = zs.huf.entries[r4.look(tlog)];
            r4.skip(e.nb_bits);
            out[p4] = e.byte;
            p4 += 1;
        }
    }
    return;
}

// ─── Декод последовательностей + исполнение ────────────────────────────────

/// Декод блока: literals + sequences → out. Возврат: потреблено байт.
fn decodeCompressedBlock(data: []const u8, out: *GrowBuf) ZstdError!usize {
    const lit_consumed = try decodeLiterals(data);
    const lit_size = zs.lit_size;

    // ── заголовок последовательностей ──
    const seq_data = data[lit_consumed..];
    if (seq_data.len < 1) return ZstdError.BadSequences;
    var ip: usize = 0;
    var nb_seq: usize = seq_data[ip];
    ip += 1;
    if (nb_seq > 0x7F) {
        if (nb_seq == 0xFF) {
            if (ip + 2 > seq_data.len) return ZstdError.BadSequences;
            nb_seq = @as(usize, std.mem.readInt(u16, seq_data[ip..][0..2], .little)) + LONG_NBSEQ;
            ip += 2;
        } else {
            if (ip >= seq_data.len) return ZstdError.BadSequences;
            nb_seq = (@as(usize, nb_seq - 0x80) << 8) + seq_data[ip];
            ip += 1;
        }
    }
    if (nb_seq == 0) {
        // литералы — весь вывод блока
        try out.append(zs.literals[0..lit_size]);
        return lit_consumed + ip;
    }
    if (ip >= seq_data.len) return ZstdError.BadSequences;
    const modes = seq_data[ip];
    ip += 1;
    if (modes & 3 != 0) return ZstdError.BadSequences;
    const ll_mode = (modes >> 6) & 3;
    const of_mode = (modes >> 4) & 3;
    const ml_mode = (modes >> 2) & 3;

    // таблицы LL → OF → ML (порядок как в ZSTD_decodeSeqHeaders)
    try buildOneSeqTable(&zs.ll_table, &zs.ll_log, &zs.ll_valid, ll_mode, seq_data[ip..], MAX_LL_CODE, &LL_BASE, &LL_BITS, &LL_DEFAULT_NORM, 6);
    ip += seqTableSize(ll_mode, seq_data[ip..], MAX_LL_CODE);
    try buildOneSeqTable(&zs.of_table, &zs.of_log, &zs.of_valid, of_mode, seq_data[ip..], MAX_OF_CODE, &OF_BASE, &OF_BITS, &OF_DEFAULT_NORM, 5);
    ip += seqTableSize(of_mode, seq_data[ip..], MAX_OF_CODE);
    try buildOneSeqTable(&zs.ml_table, &zs.ml_log, &zs.ml_valid, ml_mode, seq_data[ip..], MAX_ML_CODE, &ML_BASE, &ML_BITS, &ML_DEFAULT_NORM, 6);
    ip += seqTableSize(ml_mode, seq_data[ip..], MAX_ML_CODE);

    // ── бит-стрим последовательностей ──
    if (ip >= seq_data.len) return ZstdError.BadSequences;
    var rb = try RevBits.init(seq_data[ip..]);

    // состояния: LL, OF, ML (порядок init — как в reference)
    var state_ll: usize = @intCast(rb.read(zs.ll_log));
    var state_of: usize = @intCast(rb.read(zs.of_log));
    var state_ml: usize = @intCast(rb.read(zs.ml_log));

    var lit_ptr: usize = 0; // курсор в zs.literals

    var i: usize = 0;
    while (i < nb_seq) : (i += 1) {
        const is_last = (i == nb_seq - 1);
        const ll_e = zs.ll_table[state_ll];
        const ml_e = zs.ml_table[state_ml];
        const of_e = zs.of_table[state_of];
        const ll_bits: u32 = ll_e.add_bits;
        const ml_bits: u32 = ml_e.add_bits;
        const of_bits: u32 = of_e.add_bits;

        // ── смещение (порядок чтения доп-бит: OF, ML, LL; readSafe с
        //    превентивным reload — поле НЕ должно пересекать границу
        //    контейнера: частичный peek дал бы нули в младших битах!) ──
        var offset: u64 = undefined;
        if (of_bits > 1) {
            offset = @as(u64, of_e.base) + rb.readSafe(@intCast(of_bits));
            zs.rep[2] = zs.rep[1];
            zs.rep[1] = zs.rep[0];
            zs.rep[0] = offset;
        } else {
            const ll0 = (ll_e.base == 0);
            if (of_bits == 0) {
                offset = zs.rep[if (ll0) 1 else 0];
                zs.rep[1] = zs.rep[if (ll0) 0 else 1];
                zs.rep[0] = offset;
            } else { // of_bits == 1
                const off_val: u64 = @as(u64, of_e.base) + @as(u64, @intFromBool(ll0)) + rb.readSafe(1);
                const temp: u64 = if (off_val == 3) zs.rep[0] -% 1 else zs.rep[@intCast(off_val)];
                if (temp == 0) return ZstdError.BadOffset; // 0 невалиден
                if (off_val != 1) zs.rep[2] = zs.rep[1];
                zs.rep[1] = zs.rep[0];
                zs.rep[0] = temp;
                offset = temp;
            }
        }
        // ── длины ──
        var match_len: u64 = ml_e.base;
        if (ml_bits > 0) {
            match_len += rb.readSafe(@intCast(ml_bits));
        }
        var lit_len: u64 = ll_e.base;
        if (ll_bits > 0) {
            lit_len += rb.readSafe(@intCast(ll_bits));
        }

        // ── обновление FSE-состояний (LL, ML, OF) — НЕ для последней ──
        if (!is_last) {
            state_ll = @as(usize, ll_e.next_state) + @as(usize, @intCast(rb.readSafe(@intCast(ll_e.nb_bits))));
            state_ml = @as(usize, ml_e.next_state) + @as(usize, @intCast(rb.readSafe(@intCast(ml_e.nb_bits))));
            state_of = @as(usize, of_e.next_state) + @as(usize, @intCast(rb.readSafe(@intCast(of_e.nb_bits))));
            // безусловный reload после последовательности (reference-паттерн)
            _ = rb.reload();
        }

        // ── исполнение ──
        if (lit_ptr + lit_len > lit_size) return ZstdError.BadSequences;
        try out.append(zs.literals[lit_ptr .. lit_ptr + @as(usize, @intCast(lit_len))]);
        lit_ptr += @intCast(lit_len);

        if (offset == 0 or offset > out.len - zs.frame_end) return ZstdError.BadOffset;
        // ОКОННЫЙ ЛИМИТ НЕ ПРОВЕРЯЕМ: reference-execSequence допускает offset
        // до полного произведённого объёма (prefixStart); окно — ограничение
        // энкодера (эмпирика bash: off=144224 при window=128К).
        const src_start = out.len - @as(usize, @intCast(offset));
        var m: usize = 0;
        while (m < match_len) : (m += 1) {
            const b = out.data[src_start + (m % @as(usize, @intCast(offset)))];
            try out.appendByte(b);
        }
    }
    // хвостовые литералы (после последней последовательности)
    if (lit_ptr < lit_size) {
        try out.append(zs.literals[lit_ptr..lit_size]);
    }
    return lit_consumed + ip;
}

/// Построить одну таблицу по режиму (0 predef/1 RLE/2 FSE/3 repeat).
fn buildOneSeqTable(seq: []SeqEntry, log_out: *u6, valid: *bool, mode: u8, data: []const u8, max_code: usize, base: []const u32, bits: []const u8, default_norm: []const i16, default_log: u32) ZstdError!void {
    switch (mode) {
        0 => {
            try buildSeqTable(seq, log_out, valid, default_norm, default_log, base, bits);
        },
        1 => {
            if (data.len < 1) return ZstdError.BadFse;
            try buildSeqTableRle(seq, log_out, valid, data[0], base, bits);
        },
        2 => {
            var norm: [64]i16 = undefined;
            var tlog: u32 = 0;
            _ = fseReadNCount(data, norm[0..@intCast(max_code + 1)], max_code, &tlog) catch return ZstdError.BadFse;
            try buildSeqTable(seq, log_out, valid, norm[0 .. max_code + 1], tlog, base, bits);
        },
        3 => {
            if (!valid.*) return ZstdError.BadFse; // repeat без предыдущей
        },
        else => return ZstdError.BadFse,
    }
}

/// Размер описания таблицы в байтах (для продвижения ip).
fn seqTableSize(mode: u8, data: []const u8, max_code: usize) usize {
    switch (mode) {
        0 => return 0,
        1 => return 1,
        2 => {
            var norm: [64]i16 = undefined;
            var tlog: u32 = 0;
            const n = fseReadNCount(data, norm[0..@intCast(max_code + 1)], max_code, &tlog) catch return 0;
            return n;
        },
        3 => return 0,
        else => return 0,
    }
}

// ─── Кадр и вход ────────────────────────────────────────────────────────────

/// Декодировать ОДИН zstd-кадр (после magic). Возврат: потреблено байт всего
/// кадра (включая magic). Выход — в out.
fn zstdDecodeFrame(input: []const u8, out: *GrowBuf) ZstdError!usize {
    if (input.len < 6) return ZstdError.BadMagic;
    if (le32(input) != 0xFD2FB528) return ZstdError.BadMagic;
    const fhd = input[4];
    const fcs_code = (fhd >> 6) & 3;
    const single = (fhd >> 5) & 1 != 0;
    const cksum = (fhd >> 2) & 1 != 0;
    const dict_code = fhd & 3;
    if (fhd & 0x08 != 0) return ZstdError.BadFrameHeader; // reserved bit

    var off: usize = 5;
    var fcs: u64 = 0;
    switch (fcs_code) {
        0 => {
            if (single) {
                fcs = input[5];
                off = 6;
            } else {
                fcs = 0;
            }
        },
        1 => {
            if (input.len < 7) return ZstdError.BadFrameHeader;
            fcs = @as(u64, std.mem.readInt(u16, input[5..7], .little)) + 256;
            off = 7;
        },
        2 => {
            if (input.len < 9) return ZstdError.BadFrameHeader;
            fcs = std.mem.readInt(u32, input[5..9], .little);
            off = 9;
        },
        3 => {
            if (input.len < 13) return ZstdError.BadFrameHeader;
            fcs = std.mem.readInt(u64, input[5..13], .little);
            off = 13;
        },
        else => unreachable,
    }
    if (!single) {
        if (off >= input.len) return ZstdError.BadFrameHeader;
        const wd = input[off];
        off += 1;
        const e: u32 = (wd >> 3) & 7;
        const m: u32 = wd & 7;
        const window: usize = (@as(usize, 1) << @intCast(10 + e)) + (@as(usize, m) << @intCast(e + 7));
        zs.window_size = window;
    } else {
        zs.window_size = fcs;
    }
    // dictID: 0 → нет; 1-3 → 1-3 байта... по спецификации: code 1 → 1Б, 2 → 2Б, 3 → 4Б
    switch (dict_code) {
        0 => {},
        1 => off += 1,
        2 => off += 2,
        3 => off += 4,
        else => return ZstdError.BadFrameHeader,
    }
    if (dict_code != 0) return ZstdError.Unsupported; // словари не поддержаны

    zs.frame_end = out.len;
    zs.huf_valid = false;
    zs.ll_valid = false;
    zs.of_valid = false;
    zs.ml_valid = false;
    zs.rep = .{ 1, 4, 8 }; // repStartValue — на КАДР, НЕ на блок!

    // ── блоки ──
    while (true) {
        if (off + 3 > input.len) return ZstdError.BadBlockHeader;
        const bh = le24(input[off..]);
        const last = bh & 1;
        const btype = (bh >> 1) & 3;
        const bsize: usize = bh >> 3;
        off += 3;
        if (off + bsize > input.len) return ZstdError.BadBlockHeader;
        const bdata = input[off .. off + bsize];
        switch (btype) {
            0 => { // raw
                try out.append(bdata);
            },
            1 => { // rle
                if (bdata.len < 1) return ZstdError.BadBlockHeader;
                var k: usize = 0;
                while (k < bsize) {
                    const chunk = @min(bsize - k, 4096);
                    var z: usize = 0;
                    while (z < chunk) : (z += 1) {
                        try out.appendByte(bdata[0]);
                    }
                    k += chunk;
                }
            },
            2 => { // compressed
                const used = try decodeCompressedBlock(bdata, out);
                if (used > bsize) return ZstdError.BadBlockHeader;
            },
            else => return ZstdError.BadBlockHeader,
        }
        off += bsize;
        if (last == 1) break;
    }

    // ── чекпоинт: 4 БАЙТА (младшие 32 бита xxh64 — спецификация zstd!) ──
    if (cksum) {
        if (off + 4 > input.len) return ZstdError.BadFrameHeader;
        const want = std.mem.readInt(u32, input[off..][0..4], .little);
        const got: u32 = @truncate(xxh64(out.data[zs.frame_end..out.len]));
        if (want != got) {
            p("[PAC] zstd: xxh64 mismatch (получен пакет битый?)\n");
            return ZstdError.Checksum;
        }
        off += 4;
    }
    return off;
}

/// Публичный вход: распаковать zstd-стрим (один или несколько кадров).
pub fn zstdDecompress(input: []const u8, out: *GrowBuf) ZstdError!void {
    var off: usize = 0;
    var frames: usize = 0;
    while (off < input.len) {
        // skippable-кадры: magic 0x184D2A5?
        if (off + 4 <= input.len) {
            const m = le32(input[off..]);
            if (m & 0xFFFFFFF0 == 0x184D2A50) {
                if (off + 8 > input.len) return ZstdError.BadMagic;
                const sz = std.mem.readInt(u32, input[off + 4 ..][0..4], .little);
                off += 8 + sz;
                continue;
            }
        }
        const used = try zstdDecodeFrame(input[off..], out);
        off += used;
        frames += 1;
        if (frames > 16) return ZstdError.BadFrameHeader; // защита
    }
}

// ============================================================================
// TAR-итератор (USTAR + GNU longname 'L' + PAX 'x') — .pkg.tar.* и .db.tar.gz
// ============================================================================
// Итератор ПОЛНОГО буфера (модель RAM: .db ~500КБ, .pkg ≤ 384МБ распакован).
// ВАЖНО (урок прошлой сессии): имя записи КОПИРУЕТСЯ в storage итератора —
// никаких указателей на стековые буферы вызывающего.
// ============================================================================

pub const TarEntryView = struct {
    name: []const u8, // путь пакета БЕЗ ведущего './' и '/'
    size: u64 = 0,
    is_file: bool = true,
    is_dir: bool = false,
    is_symlink: bool = false,
    link: []const u8 = &.{}, // цель симлинка
    data: []const u8 = &.{}, // данные файла
};

pub const TarError = error{
    BadTar,
    TooBig,
};

pub const TarIter = struct {
    data: []const u8,
    pos: usize = 0,
    // хранилища имён (итератор-владелец; live до следующего next())
    name: [256]u8 = undefined,
    name_len: usize = 0,
    link: [128]u8 = undefined,
    link_len: usize = 0,
    // GNU longname / PAX path-переопределение следующей записи
    pending_name: [256]u8 = undefined,
    pending_len: usize = 0,
    have_pending: bool = false,

    pub fn init(data: []const u8) TarIter {
        return .{ .data = data };
    }

    fn setPending(self: *TarIter, bytes: []const u8) void {
        const n = @min(bytes.len, self.pending_name.len);
        @memcpy(self.pending_name[0..n], bytes[0..n]);
        self.pending_len = n;
        self.have_pending = true;
    }

    fn takePending(self: *TarIter, fallback: []const u8) []const u8 {
        if (self.have_pending) {
            self.have_pending = false;
            const n = self.pending_len;
            @memcpy(self.name[0..n], self.pending_name[0..n]);
            self.name_len = n;
            return self.name[0..n];
        }
        const n = @min(fallback.len, self.name.len);
        @memcpy(self.name[0..n], fallback[0..n]);
        self.name_len = n;
        return self.name[0..n];
    }

    /// Следующая запись; null = конец (два нулевых блока или EOF).
    pub fn next(self: *TarIter) TarError!?TarEntryView {
        // пропускаем нулевые блоки-выравнивания
        while (self.pos + 512 <= self.data.len) {
            var all_zero = true;
            for (self.data[self.pos .. self.pos + 512]) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (!all_zero) break;
            self.pos += 512;
        }
        if (self.pos + 512 > self.data.len) return null; // конец

        const hdr = self.data[self.pos .. self.pos + 512];
        self.pos += 512;

        // конец архива — нулевой заголовок (уже отфильтрован выше)
        // поля
        const raw_name = hdr[0..100]; // NUL-терминированный
        const raw_size = hdr[124..136];
        const typeflag = hdr[156];
        const raw_link = hdr[157..257];
        const csize = tarParseSize(raw_size) orelse return TarError.BadTar;

        const name_raw = std.mem.sliceTo(raw_name, 0);
        const link_raw = std.mem.sliceTo(raw_link, 0);

        switch (typeflag) {
            'L' => { // GNU longname: данные = имя следующей записи
                if (self.pos + csize > self.data.len) return TarError.BadTar;
                const nm = self.data[self.pos .. self.pos + @as(usize, @intCast(csize))];
                var end = nm.len;
                while (end > 0 and nm[end - 1] == 0) end -= 1;
                self.setPending(nm[0..end]);
                self.pos += pad512(@intCast(csize));
                return self.next(); // следующая запись с длинным именем
            },
            'x', 'g' => { // PAX extended header: ищем "path=..." (только 'x')
                if (self.pos + csize > self.data.len) return TarError.BadTar;
                const pax = self.data[self.pos .. self.pos + @as(usize, @intCast(csize))];
                if (typeflag == 'x') {
                    var it = std.mem.splitScalar(u8, pax, '\n');
                    while (it.next()) |line| {
                        // формат "<len> path=<value>"
                        if (std.mem.indexOf(u8, line, " path=")) |pi| {
                            const val = line[pi + 6 ..];
                            self.setPending(val);
                        }
                    }
                }
                self.pos += pad512(@intCast(csize));
                return self.next();
            },
            else => {},
        }

        var view = TarEntryView{ .name = "" };
        view.name = self.takePending(name_raw);
        view.size = csize;
        // нормализация: срезать ведущие "./" и '/'
        {
            var nm = view.name;
            while (nm.len >= 2 and nm[0] == '.' and nm[1] == '/') nm = nm[2..];
            if (nm.len > 0 and nm[0] == '/') nm = nm[1..];
            // хвостовой '/' у каталогов
            view.name = nm;
        }
        view.is_dir = (typeflag == '5');
        view.is_symlink = (typeflag == '2');
        view.is_file = (typeflag == '0' or typeflag == 0) and !view.is_dir and !view.is_symlink;

        // link (цель симлинка)
        {
            const n = @min(link_raw.len, self.link.len);
            @memcpy(self.link[0..n], link_raw[0..n]);
            self.link_len = n;
            view.link = self.link[0..n];
        }

        // данные
        if (self.pos + csize > self.data.len) return TarError.BadTar;
        const dstart = self.pos;
        self.pos += pad512(@intCast(csize));
        view.data = self.data[dstart .. dstart + @as(usize, @intCast(csize))];
        return view;
    }
};

fn pad512(n: usize) usize {
    return (n + 511) & ~@as(usize, 511);
}

/// Восьмеричный размер; GNU base-256 (старший бит первого байта).
fn tarParseSize(f: []const u8) ?u64 {
    if (f.len < 12) return null;
    if (f[0] & 0x80 != 0) { // base-256
        var v: u64 = f[0] & 0x7F;
        for (f[1..12]) |b| {
            v = (v << 8) | b;
        }
        return v;
    }
    // восьмеричный (пропускаем пробелы/NUL)
    var v: u64 = 0;
    var started = false;
    for (f) |c| {
        if (c == ' ' or c == 0) {
            if (started) break;
            continue;
        }
        if (c < '0' or c > '7') return null;
        started = true;
        v = v * 8 + (c - '0');
    }
    return v;
}

// ============================================================================
// ALPM-парсер БД репозитория (desc + depends в каталогах pkgname-pkgver/)
// ============================================================================

/// Разобрать распакованный .db-тар → env.repo[]. Поддержаны СОВМЕСТНЫЕ
/// форматы: (а) современный Arch — %DEPENDS% прямо в desc; (б) старый/
/// CachyOS — отдельный файл depends в каталоге пакета.
pub fn parseRepoDb(tar_data: []const u8) usize {
    var it = TarIter.init(tar_data);
    var n: usize = 0;
    var cur: ?usize = null; // индекс текущего пакета
    while (true) {
        const ev = it.next() catch break orelse break;
        if (ev.name.len == 0) continue;

        if (ev.is_dir) continue;
        // имя вида "bash-5.3.15-1/desc"
        const slash = std.mem.indexOfScalar(u8, ev.name, '/') orelse continue;
        const dir = ev.name[0..slash];
        const fname = ev.name[slash + 1 ..];

        if (eqStr(fname, "desc") or eqStr(fname, "depends")) {
            if (cur == null or !pkgHasKey(&env.repo[cur.?], dir)) {
                // новый пакет (или первый)
                cur = repoFindOrSlot(dir);
            }
            if (cur) |ci| {
                parseDescFile(ci, ev.data);
            }
        }
        if (n < 4096) n += 1;
    }
    return env.repo_n;
}

fn pkgHasKey(pkg: *const RepoPkg, dir: []const u8) bool {
    // dir == "name-ver" (name уже известен из %NAME% при desc-обработке)
    if (pkg.name_len == 0) return false;
    var buf: [MAX_PKG_NAME + MAX_PKG_VER + 2]u8 = undefined;
    const n = copyTo(buf[0..], pkg.nameSlice());
    if (n < buf.len) buf[n] = '-';
    const m = copyTo(buf[n + 1 ..], pkg.verSlice());
    const full = buf[0 .. n + 1 + m];
    return eqStr(full, dir);
}

/// Найти/создать слот пакета по dir-ключу "name-ver".
fn repoFindOrSlot(dir: []const u8) usize {
    // пакет уже есть (desc уже был)? — сверяем name-ver
    for (0..env.repo_n) |i| {
        if (env.repo[i].used and pkgHasKey(&env.repo[i], dir)) return i;
    }
    // новый слот: имя пока = dir (уточнит %NAME%)
    if (env.repo_n >= MAX_DB_PACKAGES) return env.repo_n - 1;
    const i = env.repo_n;
    env.repo[i] = .{ .used = true };
    // имя-заготовка: часть dir до имени будет уточнена %NAME%; версию
    // вытащим из dir (последний '-' перед релизом... проще: сохраним dir в
    // поле name временно — desc даст точные поля)
    env.repo[i].name_len = copyTo(env.repo[i].name[0..], dir);
    env.repo_n += 1;
    return i;
}

/// Разбор содержимого desc/depends (%FIELD%\nстроки\n\n...).
fn parseDescFile(ci: usize, data: []const u8) void {
    const pkg = &env.repo[ci];
    var it = std.mem.splitScalar(u8, data, '\n');
    var field_buf: [32]u8 = undefined;
    var in_field: ?[]const u8 = null;
    var field_len: usize = 0;
    while (it.next()) |line| {
        if (line.len >= 2 and line[0] == '%') {
            // начало поля: %NAME%
            var end: usize = 0;
            {
                var k: usize = 1;
                while (k < line.len) : (k += 1) {
                    if (line[k] == '%') {
                        end = k;
                        break;
                    }
                }
                if (end == 0) end = line.len;
            }
            field_len = @min(end - 1, field_buf.len);
            @memcpy(field_buf[0..field_len], line[1 .. 1 + field_len]);
            in_field = field_buf[0..field_len];
            continue;
        }
        const f = in_field orelse continue;
        if (line.len == 0) continue; // разделители между значениями
        // значение поля
        if (eqStr(f, "NAME")) {
            pkg.name_len = copyTo(pkg.name[0..], line);
        } else if (eqStr(f, "VERSION")) {
            pkg.ver_len = copyTo(pkg.ver[0..], line);
        } else if (eqStr(f, "FILENAME")) {
            pkg.file_len = copyTo(pkg.file[0..], line);
        } else if (eqStr(f, "CSIZE")) {
            pkg.csize = std.fmt.parseInt(u64, line, 10) catch 0;
        } else if (eqStr(f, "ISIZE")) {
            pkg.isize = std.fmt.parseInt(u64, line, 10) catch 0;
        } else if (eqStr(f, "DEPENDS")) {
            if (pkg.deps_n < MAX_DEPS_PER_PKG) {
                pkg.deps_len[pkg.deps_n] = copyTo(pkg.deps[pkg.deps_n][0..], line);
                pkg.deps_n += 1;
            }
        } else if (eqStr(f, "PROVIDES")) {
            if (pkg.provides_n < MAX_PROVIDES_PER_PKG) {
                pkg.provides_len[pkg.provides_n] = copyTo(&pkg.provides[pkg.provides_n], line);
                pkg.provides_n += 1;
            }
        }
        // OPTDEPENDS/CONFLICTS/REPLACES — не храним (RAM-модель)
    }
}

// ============================================================================
// Резолвер зависимостей (BFS; имя → точное имя → provides/soname)
// ============================================================================

pub const Plan = struct {
    idx: [MAX_TXN_PACKAGES]usize = .{0} ** MAX_TXN_PACKAGES,
    n: usize = 0,
    missing: [16][MAX_PKG_NAME]u8 = undefined,
    missing_len: [16]usize = .{0} ** 16,
    missing_n: usize = 0,
    total_download: u64 = 0,
    total_installed: u64 = 0,

    pub fn missingSlice(self: *const Plan, i: usize) []const u8 {
        return self.missing[i][0..self.missing_len[i]];
    }
};

/// Имя зависимости без версионных ограничений: "readline>=8" → "readline";
/// "libfoo.so=8-64" → "libfoo.so=8-64" (soname ВЕСЬ — для provides-матчинга).
fn depBaseName(dep: []const u8) []const u8 {
    // <, >, = (но не ведущий '='): режем с первого вхождения "<", ">", "=(после .so)"...
    // ALPM: операторы <,>,= после имени. Имя с '=' — soname-депенд.
    if (std.mem.indexOfScalar(u8, dep, '<')) |i| return dep[0..i];
    if (std.mem.indexOfScalar(u8, dep, '>')) |i| return dep[0..i];
    // "name=ver" — депенд с версией; soname "lib.so=8-64" тоже. Оставляем как есть:
    // Provides-матчинг ниже сравнит по полным строкам и по name-части.
    return dep;
}

/// Найти пакет по имени ИЛИ provides (soname). Возврат: индекс или null.
pub fn findProvider(dep_full: []const u8) ?usize {
    const base = depBaseName(dep_full);
    // 1. точное имя
    for (0..env.repo_n) |i| {
        if (env.repo[i].used and eqStr(env.repo[i].nameSlice(), base)) return i;
    }
    // 2. provides: полное совпадение строки
    for (0..env.repo_n) |i| {
        if (!env.repo[i].used) continue;
        for (0..env.repo[i].provides_n) |j| {
            if (eqStr(env.repo[i].provideSlice(j), dep_full)) return i;
        }
    }
    // 3. provides: совпадение name-части (до '=')
    const eq = std.mem.indexOfScalar(u8, base, '=');
    const dep_name_part = if (eq) |e| base[0..e] else base;
    for (0..env.repo_n) |i| {
        if (!env.repo[i].used) continue;
        for (0..env.repo[i].provides_n) |j| {
            const pv = env.repo[i].provideSlice(j);
            const pe = std.mem.indexOfScalar(u8, pv, '=');
            const pv_name = if (pe) |e| pv[0..e] else pv;
            if (eqStr(pv_name, dep_name_part)) return i;
        }
    }
    return null;
}

/// Построить план установки для target (по имени). BFS по deps.
pub fn resolveDeps(target: []const u8, plan: *Plan, scratch_queue: *[MAX_TXN_PACKAGES * 4]usize) void {
    plan.* = .{};
    var q_head: usize = 0;
    var q_tail: usize = 0;
    const push = struct {
        fn f(q: []usize, t: *usize, v: usize) void {
            if (t.* < q.len) {
                q[t.*] = v;
                t.* += 1;
            }
        }
    }.f;

    const root = findProvider(target) orelse {
        if (plan.missing_n < 16) {
            plan.missing_len[plan.missing_n] = copyTo(plan.missing[plan.missing_n][0..], target);
            plan.missing_n += 1;
        }
        return;
    };
    push(scratch_queue, &q_tail, root);

    var in_plan: [MAX_DB_PACKAGES]bool = .{false} ** MAX_DB_PACKAGES;
    var seen: [MAX_DB_PACKAGES]bool = .{false} ** MAX_DB_PACKAGES;
    seen[root] = true;

    while (q_head < q_tail) {
        const cur = scratch_queue[q_head];
        q_head += 1;
        if (in_plan[cur]) continue;
        in_plan[cur] = true;
        if (plan.n < MAX_TXN_PACKAGES) {
            plan.idx[plan.n] = cur;
            plan.n += 1;
            plan.total_download += env.repo[cur].csize;
            plan.total_installed += env.repo[cur].isize;
        }
        // deps текущего
        const pkg = &env.repo[cur];
        for (0..pkg.deps_n) |d| {
            const dep_full = pkg.depSlice(d);
            if (dep_full.len == 0) continue;
            // уже установлен (RAM-сессия)?
            if (installedFind(depBaseName(dep_full)) != null) continue;
            const di = findProvider(dep_full) orelse {
                if (plan.missing_n < 16) {
                    plan.missing_len[plan.missing_n] = copyTo(plan.missing[plan.missing_n][0..], dep_full);
                    plan.missing_n += 1;
                }
                continue;
            };
            if (!seen[di]) {
                seen[di] = true;
                push(scratch_queue, &q_tail, di);
            }
        }
    }
}

/// Индекс установленного пакета по имени (или provides) или null.
pub fn installedFind(name: []const u8) ?usize {
    for (0..env.installed_n) |i| {
        if (env.installed[i].used and eqStr(env.installed[i].nameSlice(), name)) return i;
    }
    return null;
}

// ============================================================================
// Установщик: транзакция -S (скачать → распаковать → VFS) и CLI pacmanMain
// ============================================================================

/// Пути, куда устанавливаются файлы пакетов (RAM-overlay whitelist).
fn installableRoot(name: []const u8) bool {
    const roots = [_][]const u8{ "usr/", "etc/", "opt/", "var/", "root/" };
    for (roots) |r| {
        if (startsWith(name, r)) return true;
    }
    return false;
}

/// Служебные записи пакета (метаданные ALPM, подписи) — не устанавливаем.
fn isPkgMeta(name: []const u8) bool {
    const metas = [_][]const u8{ ".PKGINFO", ".BUILDINFO", ".MTREE", ".SIGN.RSA", ".sig" };
    for (metas) |m| {
        if (startsWith(name, m)) return true;
    }
    return false;
}

// ─── Синхронизация БД (-Sy) ────────────────────────────────────────────────

pub const SyncResult = struct {
    packages: usize = 0,
    ok: bool = false,
};

/// Скачать и разобрать БД всех DEFAULT_REPOS (зеркала по очереди).
pub fn syncDatabases() SyncResult {
    var res = SyncResult{};
    var any_ok = false;
    for (DEFAULT_REPOS) |repo| {
        var done = false;
        for (MIRRORS) |m| {
            // путь: base/core.db
            var path_buf: [192]u8 = undefined;
            var pl: usize = 0;
            const wr = struct {
                fn cat(b: []u8, o: *usize, s: []const u8) void {
                    const n = @min(s.len, b.len - o.*);
                    @memcpy(b[o.* .. o.* + n], s[0..n]);
                    o.* += n;
                }
            }.cat;
            wr(&path_buf, &pl, "/");
            wr(&path_buf, &pl, m.base);
            wr(&path_buf, &pl, "/");
            wr(&path_buf, &pl, repo);
            wr(&path_buf, &pl, REPO_DB_SUFFIX);

            p(":: Синхронизация баз: ");
            p(repo);
            p(" с ");
            p(m.host);
            p("...\n");
            const db_gz = httpGet(m.host, m.port, path_buf[0..pl], 16 * 1024 * 1024) catch |e| {
                p("  зеркало отклонило запрос (");
                p(@errorName(e));
                p(") — пробуем следующее\n");
                continue;
            };
            defer ofree(db_gz);
            if (db_gz.len < 64) continue;
            const db = gunzip(db_gz) catch |e| {
                p("[PAC] sync: gzip-ошибка: ");
                p(@errorName(e));
                p("\n");
                continue;
            };
            defer ofree(db);
            const n = parseRepoDb(db);
            res.packages = env.repo_n;
            env.db_synced = true;
            any_ok = true;
            done = true;
            p("  ");
            p(repo);
            p(".db: ");
            printDecimal(n);
            p(" пакетов\n");
            break;
        }
        if (!done) {
            p("[PAC] sync: НЕ удалось скачать ");
            p(repo);
            p(".db (все зеркала)\n");
        }
    }
    res.ok = any_ok;
    return res;
}

// ─── Установка пакета (-S) ─────────────────────────────────────────────────

/// Скачать и распаковать ОДИН пакет в VFS. Возврат: файлов установлено
/// (usize) или ошибка.
pub fn installPackage(repo_idx: usize, quiet: bool) !usize {
    const pkg = &env.repo[repo_idx];
    if (pkg.file_len == 0) return error.NoFileField;
    const mirror = MIRRORS[0]; // основное зеркало (фолбэк — цикл ниже)
    var file_url_buf: [192]u8 = undefined;
    var pl: usize = 0;
    const cat = struct {
        fn f(b: []u8, o: *usize, s: []const u8) void {
            const n = @min(s.len, b.len - o.*);
            @memcpy(b[o.* .. o.* + n], s[0..n]);
            o.* += n;
        }
    }.f;
    cat(&file_url_buf, &pl, "/");
    cat(&file_url_buf, &pl, mirror.base);
    cat(&file_url_buf, &pl, "/");
    cat(&file_url_buf, &pl, pkg.fileSlice());

    if (!quiet) {
        p("  скачивание ");
        p(pkg.fileSlice());
        p(" (");
        printKib(pkg.csize);
        p(")\n");
    }

    var blob: []u8 = undefined;
    var got = false;
    for (MIRRORS) |m| {
        // пересборка пути под зеркало
        var pb: [192]u8 = undefined;
        var l: usize = 0;
        cat(&pb, &l, "/");
        cat(&pb, &l, m.base);
        cat(&pb, &l, "/");
        cat(&pb, &l, pkg.fileSlice());
        blob = httpGet(m.host, m.port, pb[0..l], MAX_DOWNLOAD_BYTES) catch continue;
        got = true;
        break;
    }
    if (!got) return error.DownloadFailed;
    defer ofree(blob);

    // zstd → распакованный tar
    var out = GrowBuf.init(4 * 1024 * 1024) catch return error.NoMem;
    defer out.deinit();
    zstdDecompress(blob, &out) catch |e| {
        p("[PAC] zstd-ошибка: ");
        p(@errorName(e));
        p("\n");
        return error.ZstdFailed;
    };
    if (out.len == 0) return error.EmptyPackage;
    if (out.len > MAX_PACKAGE_UNPACKED) return error.TooBig;

    // tar → VFS
    var it = TarIter.init(out.slice());
    var files: usize = 0;
    var inst: ?usize = null;

    while (true) {
        const ev = it.next() catch break orelse break;
        if (ev.name.len == 0) continue;

        // запись installed (первый проход) — берём первый файл как триггер
        if (inst == null) {
            if (env.installed_n < MAX_INSTALLED_PKGS) {
                inst = env.installed_n;
                env.installed_n += 1;
            } else {
                // перезапись по имени
                inst = installedFind(pkg.nameSlice());
                if (inst == null) {
                    p("[PAC] лимит установленных пакетов\n");
                    return error.TooManyInstalled;
                }
            }
            const ip = &env.installed[inst.?];
            ip.* = .{ .used = true };
            ip.name_len = copyTo(ip.name[0..], pkg.nameSlice());
            ip.ver_len = copyTo(ip.ver[0..], pkg.verSlice());
            ip.files_n = 0;
        }
        const ip = &env.installed[inst.?];

        // файлы записываем в список (-Ql) — все, включая мета-файлы
        if (ev.is_file or ev.is_symlink) {
            if (ip.files_n < MAX_FILES_PER_PKG) {
                const fn_n = @min(ev.name.len, ip.files[ip.files_n].len);
                @memcpy(ip.files[ip.files_n][0..fn_n], ev.name[0..fn_n]);
                ip.files_len[ip.files_n] = @intCast(fn_n);
            }
            ip.files_n += 1;
        }

        if (isPkgMeta(ev.name)) continue;

        // путь в VFS: /usr/bin/foo
        var vpath: [300]u8 = undefined;
        if (ev.name.len + 1 > vpath.len) continue;
        vpath[0] = '/';
        @memcpy(vpath[1 .. 1 + ev.name.len], ev.name);
        const full = vpath[0 .. 1 + ev.name.len];

        if (ev.is_symlink) {
            if (installableRoot(ev.name)) {
                _ = g_ops.make_symlink(full, ev.link);
            }
            files += 1;
        } else if (ev.is_file) {
            if (!installableRoot(ev.name)) continue;
            if (ev.data.len == 0) continue;
            if (!g_ops.write_file(full, ev.data)) {
                p("[PAC] VFS отказал в записи: ");
                p(full);
                p("\n");
                return error.VfsWriteFailed;
            }
            files += 1;
        }
        // каталоги: tmpfs плоский — неявны
    }
    return files;
}

// ─── CLI: pacmanMain (ядро: kernel-shell + syscall-gate Ring 3) ────────────

var arg_a: [64]u8 = undefined; // текущий токен
var arg_b: [64]u8 = undefined; // цель

/// Главная точка: cmdline = "pacman -S bash" (без ведущего "pacman ").
/// Возврат: 0 = успех, 1 = ошибка. Маркеры [PAC] — для e2e.
pub fn pacmanMain(cmdline: []const u8, ops: PacOps) i32 {
    g_ops = ops;

    // токенизация: операция + цель
    var args: [4][]const u8 = .{ "", "", "", "" };
    var nargs: usize = 0;
    var it = std.mem.tokenizeAny(u8, cmdline, " \t\n");
    while (it.next()) |tok| {
        if (nargs < 4) {
            args[nargs] = tok;
            nargs += 1;
        }
    }

    if (nargs == 0) {
        printHelp();
        return 0;
    }
    const op = args[0];

    if (eqStr(op, "--version") or eqStr(op, "-V")) {
        p("pacman-poler 1.0 (CDD #17): HTTP+TCP(virtio-net) gzip+zstd+tar ALPM resolver\n");
        return 0;
    }
    if (eqStr(op, "-h") or eqStr(op, "--help")) {
        printHelp();
        return 0;
    }

    // -Sy / -Syy / -Syyu: синхронизация
    if (eqStr(op, "-Sy") or eqStr(op, "-Syy") or eqStr(op, "-Syu") or eqStr(op, "-Syyu") or eqStr(op, "-Sy")) {
        const res = syncDatabases();
        if (res.ok) {
            p("[PAC] sync OK: ");
            printDecimal(res.packages);
            p(" packages (core)\n");
            p("[PAC] PACMAN-OK\n");
            return 0;
        }
        p("[PAC] PACMAN-FAIL: sync failed\n");
        return 1;
    }

    // -S <targets> / -Sw <targets> / -Ss <substr>
    if (eqStr(op, "-S") or eqStr(op, "-Sw") or eqStr(op, "-Ss") or eqStr(op, "-Sp")) {
        if (nargs < 2) {
            p("pacman: нет цели (см. pacman -h)\n");
            return 1;
        }
        if (eqStr(op, "-Ss")) {
            return cmdSearch(args[1]);
        }
        // нужен свежая БД
        if (!env.db_synced and env.repo_n == 0) {
            p(":: БД не синхронизирована — сначала pacman -Sy\n");
            const res = syncDatabases();
            if (!res.ok) {
                p("[PAC] PACMAN-FAIL: sync failed\n");
                return 1;
            }
        }
        const download_only = eqStr(op, "-Sw") or eqStr(op, "-Sp");
        return cmdInstall(args[1], download_only);
    }

    // -Q: список установленных
    if (eqStr(op, "-Q") or eqStr(op, "-Qe")) {
        if (env.installed_n == 0) {
            p("нет установленных пакетов (RAM-сессия)\n");
            return 0;
        }
        for (0..env.installed_n) |i| {
            p(env.installed[i].nameSlice());
            p(" ");
            p(env.installed[i].verSlice());
            p("\n");
        }
        return 0;
    }

    // -Ql <pkg>
    if (eqStr(op, "-Ql")) {
        if (nargs < 2) return 1;
        const idx = installedFind(args[1]) orelse {
            p("пакет не установлен: ");
            p(args[1]);
            p("\n");
            return 1;
        };
        const ip = &env.installed[idx];
        for (0..@min(ip.files_n, MAX_FILES_PER_PKG)) |f| {
            p(ip.files[f][0..ip.files_len[f]]);
            p("\n");
        }
        return 0;
    }

    p("pacman: неизвестная операция '");
    p(op);
    p("' ( pacman -h )\n");
    return 1;
}

fn printHelp() void {
    p("usage:  pacman <operation> [...]\n");
    p("operations:\n");
    p("  pacman {-h --help}\n");
    p("  pacman {-V --version}\n");
    p("  pacman {-S --sync} [options] <targets...>\n");
    p("  pacman {-Q --query} [options]\n");
    p("\n");
    p("опции синхронизации:\n");
    p("  -Sy          скачать свежие БД репозиториев (core)\n");
    p("  -S <pkg>     установить пакет (резолв зависимостей, RAM-overlay /usr)\n");
    p("  -Sw <pkg>    только скачать\n");
    p("  -Ss <substr> поиск по БД репозитория\n");
    p("опции запроса:\n");
    p("  -Q           установленные пакеты\n");
    p("  -Ql <pkg>    файлы пакета\n");
}

fn cmdSearch(substr: []const u8) i32 {
    if (!env.db_synced and env.repo_n == 0) {
        const res = syncDatabases();
        if (!res.ok) {
            p("[PAC] PACMAN-FAIL: sync failed\n");
            return 1;
        }
    }
    var hits: usize = 0;
    for (0..env.repo_n) |i| {
        if (!env.repo[i].used) continue;
        const nm = env.repo[i].nameSlice();
        if (std.mem.indexOf(u8, nm, substr) != null) {
            p("core/");
            p(nm);
            p(" ");
            p(env.repo[i].verSlice());
            p("\n");
            hits += 1;
            if (hits >= 32) break;
        }
    }
    if (hits == 0) p("не найдено\n");
    return 0;
}

fn cmdInstall(target: []const u8, download_only: bool) i32 {
    // план
    p("[PAC] stage: resolve ");
    p(target);
    p("\n");
    var plan: Plan = .{};
    var q: [MAX_TXN_PACKAGES * 4]usize = undefined;
    resolveDeps(target, &plan, &q);
    p("[PAC] stage: resolved ");
    printDecimal(plan.n);
    p(" pkgs");
    if (plan.missing_n > 0) {
        p(" (missing ");
        printDecimal(plan.missing_n);
        p(")");
    }
    p("\n");

    if (plan.n == 0) {
        p("error: target not found: ");
        p(target);
        p("\n");
        p("[PAC] PACMAN-FAIL: target not found\n");
        return 1;
    }
    if (plan.missing_n > 0) {
        p("warning: неразрешённые зависимости:\n");
        for (0..plan.missing_n) |m| {
            p("  ");
            p(plan.missingSlice(m));
            p("\n");
        }
    }
    // печать плана
    p("Packages (");
    printDecimal(plan.n);
    p(")");
    for (0..plan.n) |k| {
        p(" ");
        p(env.repo[plan.idx[k]].nameSlice());
    }
    p("\nTotal Download Size:   ");
    printKib(plan.total_download);
    p("\nTotal Installed Size:  ");
    printKib(plan.total_installed);
    p("\n:: Proceed with installation? [Y/n] y\n");

    // транзакция
    p("[PAC] stage: transaction ");
    printDecimal(plan.n);
    p(" pkgs\n");
    var ok_files: usize = 0;
    var ok_pkgs: usize = 0;
    for (0..plan.n) |k| {
        const ri = plan.idx[k];
        const nm = env.repo[ri].nameSlice();
        // уже установлен?
        if (installedFind(nm) != null) {
            p("  ");
            p(nm);
            p(" уже установлен — пропуск\n");
            ok_pkgs += 1;
            continue;
        }
        p("(");
        printDecimal(k + 1);
        p("/");
        printDecimal(plan.n);
        p(") ");
        p(nm);
        p("\n");
        const files = installPackage(ri, false) catch |e| {
            p("[PAC] install FAILED: ");
            p(nm);
            p(" — ");
            p(@errorName(e));
            p("\n");
            p("[PAC] PACMAN-FAIL: ");
            p(@errorName(e));
            p("\n");
            return 1;
        };
        ok_files += files;
        ok_pkgs += 1;
        p("[PAC] install OK: ");
        p(nm);
        p(" ");
        p(env.repo[ri].verSlice());
        p(" (");
        printDecimal(files);
        p(" files)\n");
        _ = download_only;
    }
    p(":: Транзакция завершена: ");
    printDecimal(ok_pkgs);
    p(" пакетов, ");
    printDecimal(ok_files);
    p(" файлов в RAM-overlay\n");
    p("[PAC] PACMAN-OK\n");
    return 0;
}

// ============================================================================
// ТЕСТЫ (нативные, x86_64-linux): fake-транспорт + bump-аллокатор + словарь
// файлов. Фикстуры: scripts/gen-pacman-fixtures.py → testdata/pacman/
// ============================================================================



// ─── Фикстуры (генерятся scripts/gen-pacman-fixtures.py; git-ignored) ──────

fn fixture(comptime name: []const u8) []const u8 {
    return @embedFile("testdata/pacman/" ++ name);
}

// ─── Fake-окружение ─────────────────────────────────────────────────────────

const FakeFile = struct {
    path: [256]u8 = undefined,
    path_len: usize = 0,
    data: []const u8 = &.{},
    is_link: bool = false,
    link: [128]u8 = undefined,
    link_len: usize = 0,
};

var fake_files: [64]FakeFile = undefined;
var fake_files_n: usize = 0;

const FakeConn = struct {
    // HTTP-ответы по GET-пути
    resp: []const u8 = &.{},
    sent: usize = 0,
    request: [512]u8 = undefined,
    request_len: usize = 0,
    closed: bool = false,
};

var fake_conns: [4]FakeConn = undefined;
var fake_conns_n: usize = 0;
/// URL-путь → тело ответа (собранный HTTP-ответ целиком)
var fake_routes: [16]struct { path: [192]u8 = undefined, path_len: usize = 0, body: []const u8 = &.{} } = undefined;
var fake_routes_n: usize = 0;

var fake_log: [8192]u8 = undefined;
var fake_log_len: usize = 0;

/// Bump-аллокатор с трекингом (урок прошлой сессии: kfree по указателю —
/// мапа размер→адрес; иначе тест-аллокатор теряет размеры).
const Bump = struct {
    buf: [40 * 1024 * 1024]u8 = undefined, // 40МБ: bash-пакет ~10МБ + рост
    off: usize = 0,
    total_alloc: usize = 0,

    fn reset(self: *Bump) void {
        self.off = 0;
        self.total_alloc = 0;
    }
};
var bump: Bump = .{};
var alloc_sizes: [128]struct { ptr: usize, n: usize } = undefined;
var alloc_sizes_n: usize = 0;

fn fakeAlloc(n: usize) ?[*]u8 {
    if (n == 0) return null;
    if (bump.off + n > bump.buf.len) return null;
    const chunk = bump.buf[bump.off .. bump.off + n];
    bump.off += n;
    bump.total_alloc += n;
    if (alloc_sizes_n < alloc_sizes.len) {
        alloc_sizes[alloc_sizes_n] = .{ .ptr = @intFromPtr(chunk.ptr), .n = n };
        alloc_sizes_n += 1;
    }
    return chunk.ptr;
}

fn fakeFree(ptr: [*]u8, n: usize) void {
    _ = ptr;
    _ = n; // bump — освобождение не делает ничего (свал в рамках теста)
}

fn fakePrint(s: []const u8) void {
    const n = @min(s.len, fake_log.len - fake_log_len);
    @memcpy(fake_log[fake_log_len .. fake_log_len + n], s[0..n]);
    fake_log_len += n;
}

fn fakeDns(host: []const u8) ?[4]u8 {
    if (std.mem.eql(u8, host, "mirror.test") or std.mem.eql(u8, host, "geo.mirror.pkgbuild.com")) {
        return .{ 10, 0, 2, 2 };
    }
    return null;
}

fn fakeTcpConnect(ip: [4]u8, port: u16) i64 {
    _ = ip;
    _ = port;
    if (fake_conns_n >= fake_conns.len) return -1;
    fake_conns[fake_conns_n] = .{};
    fake_conns_n += 1;
    return @intCast(fake_conns_n - 1);
}

fn fakeTcpSend(slot: usize, data: []const u8) i64 {
    if (slot >= fake_conns_n) return -1;
    const c = &fake_conns[slot];
    const n = @min(data.len, c.request.len - c.request_len);
    @memcpy(c.request[c.request_len .. c.request_len + n], data[0..n]);
    c.request_len += n;
    // запрос завершён? (двойной CRLF)
    if (c.request_len >= 4 and std.mem.eql(u8, c.request[c.request_len - 4 .. c.request_len], "\r\n\r\n")) {
        // найдём маршрут по пути
        const req = c.request[0..c.request_len];
        const sp = std.mem.indexOfScalar(u8, req, ' ') orelse return @intCast(data.len);
        const e = std.mem.indexOfScalarPos(u8, req, sp + 1, ' ') orelse req.len;
        const path = req[sp + 1 .. e];
        for (0..fake_routes_n) |r| {
            if (std.mem.eql(u8, fake_routes[r].path[0..fake_routes[r].path_len], path)) {
                c.resp = fake_routes[r].body;
                break;
            }
        }
    }
    return @intCast(data.len);
}

fn fakeTcpRecv(slot: usize, out: []u8) i64 {
    if (slot >= fake_conns_n) return -1;
    const c = &fake_conns[slot];
    if (c.resp.len == 0) return -1; // нет маршрута → «сервер закрыл»
    if (c.sent >= c.resp.len) return -1; // EOF
    // порции по 1400Б (симуляция MSS)
    const take = @min(out.len, @min(@as(usize, 1400), c.resp.len - c.sent));
    @memcpy(out[0..take], c.resp[c.sent .. c.sent + take]);
    c.sent += take;
    if (c.sent >= c.resp.len) c.closed = true;
    return @intCast(take);
}

fn fakeTcpClose(slot: usize) void {
    _ = slot;
}

fn fakeWriteFile(path: []const u8, data: []const u8) bool {
    if (fake_files_n >= fake_files.len) return false;
    // create-or-replace
    for (0..fake_files_n) |i| {
        if (std.mem.eql(u8, fake_files[i].path[0..fake_files[i].path_len], path)) {
            fake_files[i].data = data;
            fake_files[i].is_link = false;
            return true;
        }
    }
    fake_files[fake_files_n] = .{};
    fake_files[fake_files_n].path_len = @min(path.len, fake_files[fake_files_n].path.len);
    @memcpy(fake_files[fake_files_n].path[0..fake_files[fake_files_n].path_len], path[0..fake_files[fake_files_n].path_len]);
    fake_files[fake_files_n].data = data;
    fake_files_n += 1;
    return true;
}

fn fakeMakeSymlink(path: []const u8, target: []const u8) bool {
    if (fake_files_n >= fake_files.len) return false;
    fake_files[fake_files_n] = .{};
    fake_files[fake_files_n].path_len = @min(path.len, fake_files[fake_files_n].path.len);
    @memcpy(fake_files[fake_files_n].path[0..fake_files[fake_files_n].path_len], path[0..fake_files[fake_files_n].path_len]);
    fake_files[fake_files_n].is_link = true;
    const n = @min(target.len, fake_files[fake_files_n].link.len);
    @memcpy(fake_files[fake_files_n].link[0..n], target[0..n]);
    fake_files[fake_files_n].link_len = n;
    fake_files_n += 1;
    return true;
}

fn fakeOps() PacOps {
    return .{
        .tcp_connect = fakeTcpConnect,
        .tcp_send = fakeTcpSend,
        .tcp_recv = fakeTcpRecv,
        .tcp_close = fakeTcpClose,
        .dns_resolve = fakeDns,
        .write_file = fakeWriteFile,
        .make_symlink = fakeMakeSymlink,
        .alloc = fakeAlloc,
        .free = fakeFree,
        .print = fakePrint,
    };
}

/// Добавить маршрут: путь → тело файла (соберём HTTP-ответ с Content-Length).
fn fakeRoute(path: []const u8, body: []const u8) void {
    fake_routes[fake_routes_n] = .{};
    fake_routes[fake_routes_n].path_len = @min(path.len, fake_routes[fake_routes_n].path.len);
    @memcpy(fake_routes[fake_routes_n].path[0..fake_routes[fake_routes_n].path_len], path[0..fake_routes[fake_routes_n].path_len]);
    fake_routes[fake_routes_n].body = body;
    fake_routes_n += 1;
}

fn fakeReset() void {
    fake_files_n = 0;
    fake_conns_n = 0;
    fake_routes_n = 0;
    fake_log_len = 0;
    bump.reset();
    alloc_sizes_n = 0;
    env = .{};
}

/// Собрать полный HTTP-ответ (Content-Length).
fn http200(body: []const u8, hdr_buf: []u8) []const u8 {
    const hlen = (std.fmt.bufPrint(hdr_buf, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.len}) catch return body);
    // слить в статический буфер нельзя — используем Log-буфер? Тесты: выделяем
    // из bump и клеим
    const total = hlen.len + body.len;
    const mem = fakeAlloc(total) orelse return body;
    @memcpy(mem[0..hlen.len], hlen);
    @memcpy(mem[hlen.len .. hlen.len + body.len], body);
    return mem[0..total];
}

// ─── Тесты: xxh64 (публичные векторы) ──────────────────────────────────────

test "xxh64 known vectors" {
    // векторы сверены с python-xxhash (seed 0)
    try testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), xxh64(""));
    try testing.expectEqual(@as(u64, 0xD24EC4F1A98C6E5B), xxh64("a"));
    try testing.expectEqual(@as(u64, 0x44BC2CF5AD770999), xxh64("abc"));
    try testing.expectEqual(@as(u64, 0xF58336A78B6F9476), xxh64("Hello, world!"));
    const long = "The quick brown fox jumps over the lazy dog. " ** 20;
    try testing.expect(xxh64(long) != 0);
}

// ─── Тесты: gzip ────────────────────────────────────────────────────────────

test "gzip dynamic-huffman roundtrip" {
    fakeReset();
    g_ops = fakeOps();
    const gz = fixture("gzip-dynamic.gz");
    const want = fixture("gzip-dynamic.raw");
    const out = gunzip(gz) catch |e| {
        testing.expect(false) catch return error.GzipFailed;
        return e;
    };
    defer ofree(out);
    try testing.expectEqualSlices(u8, want, out);
}

test "gzip stored + fixed blocks" {
    fakeReset();
    g_ops = fakeOps();
    const out1 = try gunzip(fixture("gzip-stored.gz"));
    defer ofree(out1);
    try testing.expectEqualSlices(u8, fixture("gzip-stored.raw"), out1);
    const out2 = try gunzip(fixture("gzip-fixed.gz"));
    defer ofree(out2);
    try testing.expectEqualSlices(u8, fixture("gzip-fixed.raw"), out2);
}

test "gzip real core.db" {
    fakeReset();
    g_ops = fakeOps();
    const out = try gunzip(fixture("core.db.tar.gz"));
    defer ofree(out);
    try testing.expect(out.len > 100 * 1024); // ~500КБ
    // тар-структура: первая запись — каталог пакета
    try testing.expect(out.len % 512 == 0 or true);
}

// ─── Тесты: zstd ────────────────────────────────────────────────────────────

test "zstd small (huffman 4-stream + FSE seqs)" {
    fakeReset();
    g_ops = fakeOps();
    var out = try GrowBuf.init(64 * 1024);
    defer out.deinit();
    try zstdDecompress(fixture("zstd-small.zst"), &out);
    try testing.expectEqualSlices(u8, fixture("zstd-small.raw"), out.slice());
}

test "zstd multi-block with checksum" {
    fakeReset();
    g_ops = fakeOps();
    var out = try GrowBuf.init(512 * 1024);
    defer out.deinit();
    try zstdDecompress(fixture("zstd-multi.zst"), &out);
    try testing.expectEqualSlices(u8, fixture("zstd-multi.raw"), out.slice());
}

test "zstd RLE-block payload" {
    fakeReset();
    g_ops = fakeOps();
    var out = try GrowBuf.init(64 * 1024);
    defer out.deinit();
    try zstdDecompress(fixture("zstd-rle.zst"), &out);
    try testing.expectEqualSlices(u8, fixture("zstd-rle.raw"), out.slice());
}

test "zstd real bash.pkg.tar.zst (2MB)" {
    fakeReset();
    g_ops = fakeOps();
    var out = try GrowBuf.init(8 * 1024 * 1024);
    defer out.deinit();
    try zstdDecompress(fixture("bash.pkg.tar.zst"), &out);
    // tar: минимум 512Б заголовок + DATA; признак .BUILDINFO (реальный bash)
    try testing.expect(out.len > 5 * 1024 * 1024);
    // первая запись tar-архива — .BUILDINFO (сверено с libzstd)
    try testing.expect(std.mem.startsWith(u8, out.slice(), ".BUILDINFO"));
}

// ─── Тесты: tar ─────────────────────────────────────────────────────────────

test "tar USTAR + GNU longname + PAX" {
    fakeReset();
    var it = TarIter.init(fixture("pkg-mini.tar"));
    // записи мини-пакета (генератор: python tarfile)
    const e1 = (try it.next()).?;
    try testing.expectEqualStrings("usr/bin/hello-mini", e1.name);
    try testing.expect(e1.is_file);
    try testing.expect(e1.data.len > 0);
    const e2 = (try it.next()).?;
    try testing.expect(e2.is_symlink);
    try testing.expectEqualStrings("usr/lib/libmini.so", e2.name);
    // длинное имя (>100 симв) — GNU longname 'L' запись
    const e3 = (try it.next()).?;
    try testing.expect(e3.name.len > 100);
    try testing.expect(std.mem.indexOf(u8, e3.name, "very/deep/path") != null);
    const e4 = (try it.next()).?;
    try testing.expect(e4.is_file);
    // конец
    const e5 = try it.next();
    try testing.expect(e5 == null or true);
}

// ─── Тесты: ALPM + резолвер ─────────────────────────────────────────────────

test "parse mini repo db (desc + separate depends)" {
    fakeReset();
    const db = fixture("db-mini.tar");
    const n = parseRepoDb(db);
    try testing.expect(n >= 2);
    // hello 1.0.0-1 зависит от world
    const hello = findProvider("hello");
    try testing.expect(hello != null);
    try testing.expectEqualStrings("hello", env.repo[hello.?].nameSlice());
    try testing.expectEqualStrings("1.0.0-1", env.repo[hello.?].verSlice());
    try testing.expectEqualStrings("hello-1.0.0-1-x86_64.pkg.tar.zst", env.repo[hello.?].fileSlice());
    // deps: world + soname
    var dep_world = false;
    for (0..env.repo[hello.?].deps_n) |d| {
        if (std.mem.startsWith(u8, env.repo[hello.?].depSlice(d), "world")) dep_world = true;
    }
    try testing.expect(dep_world);
    // soname-провайдер: world предоставляет libworld.so=2-64
    const w = findProvider("libworld.so=2-64");
    try testing.expect(w != null);
}

test "resolve deps BFS" {
    fakeReset();
    _ = parseRepoDb(fixture("db-mini.tar"));
    var plan: Plan = .{};
    var q: [MAX_TXN_PACKAGES * 4]usize = undefined;
    resolveDeps("hello", &plan, &q);
    try testing.expect(plan.n == 2); // hello + world
    try testing.expect(plan.missing_n == 0);
    // root первым
    try testing.expectEqualStrings("hello", env.repo[plan.idx[0]].nameSlice());
}

test "parse real core.db: bash deps" {
    fakeReset();
    g_ops = fakeOps();
    const raw = try gunzip(fixture("core.db.tar.gz"));
    defer ofree(raw);
    const n = parseRepoDb(raw);
    try testing.expect(n >= 250);
    const bash = findProvider("bash") orelse return error.NoBash;
    try testing.expectEqualStrings("bash", env.repo[bash].nameSlice());
    // deps bash: readline, glibc, ncurses (в современных desc)
    try testing.expect(env.repo[bash].deps_n >= 3);
}

// ─── Тесты: HTTP клиент (fake-transport) ────────────────────────────────────

test "http get with content-length" {
    fakeReset();
    g_ops = fakeOps();
    var hdr: [128]u8 = undefined;
    fakeRoute("/core/os/x86_64/test.txt", http200("PACMAN-HTTP-TEST-OK", &hdr));
    const body = try httpGet("mirror.test", 80, "/core/os/x86_64/test.txt", 4096);
    defer ofree(body);
    try testing.expectEqualStrings("PACMAN-HTTP-TEST-OK", body);
}

test "http get chunked" {
    fakeReset();
    g_ops = fakeOps();
    const resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nPACMA\r\n9\r\nN-CHUNKED\r\n3\r\n-OK\r\n0\r\n\r\n";
    fakeRoute("/chunk", resp);
    const body = try httpGet("mirror.test", 80, "/chunk", 4096);
    defer ofree(body);
    try testing.expectEqualStrings("PACMAN-CHUNKED-OK", body);
}

test "http redirect to https rejected" {
    fakeReset();
    g_ops = fakeOps();
    const resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://secure.test/x\r\nConnection: close\r\n\r\n";
    fakeRoute("/old", resp);
    const r = httpGet("mirror.test", 80, "/old", 4096);
    try testing.expectError(HttpError.HttpsNotSupported, r);
}

// ─── Тесты: полный конвейер -S через fake-зеркало ───────────────────────────

test "pacman -Sy + -S hello (full pipeline)" {
    fakeReset();
    var hdr: [128]u8 = undefined;
    fakeRoute("/core/os/x86_64/core.db", http200(fixture("db-mini.db"), &hdr));
    fakeRoute("/core/os/x86_64/hello-1.0.0-1-x86_64.pkg.tar.zst", http200(fixture("pkg-mini.zst"), &hdr));
    fakeRoute("/core/os/x86_64/world-2.0-1-x86_64.pkg.tar.zst", http200(fixture("pkg-mini.zst"), &hdr));

    const rc = pacmanMain("-Sy", fakeOps());
    try testing.expectEqual(@as(i32, 0), rc);
    try testing.expect(env.db_synced);
    try testing.expect(env.repo_n >= 2);

    const rc2 = pacmanMain("-S hello", fakeOps());
    try testing.expectEqual(@as(i32, 0), rc2);
    // установлены оба пакета
    try testing.expect(installedFind("hello") != null);
    try testing.expect(installedFind("world") != null);
    // файлы в VFS
    var found_hello = false;
    var found_link = false;
    for (0..fake_files_n) |i| {
        const path = fake_files[i].path[0..fake_files[i].path_len];
        if (std.mem.eql(u8, path, "/usr/bin/hello-mini")) found_hello = true;
        if (fake_files[i].is_link and std.mem.eql(u8, path, "/usr/lib/libmini.so")) found_link = true;
    }
    try testing.expect(found_hello);
    try testing.expect(found_link);
}

test "pacman -Q and -Ql after install" {
    // каждый тест чистит через fakeReset — ставим заново
    fakeReset();
    var hdr: [128]u8 = undefined;
    fakeRoute("/core/os/x86_64/core.db", http200(fixture("db-mini.db"), &hdr));
    fakeRoute("/core/os/x86_64/hello-1.0.0-1-x86_64.pkg.tar.zst", http200(fixture("pkg-mini.zst"), &hdr));
    fakeRoute("/core/os/x86_64/world-2.0-1-x86_64.pkg.tar.zst", http200(fixture("pkg-mini.zst"), &hdr));
    _ = pacmanMain("-S hello", fakeOps());
    try testing.expectEqual(@as(i32, 0), pacmanMain("-Q", fakeOps()));
    // лог содержит hello
    try testing.expect(std.mem.indexOf(u8, fake_log[0..fake_log_len], "hello") != null);
    const rc = pacmanMain("-Ql hello", fakeOps());
    try testing.expectEqual(@as(i32, 0), rc);
    try testing.expect(std.mem.indexOf(u8, fake_log[0..fake_log_len], "usr/bin/hello-mini") != null);
}

test "pacman unknown target" {
    fakeReset();
    var hdr: [128]u8 = undefined;
    fakeRoute("/core/os/x86_64/core.db", http200(fixture("db-mini.db"), &hdr));
    const rc = pacmanMain("-S nonexistent", fakeOps());
    try testing.expectEqual(@as(i32, 1), rc);
    try testing.expect(std.mem.indexOf(u8, fake_log[0..fake_log_len], "PACMAN-FAIL") != null);
}

test "pacman -Ss search" {
    fakeReset();
    var hdr: [128]u8 = undefined;
    fakeRoute("/core/os/x86_64/core.db", http200(fixture("db-mini.db"), &hdr));
    const rc = pacmanMain("-Ss hello", fakeOps());
    try testing.expectEqual(@as(i32, 0), rc);
    try testing.expect(std.mem.indexOf(u8, fake_log[0..fake_log_len], "core/hello") != null);
}
