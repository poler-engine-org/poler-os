// ============================================================================
// POLER-OS Win32 Stub Dispatcher — x86_64 (v0.9.0, Crash-Driven Development)
// ============================================================================
//
// Диспетчер заглушек для PE-импортов. Каждая импортируемая функция получает
// свой сгенерированный код-стаб, который при вызове:
//   1. ЛОГИРУЕТ имя: «[WIN32] ВЫЗОВ kernel32.dll!CreateFileA — не реализовано»
//   2. Останавливает систему контролируемым int3 (kernel #BP → panic trace) —
//      это и есть «crash» в Crash-Driven Development: по логу видно, какую
//      функцию реализовывать следующей.
//
// Механика стаба (31 байт на функцию):
//   48 83 EC 08        sub rsp, 8             — выравнивание стека: на входе
//                                                  в стаб rsp%16==8 (адрес
//                                                  возврата); после sub — 0;
//                                                  call даёт вход в обработчик
//                                                  с rsp%16==8 = SysV/Win64-норма
//   48 BF <id:8>       movabs rdi, entry_id    — индекс в реестре
//   48 B8 <fn:8>       movabs rax, stubCommon  — общий обработчик
//   FF D0              call rax
//   48 83 C4 08        add rsp, 8              — эпилог: баланс стека
//   C3                 ret                     — возврат к PE-вызываемому
//
// ⚠ Без sub/add rsp,8 обработчик входит с rsp%16==0 → компилятор кладёт
// movaps на невыровненный стек → #GP (поймано нативным прогоном v0.9.0;
// юнит-«компиляция» это не ловила — тесты обязаны ЗАПУСКАТЬСЯ).
//
// Конвенция безопасна для Win64-вызываемого: мы трогаем только RDI и RAX
// (volatile в обеих конвенциях), аргументы RCX/RDX/R8/R9 не затираются —
// позже их можно логировать для CDD-трейса аргументов.
//
// Режимы: .int3 (ядро — контролируемый останов) / .record (нативные тесты —
// вызов фиксируется в буфере, процесс живёт для следующих проверок).
// ============================================================================

const std = @import("std");
const pe = @import("pe.zig");

pub const Pe = pe.Pe;

// ─── Реестр заглушек ────────────────────────────────────────────────────────

pub const MAX_STUB_ENTRIES: usize = 1024;
pub const STUB_CODE_SIZE: usize = 31; // байт на стаб (см. шапку)

pub const StubEntry = struct {
    dll: []const u8,
    func: pe.ImportFn,
    stub_addr: u64, // адрес сгенерированного кода
    iat_rva: u32, // RVA IAT-слота (FirstThunk + index*8)
    slot_index: usize,
};

pub const TrapMode = enum {
    int3, // ядро: лог + int3 (#BP → panic trace)
    record, // тесты: лог в буфер, вернуть управление
};

pub const Dispatcher = struct {
    entries: []StubEntry = &[_]StubEntry{},
    count: usize = 0,
    mode: TrapMode = .int3,

    /// Лог-хук: ядро подключает Serial.puts; тесты — свой сборщик.
    /// Сигнатура: (ctx, строка) — чтобы не тянуть аллокаторы.
    log_fn: ?*const fn (ctx: ?*anyopaque, msg: []const u8) void = null,
    log_ctx: ?*anyopaque = null,

    /// Буфер для режима .record (нативные тесты): индекс последнего вызова.
    last_called: usize = std.math.maxInt(usize),
    call_count: usize = 0,

    /// Сгенерированный код. В ядре — буфер, помеченный страницами как RX
    /// (в момент запуска PE); в тестах — mmap RWX.
    code: ?[]u8 = null,

    pub fn init(entries_buf: []StubEntry, code_buf: []u8, mode: TrapMode) Dispatcher {
        return .{
            .entries = entries_buf,
            .code = code_buf,
            .mode = mode,
        };
    }

    // ─── Генерация стабов под все импорты образа ───

    /// Генерирует стабиль для КАЖДОЙ функции из таблицы импортов PE.
    /// Возвращает количество сгенерированных стабов.
    /// Не патчит сам образ — IAT-слоты патчит applyToImage (образ уже
    /// скопирован в целевой буфер по своим RVA).
    pub fn generateFor(self: *Dispatcher, image: *const Pe) !usize {
        if (self.code == null) return error.NoCodeBuffer;
        const code_buf = self.code.?;

        var dlls = try image.importDlls();
        var idx: usize = 0;
        while (dlls.next()) |dll| {
            var slot: usize = 0;
            var fns = dll.functions;
            while (fns.next()) |f| {
                if (idx >= self.entries.len) return error.TooManyStubs;
                const code_off = idx * STUB_CODE_SIZE;
                if (code_off + STUB_CODE_SIZE > code_buf.len) return error.CodeBufferTooSmall;

                // ── машинный код стаба ──
                const common_addr = @intFromPtr(&stubCommon);
                const out = code_buf[code_off..][0..STUB_CODE_SIZE];
                out[0] = 0x48; // sub rsp, 8 — выравнивание (см. шапку)
                out[1] = 0x83;
                out[2] = 0xEC;
                out[3] = 0x08;
                out[4] = 0x48; // movabs rdi, imm64
                out[5] = 0xBF;
                std.mem.writeInt(u64, out[6..14], idx, .little);
                out[14] = 0x48; // movabs rax, imm64
                out[15] = 0xB8;
                std.mem.writeInt(u64, out[16..24], common_addr, .little);
                out[24] = 0xFF; // call rax
                out[25] = 0xD0;
                out[26] = 0x48; // add rsp, 8 — эпилог
                out[27] = 0x83;
                out[28] = 0xC4;
                out[29] = 0x08;
                out[30] = 0xC3; // ret

                self.entries[idx] = .{
                    .dll = dll.name,
                    .func = f,
                    .stub_addr = @intFromPtr(code_buf.ptr + code_off),
                    .iat_rva = dll.iat_rva,
                    .slot_index = slot,
                };
                idx += 1;
                slot += 1;
            }
        }
        self.count = idx;
        return idx;
    }

    /// Патчит IAT скопированного образа: каждый слот получает адрес стаба.
    /// image_mem — база ЗАГРУЖЕННОГО образа (ImageBase может отличаться при
    /// релокации; здесь работаем по фактическому размещению).
    pub fn applyToImage(self: *Dispatcher, image_mem: [*]u8) void {
        for (self.entries[0..self.count]) |e| {
            const slot_addr = @intFromPtr(image_mem) + e.iat_rva + e.slot_index * 8;
            const slot: *u64 = @ptrFromInt(slot_addr);
            slot.* = e.stub_addr;
        }
    }

    /// Поиск записи по адресу стаба (для трейса из panic-обработчика).
    pub fn findByAddress(self: *Dispatcher, addr: u64) ?*const StubEntry {
        for (self.entries[0..self.count]) |*e| {
            if (e.stub_addr == addr) return e;
        }
        return null;
    }

    fn logf(self: *Dispatcher, comptime fmt: []const u8, args: anytype) void {
        if (self.log_fn) |f| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
            f(self.log_ctx, msg);
        }
    }

    /// Отчёт о вызове: ядро → Serial; тесты → фиксирование.
    fn report(self: *Dispatcher, entry_id: usize) void {
        self.last_called = entry_id;
        self.call_count += 1;

        if (entry_id >= self.count) {
            self.logf("[WIN32] стаб #{d}: ВНЕ РЕЕСТРА (переполнение?)\n", .{entry_id});
            return;
        }
        const e = &self.entries[entry_id];
        switch (e.func) {
            .by_name => |n| self.logf(
                "[WIN32] ВЫЗОВ {s}!{s} — не реализовано (stub #{d})\n",
                .{ e.dll, n, entry_id },
            ),
            .by_ordinal => |ord| self.logf(
                "[WIN32] ВЫЗОВ {s}!ordinal#{d} — не реализовано (stub #{d})\n",
                .{ e.dll, ord, entry_id },
            ),
        }
    }
};

// ─── Общий обработчик стаба ─────────────────────────────────────────────────

/// Точка входа всех стабов. Вызывается машинным кодом: rdi = entry_id.
/// callconv(.C) = стабильный SysV-ABI адрес (нужен для movabs в генераторе).
/// Глобальный синглтон — УКАЗАТЕЛЬ на активный диспетчер (в ядре это
/// статический kdisp, в тестах — локальный экземпляр). Копирование по
/// значению теряло бы счётчики/состояние экземпляра-источника.
var dispatcher: ?*Dispatcher = null;

pub fn setDispatcher(d: *Dispatcher) void {
    dispatcher = d;
}

pub fn activeDispatcher() ?*Dispatcher {
    return dispatcher;
}

/// Обработчик: лог + останов. В режиме .int3 выполняет int3 — в ядре это
/// вектор 3 (#BP) → panic trace с RIP стаба; после возврата (если обработчик
/// пропустил) — hlt-цикл. В режиме .record просто возвращается.
fn stubCommon(entry_id: usize) callconv(.C) void {
    const d = dispatcher orelse {
        // стаб вызван до setDispatcher — сломан сам CDD-пайплайн;
        // честный int3-стоп заметнее молчаливого возврата
        asm volatile ("int3");
        return;
    };
    d.report(entry_id);
    if (d.mode == .int3) {
        asm volatile ("int3");
        // сюда попадаем, только если #BP-обработчик возобновил исполнение —
        // безопасный halt, чтобы стаб не «вернулся» в PE-код как ни в чём
        // не бывало
        while (true) {
            asm volatile ("hlt");
        }
    }
    // .record — контроль возвращается сгенерированному стабу → ret → PE
}

// ─── Утилита отчёта для шелла ядра (peinfo/pestubs) ─────────────────────────

pub fn fmtEntryName(entry: *const StubEntry, buf: []u8) []const u8 {
    return switch (entry.func) {
        .by_name => |n| std.fmt.bufPrint(buf, "{s}!{s}", .{ entry.dll, n }) catch "!",
        .by_ordinal => |ord| std.fmt.bufPrint(buf, "{s}!ordinal#{d}", .{ entry.dll, ord }) catch "!",
    };
}

// ============================================================================
// Тесты (нативно). Полный CDD-цикл: parse → generate → load → patch IAT →
// ВЫЗОВ импорта → стаб срабатывает → имя функции зафиксировано.
// ============================================================================

const testing = std.testing;

fn loadFixture(comptime name: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(testing.allocator, name, 64 << 20);
}

var test_log_buf: [4096]u8 = undefined;
var test_log_len: usize = 0;

fn testLogger(_: ?*anyopaque, msg: []const u8) void {
    const n = @min(msg.len, test_log_buf.len - test_log_len);
    @memcpy(test_log_buf[test_log_len .. test_log_len + n], msg[0..n]);
    test_log_len += n;
}

fn testLogContains(needle: []const u8) bool {
    return std.mem.indexOf(u8, test_log_buf[0..test_log_len], needle) != null;
}

test "stub generator: полный CDD-цикл на curl.exe" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);

    const image = try Pe.parse(data);
    const counts = image.countImports();
    try testing.expectEqual(@as(usize, 274), counts.functions);

    // 1. RWX-буфер под код стабов (нативный тест; в ядре — exec-страницы)
    const n = counts.functions;
    const code_len = n * STUB_CODE_SIZE + 4096;
    const code_mem = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_mem);

    // 2. Симуляция «загруженного» образа: SizeOfImage байт по ImageBase-смещению
    //    (аллоцируем SizeOfImage, копируем секции по RVA — как VMM-лоадер)
    const img_mem = try std.posix.mmap(
        null,
        image.sizeOfImage() + 0x1000,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(img_mem);
    @memset(img_mem, 0);
    // копия заголовков
    const hdr_len = @min(image.sizeOfHeaders(), data.len);
    @memcpy(img_mem[0..hdr_len], data[0..hdr_len]);
    // копия секций
    for (image.sections) |*sec| {
        if (sec.size_of_raw_data == 0) continue;
        const dst = img_mem[sec.virtual_address .. sec.virtual_address + sec.size_of_raw_data];
        const src = data[sec.pointer_to_raw_data .. sec.pointer_to_raw_data + sec.size_of_raw_data];
        @memcpy(dst, src);
    }

    // 3. Генерация стабов в режиме record
    const entries = try testing.allocator.alloc(StubEntry, n);
    defer testing.allocator.free(entries);

    var disp = Dispatcher.init(entries, code_mem[0..code_len], .record);
    disp.log_fn = testLogger;
    disp.log_ctx = null;

    const generated = try disp.generateFor(&image);
    try testing.expectEqual(n, generated);

    // Активируем глобальный диспетчер (стаб-код зовёт stubCommon)
    setDispatcher(&disp);

    // 5. Патчим IAT в «загруженном» образе
    disp.applyToImage(img_mem.ptr);

    // 6. Проверка: IAT-слот KERNEL32.dll!CreateFileA указывает на стаб,
    //    и прямой вызов через слот срабатывает как надо.
    var create_file_a_addr: ?u64 = null;
    var dlls = try image.importDlls();
    outer: while (dlls.next()) |dll| {
        if (!std.ascii.eqlIgnoreCase(dll.name, "KERNEL32.dll")) continue;
        var slot: usize = 0;
        var fns = dll.functions;
        while (fns.next()) |f| {
            switch (f) {
                .by_name => |fname| if (std.mem.eql(u8, fname, "CreateFileA")) {
                    const slot_off = dll.iat_rva + slot * 8;
                    create_file_a_addr = std.mem.readInt(u64, img_mem[slot_off..][0..8], .little);
                    break :outer;
                },
                .by_ordinal => {},
            }
            slot += 1;
        }
    }
    try testing.expect(create_file_a_addr != null);
    try testing.expect(disp.findByAddress(create_file_a_addr.?) != null);

    // 7. ВЫЗОВ импорта через IAT-слот — так делает сам PE-код.
    //    (Win64-конвенция: первые 4 аргумента в RCX/RDX/R8/R9 — стаб их
    //    не трогает; здесь аргументы не важны)
    const CreateFileA: *const fn () callconv(.C) usize = @ptrFromInt(create_file_a_addr.?);
    _ = CreateFileA();

    // 8. Стаб сработал: имя зафиксировано в логе
    try testing.expectEqual(@as(usize, 1), disp.call_count);
    // имя DLL — в том виде, в каком оно лежит в IMAGE_IMPORT_DESCRIPTOR
    try testing.expect(testLogContains("KERNEL32.dll!CreateFileA"));

    // 9. Второй вызов — другая функция (WS2_32.dll!WSAStartup)
    var wsa_addr: ?u64 = null;
    var dlls2 = try image.importDlls();
    outer2: while (dlls2.next()) |dll| {
        if (!std.ascii.eqlIgnoreCase(dll.name, "WS2_32.dll")) continue;
        var slot: usize = 0;
        var fns = dll.functions;
        while (fns.next()) |f| {
            switch (f) {
                .by_name => |fname| if (std.mem.eql(u8, fname, "WSAStartup")) {
                    const slot_off = dll.iat_rva + slot * 8;
                    wsa_addr = std.mem.readInt(u64, img_mem[slot_off..][0..8], .little);
                    break :outer2;
                },
                .by_ordinal => {},
            }
            slot += 1;
        }
    }
    try testing.expect(wsa_addr != null);
    const WSAStartup: *const fn () callconv(.C) usize = @ptrFromInt(wsa_addr.?);
    _ = WSAStartup();
    try testing.expectEqual(@as(usize, 2), disp.call_count);
    try testing.expect(testLogContains("WS2_32.dll!WSAStartup"));
}

test "stub code layout: sub/movabs/call/add/ret байты корректны" {
    // маленький синтетический «PE» не нужен — проверяем байты на curl-стабах
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    const n = @min(counts.functions, 4); // хватит четырёх

    var code_buf: [4 * STUB_CODE_SIZE]u8 align(8) = undefined;
    var entries: [4]StubEntry = undefined;

    // генерируем вручную первые n — проверяем машинный код
    var dlls = try image.importDlls();
    var idx: usize = 0;
    while (dlls.next()) |dll| {
        var fns = dll.functions;
        while (fns.next()) |f| {
            if (idx >= n) break;
            const off = idx * STUB_CODE_SIZE;
            const common_addr = @intFromPtr(&stubCommon);
            code_buf[off + 0] = 0x48;
            code_buf[off + 1] = 0x83;
            code_buf[off + 2] = 0xEC;
            code_buf[off + 3] = 0x08;
            code_buf[off + 4] = 0x48;
            code_buf[off + 5] = 0xBF;
            std.mem.writeInt(u64, code_buf[off + 6 ..][0..8], idx, .little);
            code_buf[off + 14] = 0x48;
            code_buf[off + 15] = 0xB8;
            std.mem.writeInt(u64, code_buf[off + 16 ..][0..8], common_addr, .little);
            code_buf[off + 24] = 0xFF;
            code_buf[off + 25] = 0xD0;
            code_buf[off + 26] = 0x48;
            code_buf[off + 27] = 0x83;
            code_buf[off + 28] = 0xC4;
            code_buf[off + 29] = 0x08;
            code_buf[off + 30] = 0xC3;
            entries[idx] = .{
                .dll = dll.name,
                .func = f,
                .stub_addr = @intFromPtr(&code_buf[off]),
                .iat_rva = dll.iat_rva,
                .slot_index = idx,
            };
            idx += 1;
        }
        if (idx >= n) break;
    }
    try testing.expectEqual(@as(usize, n), idx);
    // проверка опкодов первого стаба: sub rsp,8 | movabs rdi | movabs rax | call | add rsp,8 | ret
    try testing.expectEqual(@as(u8, 0x48), code_buf[0]);
    try testing.expectEqual(@as(u8, 0x83), code_buf[1]);
    try testing.expectEqual(@as(u8, 0xEC), code_buf[2]);
    try testing.expectEqual(@as(u8, 0x08), code_buf[3]);
    try testing.expectEqual(@as(u8, 0x48), code_buf[4]);
    try testing.expectEqual(@as(u8, 0xBF), code_buf[5]);
    try testing.expectEqual(@as(u8, 0x48), code_buf[14]);
    try testing.expectEqual(@as(u8, 0xB8), code_buf[15]);
    try testing.expectEqual(@as(u8, 0xFF), code_buf[24]);
    try testing.expectEqual(@as(u8, 0xD0), code_buf[25]);
    try testing.expectEqual(@as(u8, 0x48), code_buf[26]);
    try testing.expectEqual(@as(u8, 0x83), code_buf[27]);
    try testing.expectEqual(@as(u8, 0xC4), code_buf[28]);
    try testing.expectEqual(@as(u8, 0x08), code_buf[29]);
    try testing.expectEqual(@as(u8, 0xC3), code_buf[30]);
    // id в imm64
    const id0 = std.mem.readInt(u64, code_buf[6..14], .little);
    try testing.expectEqual(@as(u64, 0), id0);
}

test "fmtEntryName: имя для panic-трейса" {
    var buf: [128]u8 = undefined;
    const e = StubEntry{
        .dll = "user32.dll",
        .func = .{ .by_name = "CreateWindowExW" },
        .stub_addr = 0,
        .iat_rva = 0,
        .slot_index = 0,
    };
    const name = fmtEntryName(&e, &buf);
    try testing.expectEqualStrings("user32.dll!CreateWindowExW", name);
}
