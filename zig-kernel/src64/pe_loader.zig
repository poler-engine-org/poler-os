// ============================================================================
// POLER-OS PE Image Loader (Ring 3) — x86_64 (v0.10.0, CDD-цикл №1)
// ============================================================================
//
// Загрузка PE32+-образа в адресное пространство ЗАДАЧИ ПОЛЬЗОВАТЕЛЯ:
//   1. Выделение физически последовательных страниц под SizeOfImage.
//   2. Копия заголовков + секций по RVA (VirtualSize > SizeOfRawData →
//      хвост .bss уже нулевой — страницы приходят обнулёнными).
//   3. Посекционный маппинг user-VA → phys с правами страниц:
//      PTE_USER везде, PTE_WRITABLE по C–флагу секции, PTE_NO_EXECUTE
//      для не-исполняемых секций (EFER.NXE включён в boot64.S).
//   4. User-контекст Win64: стек, TEB (Self/PEB/TLS/StackBase), PEB
//      (ImageBase/ProcessParameters), RTL_USER_PROCESS_PARAMETERS c
//      командной строкой (ANSI + UTF-16) и TLS-страницей.
//
// Релокация: НЕ выполняем — образ маппится по предпочтённому ImageBase
// (curl.exe: 0x140000000, low-half < 512ГБ), .reloc не активируется.
//
// IAT-патч: НЕ требует writable-страниц. Заглушки пишутся в образ через
// kernel-identity (backing-указатель, CPL=0 пишет через RW identity-map),
// а для Ring 3 листовые права секции остаются как в PE-заголовке (.rdata
// IAT — read-only для пользователя: приложение свой IAT не переписывает).
//
// Архитектура двойной компиляции: ядро (freestanding) и нативные тесты
// (x86_64-linux-gnu) используют ОДИН код через LoaderOps — инъекцию
// аллокатора/маппера. Ядро передаёт PMM/VMM, тесты — фейковую память,
// поэтому весь логика загрузки покрыта юнит-тестами на реальном curl.exe.
// ============================================================================
//
// ⚠ Изоляция (fix v0.10.0): все user-VA обязаны быть ≥ 4ГБ — identity-map
// ядра (0–4ГБ, 2МБ huge pages, supervisor-only) занимает PML4[0]/PDPT[0..3].
// Маппинг user-VA в PDPT[4+] не задевает общие таблицы; validateImageBase
// отклоняет base < 4ГБ (пересечение с identity — риск #PF/kernel leak).
// ============================================================================

const std = @import("std");
const pe = @import("pe.zig");

// ─── Флаги PTE (совпадают с vmm64.zig; локальные константы — чтобы модуль
// не тянул kernel-only импорты и жил в нативных тестах) ────────────────────

pub const PTE_PRESENT: u64 = 0x01;
pub const PTE_WRITABLE: u64 = 0x02;
pub const PTE_USER: u64 = 0x04;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;
pub const PAGE_SIZE: u64 = 4096;

/// Верхняя граница canonical user-пространства (нижняя половина).
pub const USER_VA_LIMIT: u64 = 0x0000_8000_0000_0000;
/// Identity-map ядра занимает 0–4ГБ — user-VA строго выше.
pub const IDENTITY_LIMIT: u64 = 4 << 30;

// ─── Планировка user-VA (всё в PDPT[4+], выше 4ГБ, ниже 512ГБ) ─────────────

/// Стандартная планировка одного PE-процесса. Меняется от процесса к
/// процессу только image base (предпочтённый из PE-заголовка).
pub const UserLayout = struct {
    image_base: u64 = 0x1400_0000_00,
    stubs_va: u64 = 0x20_0000_0000, // 8ГБ — код заглушек (RX)
    teb_va: u64 = 0x21_0000_0000, // TEB (1 стр.)
    peb_va: u64 = 0x21_0001_0000, // PEB (1 стр.)
    params_va: u64 = 0x21_0002_0000, // ProcessParameters + cmdline (1 стр.)
    tls_va: u64 = 0x21_0003_0000, // TLS-массив (1 стр., нули)
    stack_top: u64 = 0x22_0000_0000, // верх стека (эксклюзивно)
    stack_pages: u64 = 32, // 128КБ committed
    heap_base: u64 = 0x30_0000_0000, // 12ГБ — VirtualAlloc-регион
    heap_limit: u64 = 0x30_4000_0000, // бюджет 4МБ
};

// ─── Win64-смещения структур (x64, ReactOS-референс: docs/pe-reference) ────

pub const Win64 = struct {
    // TEB (NT_TIB + расширения)
    pub const TEB_STACK_BASE: u16 = 0x08;
    pub const TEB_STACK_LIMIT: u16 = 0x10;
    pub const TEB_SELF: u16 = 0x30; // NT_TIB.Self — читает mingw CRT
    pub const TEB_CLIENT_ID: u16 = 0x40; // UniqueProcess (u64) + UniqueThread
    pub const TEB_TLS_PTR: u16 = 0x58; // ThreadLocalStoragePointer
    pub const TEB_PEB: u16 = 0x60; // ProcessEnvironmentBlock

    // PEB
    pub const PEB_IMAGE_BASE: u16 = 0x08; // ImageBaseAddress
    pub const PEB_LDR: u16 = 0x10; // Ldr (GetModuleHandle-walk; NULL в v0.10)
    pub const PEB_PARAMS: u16 = 0x20; // ProcessParameters

    // RTL_USER_PROCESS_PARAMETERS
    pub const PP_IMAGE_PATH: u16 = 0x60; // UNICODE_STRING ImagePathName
    pub const PP_CMDLINE: u16 = 0x70; // UNICODE_STRING CommandLine

    // Внутри нашей params-страницы: строки после структуры
    pub const PP_CMD_A_OFF: u16 = 0x200; // ANSI-строка cmdline
    pub const PP_CMD_W_OFF: u16 = 0x280; // UTF-16LE cmdline
};

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const LoaderOps = struct {
    /// Выделить ОБНУЛЁННЫЙ блок из count физически последовательных страниц.
    /// Контракт: страницы нулевые (PE-образ, TEB/PEB, стек несут мусор иначе).
    alloc_contig: *const fn (count: u64) ?u64,
    /// Маппинг user-VA → phys в ЦЕЛЕВОМ PML4 (не в активном CR3).
    /// false → маппинг отклонён (конфликт/гранулярность).
    map_user: *const fn (pml4: u64, va: u64, pa: u64, flags: u64) bool,
    /// Указатель ЗАПИСИ на физ. страницу: ядро — identity (pa == VA),
    /// нативные тесты — база фейкового буфера + смещение.
    page_ptr: *const fn (pa: u64) [*]u8,
};

pub const LoadError = error{
    BadImageBase, // вне canonical user / ниже 4ГБ / не выровнена
    OutOfMemory,
    MapFailed,
    BadHeaders, // заголовки/секции вне образа (битый файл)
    SectionOverflow, // секция выходит за SizeOfImage
};

// ─── Утилиты (чистые, тестируемые) ─────────────────────────────────────────

pub fn pageCount(bytes: u64) u64 {
    return (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
}

/// Допустимый base user-образа: canonical user, выше identity 4ГБ,
/// выровнен на страницу, base+size в пределах нижней половины.
pub fn validateImageBase(base: u64, size_of_image: u32) bool {
    if (base % PAGE_SIZE != 0) return false;
    if (base < IDENTITY_LIMIT) return false; // пересечение с kernel identity
    const end = base + @as(u64, size_of_image);
    if (end > USER_VA_LIMIT) return false;
    if (end <= base) return false; // переполнение
    return true;
}

/// PTE-флаги страницы секции: USER + W(по флагу) + NX(если не код).
pub fn sectionFlags(sec: *const pe.ImageSectionHeader) u64 {
    var f: u64 = PTE_USER;
    if (sec.isWritable()) f |= PTE_WRITABLE;
    if (!sec.isExecutable()) f |= PTE_NO_EXECUTE;
    return f;
}

/// Заголовки образа: read-only + NX для пользователя.
pub const header_page_flags: u64 = PTE_USER | PTE_NO_EXECUTE;

/// Флаги страницы по RVA-смещению внутри образа (какая секция накрывает).
/// Страницы header-области и межсекционных щелей → header_page_flags.
pub fn pageFlagsAt(image: *const pe.Pe, page_rva: u64) u64 {
    for (image.sections) |*sec| {
        const start: u64 = sec.virtual_address;
        const span = @max(sec.virtual_size, sec.size_of_raw_data);
        if (page_rva >= start and page_rva < start + span) {
            return sectionFlags(sec);
        }
    }
    return header_page_flags;
}

// ─── Регион user-памяти (последовательные страницы) ────────────────────────

pub const Region = struct {
    va: u64, // user-базовый адрес
    backing: [*]u8, // kernel-identity указатель (запись ДО старта задачи)
    phys: u64,
    pages: u64,
    size: u64, // pages * PAGE_SIZE
};

/// Выделить + замаппить регион с ЕДИНЫМИ флагами (стек, стабы, TEB…).
pub fn mapRegion(
    ops: LoaderOps,
    pml4: u64,
    va: u64,
    nbytes: u64,
    flags: u64,
) LoadError!Region {
    const n = pageCount(nbytes);
    if (n == 0) return LoadError.OutOfMemory;
    if (va % PAGE_SIZE != 0) return LoadError.BadImageBase;
    const base_pa = ops.alloc_contig(n) orelse return LoadError.OutOfMemory;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        if (!ops.map_user(pml4, va + i * PAGE_SIZE, base_pa + i * PAGE_SIZE, flags)) {
            return LoadError.MapFailed;
        }
    }
    return Region{
        .va = va,
        .backing = ops.page_ptr(base_pa),
        .phys = base_pa,
        .pages = n,
        .size = n * PAGE_SIZE,
    };
}

// ─── Загруженный образ ─────────────────────────────────────────────────────

pub const LoadedImage = struct {
    base_va: u64, // фактический VA образа (== предпочтённому ImageBase)
    entry_va: u64, // base_va + AddressOfEntryPoint
    backing: [*]u8, // identity-указатель: сюда скопированы секции,
    // сюда же пишет IAT-патчер (Dispatcher.applyToImage)
    phys: u64,
    pages: u64,
    size_of_image: u32,
};

/// Полный маппинг PE-образа в user-пространство задачи.
/// image: результат pe.Pe.parse(file). base_va: предпочтённый ImageBase.
pub fn loadImage(
    ops: LoaderOps,
    pml4: u64,
    image: *const pe.Pe,
    base_va: u64,
) LoadError!LoadedImage {
    const soi = image.sizeOfImage();
    if (!validateImageBase(base_va, soi)) return LoadError.BadImageBase;

    const file = image.data;
    const n = pageCount(soi);
    const base_pa = ops.alloc_contig(n) orelse return LoadError.OutOfMemory;
    const backing: [*]u8 = ops.page_ptr(base_pa);
    // alloc_contig контракт: страницы ОБНУЛЕНЫ (BSS/щели чисты по построению)

    // 1. Заголовки (DOS + NT + таблица секций) — побайтовая копия
    const hdr_len = @min(@as(usize, image.sizeOfHeaders()), file.len);
    if (hdr_len > soi) return LoadError.BadHeaders;
    @memcpy(backing[0..hdr_len], file[0..hdr_len]);

    // 2. Секции: RawData → по VirtualAddress (RVA)
    for (image.sections) |*sec| {
        if (sec.size_of_raw_data == 0) continue; // чистый BSS — уже нули
        const dst: u64 = sec.virtual_address;
        if (dst + @as(u64, sec.size_of_raw_data) > soi) {
            return LoadError.SectionOverflow;
        }
        const src: u64 = sec.pointer_to_raw_data;
        if (src + @as(u64, sec.size_of_raw_data) > file.len) {
            return LoadError.BadHeaders;
        }
        @memcpy(
            backing[dst..][0..sec.size_of_raw_data],
            file[src..][0..sec.size_of_raw_data],
        );
    }

    // 3. Посекционный маппинг (права — по флагам PE-секций)
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const flags = pageFlagsAt(image, i * PAGE_SIZE);
        if (!ops.map_user(pml4, base_va + i * PAGE_SIZE, base_pa + i * PAGE_SIZE, flags)) {
            return LoadError.MapFailed;
        }
    }

    return LoadedImage{
        .base_va = base_va,
        .entry_va = base_va + image.entryPointRva(),
        .backing = backing,
        .phys = base_pa,
        .pages = n,
        .size_of_image = soi,
    };
}

// ─── Чистые инициализаторы структур Win64 (тестируемые) ────────────────────

fn writeQ(page: []u8, off: u16, val: u64) void {
    std.mem.writeInt(u64, page[off..][0..8], val, .little);
}
fn writeD(page: []u8, off: u16, val: u32) void {
    std.mem.writeInt(u32, page[off..][0..4], val, .little);
}
fn writeW(page: []u8, off: u16, val: u16) void {
    std.mem.writeInt(u16, page[off..][0..2], val, .little);
}

/// TEB: Self/PEB/TLS/стек — то, что читает mingw CRT и NtCurrentTeb().
pub fn initTeb(page: []u8, teb_va: u64, peb_va: u64, tls_va: u64, stack_base: u64, stack_limit: u64) void {
    @memset(page, 0);
    writeQ(page, Win64.TEB_STACK_BASE, stack_base);
    writeQ(page, Win64.TEB_STACK_LIMIT, stack_limit);
    writeQ(page, Win64.TEB_SELF, teb_va);
    writeQ(page, Win64.TEB_CLIENT_ID, 1); // PID
    writeD(page, Win64.TEB_CLIENT_ID + 4, 2); // TID
    writeQ(page, Win64.TEB_TLS_PTR, tls_va);
    writeQ(page, Win64.TEB_PEB, peb_va);
}

/// PEB: ImageBaseAddress + ProcessParameters (Ldr=NULL — v0.10).
pub fn initPeb(page: []u8, image_base_va: u64, params_va: u64) void {
    @memset(page, 0);
    // 0x01 BeingDebugged=0, 0x00 InheritedAddressSpace=0 — уже нули
    writeQ(page, Win64.PEB_IMAGE_BASE, image_base_va);
    writeQ(page, Win64.PEB_PARAMS, params_va);
}

/// RTL_USER_PROCESS_PARAMETERS: CommandLine (UNICODE_STRING) + ANSI/UTF-16
/// строки в хвосте страницы. Возвращает (cmd_a_va, cmd_w_va).
pub fn initParams(page: []u8, params_va: u64, cmdline: []const u8) struct { cmd_a: u64, cmd_w: u64 } {
    @memset(page, 0);
    const cmd_a_va = params_va + Win64.PP_CMD_A_OFF;
    const cmd_w_va = params_va + Win64.PP_CMD_W_OFF;

    // ANSI-строка (GetCommandLineA)
    const n = @min(cmdline.len, 0x78);
    @memcpy(page[Win64.PP_CMD_A_OFF..][0..n], cmdline[0..n]);

    // UTF-16LE (GetCommandLineW)
    var i: usize = 0;
    while (i < n) : (i += 1) {
        writeW(page, Win64.PP_CMD_W_OFF + @as(u16, @intCast(i * 2)), cmdline[i]);
    }

    // UNICODE_STRING CommandLine @0x70: {u16 len, u16 maxlen, u32 pad, u64 buf}
    writeW(page, Win64.PP_CMDLINE, @intCast(n * 2)); // Length (без NUL)
    writeW(page, Win64.PP_CMDLINE + 2, @intCast((n + 1) * 2)); // MaximumLength
    writeQ(page, Win64.PP_CMDLINE + 8, cmd_w_va);
    // ImagePathName @0x60 — тот же буфер (упрощение v0.10)
    writeW(page, Win64.PP_IMAGE_PATH, @intCast(n * 2));
    writeW(page, Win64.PP_IMAGE_PATH + 2, @intCast((n + 1) * 2));
    writeQ(page, Win64.PP_IMAGE_PATH + 8, cmd_w_va);

    return .{ .cmd_a = cmd_a_va, .cmd_w = cmd_w_va };
}

// ─── Полный user-контекст (стек + TEB/PEB/params/TLS) ──────────────────────

pub const UserContext = struct {
    stack_top: u64,
    stack_rsp: u64, // начальный RSP (top-8, фейковый ret=0)
    teb_va: u64,
    peb_va: u64,
    params_va: u64,
    tls_va: u64,
    cmdline_a_va: u64, // ANSI (GetCommandLineA)
    cmdline_w_va: u64, // UTF-16 (GetCommandLineW)
    heap_base: u64,
    heap_limit: u64,
    stack_pages: u64,
};

/// Собрать окружение Win64-задачи: стек, TEB, PEB, params+cmdline, TLS.
pub fn buildUserContext(
    ops: LoaderOps,
    pml4: u64,
    layout: UserLayout,
    image_base_va: u64,
    cmdline: []const u8,
) LoadError!UserContext {
    // Стек: RW+NX, страницы обнулены; фейковый return-address=0 на top-8
    const stack_bytes = layout.stack_pages * PAGE_SIZE;
    const stack = try mapRegion(ops, pml4, layout.stack_top - stack_bytes, stack_bytes, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);
    std.mem.writeInt(u64, stack.backing[stack.size - 8 ..][0..8], 0, .little); // stray ret → VA 0 → #PF → видимый CDD-крах

    // TEB / PEB / params / TLS — по странице (TLS-страница остаётся нулевой)
    const teb = try mapRegion(ops, pml4, layout.teb_va, PAGE_SIZE, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);
    const peb = try mapRegion(ops, pml4, layout.peb_va, PAGE_SIZE, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);
    const params = try mapRegion(ops, pml4, layout.params_va, PAGE_SIZE, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);
    _ = try mapRegion(ops, pml4, layout.tls_va, PAGE_SIZE, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);

    initTeb(teb.backing[0..PAGE_SIZE], layout.teb_va, layout.peb_va, layout.tls_va, layout.stack_top, layout.stack_top - stack_bytes);
    initPeb(peb.backing[0..PAGE_SIZE], image_base_va, layout.params_va);
    const strs = initParams(params.backing[0..PAGE_SIZE], layout.params_va, cmdline);
    // tls-страница нулевая (alloc_contig-контракт) — TLS-слоты = 0

    return UserContext{
        .stack_top = layout.stack_top,
        .stack_rsp = layout.stack_top - 8,
        .teb_va = layout.teb_va,
        .peb_va = layout.peb_va,
        .params_va = layout.params_va,
        .tls_va = layout.tls_va,
        .cmdline_a_va = strs.cmd_a,
        .cmdline_w_va = strs.cmd_w,
        .heap_base = layout.heap_base,
        .heap_limit = layout.heap_limit,
        .stack_pages = layout.stack_pages,
    };
}

// ============================================================================
// Тесты (нативно, x86_64-linux-gnu): фейковый физ-аллокатор + мап-логер на
// РЕАЛЬНОМ curl.exe — та же логика, что крутится в ядре (LoaderOps-инъекция).
// ============================================================================

const testing = std.testing;

fn loadFixture(comptime name: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(testing.allocator, name, 64 << 20);
}

/// Фейковое «физическое» пространство: bump-аллокатор + логер маппингов.
const FakePhys = struct {
    const MapRec = struct { va: u64, pa: u64, flags: u64 };

    mem: []u8,
    cursor: u64, // байтовый курсор (кратно 4096)
    maps: std.ArrayList(MapRec),

    fn init(size: u64) !FakePhys {
        return .{
            .mem = try testing.allocator.alloc(u8, @intCast(size)),
            // старт с 1МБ: как реальный PMM (первый мегабайт — BIOS/VGA),
            // и pa=0 невозможен (@ptrFromInt(0) = null-паника Zig)
            .cursor = 0x100000,
            .maps = std.ArrayList(MapRec).init(testing.allocator),
        };
    }
    fn deinit(self: *FakePhys) void {
        testing.allocator.free(self.mem);
        self.maps.deinit();
    }
    fn allocContig(self: *FakePhys, count: u64) ?u64 {
        const bytes = count * PAGE_SIZE;
        if (self.cursor + bytes > self.mem.len) return null;
        const base = self.cursor;
        self.cursor += bytes;
        @memset(self.mem[@intCast(base)..@intCast(base + bytes)], 0); // контракт: обнулено
        return base;
    }
    fn mapUser(self: *FakePhys, pml4: u64, va: u64, pa: u64, flags: u64) bool {
        if (va % PAGE_SIZE != 0 or pa % PAGE_SIZE != 0) return false;
        if (pa + PAGE_SIZE > self.mem.len) return false;
        self.maps.append(.{ .va = va, .pa = pa, .flags = flags }) catch return false;
        _ = pml4;
        return true;
    }
    fn ops(_: *FakePhys) LoaderOps {
        return .{
            .alloc_contig = allocContigClosure,
            .map_user = mapUserClosure,
            .page_ptr = pagePtrClosure,
        };
    }
    const allocContigClosure = struct {
        fn call(count: u64) ?u64 {
            return global_fake.?.allocContig(count);
        }
    }.call;
    const mapUserClosure = struct {
        fn call(pml4: u64, va: u64, pa: u64, flags: u64) bool {
            return global_fake.?.mapUser(pml4, va, pa, flags);
        }
    }.call;
    const pagePtrClosure = struct {
        fn call(pa: u64) [*]u8 {
            return global_fake.?.mem.ptr + pa;
        }
    }.call;
};
var global_fake: ?*FakePhys = null;

fn fakeSetup(size: u64) !*FakePhys {
    const fp = try testing.allocator.create(FakePhys);
    fp.* = try FakePhys.init(size);
    global_fake = fp;
    return fp;
}
fn fakeTeardown(fp: *FakePhys) void {
    global_fake = null;
    fp.deinit();
    testing.allocator.destroy(fp);
}
fn findMap(fp: *FakePhys, va: u64) ?FakePhys.MapRec {
    for (fp.maps.items) |m| {
        if (m.va == va) return m;
    }
    return null;
}

test "flags: sectionFlags по характеристикам секций curl.exe" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try pe.Pe.parse(data);

    const text = image.sectionByName(".text").?;
    try testing.expectEqual(pe_loader_test_flags(.{ .user = true, .nx = false, .w = false }), sectionFlags(text));

    const data_sec = image.sectionByName(".data").?;
    try testing.expectEqual(pe_loader_test_flags(.{ .user = true, .nx = true, .w = true }), sectionFlags(data_sec));
}

fn pe_loader_test_flags(comptime f: anytype) u64 {
    var out: u64 = PTE_USER;
    if (f.w) out |= PTE_WRITABLE;
    if (f.nx) out |= PTE_NO_EXECUTE;
    return out;
}

test "validateImageBase: canonical user, ≥4ГБ, выравнивание" {
    try testing.expect(validateImageBase(0x140000000, 0x60000));
    try testing.expect(validateImageBase(0x21_0000_0000, 0x1000));
    // ниже identity 4ГБ — отклоняем (kernel identity 0–4ГБ)
    try testing.expect(!validateImageBase(0x1000000, 0x1000));
    try testing.expect(!validateImageBase(0x40000000, 0x1000));
    // невыверена
    try testing.expect(!validateImageBase(0x140000001, 0x1000));
    // за canonical user
    try testing.expect(!validateImageBase(0x0000_8000_0000_0000, 0x1000));
    // переполнение
    try testing.expect(!validateImageBase(0x0000_7FFF_FFFF_F000, 0x100000));
}

test "loadImage: полный маппинг curl.exe — секции, флаги, entry" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try pe.Pe.parse(data);

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);

    const base: u64 = 0x140000000; // предпочтённый ImageBase curl.exe
    const img = try loadImage(fp.ops(), 0xDEAD000, &image, base);

    // entry
    try testing.expectEqual(base + image.entryPointRva(), img.entry_va);
    try testing.expectEqual(pageCount(image.sizeOfImage()), img.pages);

    // страницы замаплены все, подряд, user
    var i: u64 = 0;
    while (i < img.pages) : (i += 1) {
        const m = findMap(fp, base + i * PAGE_SIZE) orelse return error.MapMissing;
        try testing.expect(m.flags & PTE_USER != 0);
        try testing.expect(m.flags & PTE_PRESENT == 0); // present ставит VMM
    }

    // копия заголовков: DOS-магия и PE-сигнатура в backing
    try testing.expectEqual(@as(u8, 'M'), img.backing[0]);
    try testing.expectEqual(@as(u8, 'Z'), img.backing[1]);
    const lfanew = std.mem.readInt(u32, img.backing[0x3C..][0..4], .little);
    try testing.expectEqual(pe.PE_SIGNATURE, std.mem.readInt(u32, img.backing[lfanew..][0..4], .little));

    // .text скопирован по RVA: первый байт совпадает с file@PointerToRawData
    const text = image.sectionByName(".text").?;
    try testing.expectEqual(data[text.pointer_to_raw_data], img.backing[text.virtual_address]);
    // возьмём байт из середины .text и сверим с файлом
    const mid = text.pointer_to_raw_data + text.size_of_raw_data / 2;
    try testing.expectEqual(data[mid], img.backing[text.virtual_address + text.size_of_raw_data / 2]);

    // .text-страница: executable → нет NX
    const text_map = findMap(fp, base + text.virtual_address).?;
    try testing.expect(text_map.flags & PTE_NO_EXECUTE == 0);

    // .data-страница: RW + NX
    const dsec = image.sectionByName(".data").?;
    const data_map = findMap(fp, base + dsec.virtual_address).?;
    try testing.expect(data_map.flags & PTE_WRITABLE != 0);
    try testing.expect(data_map.flags & PTE_NO_EXECUTE != 0);

    // header-страница: RO + NX
    const hdr_map = findMap(fp, base).?;
    try testing.expect(hdr_map.flags & PTE_WRITABLE == 0);
    try testing.expect(hdr_map.flags & PTE_NO_EXECUTE != 0);
}

test "loadImage: BSS-хвост (VirtualSize > RawData) нулевой" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try pe.Pe.parse(data);

    // ищем секцию с BSS-хвостом (mingw: .bss или .data с VSize>Raw)
    var bss_sec: ?*const pe.ImageSectionHeader = null;
    for (image.sections) |*s| {
        if (s.virtual_size > s.size_of_raw_data) {
            bss_sec = s;
            break;
        }
    }
    const sec = bss_sec orelse return error.NoBssSection; // curl обязан иметь

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);
    const img = try loadImage(fp.ops(), 0x1000, &image, 0x140000000);

    // байт сразу после RawData — в пределах VirtualSize — нулевой
    const tail_rva = sec.virtual_address + sec.size_of_raw_data + 0x10;
    try testing.expect(tail_rva < sec.virtual_address + sec.virtual_size);
    try testing.expectEqual(@as(u8, 0), img.backing[tail_rva]);
}

test "loadImage: BadImageBase отклоняется" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try pe.Pe.parse(data);

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);

    try testing.expectError(LoadError.BadImageBase, loadImage(fp.ops(), 0, &image, 0x1000)); // identity-зона
    try testing.expectError(LoadError.BadImageBase, loadImage(fp.ops(), 0, &image, 0x0000_8000_0000_0000)); // за user
}

test "initTeb/initPeb/initParams: поля Win64-структур" {
    var teb: [4096]u8 align(8) = undefined;
    var peb: [4096]u8 align(8) = undefined;
    var params: [4096]u8 align(8) = undefined;

    initTeb(&teb, 0x210000000, 0x210001000, 0x210003000, 0x220000000, 0x21FFF8000);
    try testing.expectEqual(@as(u64, 0x210000000), std.mem.readInt(u64, teb[0x30..][0..8], .little));
    try testing.expectEqual(@as(u64, 0x210001000), std.mem.readInt(u64, teb[0x60..][0..8], .little));
    try testing.expectEqual(@as(u64, 0x210003000), std.mem.readInt(u64, teb[0x58..][0..8], .little));
    try testing.expectEqual(@as(u64, 0x220000000), std.mem.readInt(u64, teb[0x08..][0..8], .little));

    initPeb(&peb, 0x140000000, 0x210002000);
    try testing.expectEqual(@as(u64, 0x140000000), std.mem.readInt(u64, peb[0x08..][0..8], .little));
    try testing.expectEqual(@as(u64, 0x210002000), std.mem.readInt(u64, peb[0x20..][0..8], .little));
    try testing.expectEqual(@as(u8, 0), peb[2]); // BeingDebugged

    const strs = initParams(&params, 0x210002000, "curl.exe");
    // ANSI
    try testing.expectEqualStrings("curl.exe", params[0x200..0x208]);
    // UTF-16LE: 'c'=0x63, 'u'=0x75 … ('curl.exe' → '.' на 5-й позиции)
    try testing.expectEqual(@as(u16, 'c'), std.mem.readInt(u16, params[0x280..][0..2], .little));
    try testing.expectEqual(@as(u16, '.'), std.mem.readInt(u16, params[0x288..][0..2], .little));
    // UNICODE_STRING @0x70
    try testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, params[0x70..][0..2], .little)); // 8*2
    try testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, params[0x72..][0..2], .little)); // 9*2
    try testing.expectEqual(@as(u64, 0x210002280), std.mem.readInt(u64, params[0x78..][0..8], .little));
    try testing.expectEqual(@as(u64, 0x210002200), strs.cmd_a);
    try testing.expectEqual(@as(u64, 0x210002280), strs.cmd_w);
}

test "buildUserContext: стек, TEB-страницы, cmdline, фейковый ret" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try pe.Pe.parse(data);

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);

    const layout = UserLayout{};
    const img = try loadImage(fp.ops(), 0x1000, &image, layout.image_base);
    const ctx = try buildUserContext(fp.ops(), 0x1000, layout, img.base_va, "curl.exe");

    try testing.expectEqual(layout.stack_top - 8, ctx.stack_rsp);
    try testing.expectEqual(layout.teb_va, ctx.teb_va);

    // TEB-страница в фейковой физ-памяти: Self указывает на свой VA
    const teb_map = findMap(fp, layout.teb_va).?;
    const teb_mem = fp.mem[@intCast(teb_map.pa)..][0..4096];
    try testing.expectEqual(layout.teb_va, std.mem.readInt(u64, teb_mem[0x30..][0..8], .little));
    try testing.expectEqual(layout.peb_va, std.mem.readInt(u64, teb_mem[0x60..][0..8], .little));
    // PEB.ImageBaseAddress
    const peb_map = findMap(fp, layout.peb_va).?;
    const peb_mem = fp.mem[@intCast(peb_map.pa)..][0..4096];
    try testing.expectEqual(img.base_va, std.mem.readInt(u64, peb_mem[0x08..][0..8], .little));
    // cmdline ANSI в params-странице
    const pp_map = findMap(fp, layout.params_va).?;
    const pp_mem = fp.mem[@intCast(pp_map.pa)..][0..4096];
    try testing.expectEqualStrings("curl.exe", pp_mem[0x200..0x208]);

    // стек: верхняя страница RW+NX, фейковый ret=0 на top-8
    const stack_map = findMap(fp, layout.stack_top - PAGE_SIZE).?;
    try testing.expect(stack_map.flags & PTE_WRITABLE != 0);
    try testing.expect(stack_map.flags & PTE_NO_EXECUTE != 0);
    const stack_mem = fp.mem[@intCast(stack_map.pa)..][0..4096];
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, stack_mem[4096 - 8 ..][0..8], .little));

    // TLS-страница нулевая
    const tls_map = findMap(fp, layout.tls_va).?;
    const tls_mem = fp.mem[@intCast(tls_map.pa)..][0..4096];
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, tls_mem[0..][0..8], .little));
}
