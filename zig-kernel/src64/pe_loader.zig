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
    /// v0.18.0 (CDD №9 hardening): снять маппинг va в целевом PML4
    /// (PMM-rollback при сбоях загрузки — анти-утечка физпамяти).
    /// false → записи не было (идемпотентно, ошибки не было).
    unmap_user: *const fn (pml4: u64, va: u64) bool,
    /// v0.18.0 (CDD №9 hardening): освободить contiguous-блок PMM
    /// (base_pa из alloc_contig, тот же count) — только на путях ОТКАЗА
    /// до передачи региона владельцу. Успешные маппинги не освобождаются.
    free_contig: *const fn (base_pa: u64, count: u64) void,
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
/// v0.18.0 (CDD №9): при сбое маппинга — полный откат (unmap уже
/// замапленных страниц + free_contig) — PMM не течёт на битых образах.
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
            // ROLLBACK: снимаем уже поставленные маппинги [0, i) и
            // возвращаем блок PMM (v0.17: утечка при сбое посреди образа)
            var j: u64 = 0;
            while (j < i) : (j += 1) {
                _ = ops.unmap_user(pml4, va + j * PAGE_SIZE);
            }
            ops.free_contig(base_pa, n);
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
/// v0.18.0 (CDD №9 hardening): ВСЕ пути ошибок после alloc_contig делают
/// полный откат — unmap замапленных страниц [0, i) + free_contig блока
/// (v0.17: повреждённый PE с секцией вне образа/конфликтом VA оставлял
/// выделенные страницы PMM занятыми навсегда — утечка физпамяти).
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

    // v0.18.0 (CDD №9): единый откат — снять mapped замаппингов [0, mapped)
    // + free_contig блока. Для ошибок ДО маппинг-цикла mapped = 0.
    const rollback = struct {
        fn call(o: LoaderOps, p: u64, va: u64, mapped: u64, pa: u64, pages: u64, e: LoadError) LoadError!LoadedImage {
            var j: u64 = 0;
            while (j < mapped) : (j += 1) {
                _ = o.unmap_user(p, va + j * PAGE_SIZE);
            }
            o.free_contig(pa, pages);
            return e;
        }
    }.call;

    // 1. Заголовки (DOS + NT + таблица секций) — побайтовая копия
    const hdr_len = @min(@as(usize, image.sizeOfHeaders()), file.len);
    if (hdr_len > soi) return rollback(ops, pml4, base_va, 0, base_pa, n, LoadError.BadHeaders);
    @memcpy(backing[0..hdr_len], file[0..hdr_len]);

    // 2. Секции: RawData → по VirtualAddress (RVA)
    for (image.sections) |*sec| {
        if (sec.size_of_raw_data == 0) continue; // чистый BSS — уже нули
        const dst: u64 = sec.virtual_address;
        if (dst + @as(u64, sec.size_of_raw_data) > soi) {
            return rollback(ops, pml4, base_va, 0, base_pa, n, LoadError.SectionOverflow);
        }
        const src: u64 = sec.pointer_to_raw_data;
        if (src + @as(u64, sec.size_of_raw_data) > file.len) {
            return rollback(ops, pml4, base_va, 0, base_pa, n, LoadError.BadHeaders);
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
            return rollback(ops, pml4, base_va, i, base_pa, n, LoadError.MapFailed);
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

// ============================================================================
// v0.17.0 (CDD №8): Base Relocations (.reloc / ASLR / DYNAMIC_BASE)
// ============================================================================
// Образы с ImageBase < 4ГБ (7za.exe: 0x400000) не проходят validateImageBase
// (identity-map ядра 0–4ГБ) — грузим по ВЫСОКОМУ базису и правим абсолютные
// 64-битные указатели таблицей .reloc. Формат: последовательность блоков
// { u32 page_rva, u32 block_size, u16 entries[] }; entry = (type<<12)|offset;
// type 10 = IMAGE_REL_BASED_DIR64 — *(u64*)(page_rva+offset) += delta.
// ============================================================================

/// Типы записей таблицы релокаций (winnt.h).
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0; // паддинг (пропуск)
pub const IMAGE_REL_BASED_DIR64: u16 = 10; // 64-битный абсолютный указатель

/// Статистика применения релокаций (лог ядра + юнит-тесты).
pub const RelocStats = struct {
    applied: u64 = 0, // DIR64-фикспов применено
    skipped_type: u64 = 0, // неподдержанные типы (HIGHLOW/HIGHADJ…)
    skipped_bounds: u64 = 0, // фикспы за пределами SizeOfImage
    delta: i64 = 0, // фактический_базис − предпочтённый
};

/// Применить таблицу базовых релокаций DIR64 к ЗАГРУЖЕННОМУ образу
/// (секции уже скопированы в backing по RVA; таблица .reloc читается
/// из самого backing — её RVA из data-директории №5).
/// base_va — фактический адрес загрузки; preferred — ImageBase из PE.
/// Идемпотентно при delta == 0 (загружен по предпочтённому базису).
pub fn applyRelocations(
    image: *const pe.Pe,
    backing: [*]u8,
    base_va: u64,
    preferred: u64,
) RelocStats {
    var stats = RelocStats{
        .delta = @as(i64, @bitCast(base_va)) -% @as(i64, @bitCast(preferred)),
    };
    if (stats.delta == 0) return stats;

    const dir = image.dataDirectory(pe.DIR_BASERELOC);
    if (dir.virtual_address == 0 or dir.size == 0) return stats; // таблицы нет — нечего править

    const soi: u64 = image.sizeOfImage();
    const end: u64 = @as(u64, dir.virtual_address) + dir.size;
    if (end > soi) return stats; // битая директория — молча отказ

    var off: u64 = dir.virtual_address;
    while (off + 8 <= end) {
        const page_rva = std.mem.readInt(u32, backing[off..][0..4], .little);
        const block_size = std.mem.readInt(u32, backing[off..][4..8], .little);
        if (block_size < 8 or off + block_size > end) break; // битый блок — стоп
        const n: u32 = (block_size - 8) / 2;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const e = std.mem.readInt(u16, backing[off + 8 + i * 2 ..][0..2], .little);
            const typ: u16 = e >> 12;
            if (typ == IMAGE_REL_BASED_ABSOLUTE) continue; // паддинг
            if (typ != IMAGE_REL_BASED_DIR64) {
                stats.skipped_type += 1;
                continue;
            }
            const fix_rva: u64 = @as(u64, page_rva) + (e & 0xFFF);
            if (fix_rva + 8 > soi) {
                stats.skipped_bounds += 1;
                continue; // виниграммная таблица не должна так делать — но не падаем
            }
            const old = std.mem.readInt(u64, backing[fix_rva..][0..8], .little);
            const fixed = old +% @as(u64, @bitCast(stats.delta));
            std.mem.writeInt(u64, backing[fix_rva..][0..8], fixed, .little);
            stats.applied += 1;
        }
        off += block_size;
    }
    return stats;
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
    // Стек: RW+NX, страницы обнулены.
    const stack_bytes = layout.stack_pages * PAGE_SIZE;
    const stack = try mapRegion(ops, pml4, layout.stack_top - stack_bytes, stack_bytes, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);

    // v0.17.0 (CDD №8): начальный RSP = top − 0x108.
    //   ① Win64 ABI: на входе функции RSP ≡ 8 (mod 16) — как после call,
    //     вытолкнувшего 8-байтный адрес возврата (0x108 % 16 == 8).
    //   ② «Тень вызвавшего»: entry-код Win64-бинарников (MSVC CRT
    //     mainCRTStartup, entry 7-Zip) пишет в caller shadow space
    //     [rsp+8..rsp+0x28] ВЫШЕ входного RSP. С top−8 записи [rsp+0x18]
    //     попадали на top+0x10 — ЗА границей стека (#PF). headroom 0x100
    //     над RSP = 256Б «фрейма вызвавшего» внутри стека.
    //   ③ Фейковый return-address=0 в [RSP] — stray ret → VA 0 → #PF →
    //     видимый CDD-крах (не немой уход в мусор).
    const stack_rsp = layout.stack_top - 0x108;
    std.mem.writeInt(u64, stack.backing[stack.size - 0x108 ..][0..8], 0, .little); // stray ret → VA 0 → #PF → видимый CDD-крах

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
        .stack_rsp = stack_rsp,
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

fn loadFixture(comptime name: []const u8) ![]const u8 {
    if (comptime std.mem.eql(u8, name, "testdata/curl.exe")) {
        return @embedFile("testdata/curl.exe");
    } else if (comptime std.mem.eql(u8, name, "testdata/7za.exe")) {
        return @embedFile("testdata/7za.exe");
    } else if (comptime std.mem.eql(u8, name, "testdata/7zr.exe")) {
        return @embedFile("testdata/7zr.exe");
    } else {
        return error.FileNotFound;
    }
}

/// Фейковое «физическое» пространство: bump-аллокатор + логер маппингов.
/// v0.18.0 (CDD №9): + unmapUser (удаление MapRec по VA) + freeContig
/// (откат курсора для хвостовой выделечки + счётчик свободождённых страниц)
/// + инъекция сбоя маппинга fail_map_after (rollback-тесты).
const FakePhys = struct {
    const MapRec = struct { va: u64, pa: u64, flags: u64 };

    mem: []u8,
    cursor: u64, // байтовый курсор (кратно 4096)
    maps: std.ArrayList(MapRec),
    /// v0.18.0: инъекция сбоя — mapUser вернёт false, когда число уже
    /// успешных маппингов достигнет порога (null = не сбивать).
    fail_map_after: ?u64 = null,
    /// v0.18.0: статистика rollback-путей (assert'ы тестов).
    freed_calls: u64 = 0,
    freed_pages: u64 = 0,
    unmapped: u64 = 0,

    fn init(size: u64) !FakePhys {
        return .{
            .mem = try testing.allocator.alloc(u8, @intCast(size)),
            // старт с 1МБ: как реальный PMM (первый мегабайт — BIOS/VGA),
            // и pa=0 невозможен (@ptrFromInt(0) = null-паника Zig)
            .cursor = 0x100000,
            .maps = std.ArrayList(MapRec).empty,
        };
    }
    fn deinit(self: *FakePhys) void {
        testing.allocator.free(self.mem);
        self.maps.deinit(testing.allocator);
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
        // v0.18.0: инъекция сбоя маппинга для rollback-тестов
        if (self.fail_map_after) |thr| {
            if (self.maps.items.len >= thr) return false;
        }
        self.maps.append(testing.allocator, .{ .va = va, .pa = pa, .flags = flags }) catch return false;
        _ = pml4;
        return true;
    }
    /// v0.18.0: снять маппинг по VA (первое вхождение) — зеркало VMM.
    fn unmapUser(self: *FakePhys, pml4: u64, va: u64) bool {
        for (self.maps.items, 0..) |m, idx| {
            if (m.va == va) {
                _ = self.maps.orderedRemove(idx);
                self.unmapped += 1;
                _ = pml4;
                return true;
            }
        }
        return false;
    }
    /// v0.18.0: free contiguous-блока. Хвостовой блок (top-of-bump) реально
    /// возвращает память (курсор назад) — как PMM freeContiguousPages;
    /// нет хвостовой — считаем_pages для assert'ов (реальный PMM умеет
    /// оба случая, тестам достаточно инварианта «free вызван с теми же
    /// base/count, что и alloc»).
    fn freeContig(self: *FakePhys, base_pa: u64, count: u64) void {
        const bytes = count * PAGE_SIZE;
        if (base_pa + bytes == self.cursor) {
            self.cursor = base_pa; // полный возврат хвоста bump-аллокатору
        }
        self.freed_calls += 1;
        self.freed_pages += count;
    }
    fn ops(_: *FakePhys) LoaderOps {
        return .{
            .alloc_contig = allocContigClosure,
            .map_user = mapUserClosure,
            .page_ptr = pagePtrClosure,
            .unmap_user = unmapUserClosure,
            .free_contig = freeContigClosure,
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
    const unmapUserClosure = struct {
        fn call(pml4: u64, va: u64) bool {
            return global_fake.?.unmapUser(pml4, va);
        }
    }.call;
    const freeContigClosure = struct {
        fn call(base_pa: u64, count: u64) void {
            global_fake.?.freeContig(base_pa, count);
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

    const image = try pe.Pe.parse(data);

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);

    const layout = UserLayout{};
    const img = try loadImage(fp.ops(), 0x1000, &image, layout.image_base);
    const ctx = try buildUserContext(fp.ops(), 0x1000, layout, img.base_va, "curl.exe");

    // v0.17.0 (CDD №8): RSP = top−0x108 — ABI ≡8 (mod 16) + 256Б тени вызвавшего
    try testing.expectEqual(layout.stack_top - 0x108, ctx.stack_rsp);
    try testing.expectEqual(@as(u64, 0x22_0000_0000 - 0x108) % 16, @as(u64, 8)); // Win64 ABI: entry RSP ≡ 8 (mod 16)
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
    // v0.17.0 (CDD №8): фейковый ret=0 в [RSP] (top−0x108), а не в top−8
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, stack_mem[4096 - 0x108 ..][0..8], .little));

    // TLS-страница нулевая
    const tls_map = findMap(fp, layout.tls_va).?;
    const tls_mem = fp.mem[@intCast(tls_map.pa)..][0..4096];
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, tls_mem[0..][0..8], .little));
}

// ============================================================================
// v0.17.0 (CDD №8): тесты движка базовых релокаций (.reloc / DYNAMIC_BASE)
// ============================================================================

/// Подсчёт DIR64-записей таблицы .reloc по ФАЙЛОВЫМ данным (эталон для тестов).
fn countDir64InFile(image: *const pe.Pe) u64 {
    const dir = image.dataDirectory(pe.DIR_BASERELOC);
    if (dir.virtual_address == 0 or dir.size == 0) return 0;
    const data = image.data;
    const start = image.rvaToOffset(dir.virtual_address) orelse return 0;
    var file_off: u64 = start;
    const end = start + dir.size;
    var total: u64 = 0;
    while (file_off + 8 <= end) {
        const block_size = std.mem.readInt(u32, data[@intCast(file_off + 4)..][0..4], .little);
        if (block_size < 8 or file_off + block_size > end) break;
        const n = (block_size - 8) / 2;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const e = std.mem.readInt(u16, data[@intCast(file_off + 8 + i * 2)..][0..2], .little);
            if ((e >> 12) == IMAGE_REL_BASED_DIR64) total += 1;
        }
        file_off += block_size;
    }
    return total;
}

test "cdd8-reloc: 7za.exe x64 — 2258 DIR64 применены, значения = файл + delta" {
    const data = try loadFixture("testdata/7za.exe");

    const image = try pe.Pe.parse(data);

    // 7za.exe: ImageBase=0x400000 (ниже identity 4ГБ!) — грузим высоко.
    const preferred = image.imageBase();
    const base: u64 = 0x140000000;
    try testing.expect(preferred == 0x400000);
    try testing.expect(!validateImageBase(preferred, image.sizeOfImage()));
    try testing.expect(validateImageBase(base, image.sizeOfImage()));

    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);
    const img = try loadImage(fp.ops(), 0xDEAD000, &image, base);

    // До релокаций: абсолютный указатель в образе указывает на СТАРЫЙ базис.
    const stats = applyRelocations(&image, img.backing, base, preferred);
    try testing.expectEqual(countDir64InFile(&image), stats.applied);
    try testing.expectEqual(@as(u64, 2258), stats.applied);
    try testing.expectEqual(@as(u64, 0), stats.skipped_type);
    try testing.expectEqual(@as(u64, 0), stats.skipped_bounds);
    try testing.expectEqual(@as(i64, 0x140000000 - 0x400000), stats.delta);

    // Выборочная сверка 3 фикспов: backing[fix_rva] == file[fix_rva] + delta.
    const dir = image.dataDirectory(pe.DIR_BASERELOC);
    var checked: usize = 0;
    var file_off: u64 = (image.rvaToOffset(dir.virtual_address) orelse return error.BadRelocDir);
    const end = file_off + dir.size;
    outer: while (file_off + 8 <= end) {
        const page_rva = std.mem.readInt(u32, data[@intCast(file_off)..][0..4], .little);
        const block_size = std.mem.readInt(u32, data[@intCast(file_off + 4)..][0..4], .little);
        if (block_size < 8 or file_off + block_size > end) break;
        const n = (block_size - 8) / 2;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const e = std.mem.readInt(u16, data[@intCast(file_off + 8 + i * 2)..][0..2], .little);
            if ((e >> 12) != IMAGE_REL_BASED_DIR64) continue;
            const fix_rva: u64 = @as(u64, page_rva) + (e & 0xFFF);
            const file_val = std.mem.readInt(u64, data[@intCast(image.rvaToOffset(@intCast(fix_rva)) orelse continue)..][0..8], .little);
            const mem_val = std.mem.readInt(u64, img.backing[fix_rva..][0..8], .little);
            try testing.expectEqual(file_val +% @as(u64, @bitCast(stats.delta)), mem_val);
            checked += 1;
            if (checked == 3) break :outer;
        }
        file_off += block_size;
    }
    try testing.expect(checked == 3);
}

test "cdd8-reloc: curl.exe — таблица DYNAMIC_BASE применяется при сдвиге базиса" {
    const data = try loadFixture("testdata/curl.exe");

    const image = try pe.Pe.parse(data);

    // curl.exe грузится по предпочтённому 0x140000000 обычно; сдвинем базис —
    // активируем .reloc, как это делает Windows ASLR.
    const preferred = image.imageBase();
    const base: u64 = preferred + 0x1000000; // +16МБ
    try testing.expect(base != preferred);

    const fp = try fakeSetup(96 << 20);
    defer fakeTeardown(fp);
    const img = try loadImage(fp.ops(), 0xDEAD000, &image, base);

    const stats = applyRelocations(&image, img.backing, base, preferred);
    try testing.expectEqual(countDir64InFile(&image), stats.applied);
    try testing.expect(stats.applied > 9000); // curl.exe: ~10.9K DIR64-фикспов
    try testing.expectEqual(@as(u64, 0), stats.skipped_type);
    try testing.expectEqual(@as(u64, 0), stats.skipped_bounds);

    // Дельта ноль — идемпотентность (загружен по предпочтённому базису).
    const stats0 = applyRelocations(&image, img.backing, preferred, preferred);
    try testing.expectEqual(@as(u64, 0), stats0.applied);
}

test "cdd8-reloc: синтетика — ABSOLUTE-паддинг пропускается, битые границы не роняют ядро" {
    // Ручная мини-таблица (копируется в backing поверх .reloc 7za):
    // блок 1 { page_rva=0x1000, size=8+3*2=14 }:
    //   entry1 = (0<<12)|0x00 — ABSOLUTE (паддинг — пропуск)
    //   entry2 = (3<<12)|0x10 — HIGHLOW (неподдержанный тип → skipped_type)
    //   entry3 = (10<<12)|0x20 — DIR64 на RVA 0x1020 (валидный)
    // блок 2 { page_rva=0x200000, size=10 }: entry = (10<<12)|0xF00
    //   → RVA 0x200F00 — за SizeOfImage 7za (~0x137000) → skipped_bounds
    var buf = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, buf[0x00..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, buf[0x04..][0..4], 14, .little);
    std.mem.writeInt(u16, buf[0x08..][0..2], (0 << 12) | 0x00, .little);
    std.mem.writeInt(u16, buf[0x0A..][0..2], (3 << 12) | 0x10, .little);
    std.mem.writeInt(u16, buf[0x0C..][0..2], (10 << 12) | 0x20, .little);
    std.mem.writeInt(u32, buf[0x0E..][0..4], 0x200000, .little);
    std.mem.writeInt(u32, buf[0x12..][0..4], 10, .little);
    std.mem.writeInt(u16, buf[0x16..][0..2], (10 << 12) | 0xF00, .little);

    const data = try loadFixture("testdata/7za.exe");

    const image = try pe.Pe.parse(data);
    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);
    const img = try loadImage(fp.ops(), 0xDEAD000, &image, 0x140000000);

    // Подменяем .reloc-область backing нашей синтетической таблицей.
    const dir = image.dataDirectory(pe.DIR_BASERELOC);
    @memcpy(img.backing[dir.virtual_address..][0..0x20], buf[0..0x20]);
    // Цель фикспа — RVA 0x1020 (внутри .text 7za): кладём «старый базис».
    std.mem.writeInt(u64, img.backing[0x1020..][0..8], 0x400000, .little);

    const stats = applyRelocations(&image, img.backing, 0x140000000, 0x400000);
    try testing.expectEqual(@as(u64, 1), stats.applied); // только валидный DIR64
    try testing.expectEqual(@as(u64, 1), stats.skipped_type); // HIGHLOW
    try testing.expectEqual(@as(u64, 1), stats.skipped_bounds); // за SOI — НЕ падение
    // Цель исправлена: 0x400000 + (0x140000000 − 0x400000) = 0x140000000
    try testing.expectEqual(@as(u64, 0x140000000), std.mem.readInt(u64, img.backing[0x1020..][0..8], .little));
}

// ============================================================================
//  v0.18.0 (CDD №9 hardening): PMM-rollback при сбоях маппинга PE
// ============================================================================

test "rollback: mapRegion при сбое маппинга — unmap + free, PMM не течёт" {
    const fp = try fakeSetup(16 << 20);
    defer fakeTeardown(fp);
    const cursor_before = fp.cursor;

    // Сбой на 3-й странице 5-страничного региона
    fp.fail_map_after = 2;
    const r = mapRegion(fp.ops(), 0xDEAD000, 0x40000000, 5 * PAGE_SIZE, PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE);
    try testing.expectError(LoadError.MapFailed, r);

    // Инварианты отката: все частичные маппинги сняты, блок освобождён
    try testing.expectEqual(@as(u64, 2), fp.unmapped);
    try testing.expectEqual(@as(u64, 1), fp.freed_calls);
    try testing.expectEqual(@as(u64, 5), fp.freed_pages);
    try testing.expectEqual(@as(usize, 0), fp.maps.items.len);
    // Хвостовой bump-блок реально возвращён: курсор на месте
    try testing.expectEqual(cursor_before, fp.cursor);
}

test "rollback: loadImage при сбое маппинга посреди образа — полный откат" {
    const data = try loadFixture("testdata/curl.exe");

    const image = try pe.Pe.parse(data);
    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);
    const cursor_before = fp.cursor;
    const n = pageCount(image.sizeOfImage());

    // Сбой на 4-й странице образа (curl.exe ~1.5МБ = сотни страниц)
    fp.fail_map_after = 3;
    const r = loadImage(fp.ops(), 0xDEAD000, &image, 0x140000000);
    try testing.expectError(LoadError.MapFailed, r);

    // 3 замапленных страницы сняты, весь блок образа освобождён
    try testing.expectEqual(@as(u64, 3), fp.unmapped);
    try testing.expectEqual(@as(u64, 1), fp.freed_calls);
    try testing.expectEqual(n, fp.freed_pages);
    try testing.expectEqual(@as(usize, 0), fp.maps.items.len);
    try testing.expectEqual(cursor_before, fp.cursor); // bump-хвост возвращён
}

test "rollback: битый PE (SectionOverflow) — блок PMM освобождён" {
    // Собираем битый образ в памяти: валидные заголовки + секция ВНЕ
    // SizeOfImage → loadImage обязан откатить выделенный блок.
    const data = try loadFixture("testdata/curl.exe");

    const image = try pe.Pe.parse(data);

    // Мутируем копию секции .text: virtual_address за пределы образа.
    // pe.Pe парсит поверх того же буфера — берём мутабельную копию данных.
    const bad = try testing.allocator.dupe(u8, data);
    defer testing.allocator.free(bad);
    const text = image.sectionByName(".text").?;
    const sec_hdr_off = @intFromPtr(text) - @intFromPtr(image.data.ptr);
    std.mem.writeInt(u32, bad[sec_hdr_off + 12..][0..4], 0x7F000000, .little); // VA за SOI

    const bad_image = try pe.Pe.parse(bad);
    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);
    const cursor_before = fp.cursor;

    const r = loadImage(fp.ops(), 0xDEAD000, &bad_image, 0x140000000);
    try testing.expectError(LoadError.SectionOverflow, r);

    // Откат без маппингов (ошибка до цикла) — но блок PMM освобождён
    try testing.expectEqual(@as(u64, 0), fp.unmapped);
    try testing.expectEqual(@as(u64, 1), fp.freed_calls);
    try testing.expectEqual(pageCount(image.sizeOfImage()), fp.freed_pages);
    try testing.expectEqual(cursor_before, fp.cursor);
}

test "rollback: успешная загрузка НЕ трогает free-путь (нулевые счётчики)" {
    const data = try loadFixture("testdata/curl.exe");

    const image = try pe.Pe.parse(data);
    const fp = try fakeSetup(64 << 20);
    defer fakeTeardown(fp);

    _ = try loadImage(fp.ops(), 0xDEAD000, &image, 0x140000000);

    // Happy path: ни unmap, ни free — регион живёт у владельца
    try testing.expectEqual(@as(u64, 0), fp.freed_calls);
    try testing.expectEqual(@as(u64, 0), fp.freed_pages);
    try testing.expectEqual(@as(u64, 0), fp.unmapped);
    try testing.expect(fp.maps.items.len > 0);
}
