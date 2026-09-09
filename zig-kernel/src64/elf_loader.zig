// ============================================================================
// POLER-OS ELF64 Loader — Linux-ABI (v0.20.0, CDD №11 p1)
// ============================================================================
//
// ПЕРВЫЙ ELF-ПРОЦЕСС CachyOS: загрузка статических/PIE-бинарников Linux
// x86-64 в Ring 3 и первичный стек Linux-ABI (argc/argv/envp/auxv).
//
// Поддержка:
//   - ET_EXEC (фиксированные адреса; сегменты ОБЯЗАНЫ быть ≥ 4ГБ — ниже
//     identity-зона ядра) и ET_DYN (PIE: базис выбирает загрузчик)
//   - PT_LOAD сегменты: R/W/X → PTE-флаги (NX для не-X, W для W)
//   - BSS (p_memsz > p_filesz) — нули (alloc_contig даёт нулевые страницы,
//     явная добивка на границах сегментов)
//   - Первичный стек Linux-ABI: argc/argv[]/envp[]/auxv (AT_PHDR/AT_PHENT/
//     AT_PHNUM/AT_PAGESZ/AT_ENTRY/AT_BASE/AT_RANDOM/AT_PLATFORM/AT_UID/…)
//     — glibc/musl совместимая раскладка, rsp 16-выровнен
//
// Модель Starnix (прецедент pe_loader.LoaderOps): СЕМАНТИЧЕСКОЕ ядро чистое
// — все платформенные эффекты (физ-аллокации, маппинги, запись) за ElfOps-
// указателями. Ядро регистрирует боевой runtime (main64: kernelElfOps —
// PMM/vmm identity), нативные тесты — фейковый аллокатор с mock-памятью.
//
// Инвариант CDD №11: НИКАКОЙ мусорный ELF (обрезанный header, phoff-
// переполнение, p_filesz > файла, сегменты в identity-зоне) не должен
// паниковать ядро — только error.UploadLimit/InvalidElf.
// ============================================================================

const std = @import("std");
const testing = std.testing;

pub const PAGE_SIZE: u64 = 4096;

// ─── PTE-флаги (зеркало vmm64 — самостоятельные константы модуля) ──────────
pub const PTE_PRESENT: u64 = 0x01;
pub const PTE_WRITABLE: u64 = 0x02;
pub const PTE_USER: u64 = 0x04;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;

// ─── Раскладка Linux-процесса (v0.20.0) ─────────────────────────────────────
//
//   0x0000_1000_0000_0000 (16ТБ) — образ ELF (ET_DYN-базис / ET_EXEC-сегменты)
//   0x0000_0800_0000_0000  (8ТБ) — верх первичного стека (вниз, 64КБ)
//   0x40_0000_0000       (256ГБ) — mmap-регион (анонимный + устройства)
//
// Выбор зон: канонический user-диапазон, НОЛЬ пересечений с Win32-планировкой
// (image 5ГБ … heap 0x30_4000_0000) и mmap-регионом Linux-задач. Процессы
// имеют собственные PML4 — коллизий между ABI нет, зоны разведены для
// читаемости дамп-диагностики.
pub const LINUX_IMAGE_BASE: u64 = 0x0000_1000_0000_0000;
/// Базис интерпретатора (ld.so): вторая ET_DYN-картинка (4ТБ — между
/// mmap-регионом и стеком; никаких пересечений с зонами образа/стека).
pub const LINUX_INTERP_BASE: u64 = 0x0000_0400_0000_0000;
pub const LINUX_STACK_TOP: u64 = 0x0000_0800_0000_0000;
/// CDD №12 p3: 64МБ — эмпирика run8/run9: 8МБ тоже малы (lavapipe/LLVM
/// инициализация — монотонный спуск RSP основного треда до дна; Linux
/// растит стек авто, мы премапим с запасом: 2ГБ гостя позволяет).
pub const LINUX_STACK_PAGES: u64 = 32768; // 128МБ первичный стек (CDD №12 p3: тест предела рекурсии)
/// Нижняя граница валидных user-сегментов: ниже — identity-маппинги ядра
/// (PML4[0] копируется в user-PML4 БЕЗ User-бита — Ring 3 туда не ходит,
/// но конфликт маппинга гарантирован).
pub const MIN_USER_VA: u64 = 0x1_0000_0000; // 4ГБ
pub const USER_VA_CEILING: u64 = 0x0000_8000_0000_0000; // канонический user-потолок

// ─── ELF64 структуры (System V ABI, байт-в-байт) ────────────────────────────

pub const EI_NIDENT: usize = 16;

pub const Elf64_Ehdr = extern struct {
    e_ident: [EI_NIDENT]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

pub const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 62;

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3; // динамический: путь интерпретатора (ld.so)
pub const PT_GNU_STACK: u32 = 0x6474_E551; // флаги стека — просто фиксируем
pub const PT_GNU_RELRO: u32 = 0x6474_E552; // relro-инфо, маппинга не требует

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Размер Elf64_Phdr по ABI (раскладка выше обязана давать 56).
pub const _ABI_SIZE_CHECK = if (@sizeOf(Elf64_Ehdr) != 64) @compileError("Elf64_Ehdr must be 64 bytes");
pub const _ABI_SIZE_CHECK2 = if (@sizeOf(Elf64_Phdr) != 56) @compileError("Elf64_Phdr must be 56 bytes");

// ─── Auxv-ключи (linux/elf.h — якоря для glibc/musl) ────────────────────────

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────
//
// Контракт зеркален pe_loader.LoaderOps (прецедент v0.10+):
//   • alloc_contig — ОБНУЛЁННЫЙ блок физически последовательных страниц
//     (PMM.allocContiguousZeroed в ядре; фейковый аллокатор в тестах);
//   • map_user — маппинг user-VA → phys в ЦЕЛЕВОМ PML4 (false = конфликт/
//     отказ; AlreadyMapped от соседнего сегмента — НЕ ошибка, страница
//     разделяется, данные копируются поверх);
//   • page_ptr — указатель ЗАПИСИ на физ-страницу (ядро: identity pa == VA);
//   • unmap_user / free_contig — ОТКАТ на путях ошибки (анти-утечка
//     физпамяти, дисциплина v0.18.0 hardening).

pub const ElfOps = struct {
    alloc_contig: *const fn (count: u64) ?u64,
    map_user: *const fn (pml4: u64, va: u64, pa: u64, flags: u64) bool,
    page_ptr: *const fn (pa: u64) [*]u8,
    unmap_user: *const fn (pml4: u64, va: u64) bool,
    free_contig: *const fn (base_pa: u64, count: u64) void,
};

// ─── Ошибки ────────────────────────────────────────────────────────────────

pub const ElfError = error{
    Truncated, // header/фантомы не влезают в буфер
    InvalidMagic, // нет 0x7F 'E' 'L' 'F'
    Not64Bit, // ELFCLASS32
    WrongEndian, // EI_DATA != little-endian
    NotExecutable, // ET_REL/core/OS-specific
    WrongArchitecture, // e_machine != EM_X86_64
    NoProgramHeaders, // e_phnum == 0
    BadPhdrTable, // e_phoff/entsize/num вне файла
    SegmentBounds, // p_offset+p_filesz > файла / memsz < filesz
    ImageBaseInvalid, // сегменты в identity-зоне/над потолком user
    OutOfMemory, // физпамять кончилась
    MapFailed, // маппинг отклонён (не конфликт соседа)
    StackOverflow, // стек-контент больше региона
};

// ─── Результат загрузки образа ─────────────────────────────────────────────

pub const ElfImage = struct {
    /// Фактический базис образа (ET_DYN — выбранный, ET_EXEC — p_vaddr min).
    base_va: u64,
    entry_va: u64,
    /// VA таблицы программных заголовков (auxv AT_PHDR).
    phdr_va: u64,
    phentsize: u64,
    phnum: u64,
    /// Конец образа (page-up последнего PT_LOAD) — старт brk.
    brk: u64,
    /// Суммарные страницы образа (диагностика).
    pages: u64,
    is_pie: bool,
    /// PT_INTERP обнаружен: путь интерпретатора (slice в буфере данных
    /// ЗАГРУЖАЕМОГО бинарника — валиден до конца загрузки). null = статик.
    interp: ?[]const u8 = null,
};

// ─── p_flags → PTE ─────────────────────────────────────────────────────────

pub fn flagsToPte(p_flags: u32) u64 {
    var pte: u64 = PTE_PRESENT | PTE_USER;
    if (p_flags & PF_W != 0) pte |= PTE_WRITABLE;
    if (p_flags & PF_X == 0) pte |= PTE_NO_EXECUTE;
    return pte;
}

// ─── Валидация заголовка ───────────────────────────────────────────────────

/// Bounce-буферы парсинга: CPIO-данные НЕ обязаны быть выровнены
/// (эмпирика glibc-static: файл 758КБ на смещении ≠ 8 — @alignCast паниковал
/// ядро). Копируем заголовок/фантом в выровненный .bss, разбор идёт оттуда.
var hdr_bounce: [64]u8 align(8) = [_]u8{0} ** 64;
var ph_bounce: [56]u8 align(8) = [_]u8{0} ** 56;

fn validateEhdr(data: []const u8) ElfError!*const Elf64_Ehdr {
    if (data.len < @sizeOf(Elf64_Ehdr)) return ElfError.Truncated;
    @memcpy(hdr_bounce[0..64], data[0..64]);
    const ehdr: *const Elf64_Ehdr = @ptrCast(&hdr_bounce);
    if (ehdr.e_ident[0] != 0x7F or ehdr.e_ident[1] != 'E' or
        ehdr.e_ident[2] != 'L' or ehdr.e_ident[3] != 'F')
    {
        return ElfError.InvalidMagic;
    }
    if (ehdr.e_ident[4] != 2) return ElfError.Not64Bit; // ELFCLASS64
    if (ehdr.e_ident[5] != 1) return ElfError.WrongEndian; // ELFDATA2LSB
    if (ehdr.e_machine != EM_X86_64) return ElfError.WrongArchitecture;
    switch (ehdr.e_type) {
        ET_EXEC, ET_DYN => {},
        else => return ElfError.NotExecutable,
    }
    if (ehdr.e_phnum == 0) return ElfError.NoProgramHeaders;
    // Таблица фантомов обязана ЦЕЛИКОМ лежать в буфере
    const sum = @addWithOverflow(ehdr.e_phoff, @as(u64, ehdr.e_phnum) * ehdr.e_phentsize);
    if (sum[1] != 0 or sum[0] > data.len) return ElfError.BadPhdrTable;
    if (ehdr.e_phentsize < @sizeOf(Elf64_Phdr)) return ElfError.BadPhdrTable;
    return ehdr;
}

/// Вычислить базис образа: ET_DYN → базис-параметр (дефолт LINUX_IMAGE_BASE,
/// ядро может передать иной); ET_EXEC → 0 (сегменты уже абсолютны) с
/// проверкой ВЕРХНЕЙ границы зоны образа.
fn imageBaseFor(ehdr: *const Elf64_Ehdr, dyn_base: u64, max_vaddr_end: u64) ElfError!u64 {
    if (ehdr.e_type == ET_DYN) {
        const sum = @addWithOverflow(dyn_base, max_vaddr_end);
        if (sum[1] != 0 or sum[0] > USER_VA_CEILING) return ElfError.ImageBaseInvalid;
        return dyn_base;
    }
    return 0;
}

// ─── Загрузка PT_LOAD-сегментов в целевой PML4 ─────────────────────────────
//
// По сегменту:
//   1. eff_vaddr = base + p_vaddr (ET_DYN) | p_vaddr (ET_EXEC);
//   2.ET_EXEC: eff_vaddr ≥ MIN_USER_VA (identity-зона ядра — запрет),
//      [eff_vaddr, eff_vaddr+p_memsz) ≤ USER_VA_CEILING;
//   3. страницы [vaddr&~0xFFF, page-up(end)) маппятся флагами flagsToPte;
//      уже размаппированная соседом страница (общая граница RX|RW) — НЕ
//      ошибка: страница разделяется, данные копируются поверх (флаги
//      первого сегмента остаются — документировано, современные линкеры
//      с -z separate-code не пересекаются);
//   4. копия файла: постранично (page_ptr + смещение в странице);
//   5. BSS [filesz, memsz) — явные нули (страницы нулевые, но границу
//      может делить соседний сегмент).
//
// Отказ на любом шаге → полный откат (unmap_user + free_contig).

pub fn loadElf(ops: ElfOps, pml4: u64, data: []const u8, dyn_base: u64) ElfError!ElfImage {
    const ehdr = try validateEhdr(data);

    // Проход 1: валидация сегментов + вычисление span и brk + PT_INTERP
    var seg_lo: u64 = std.math.maxInt(u64);
    var seg_hi: u64 = 0;
    var interp: ?[]const u8 = null;
    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const ph = phdrAt(data, ehdr, i);
        if (ph.p_type == PT_INTERP) {
            // путь интерпретатора: C-строка в данных бинарника
            const end = ph.p_offset + ph.p_filesz;
            if (end > data.len) return ElfError.SegmentBounds;
            const start = data[@intCast(ph.p_offset)..@intCast(end)];
            const nul = std.mem.indexOfScalar(u8, start, 0) orelse start.len;
            interp = start[0..nul];
        }
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_memsz < ph.p_filesz) return ElfError.SegmentBounds;
        const fsum = @addWithOverflow(ph.p_offset, ph.p_filesz);
        if (fsum[1] != 0 or fsum[0] > data.len) return ElfError.SegmentBounds;
        const vsum = @addWithOverflow(ph.p_vaddr, ph.p_memsz);
        if (vsum[1] != 0) return ElfError.ImageBaseInvalid;
        if (ph.p_vaddr < seg_lo) seg_lo = ph.p_vaddr;
        if (vsum[0] > seg_hi) seg_hi = vsum[0];
    }
    if (seg_lo == std.math.maxInt(u64)) return ElfError.NoProgramHeaders; // PT_LOAD нет

    const base = try imageBaseFor(ehdr, dyn_base, seg_hi);

    // ET_EXEC: все сегменты выше identity-зоны и ниже потолка
    if (ehdr.e_type == ET_EXEC) {
        if (seg_lo < MIN_USER_VA) return ElfError.ImageBaseInvalid;
        if (seg_hi > USER_VA_CEILING) return ElfError.ImageBaseInvalid;
    }

    const bsum = @addWithOverflow(base, seg_hi);
    if (bsum[1] != 0 or bsum[0] > USER_VA_CEILING) return ElfError.ImageBaseInvalid;

    const img_lo = (base + seg_lo) & ~@as(u64, PAGE_SIZE - 1);
    const img_hi = (base + seg_hi + PAGE_SIZE - 1) & ~@as(u64, PAGE_SIZE - 1);
    const total_pages = (img_hi - img_lo) / PAGE_SIZE;

    // Один сплошной нулевой блок на весь образ (проще отката, BSS нулевой)
    const backing = ops.alloc_contig(total_pages) orelse
        return ElfError.OutOfMemory;

    // Проход 2: маппинг страниц
    var mapped: u64 = 0;
    var map_failed = false;
    while (mapped < total_pages) : (mapped += 1) {
        const va = img_lo + mapped * PAGE_SIZE;
        const pa = backing + mapped * PAGE_SIZE;
        // Первый сегмент задаёт флаги страницы; для простоты v0.20 весь
        // образ маппится RWX-минимумом: флаги страницы = flagsToPte сегмента,
        // владеющего её НАЧАЛОМ (page-granular permissions — прецедент
        // pe_loader посекционного маппинга; -z separate-code даёт
        // непересекающиеся страницы).
        const pte = pageOwnerPte(data, ehdr, base, va);
        if (!ops.map_user(pml4, va, pa, pte)) {
            map_failed = true;
            break;
        }
    }
    if (map_failed) {
        var j: u64 = 0;
        while (j < mapped) : (j += 1) _ = ops.unmap_user(pml4, img_lo + j * PAGE_SIZE);
        ops.free_contig(backing, total_pages);
        return ElfError.MapFailed;
    }

    // Проход 3: копия файлов + BSS
    i = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const ph = phdrAt(data, ehdr, i);
        if (ph.p_type != PT_LOAD) continue;
        const seg_va = base + ph.p_vaddr;

        // файловые байты: постраничная перекачка в backing
        var done: u64 = 0;
        while (done < ph.p_filesz) {
            const va = seg_va + done;
            const page_idx = (va - img_lo) / PAGE_SIZE;
            const in_page = va % PAGE_SIZE;
            const chunk = @min(ph.p_filesz - done, PAGE_SIZE - in_page);
            const src = data[@intCast(ph.p_offset + done)..][0..@intCast(chunk)];
            const dst = ops.page_ptr(backing + page_idx * PAGE_SIZE)[@intCast(in_page)..][0..@intCast(chunk)];
            @memcpy(dst, src);
            done += chunk;
        }

        // BSS: [filesz, memsz) — явный нуль (границы страниц могут
        // использоваться соседом — перекрываем честно)
        if (ph.p_memsz > ph.p_filesz) {
            var z = ph.p_filesz;
            while (z < ph.p_memsz) {
                const va = seg_va + z;
                const page_idx = (va - img_lo) / PAGE_SIZE;
                const in_page = va % PAGE_SIZE;
                const chunk = @min(ph.p_memsz - z, PAGE_SIZE - in_page);
                const dst = ops.page_ptr(backing + page_idx * PAGE_SIZE)[@intCast(in_page)..][0..@intCast(chunk)];
                @memset(dst, 0);
                z += chunk;
            }
        }
    }

    return ElfImage{
        .base_va = base + seg_lo,
        .entry_va = base + ehdr.e_entry,
        .phdr_va = base + ehdr.e_phoff,
        .phentsize = ehdr.e_phentsize,
        .phnum = ehdr.e_phnum,
        .brk = img_hi,
        .pages = total_pages,
        .is_pie = ehdr.e_type == ET_DYN,
        .interp = interp,
    };
}

/// PTE-флаги для страницы va: сегмент, ВЛАДЕЮЩИЙ началом страницы.
fn pageOwnerPte(data: []const u8, ehdr: *const Elf64_Ehdr, base: u64, va: u64) u64 {
    var i: usize = 0;
    while (i < ehdr.e_phnum) : (i += 1) {
        const ph = phdrAt(data, ehdr, i);
        if (ph.p_type != PT_LOAD) continue;
        const seg_start = base + ph.p_vaddr;
        const seg_end = seg_start + ph.p_memsz;
        if (va >= seg_start and va < seg_end) return flagsToPte(ph.p_flags);
    }
    // Страница вне сегментов (последний хвост выравнивания) — RW+NX
    return PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE;
}

/// Фантом по индексу — ЗНАЧЕНИЕМ (копия в выровненный bounce: CPIO-данные
/// могут лежать на невыровненном смещении — @alignCast запрещён).
fn phdrAt(data: []const u8, ehdr: *const Elf64_Ehdr, idx: usize) Elf64_Phdr {
    const off = ehdr.e_phoff + idx * ehdr.e_phentsize;
    @memcpy(ph_bounce[0..56], data[@intCast(off)..][0..56]);
    const ph: *const Elf64_Phdr = @ptrCast(&ph_bounce);
    return ph.*;
}

// ─── Первичный стек Linux-ABI ──────────────────────────────────────────────
//
// Раскладка СВЕРХУ ВНИЗ (System V x86-64 ABI, glibc/musl-совместимая):
//
//   stack_top
//     [ argv-строки | env-строки | platform "x86_64" | AT_RANDOM 16Б ]
//     --- выравнивание 16 ---
//     [ auxv pairs… AT_NULL ]
//     [ envp[] NULL ] [ argv[] NULL ] [ argc ]
//   ← entry_rsp (16-выровнен, [rsp] = argc)
//
// AT_RANDOM — 16 псевдослучайных байт (seed-параметр: ядро даёт PUF-энтропию,
// тесты — константу). glibc использует их для stack-canary — ОБЯЗАТЕЛЕН.

pub const StackStrings = struct {
    argv: []const []const u8,
    envp: []const []const u8,
    execfn: []const u8, // argv[0] — дублируется в AT_EXECFN
};

pub const StackResult = struct {
    entry_rsp: u64,
    random_va: u64,
    platform_va: u64,
};

pub fn buildUserStack(
    ops: ElfOps,
    pml4: u64,
    stack_top: u64,
    stack_pages: u64,
    strings: StackStrings,
    img: ElfImage,
    random_seed: [16]u8,
    at_base: u64, // базис ld.so (динамик) или 0 (статик)
) ElfError!StackResult {
    const stack_bytes = stack_pages * PAGE_SIZE;
    const stack_lo = stack_top - stack_bytes;
    if (stack_lo < MIN_USER_VA) return ElfError.ImageBaseInvalid;

    // 1. Маппинг региона стека (RW + USER + NX)
    const backing = ops.alloc_contig(stack_pages) orelse
        return ElfError.OutOfMemory;
    var mapped: u64 = 0;
    while (mapped < stack_pages) : (mapped += 1) {
        const pte = PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NO_EXECUTE;
        if (!ops.map_user(pml4, stack_lo + mapped * PAGE_SIZE, backing + mapped * PAGE_SIZE, pte)) {
            var j: u64 = 0;
            while (j < mapped) : (j += 1) _ = ops.unmap_user(pml4, stack_lo + j * PAGE_SIZE);
            ops.free_contig(backing, stack_pages);
            return ElfError.MapFailed;
        }
    }

    // 2. Контент-бюджет: строки + векторы. Контент пишем через Helper:
    // VA-страница внутри [lo, hi) → page_ptr(backing + страница).
    const Helper = struct {
        ops: ElfOps,
        backing: u64,
        lo: u64,
        hi: u64,
        fn writeByteAt(self: @This(), va: u64, byte: u8) bool {
            if (va < self.lo or va >= self.hi) return false;
            const page = (va & ~@as(u64, PAGE_SIZE - 1)) - self.lo;
            const off = va % PAGE_SIZE;
            self.ops.page_ptr(self.backing + page)[@intCast(off)] = byte;
            return true;
        }
        fn writeBytesAt(self: @This(), va: u64, bytes: []const u8) bool {
            for (bytes, 0..) |b, k| {
                if (!self.writeByteAt(va + k, b)) return false;
            }
            return true;
        }
        fn writeWordAt(self: @This(), va: u64, word: u64) bool {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, word, .little);
            return self.writeBytesAt(va, &buf);
        }
    };
    const h = Helper{ .ops = ops, .backing = backing, .lo = stack_lo, .hi = stack_top };

    // 3. Строки сверху вниз
    var cursor = stack_top;

    // AT_RANDOM: 16Б
    cursor -= 16;
    const random_va = cursor;
    if (!h.writeBytesAt(random_va, &random_seed)) return ElfError.StackOverflow;

    // platform "x86_64\0"
    const platform_str = "x86_64";
    cursor -= platform_str.len + 1;
    const platform_va = cursor;
    if (!h.writeBytesAt(platform_va, platform_str ++ [_]u8{0})) return ElfError.StackOverflow;

    // env-строки (снизу вверх по списку = сверху вниз по памяти)
    var env_ptrs_buf: [64]u64 = .{0} ** 64; // CDD №15 p4: 32 → 64 (envp)
    var env_n: usize = 0;
    var e = strings.envp.len;
    while (e > 0) {
        e -= 1;
        const s = strings.envp[e];
        if (s.len + 1 > cursor - stack_lo) return ElfError.StackOverflow;
        cursor -= s.len + 1;
        if (!h.writeBytesAt(cursor, s) or !h.writeByteAt(cursor + s.len, 0))
            return ElfError.StackOverflow;
        env_ptrs_buf[env_n] = cursor;
        env_n += 1;
    }
    // прямой порядок указателей
    var env_ptrs: [64]u64 = .{0} ** 64;
    for (0..env_n) |k| env_ptrs[k] = env_ptrs_buf[env_n - 1 - k];

    // argv-строки (в обратном порядке записи, адреса разворачиваем)
    var argv_ptrs_buf: [64]u64 = .{0} ** 64; // CDD №15 p4: 32 → 64
    var argv_n: usize = 0;
    var a = strings.argv.len;
    while (a > 0) {
        a -= 1;
        const s = strings.argv[a];
        if (s.len + 1 > cursor - stack_lo) return ElfError.StackOverflow;
        cursor -= s.len + 1;
        if (!h.writeBytesAt(cursor, s) or !h.writeByteAt(cursor + s.len, 0))
            return ElfError.StackOverflow;
        argv_ptrs_buf[argv_n] = cursor;
        argv_n += 1;
    }
    var argv_ptrs: [64]u64 = .{0} ** 64;
    for (0..argv_n) |k| argv_ptrs[k] = argv_ptrs_buf[argv_n - 1 - k];

    // execfn-строка (AT_EXECFN = argv[0]-копия выше всех)
    if (strings.execfn.len + 1 > cursor - stack_lo) return ElfError.StackOverflow;
    cursor -= strings.execfn.len + 1;
    const execfn_va = cursor;
    if (!h.writeBytesAt(execfn_va, strings.execfn) or
        !h.writeByteAt(execfn_va + strings.execfn.len, 0))
    {
        return ElfError.StackOverflow;
    }

    // 4. Выравнивание векторов (entry_rsp ≡ 0 mod 16)
    const argc: u64 = strings.argv.len;
    var vec_words: u64 = 1; // argc
    vec_words += strings.argv.len + 1; // argv[] + NULL
    vec_words += strings.envp.len + 1; // envp[] + NULL
    const auxv = [_][2]u64{
        .{ AT_PHDR, img.phdr_va },
        .{ AT_PHENT, img.phentsize },
        .{ AT_PHNUM, img.phnum },
        .{ AT_PAGESZ, PAGE_SIZE },
        .{ AT_BASE, at_base },
        .{ AT_FLAGS, 0 },
        .{ AT_ENTRY, img.entry_va },
        .{ AT_UID, 1000 },
        .{ AT_EUID, 1000 },
        .{ AT_GID, 1000 },
        .{ AT_EGID, 1000 },
        .{ AT_HWCAP, 0 },
        .{ AT_CLKTCK, 100 },
        .{ AT_SECURE, 0 },
        .{ AT_RANDOM, random_va },
        .{ AT_PLATFORM, platform_va },
        .{ AT_EXECFN, execfn_va },
        .{ AT_NULL, 0 },
    };
    vec_words += auxv.len * 2;
    const vec_bytes = vec_words * 8;
    cursor = (cursor - vec_bytes) & ~@as(u64, 15);

    const entry_rsp = cursor;
    // argc
    if (!h.writeWordAt(cursor, argc)) return ElfError.StackOverflow;
    cursor += 8;
    // argv[]
    for (argv_ptrs[0..strings.argv.len]) |va| {
        if (!h.writeWordAt(cursor, va)) return ElfError.StackOverflow;
        cursor += 8;
    }
    if (!h.writeWordAt(cursor, 0)) return ElfError.StackOverflow; // argv NULL
    cursor += 8;
    // envp[]
    for (env_ptrs[0..strings.envp.len]) |va| {
        if (!h.writeWordAt(cursor, va)) return ElfError.StackOverflow;
        cursor += 8;
    }
    if (!h.writeWordAt(cursor, 0)) return ElfError.StackOverflow; // envp NULL
    cursor += 8;
    // auxv
    for (auxv) |pair| {
        if (!h.writeWordAt(cursor, pair[0]) or !h.writeWordAt(cursor + 8, pair[1]))
            return ElfError.StackOverflow;
        cursor += 16;
    }

    return StackResult{
        .entry_rsp = entry_rsp,
        .random_va = random_va,
        .platform_va = platform_va,
    };
}

// ============================================================================
// ЮНИТ-ТЕСТЫ (нативные, ElfOps-инъекция с mock-памятью)
// ============================================================================

// ─── Mock-окружение ────────────────────────────────────────────────────────
//
// Фейковая физпамять: 256КБ, физ-адреса начинаются с FAKE_PA_BASE (страница 0
// зарезервирована под NULL-детект). Маппинги записываются в таблицу — тесты
// проверяют PTE-флаги и геометрию.

const FAKE_PA_BASE: u64 = 0x1_0000;
const MOCK_MEM_PAGES: usize = 64;

const MapRec = struct { va: u64, pa: u64, flags: u64 };

const Mock = struct {
    mem: [MOCK_MEM_PAGES * 4096]u8 align(4096) = [_]u8{0} ** (MOCK_MEM_PAGES * 4096),
    bump: usize = 0,
    maps: [512]MapRec = [_]MapRec{.{ .va = 0, .pa = 0, .flags = 0 }} ** 512,
    map_n: usize = 0,
    frees: usize = 0,
};

var mock: Mock = .{};

fn mockReset() void {
    mock = .{};
}

fn mockAllocContig(count: u64) ?u64 {
    if (mock.bump + count > MOCK_MEM_PAGES) return null;
    const pa = FAKE_PA_BASE + mock.bump * 4096;
    const off = mock.bump * 4096;
    @memset(mock.mem[off..][0..@as(usize, @intCast(count)) * 4096], 0);
    mock.bump += @intCast(count);
    return pa;
}

fn mockMapUser(pml4: u64, va: u64, pa: u64, flags: u64) bool {
    _ = pml4;
    if (mock.map_n >= mock.maps.len) return false;
    for (mock.maps[0..mock.map_n]) |m| {
        if (m.va == va) return false; // конфликт
    }
    mock.maps[mock.map_n] = .{ .va = va, .pa = pa, .flags = flags };
    mock.map_n += 1;
    return true;
}

fn mockPagePtr(pa: u64) [*]u8 {
    if (pa < FAKE_PA_BASE) unreachable;
    const off: usize = @intCast(pa - FAKE_PA_BASE);
    if (off >= mock.mem.len) unreachable;
    return mock.mem[off..].ptr;
}

fn mockUnmapUser(pml4: u64, va: u64) bool {
    _ = pml4;
    for (mock.maps[0..mock.map_n], 0..) |m, i| {
        if (m.va == va) {
            mock.maps[i] = mock.maps[mock.map_n - 1];
            mock.map_n -= 1;
            return true;
        }
    }
    return false;
}

fn mockFreeContig(base_pa: u64, count: u64) void {
    _ = base_pa;
    _ = count;
    mock.frees += 1; // диагностика отката
}

fn mockOps() ElfOps {
    return .{
        .alloc_contig = mockAllocContig,
        .map_user = mockMapUser,
        .page_ptr = mockPagePtr,
        .unmap_user = mockUnmapUser,
        .free_contig = mockFreeContig,
    };
}

/// Чтение слова из user-VA через mock-таблицу маппингов (тест-ассерты).
fn mockReadWord(va: u64) u64 {
    const page = va & ~@as(u64, 4095);
    for (mock.maps[0..mock.map_n]) |m| {
        if (m.va == page) {
            const p = mockPagePtr(m.pa)[@intCast(va % 4096)..][0..8];
            return std.mem.readInt(u64, p[0..8], .little);
        }
    }
    unreachable; // страница не замаплена — тест сломан
}

/// Чтение C-строки из user-VA (стековые argv/envp).
fn mockReadStr(va: u64, max: usize) []const u8 {
    const page = va & ~@as(u64, 4095);
    for (mock.maps[0..mock.map_n]) |m| {
        if (m.va == page) {
            const base = mockPagePtr(m.pa);
            const off: usize = @intCast(va % 4096);
            var n: usize = 0;
            while (n < max and off + n < 4096) : (n += 1) {
                if (base[off + n] == 0) return base[off .. off + n];
            }
            return base[off .. off + @min(n, max)];
        }
    }
    unreachable;
}

fn mockMapFlagsFor(va: u64) u64 {
    const page = va & ~@as(u64, 4095);
    for (mock.maps[0..mock.map_n]) |m| {
        if (m.va == page) return m.flags;
    }
    return 0;
}

// ─── Билдер тестовых ELF-бинарников ────────────────────────────────────────
//
// Минимальный корректный ELF64: ehdr (64Б) + 2 PT_LOAD (RX-код, RW-данные+BSS)
// + GNU_STACK. Файловые смещения: phdrs @64, код @0x200, данные @0x300.

const TestElf = struct {
    buf: [2048]u8 = [_]u8{0} ** 2048,
    len: usize = 0,

    /// seg1_va — p_vaddr первого PT_LOAD (RX: заголовки + код, как реальные
    /// PIE: p_offset=0 покрывает ehdr+phdrs); seg2_va — RW-сегмент (данные+BSS).
    fn init(self: *TestElf, e_type: u16, seg1_va: u64, seg2_va: u64) void {
        const ehdr: *Elf64_Ehdr = @ptrCast(@alignCast(&self.buf));
        ehdr.e_ident = .{
            0x7F, 'E', 'L', 'F', // magic
            2, // ELFCLASS64
            1, // ELFDATA2LSB
            1, // EV_CURRENT
            0, 0, // ELFOSABI_NONE
            0, 0, 0, 0, 0, 0, 0,
        };
        ehdr.e_type = e_type;
        ehdr.e_machine = EM_X86_64;
        ehdr.e_version = 1;
        ehdr.e_entry = seg1_va + 0x208; // _start в середине кода
        ehdr.e_phoff = 64;
        ehdr.e_shoff = 0;
        ehdr.e_flags = 0;
        ehdr.e_ehsize = 64;
        ehdr.e_phentsize = 56;
        ehdr.e_phnum = 3;
        ehdr.e_shentsize = 0;
        ehdr.e_shnum = 0;
        ehdr.e_shstrndx = 0;

        const ph: [*]Elf64_Phdr = @ptrCast(@alignCast(self.buf[64..].ptr));
        // PT_LOAD RX: заголовки (64Б) + фантьмы (168Б) + код (16Б @0x200)
        ph[0] = .{
            .p_type = PT_LOAD,
            .p_flags = PF_R | PF_X,
            .p_offset = 0,
            .p_vaddr = seg1_va,
            .p_paddr = 0,
            .p_filesz = 0x210,
            .p_memsz = 0x210,
            .p_align = 4096,
        };
        // PT_LOAD RW: данные 8Б + BSS 256Б
        ph[1] = .{
            .p_type = PT_LOAD,
            .p_flags = PF_R | PF_W,
            .p_offset = 0x300,
            .p_vaddr = seg2_va,
            .p_paddr = 0,
            .p_filesz = 8,
            .p_memsz = 8 + 0x100, // BSS 256Б
            .p_align = 4096,
        };
        // PT_GNU_STACK RW (невыполнимый стек)
        ph[2] = .{
            .p_type = PT_GNU_STACK,
            .p_flags = PF_R | PF_W,
            .p_offset = 0,
            .p_vaddr = 0,
            .p_paddr = 0,
            .p_filesz = 0,
            .p_memsz = 0,
            .p_align = 0x10,
        };

        @memcpy(self.buf[0x200..0x210], "CODECODECODECOD1");
        @memcpy(self.buf[0x300..0x308], "DATADAT1");
        self.len = 0x400;
    }

    fn data(self: *const TestElf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ─── Тесты загрузчика ──────────────────────────────────────────────────────

test "loadElf: PIE (ET_DYN) загружается на выбранный базис, PTE-флаги по сегментам" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);

    const img = try loadElf(mockOps(), 0x777, te.data(), LINUX_IMAGE_BASE);

    // Образ: [base+0, base+0x2108) → 3 страницы (0..0x3000)
    try testing.expectEqual(LINUX_IMAGE_BASE, img.base_va);
    try testing.expectEqual(LINUX_IMAGE_BASE + 0x208, img.entry_va);
    try testing.expectEqual(LINUX_IMAGE_BASE + 64, img.phdr_va); // AT_PHDR
    try testing.expect(img.is_pie);
    try testing.expectEqual(@as(u64, 3), img.pages);
    // brk = page-up конца RW-сегмента (0x2000 + 0x108 → 0x3000)
    try testing.expectEqual(LINUX_IMAGE_BASE + 0x3000, img.brk);

    // Маппинги: RX-страница без NX и без W; RW-страницы с W и NX
    const rx_flags = mockMapFlagsFor(LINUX_IMAGE_BASE + 0x0); // страница заголовков+кода
    try testing.expect(rx_flags & PTE_NO_EXECUTE == 0);
    try testing.expect(rx_flags & PTE_WRITABLE == 0);
    try testing.expect(rx_flags & PTE_USER != 0);
    const rw_flags = mockMapFlagsFor(LINUX_IMAGE_BASE + 0x2000);
    try testing.expect(rw_flags & PTE_WRITABLE != 0);
    try testing.expect(rw_flags & PTE_NO_EXECUTE != 0);

    // Данные скопированы: код и данные читаются через mock-страницы
    const code_pa = pagePaFor(LINUX_IMAGE_BASE + 0x0);
    const code = mockPagePtr(code_pa)[0x200..0x210];
    try testing.expectEqualStrings("CODECODECODECOD1", code);
    const data_pa = pagePaFor(LINUX_IMAGE_BASE + 0x2000);
    const dat = mockPagePtr(data_pa)[0..8];
    try testing.expectEqualStrings("DATADAT1", dat);

    // BSS [8, 0x108) — нули (страницы нулевые — проверим границу)
    try testing.expectEqual(@as(u8, 0), mockPagePtr(data_pa)[8]);
    try testing.expectEqual(@as(u8, 0), mockPagePtr(data_pa)[0x107]);
}

fn pagePaFor(va: u64) u64 {
    const page = va & ~@as(u64, 4095);
    for (mock.maps[0..mock.map_n]) |m| {
        if (m.va == page) return m.pa;
    }
    unreachable;
}

test "loadElf: ET_EXEC с высокими адресами грузится по p_vaddr" {
    mockReset();
    const high = LINUX_IMAGE_BASE + 0x10_0000;
    var te = TestElf{};
    te.init(ET_EXEC, high, high + 0x2000);

    const img = try loadElf(mockOps(), 0x777, te.data(), 0);
    try testing.expectEqual(high, img.base_va);
    try testing.expect(!img.is_pie);
    try testing.expectEqual(@as(u64, 3), img.pages);
}

test "loadElf: ET_EXEC в identity-зоне (0x400000) отклоняется" {
    mockReset();
    var te = TestElf{};
    te.init(ET_EXEC, 0x400000, 0x401000);
    try testing.expectError(ElfError.ImageBaseInvalid, loadElf(mockOps(), 0x777, te.data(), 0));
    // Ни одной страницы не замаплено (полный откат)
    try testing.expectEqual(@as(usize, 0), mock.map_n);
}

test "loadElf: мусорные заголовки отклоняются без паник" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);

    // обрезанный буфер
    try testing.expectError(ElfError.Truncated, loadElf(mockOps(), 1, te.data()[0..10], 0));
    // битая магия
    var bad = te;
    bad.buf[0] = 'X';
    try testing.expectError(ElfError.InvalidMagic, loadElf(mockOps(), 1, bad.data(), 0));
    // не x86-64
    var wrong_m = te;
    wrong_m.buf[@offsetOf(Elf64_Ehdr, "e_machine")] = 3; // EM_386 (lo byte)
    try testing.expectError(ElfError.WrongArchitecture, loadElf(mockOps(), 1, wrong_m.data(), 0));
    // ET_REL (объектник, не исполняемый)
    var rel = te;
    rel.buf[@offsetOf(Elf64_Ehdr, "e_type")] = ET_REL;
    try testing.expectError(ElfError.NotExecutable, loadElf(mockOps(), 1, rel.data(), 0));
    // phnum = 0
    var noph = te;
    noph.buf[@offsetOf(Elf64_Ehdr, "e_phnum")] = 0;
    try testing.expectError(ElfError.NoProgramHeaders, loadElf(mockOps(), 1, noph.data(), 0));
    // phoff за пределами файла
    var badoff = te;
    std.mem.writeInt(u64, badoff.buf[@offsetOf(Elf64_Ehdr, "e_phoff")..][0..8], 0x100000, .little);
    try testing.expectError(ElfError.BadPhdrTable, loadElf(mockOps(), 1, badoff.data(), 0));
}

test "loadElf: p_filesz больше файла → SegmentBounds, откат страниц" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);
    // файл режем до 0x380 — p_offset 0x300 + p_filesz 8 ок, а коду (0x200+16) ок,
    // поэтому ломаем p_filesz сегмента данных на 0x800
    std.mem.writeInt(u64, te.buf[64 + @sizeOf(Elf64_Phdr) + @offsetOf(Elf64_Phdr, "p_filesz") ..][0..8], 0x800, .little);
    try testing.expectError(ElfError.SegmentBounds, loadElf(mockOps(), 1, te.data(), 0));
    try testing.expectEqual(@as(usize, 0), mock.map_n);
}

test "loadElf: ET_DYN базис над потолком user отклоняется" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);
    const over = USER_VA_CEILING; // + сегменты уйдут за потолок
    try testing.expectError(ElfError.ImageBaseInvalid, loadElf(mockOps(), 1, te.data(), over));
}

// ─── Тесты первичного стека Linux-ABI ──────────────────────────────────────

test "buildUserStack: раскладка argc/argv/envp/auxv, выравнивание 16" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);
    const img = try loadElf(mockOps(), 0x777, te.data(), LINUX_IMAGE_BASE);

    const argv = [_][]const u8{ "elftest", "--flag1" };
    const envp = [_][]const u8{"HOME=/root"};
    const seed = [_]u8{0xAA} ** 16;
    const res = try buildUserStack(
        mockOps(),
        0x777,
        LINUX_STACK_TOP,
        16,
        .{ .argv = &argv, .envp = &envp, .execfn = "elftest" },
        img,
        seed,
        0, // статик: AT_BASE=0
    );

    // entry_rsp 16-выровнен, внутри региона стека
    try testing.expectEqual(@as(u64, 0), res.entry_rsp % 16);
    try testing.expect(res.entry_rsp > LINUX_STACK_TOP - LINUX_STACK_PAGES * 4096);
    try testing.expect(res.entry_rsp < LINUX_STACK_TOP);

    // argc
    try testing.expectEqual(@as(u64, 2), mockReadWord(res.entry_rsp));
    // argv[0..2] + NULL
    const a0 = mockReadWord(res.entry_rsp + 8);
    const a1 = mockReadWord(res.entry_rsp + 16);
    const a_null = mockReadWord(res.entry_rsp + 24);
    try testing.expectEqualStrings("elftest", mockReadStr(a0, 32));
    try testing.expectEqualStrings("--flag1", mockReadStr(a1, 32));
    try testing.expectEqual(@as(u64, 0), a_null);
    // envp[0] + NULL
    const e0 = mockReadWord(res.entry_rsp + 32);
    const e_null = mockReadWord(res.entry_rsp + 40);
    try testing.expectEqualStrings("HOME=/root", mockReadStr(e0, 32));
    try testing.expectEqual(@as(u64, 0), e_null);

    // auxv стартует после envp: [entry_rsp + 48, …), ищем якоря
    var off: u64 = res.entry_rsp + 48;
    var at_pagesz: u64 = 0;
    var at_phdr: u64 = 0;
    var at_entry: u64 = 0;
    var at_random: u64 = 0;
    var at_null_seen = false;
    var pairs: usize = 0;
    while (pairs < 32) : (pairs += 1) {
        const key = mockReadWord(off);
        const val = mockReadWord(off + 8);
        if (key == AT_NULL) {
            at_null_seen = true;
            break;
        }
        switch (key) {
            AT_PAGESZ => at_pagesz = val,
            AT_PHDR => at_phdr = val,
            AT_ENTRY => at_entry = val,
            AT_RANDOM => at_random = val,
            AT_BASE, AT_PHENT, AT_PHNUM, AT_UID, AT_EGID, AT_PLATFORM, AT_EXECFN => {},
            else => {}, // прочие пары допустимы
        }
        off += 16;
    }
    try testing.expect(at_null_seen); // терминатор обязателен
    try testing.expectEqual(@as(u64, 4096), at_pagesz);
    try testing.expectEqual(img.phdr_va, at_phdr);
    try testing.expectEqual(img.entry_va, at_entry);
    // AT_RANDOM указывает на 16 байт внутри стека — байты совпадают с seed
    try testing.expect(at_random > res.entry_rsp);
    try testing.expect(at_random < LINUX_STACK_TOP);
    const rnd0 = mockReadWord(at_random);
    try testing.expectEqual(@as(u64, 0xAAAAAAAAAAAAAAAA), rnd0);

    // Стек замаплен RW+USER+NX
    const st_flags = mockMapFlagsFor(res.entry_rsp);
    try testing.expect(st_flags & PTE_WRITABLE != 0);
    try testing.expect(st_flags & PTE_USER != 0);
    try testing.expect(st_flags & PTE_NO_EXECUTE != 0);
}

test "buildUserStack: контент больше региона → StackOverflow" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);
    const img = try loadElf(mockOps(), 0x777, te.data(), LINUX_IMAGE_BASE);

    // Строка 6КБ + векторы/auxv — не влезает в ОДНУ страницу стека
    const big = [_][]const u8{"A" ** 6000};
    try testing.expectError(ElfError.StackOverflow, buildUserStack(
        mockOps(),
        0x777,
        LINUX_STACK_TOP,
        1, // одна страница — 4КБ
        .{ .argv = &big, .envp = &[_][]const u8{}, .execfn = "x" },
        img,
        [_]u8{0} ** 16,
        0,
    ));
}

test "flagsToPte: комбинации R/W/X" {
    // RX: исполняемый — без NX, без W
    const rx = flagsToPte(PF_R | PF_X);
    try testing.expect(rx & PTE_PRESENT != 0);
    try testing.expect(rx & PTE_USER != 0);
    try testing.expect(rx & PTE_NO_EXECUTE == 0);
    try testing.expect(rx & PTE_WRITABLE == 0);
    // RW: данные — с W и NX
    const rw = flagsToPte(PF_R | PF_W);
    try testing.expect(rw & PTE_WRITABLE != 0);
    try testing.expect(rw & PTE_NO_EXECUTE != 0);
    // RWX
    const rwx = flagsToPte(PF_R | PF_W | PF_X);
    try testing.expect(rwx & PTE_WRITABLE != 0);
    try testing.expect(rwx & PTE_NO_EXECUTE == 0);
}

test "layout: константы зон не пересекаются" {
    // Образ и стек разведены (между ними ≥ 8ТБ)
    try testing.expect(LINUX_IMAGE_BASE - LINUX_STACK_TOP >= 0x800_0000_0000);
    // Стек каноничен и ниже потолка
    try testing.expect(LINUX_STACK_TOP < USER_VA_CEILING);
    try testing.expect(LINUX_IMAGE_BASE < USER_VA_CEILING);
    // Минимальный user-VA — выше identity-зоны ядра
    try testing.expect(MIN_USER_VA == 0x1_0000_0000);
}


test "loadElf: PT_INTERP — путь интерпретатора (динамические бинарники)" {
    mockReset();
    var te = TestElf{};
    te.init(ET_DYN, 0, 0x2000);
    // добавляем PT_INTERP: phnum 3→4, interp-фантом: "/lib64/ld-linux-x86-64.so.2"
    const ehdr: *Elf64_Ehdr = @ptrCast(@alignCast(&te.buf));
    ehdr.e_phnum = 4;
    const ph: [*]Elf64_Phdr = @ptrCast(@alignCast(te.buf[64..].ptr));
    ph[3] = .{
        .p_type = PT_INTERP,
        .p_flags = PF_R,
        .p_offset = 0x310,
        .p_vaddr = 0,
        .p_paddr = 0,
        .p_filesz = 27,
        .p_memsz = 0,
        .p_align = 1,
    };
    const interp_path = "/lib64/ld-linux-x86-64.so.2";
    @memcpy(te.buf[0x310..][0..interp_path.len], interp_path);
    te.buf[0x310 + interp_path.len] = 0;

    const img = try loadElf(mockOps(), 0x777, te.data(), LINUX_IMAGE_BASE);
    try testing.expect(img.interp != null);
    try testing.expectEqualStrings("/lib64/ld-linux-x86-64.so.2", img.interp.?);

    // статик (без PT_INTERP) → null
    mockReset();
    var te2 = TestElf{};
    te2.init(ET_DYN, 0, 0x2000);
    const img2 = try loadElf(mockOps(), 0x777, te2.data(), LINUX_IMAGE_BASE);
    try testing.expect(img2.interp == null);

    // PT_INTERP с p_offset вне файла → SegmentBounds
    mockReset();
    var te3 = TestElf{};
    te3.init(ET_DYN, 0, 0x2000);
    const ehdr3: *Elf64_Ehdr = @ptrCast(@alignCast(&te3.buf));
    ehdr3.e_phnum = 4;
    const ph3: [*]Elf64_Phdr = @ptrCast(@alignCast(te3.buf[64..].ptr));
    ph3[3] = .{ .p_type = PT_INTERP, .p_flags = PF_R, .p_offset = 0x2000, .p_vaddr = 0, .p_paddr = 0, .p_filesz = 10, .p_memsz = 0, .p_align = 1 };
    try testing.expectError(ElfError.SegmentBounds, loadElf(mockOps(), 0x777, te3.data(), LINUX_IMAGE_BASE));
}
