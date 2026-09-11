// ============================================================================
// POLER-OS PE/COFF Parser & Loader — x86_64 (v0.9.0, Crash-Driven Development)
// ============================================================================
//
// Парсер PE32+ (x86-64) образов для слоя Win32-совместимости:
//   DOS Header → NT Headers → File Header → Optional Header64 →
//   Section Table → Import Directory (IAT).
//
// Философия CDD (Crash-Driven Development): грузим РЕАЛЬНОЕ тяжёлое PE64-
// приложение (testdata/curl.exe — 3.8 МБ, 274 функции из 22 DLL), а недостающие
// Win32-функции реализуем по мере падений. Этот модуль отвечает на вопрос
// «что именно приложение просит» — до первого вызова.
//
// Совместимость: модуль компилируется и в freestanding-ядре (без аллокаций,
// только срезы поверх готового буфера), и в нативных тестах x86_64-linux-gnu
// (zig build test). Форматные константы — по MS PE/COFF spec (winnt.h),
// ссылка: docs/pe-reference/pe_specs/.
//
// ХАРДЕНИНГ ВЫРАВНИВАНИЯ: образ приходит из непроверенного источника
// (initrd-cpio: файл лежит по произвольному смещению внутри архива), поэтому
// все указатели на структуры формата — `*align(1) const T`: никакие поля не
// обязаны быть выровненными, @alignCast-паник нет по построению.
//
// Ограничения v0.9.0: PE32 (i386) распознаётся, но отклоняется (лоадер
// таргетирует только PE32+); bound imports / delay-load / TLS-callback
// directory не парсятся (добавляются по мере требований CDD-цикла).
// ============================================================================

const std = @import("std");

// ─── Магии и константы формата ─────────────────────────────────────────────

pub const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const OPT_MAGIC_PE32_PLUS: u16 = 0x20B; // PE32+ (64-bit)
pub const OPT_MAGIC_PE32: u16 = 0x10B; // PE32 (32-bit)
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_I386: u16 = 0x14C;
pub const ORDINAL_FLAG64: u64 = 0x8000000000000000;

pub const MAX_SECTIONS: usize = 96; // реальное — NumberOfSections, это сан-лимит

// DataDirectory indices
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_SECURITY: usize = 4;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;

// Section characteristics flags (используем для отчёта)
pub const SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const SCN_MEM_READ: u32 = 0x40000000;
pub const SCN_MEM_WRITE: u32 = 0x80000000;
pub const SCN_CNT_CODE: u32 = 0x00000020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;

// Subsystem
pub const SUBSYSTEM_NATIVE: u16 = 1;
pub const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;

// ─── Структуры формата (extern → предсказуемая раскладка) ───────────────────

pub const ImageDosHeader = extern struct {
    // Все скалярные поля — align(1): образ может лежать в памяти по любому
    // смещению (initrd-cpio, стек тестов), а раскладка обязана совпадать
    // с winnt.h байт-в-байт (см. comptime-страховку ниже).
    e_magic: u16 align(1),
    e_cblp: u16 align(1),
    e_cp: u16 align(1),
    e_crlc: u16 align(1),
    e_cparhdr: u16 align(1),
    e_minalloc: u16 align(1),
    e_maxalloc: u16 align(1),
    e_ss: u16 align(1),
    e_sp: u16 align(1),
    e_csum: u16 align(1),
    e_ip: u16 align(1),
    e_cs: u16 align(1),
    e_lfarlc: u16 align(1),
    e_ovno: u16 align(1),
    e_res: [4]u16 align(1),
    e_oemid: u16 align(1),
    e_oeminfo: u16 align(1),
    e_res2: [10]u16 align(1),
    e_lfanew: u32 align(1),
};

pub const ImageFileHeader = extern struct {
    machine: u16 align(1),
    number_of_sections: u16 align(1),
    time_date_stamp: u32 align(1),
    pointer_to_symbol_table: u32 align(1),
    number_of_symbols: u32 align(1),
    size_of_optional_header: u16 align(1),
    characteristics: u16 align(1),
};

pub const ImageDataDirectory = extern struct {
    virtual_address: u32 align(1),
    size: u32 align(1),
};

pub const ImageOptionalHeader64 = extern struct {
    magic: u16 align(1),
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32 align(1),
    size_of_initialized_data: u32 align(1),
    size_of_uninitialized_data: u32 align(1),
    address_of_entry_point: u32 align(1),
    base_of_code: u32 align(1),
    image_base: u64 align(1),
    section_alignment: u32 align(1),
    file_alignment: u32 align(1),
    major_operating_system_version: u16 align(1),
    minor_operating_system_version: u16 align(1),
    major_image_version: u16 align(1),
    minor_image_version: u16 align(1),
    major_subsystem_version: u16 align(1),
    minor_subsystem_version: u16 align(1),
    win32_version_value: u32 align(1),
    size_of_image: u32 align(1),
    size_of_headers: u32 align(1),
    check_sum: u32 align(1),
    subsystem: u16 align(1),
    dll_characteristics: u16 align(1),
    size_of_stack_reserve: u64 align(1),
    size_of_stack_commit: u64 align(1),
    size_of_heap_reserve: u64 align(1),
    size_of_heap_commit: u64 align(1),
    loader_flags: u32 align(1),
    number_of_rva_and_sizes: u32 align(1),
    data_directory: [16]ImageDataDirectory,
};

pub const ImageNtHeaders64 = extern struct {
    signature: u32 align(1),
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
};

pub const ImageSectionHeader = extern struct {
    name: [8]u8,
    virtual_size: u32 align(1),
    virtual_address: u32 align(1),
    size_of_raw_data: u32 align(1),
    pointer_to_raw_data: u32 align(1),
    pointer_to_relocations: u32 align(1),
    pointer_to_linenumbers: u32 align(1),
    number_of_relocations: u16 align(1),
    number_of_linenumbers: u16 align(1),
    characteristics: u32 align(1),

    /// Имя секции (обрезано от нулей; длинные имена через строковую таблицу
    /// не поддерживаем — для объектных файлов это не нужно).
    pub fn nameSlice(self: *const ImageSectionHeader) []const u8 {
        var len: usize = 0;
        while (len < 8 and self.name[len] != 0) : (len += 1) {}
        return self.name[0..len];
    }

    pub fn isExecutable(self: *const ImageSectionHeader) bool {
        return (self.characteristics & SCN_MEM_EXECUTE) != 0;
    }
    pub fn isWritable(self: *const ImageSectionHeader) bool {
        return (self.characteristics & SCN_MEM_WRITE) != 0;
    }
};

pub const ImageImportDescriptor = extern struct {
    /// RVA к массиву IMAGE_THUNK_DATA64 (OriginalFirstThunk, ILT).
    /// Поле union с Characteristics в winnt.h — для загрузчика это ILT.
    original_first_thunk: u32 align(1),
    time_date_stamp: u32 align(1),
    forwarder_chain: u32 align(1),
    /// RVA к ASCIIZ-имени DLL
    name: u32 align(1),
    /// RVA к массиву IMAGE_THUNK_DATA64 (FirstThunk, IAT) — куда загрузчик
    /// пишет адреса. Именно это место патчат наши заглушки (win32_stubs.zig).
    first_thunk: u32 align(1),
};

comptime {
    // Страховка раскладки: PE-структуры обязаны байт-в-байт совпадать с winnt.h
    std.debug.assert(@sizeOf(ImageDosHeader) == 64);
    std.debug.assert(@sizeOf(ImageFileHeader) == 20);
    std.debug.assert(@sizeOf(ImageOptionalHeader64) == 240);
    std.debug.assert(@sizeOf(ImageNtHeaders64) == 264);
    std.debug.assert(@sizeOf(ImageSectionHeader) == 40);
    std.debug.assert(@sizeOf(ImageImportDescriptor) == 20);
    std.debug.assert(@offsetOf(ImageDosHeader, "e_lfanew") == 0x3C);
    std.debug.assert(@offsetOf(ImageNtHeaders64, "optional_header") == 24);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "image_base") == 24);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "size_of_image") == 56);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "subsystem") == 68);
    std.debug.assert(@offsetOf(ImageOptionalHeader64, "data_directory") == 112);
    // Харденинг: все структуры формата — байтово-выровненные (вход из
    // initrd-cpio не гарантирует выравнивания; @alignCast запрещён по построению)
    std.debug.assert(@alignOf(ImageDosHeader) == 1);
    std.debug.assert(@alignOf(ImageFileHeader) == 1);
    std.debug.assert(@alignOf(ImageDataDirectory) == 1);
    std.debug.assert(@alignOf(ImageOptionalHeader64) == 1);
    std.debug.assert(@alignOf(ImageNtHeaders64) == 1);
    std.debug.assert(@alignOf(ImageSectionHeader) == 1);
    std.debug.assert(@alignOf(ImageImportDescriptor) == 1);
}

// ─── Ошибки парсинга ────────────────────────────────────────────────────────

pub const ParseError = error{
    Truncated, // файл меньше минимального размера
    NotMZ, // нет DOS-магии "MZ"
    BadLfanew, // e_lfanew вне файла
    NotPE, // нет сигнатуры "PE\0\0"
    UnsupportedMachine, // не AMD64 (PE32/i386 и пр. — отдельные ветки)
    BadOptionalHeader, // не 0x20B (PE32+) / неконсистентный размер
    TooManySections,
    BadSectionTable, // таблица секций вне файла
    BadImportDirectory, // директория импортов вне файла/кривая
};

// ─── Импорт: представление без аллокаций ───────────────────────────────────

/// Одна импортируемая функция: либо по имени, либо по ординалу.
pub const ImportFn = union(enum) {
    by_name: []const u8,
    by_ordinal: u16,
};

/// Итератор функций одной DLL (массив ILT/IAT-танков).
pub const FunctionIterator = struct {
    pe: *const Pe,
    thunk_rva: u32, // текущая позиция (RVA)
    end_rva: u32, // граница массива

    pub fn next(self: *FunctionIterator) ?ImportFn {
        if (self.thunk_rva >= self.end_rva) return null;
        const off = self.pe.rvaToOffset(self.thunk_rva) orelse return null;
        if (off + 8 > self.pe.data.len) return null;
        const thunk = std.mem.readInt(u64, self.pe.data[off..][0..8], .little);
        self.thunk_rva += 8;
        if (thunk == 0) return null; // терминатор массива
        if (thunk & ORDINAL_FLAG64 != 0) {
            return ImportFn{ .by_ordinal = @intCast(thunk & 0xFFFF) };
        }
        // RVA → IMAGE_IMPORT_BY_NAME: u16 hint + ASCIIZ имя
        const name_rva: u32 = @intCast(thunk & 0x7FFFFFFF);
        const name_off = self.pe.rvaToOffset(name_rva) orelse return null;
        if (name_off + 2 >= self.pe.data.len) return null;
        var len: usize = 0;
        const max_len = self.pe.data.len - name_off - 2;
        while (len < max_len and self.pe.data[name_off + 2 + len] != 0) : (len += 1) {}
        return ImportFn{ .by_name = self.pe.data[name_off + 2 .. name_off + 2 + len] };
    }
};

/// Просмотр импортов одной DLL: имя + итератор функций.
pub const ImportDll = struct {
    name: []const u8,
    /// RVA массива IAT-слотов (FirstThunk) — адрес для патча заглушками
    iat_rva: u32,
    functions: FunctionIterator,

    pub fn countFunctions(self: *const ImportDll) usize {
        var it = self.functions; // локальная копия — self не мутируем
        var n: usize = 0;
        while (it.next() != null) : (n += 1) {}
        return n;
    }
};

/// Итератор DLL из таблицы импортов (IMAGE_IMPORT_DESCRIPTOR массив).
pub const ImportDllIterator = struct {
    pe: *const Pe,
    desc_rva: u32,
    desc_end_rva: u32,

    pub fn next(self: *ImportDllIterator) ?ImportDll {
        if (self.desc_rva + @sizeOf(ImageImportDescriptor) > self.desc_end_rva) return null;
        const off = self.pe.rvaToOffset(self.desc_rva) orelse return null;
        if (off + @sizeOf(ImageImportDescriptor) > self.pe.data.len) return null;
        const desc: *const ImageImportDescriptor = @ptrCast(self.pe.data.ptr + off);
        self.desc_rva += @sizeOf(ImageImportDescriptor);
        if (desc.name == 0) return null; // терминатор таблицы

        const name_off = self.pe.rvaToOffset(desc.name) orelse return null;
        var len: usize = 0;
        const max_len = self.pe.data.len - name_off;
        while (len < max_len and self.pe.data[name_off + len] != 0) : (len += 1) {}

        // ILT (OriginalFirstThunk) приоритетен; если 0 — валиден только IAT
        const ilt_rva = if (desc.original_first_thunk != 0) desc.original_first_thunk else desc.first_thunk;
        // граница массива танков — до терминатора; безопасный верхний предел:
        // до конца маппинга секции, итератор сам остановится на 0
        const sec = self.pe.sectionByRva(ilt_rva) orelse return null;
        const sec_end_rva = sec.virtual_address + @max(sec.virtual_size, sec.size_of_raw_data);

        return ImportDll{
            .name = self.pe.data[name_off .. name_off + len],
            .iat_rva = desc.first_thunk,
            .functions = .{
                .pe = self.pe,
                .thunk_rva = ilt_rva,
                .end_rva = sec_end_rva,
            },
        };
    }
};

// ─── Главный объект парсера ────────────────────────────────────────────────

pub const Pe = struct {
    data: []const u8,
    // структуры формата имеют @alignOf == 1 (см. comptime-страховку):
    // образ — непроверенные байты, выравнивание не гарантировано
    nt: *const ImageNtHeaders64,
    sections: []const ImageSectionHeader,

    // ── Валидация и разбор ──

    /// Полный разбор PE32+ (AMD64). 32-битные образы распознаются, но
    /// отклоняются ошибкой UnsupportedMachine (лоадер — только PE32+).
    pub fn parse(data: []const u8) ParseError!Pe {
        if (data.len < @sizeOf(ImageDosHeader)) return ParseError.Truncated;
        const dos: *const ImageDosHeader = @ptrCast(data.ptr);
        if (dos.e_magic != DOS_MAGIC) return ParseError.NotMZ;

        const nt_off: usize = dos.e_lfanew;
        if (nt_off < @sizeOf(ImageDosHeader) or nt_off + @sizeOf(ImageNtHeaders64) > data.len)
            return ParseError.BadLfanew;

        const nt: *const ImageNtHeaders64 = @ptrCast(data.ptr + nt_off);
        if (nt.signature != PE_SIGNATURE) return ParseError.NotPE;

        // Машина: поддерживаем AMD64; i386 — осознанный отказ
        if (nt.file_header.machine != MACHINE_AMD64) return ParseError.UnsupportedMachine;

        if (nt.optional_header.magic != OPT_MAGIC_PE32_PLUS) return ParseError.BadOptionalHeader;
        if (nt.file_header.size_of_optional_header < @sizeOf(ImageOptionalHeader64))
            return ParseError.BadOptionalHeader;

        const nsec: usize = nt.file_header.number_of_sections;
        if (nsec == 0 or nsec > MAX_SECTIONS) return ParseError.TooManySections;

        const sec_off = nt_off + @sizeOf(ImageNtHeaders64);
        const sec_table_len = nsec * @sizeOf(ImageSectionHeader);
        if (sec_off + sec_table_len > data.len) return ParseError.BadSectionTable;

        const sections: [*]const ImageSectionHeader = @ptrCast(data.ptr + sec_off);

        // Сан-проверки optional header (доверяем, но проверяем)
        const opt = &nt.optional_header;
        if (opt.size_of_image == 0) return ParseError.BadOptionalHeader;
        if (opt.section_alignment == 0 or opt.file_alignment == 0) return ParseError.BadOptionalHeader;
        if (opt.number_of_rva_and_sizes > 16) return ParseError.BadOptionalHeader;

        return Pe{
            .data = data,
            .nt = nt,
            .sections = sections[0..nsec],
        };
    }

    // ── Доступ к заголовкам ──

    pub fn machine(self: *const Pe) u16 {
        return self.nt.file_header.machine;
    }
    pub fn timestamp(self: *const Pe) u32 {
        return self.nt.file_header.time_date_stamp;
    }
    pub fn numSections(self: *const Pe) usize {
        return self.sections.len;
    }
    pub fn entryPointRva(self: *const Pe) u32 {
        return self.nt.optional_header.address_of_entry_point;
    }
    pub fn entryPointVa(self: *const Pe) u64 {
        return self.nt.optional_header.image_base + self.nt.optional_header.address_of_entry_point;
    }
    pub fn imageBase(self: *const Pe) u64 {
        return self.nt.optional_header.image_base;
    }
    pub fn sizeOfImage(self: *const Pe) u32 {
        return self.nt.optional_header.size_of_image;
    }
    pub fn sizeOfHeaders(self: *const Pe) u32 {
        return self.nt.optional_header.size_of_headers;
    }
    pub fn sectionAlignment(self: *const Pe) u32 {
        return self.nt.optional_header.section_alignment;
    }
    pub fn fileAlignment(self: *const Pe) u32 {
        return self.nt.optional_header.file_alignment;
    }
    pub fn subsystem(self: *const Pe) u16 {
        return self.nt.optional_header.subsystem;
    }
    pub fn isConsole(self: *const Pe) bool {
        return self.nt.optional_header.subsystem == SUBSYSTEM_WINDOWS_CUI;
    }
    pub fn stackReserve(self: *const Pe) u64 {
        return self.nt.optional_header.size_of_stack_reserve;
    }
    pub fn heapReserve(self: *const Pe) u64 {
        return self.nt.optional_header.size_of_heap_reserve;
    }

    pub fn dataDirectory(self: *const Pe, index: usize) ImageDataDirectory {
        if (index >= self.nt.optional_header.number_of_rva_and_sizes) {
            return .{ .virtual_address = 0, .size = 0 };
        }
        return self.nt.optional_header.data_directory[index];
    }

    // ── Работа с секциями / RVA ──

    /// Секция, содержащая RVA (по виртуальному диапазону).
    pub fn sectionByRva(self: *const Pe, rva: u32) ?*const ImageSectionHeader {
        for (self.sections) |*sec| {
            const sec_size = @max(sec.virtual_size, sec.size_of_raw_data);
            if (sec.virtual_address <= rva and rva < sec.virtual_address + sec_size) {
                return sec;
            }
        }
        // RVA может попадать в заголовок (до первой секции)
        if (rva < self.sizeOfHeaders()) {
            return null; // в header-области — файловое смещение == RVA
        }
        return null;
    }

    /// RVA → файловое смещение. null, если RVA невалиден или в секции
    /// без сырых данных (BSS). Для header-области RVA == file offset.
    pub fn rvaToOffset(self: *const Pe, rva: u32) ?u32 {
        if (rva < self.sizeOfHeaders()) return rva; // DOS+NT+таблица секций
        const sec = self.sectionByRva(rva) orelse return null;
        if (sec.size_of_raw_data == 0) return null; // uninitialized (BSS)
        const delta = rva - sec.virtual_address;
        if (delta >= sec.size_of_raw_data) return null; // хвост BSS-а
        return sec.pointer_to_raw_data + delta;
    }

    pub fn sectionByName(self: *const Pe, comptime name: []const u8) ?*const ImageSectionHeader {
        for (self.sections) |*sec| {
            if (std.mem.eql(u8, sec.nameSlice(), name)) return sec;
        }
        return null;
    }

    // ── Импорты (IAT) ──

    /// Итератор DLL из таблицы импортов. Требует валидную IMPORT-директорию.
    pub fn importDlls(self: *const Pe) ParseError!ImportDllIterator {
        const dir = self.dataDirectory(DIR_IMPORT);
        if (dir.virtual_address == 0) {
            // нет импортов — пустой итератор
            return ImportDllIterator{
                .pe = self,
                .desc_rva = 0,
                .desc_end_rva = 0,
            };
        }
        const off = self.rvaToOffset(dir.virtual_address) orelse return ParseError.BadImportDirectory;
        _ = off; // проверили конвертируемость; итератор сам разыменует
        if (dir.size < @sizeOf(ImageImportDescriptor)) return ParseError.BadImportDirectory;
        // вычисляем RVA-границу по секции
        const sec = self.sectionByRva(dir.virtual_address) orelse return ParseError.BadImportDirectory;
        const sec_end = sec.virtual_address + @max(sec.virtual_size, sec.size_of_raw_data);
        const dir_end = @min(dir.virtual_address + dir.size, sec_end);
        return ImportDllIterator{
            .pe = self,
            .desc_rva = dir.virtual_address,
            .desc_end_rva = dir_end,
        };
    }

    /// Есть ли импорт dll!func (имена case-insensitive, как в Windows).
    pub fn findImport(self: *const Pe, dll_needle: []const u8, func_needle: []const u8) bool {
        var dlls = self.importDlls() catch return false;
        while (dlls.next()) |dll| {
            if (std.ascii.eqlIgnoreCase(dll.name, dll_needle)) {
                var fns = dll.functions;
                while (fns.next()) |f| {
                    switch (f) {
                        .by_name => |n| if (std.mem.eql(u8, n, func_needle)) return true,
                        .by_ordinal => {},
                    }
                }
            }
        }
        return false;
    }

    /// Подсчёт: (кол-во DLL, суммарное кол-во функций).
    pub fn countImports(self: *const Pe) struct { dlls: usize, functions: usize } {
        var n_dlls: usize = 0;
        var n_fns: usize = 0;
        var dlls = self.importDlls() catch return .{ .dlls = 0, .functions = 0 };
        while (dlls.next()) |dll| {
            n_dlls += 1;
            var fns = dll.functions;
            while (fns.next() != null) : (n_fns += 1) {}
        }
        return .{ .dlls = n_dlls, .functions = n_fns };
    }
};

// ============================================================================
// Тесты (нативно: x86_64-linux-gnu через `zig build test`)
// Фикстуры: testdata/curl.exe (PE32+/AMD64, консоль, 274 импорта из 22 DLL),
//            testdata/7zr.exe (PE32/i386 — негативный кейс).
// ============================================================================
//
// ⚠ Инвариант теста: `zig build test` ОБЯЗАН запускать бинарники (RunArtifact),
// иначе паники/падения тестов не ловятся (урок v0.9.0: сборка ≠ прогон).==

const testing = std.testing;

fn loadFixture(comptime name: []const u8) ![]const u8 {
    if (comptime std.mem.eql(u8, name, "testdata/curl.exe")) {
        return @embedFile("testdata/curl.exe");
    } else if (comptime std.mem.eql(u8, name, "testdata/7zr.exe")) {
        return @embedFile("testdata/7zr.exe");
    } else {
        return error.FileNotFound;
    }
}

test "parse: curl.exe — PE32+/AMD64, 9 секций, консоль" {
    const data = try loadFixture("testdata/curl.exe");

    const pe = try Pe.parse(data);
    try testing.expectEqual(MACHINE_AMD64, pe.machine());
    try testing.expectEqual(OPT_MAGIC_PE32_PLUS, pe.nt.optional_header.magic);
    try testing.expectEqual(@as(usize, 9), pe.numSections());
    try testing.expect(pe.isConsole());
    try testing.expect(pe.entryPointRva() != 0);
    // mingw-сборка: базовый адрес 0x140000000, выравнивание секций 0x1000
    try testing.expectEqual(@as(u64, 0x140000000), pe.imageBase());
    try testing.expectEqual(@as(u32, 0x1000), pe.sectionAlignment());
    // SizeOfImage больше RAW-размера (BSS-хвосты)
    try testing.expect(pe.sizeOfImage() > 0);
}

test "parse: 7zr.exe (i386) отклоняется как UnsupportedMachine" {
    const data = try loadFixture("testdata/7zr.exe");

    try testing.expectError(ParseError.UnsupportedMachine, Pe.parse(data));
}

test "parse: мусор и невыровненный буфер отклоняются по магии" {
    // стековый массив имеет выравнивание 1 — исторически здесь ловился
    // alignCast-panic; теперь парсер обязан терпеть любой вход
    const not_mz = [_]u8{0} ** 128;
    try testing.expectError(ParseError.NotMZ, Pe.parse(&not_mz));

    const short = [_]u8{ 'M', 'Z' };
    try testing.expectError(ParseError.Truncated, Pe.parse(&short));

    // смещённый MZ: e_lfanew указывает внутрь файла, но NT-сигнатуры нет
    var shifted: [1024]u8 = undefined;
    @memset(&shifted, 0);
    shifted[0] = 'M';
    shifted[1] = 'Z';
    std.mem.writeInt(u32, shifted[0x3C..][0..4], 0x80, .little);
    try testing.expectError(ParseError.NotPE, Pe.parse(&shifted));
}

test "sections: имена, флаги, rvaToOffset round-trip" {
    const data = try loadFixture("testdata/curl.exe");
    const pe = try Pe.parse(data);

    // .text обязан существовать и быть исполняемым
    const text = pe.sectionByName(".text") orelse return error.NoDotText;
    try testing.expect(text.isExecutable());
    try testing.expect(!text.isWritable());
    try testing.expect(text.virtual_size > 0);

    // rvaToOffset: для каждой секции конверсия VA→file и обратно в границах raw
    for (pe.sections) |*sec| {
        if (sec.size_of_raw_data == 0) continue;
        const mid_rva = sec.virtual_address + @min(sec.size_of_raw_data - 1, 0x1000);
        const off = pe.rvaToOffset(mid_rva) orelse continue;
        try testing.expect(off < data.len);
    }

    // header-область: RVA == file offset
    try testing.expectEqual(@as(u32, 0x10), pe.rvaToOffset(0x10).?);
}

test "imports: curl.exe — 22 DLL, 274 функции, KERNEL32=80" {
    const data = try loadFixture("testdata/curl.exe");
    const pe = try Pe.parse(data);

    const counts = pe.countImports();
    std.debug.print("\n[curl imports] dlls={d} functions={d}\n", .{ counts.dlls, counts.functions });
    try testing.expectEqual(@as(usize, 22), counts.dlls);
    try testing.expectEqual(@as(usize, 274), counts.functions);

    // точечные проверки функций из спеки CDD
    try testing.expect(pe.findImport("KERNEL32.dll", "CreateFileA"));
    try testing.expect(pe.findImport("KERNEL32.dll", "CreateThread"));
    try testing.expect(pe.findImport("WS2_32.dll", "WSAStartup"));
    try testing.expect(pe.findImport("USER32.dll", "FindWindowA"));
    try testing.expect(pe.findImport("bcrypt.dll", "BCryptGenRandom"));
    // case-insensitive DLL-имена (привычка Windows)
    try testing.expect(pe.findImport("kernel32.DLL", "CloseHandle"));
    // отсутствующее
    try testing.expect(!pe.findImport("KERNEL32.dll", "NoSuchFunctionXYZ"));
}

test "imports: итератор выдаёт имена DLL и IAT RVA" {
    const data = try loadFixture("testdata/curl.exe");
    const pe = try Pe.parse(data);

    var dlls = try pe.importDlls();
    var saw_kernel32 = false;
    var saw_ws2 = false;
    while (dlls.next()) |dll| {
        if (std.ascii.eqlIgnoreCase(dll.name, "KERNEL32.dll")) {
            saw_kernel32 = true;
            const n = dll.countFunctions();
            try testing.expectEqual(@as(usize, 80), n);
            try testing.expect(dll.iat_rva != 0);
        }
        if (std.ascii.eqlIgnoreCase(dll.name, "WS2_32.dll")) {
            saw_ws2 = true;
        }
    }
    try testing.expect(saw_kernel32);
    try testing.expect(saw_ws2);
}

test "imports: функция с известным именем читается из ILT" {
    const data = try loadFixture("testdata/curl.exe");
    const pe = try Pe.parse(data);

    var dlls = try pe.importDlls();
    var found = false;
    while (dlls.next()) |dll| {
        if (!std.ascii.eqlIgnoreCase(dll.name, "USER32.dll")) continue;
        var fns = dll.functions;
        while (fns.next()) |f| {
            switch (f) {
                .by_name => |n| if (std.mem.eql(u8, n, "SendMessageA")) {
                    found = true;
                },
                .by_ordinal => {},
            }
        }
    }
    try testing.expect(found);
}
