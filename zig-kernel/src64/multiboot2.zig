// ============================================================================
// POLER-OS Multiboot2 Specification Parser — x86_64
// ============================================================================

pub const Tag = extern struct {
    type: u32,
    size: u32,
};

pub const MmapEntry = extern struct {
    addr: u64,
    len: u64,
    entry_type: u32, // 1 = RAM, 2 = Reserved, 3 = ACPI, 4 = NVS, 5 = Unusable, 6 = ACPI Reclaimable
    zero: u32,
};

pub const MmapTag = extern struct {
    type: u32,
    size: u32,
    entry_size: u32,
    entry_version: u32,
    
    pub fn getEntries(self: *const MmapTag) []const MmapEntry {
        const entries_ptr: [*]const MmapEntry = @ptrFromInt(@intFromPtr(self) + 16);
        const num_entries = (self.size - 16) / self.entry_size;
        return entries_ptr[0..num_entries];
    }
};

pub const BasicMemTag = extern struct {
    type: u32,
    size: u32,
    mem_lower: u32,
    mem_upper: u32,
};

pub const FramebufferTag = extern struct {
    type: u32,
    size: u32,
    fb_addr: u64,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u8,
    fb_type: u8,
    reserved: u16,
};

pub const CmdlineTag = extern struct {
    type: u32,
    size: u32,
    
    pub fn getCmdline(self: *const CmdlineTag) []const u8 {
        const str_ptr: [*]const u8 = @ptrFromInt(@intFromPtr(self) + 8);
        return str_ptr[0..(self.size - 8 - 1)]; // exclude null terminator
    }
};

pub const ModuleTag = extern struct {
    type: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    
    pub fn getCmdline(self: *const ModuleTag) []const u8 {
        const str_ptr: [*]const u8 = @ptrFromInt(@intFromPtr(self) + 16);
        var len: usize = 0;
        while (str_ptr[len] != 0) : (len += 1) {}
        return str_ptr[0..len];
    }
};



pub const InfoHeader = extern struct {
    total_size: u32,
    reserved: u32,
};

pub const Parser = struct {
    total_size: u32,
    info_ptr: u64,

    pub fn init(info_ptr: u64) Parser {
        // PVH/нулевой указатель: не кастуем 0 в non-optional указатель
        // (Zig safety: «cast causes pointer to be null»), отдаём пустой
        // парсер — все find* вернут null через mbInfoLooksValid.
        if (info_ptr == 0) return Parser{ .total_size = 0, .info_ptr = 0 };
        const header: *const InfoHeader = @ptrFromInt(info_ptr);
        return Parser{
            .total_size = header.total_size,
            .info_ptr = info_ptr,
        };
    }

    /// Санитарная проверка MBI: корректная структура занимает 8 байт..1 МБ.
    /// Защита от мусорного указателя (например, PVH EBX ≠ 0 без мagic-гейта)
    /// и от повреждённого total_size, которые раньше давали бесконечный
    //  цикл в findTag (диагностировано по QEMU -d int: RIP в findTag:103).
    fn mbInfoLooksValid(self: *const Parser) bool {
        return self.total_size >= 8 and self.total_size <= 0x100000;
    }

    pub fn findTag(self: *const Parser, tag_type: u32) ?u64 {
        if (!self.mbInfoLooksValid()) return null;
        var offset: u64 = 8; // skip InfoHeader
        while (offset < self.total_size) {
            const tag: *const Tag = @ptrFromInt(self.info_ptr + offset);
            if (tag.type == tag_type) {
                return self.info_ptr + offset;
            }
            if (tag.type == 0 and tag.size == 8) {
                break; // End tag
            }
            // Malformed-тег (size<8) — гарантия прогресса цикла
            if (tag.size < 8) break;
            // Align tag size to 8-byte boundary
            offset += (tag.size + 7) & ~@as(u32, 7);
        }
        return null;
    }

    pub fn findModuleTag(self: *const Parser, start_offset: *u64) ?*const ModuleTag {
        if (!self.mbInfoLooksValid()) return null;
        var offset = start_offset.*;
        while (offset < self.total_size) {
            const tag: *const Tag = @ptrFromInt(self.info_ptr + offset);
            if (tag.type == 0 and tag.size == 8) {
                break; // End tag
            }
            if (tag.size < 8) break; // malformed — гарантия прогресса
            const next_offset = offset + ((tag.size + 7) & ~@as(u32, 7));
            if (tag.type == 3) {
                start_offset.* = next_offset;
                const module_ptr: *const ModuleTag = @ptrCast(tag);
                return module_ptr;
            }
            offset = next_offset;
        }
        return null;
    }
};
