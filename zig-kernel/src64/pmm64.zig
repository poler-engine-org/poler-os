// ============================================================================
// POLER-OS Physical Memory Manager — x86_64
// ============================================================================

const multiboot2 = @import("multiboot2.zig");
const hal = @import("hal.zig");

const PAGE_SIZE: u64 = 4096;
const MAX_MEM_SUPPORTED: u64 = 0x100000000; // 4GB for Phase 1
const MAX_PAGES: u64 = MAX_MEM_SUPPORTED / PAGE_SIZE;

// Bitmap: 1 bit per page (128 KB bitmap for 4GB RAM)
var bitmap: [MAX_PAGES / 8]u8 = undefined;
var total_ram_bytes: u64 = 0;
var usable_pages: u64 = 0;
pub var allocated_pages: u64 = 0;
/// CDD №15 p5-FORENSICS: физ-ловушка. pageWatch/demand-zero выставляют
/// phys краш-В-страницы (bump-слаб); ЛЮБОЙ free/alloc этого кадра печатается
/// с таском: poisoner-free (кто отдал живой кадр в PMM) + reissue-alloc
/// (кто получил его повторно → memset → вайп на месте). Ответ на главный
/// вопрос run15: WHO freed 0x199E000 между BORN (t=362) и ZEROED (t=363).
pub var watch_pa: u64 = 0;
var next_free_hint: u64 = 0; // Next-fit hint to avoid O(n) scan from 0

// CDD №12 p10: ТИХИЕ УБИЙЦЫ АЛИАСИНГА → ГРОМКИЕ. freePage молча глотал
// повторный free (бит уже чист — no-op) — двойное владение кадром
// маскировалось, PMM выдавал ОДНУ физику ДВУМ VA (кросс-маппинг).
// Счётчики видны в e2e-логах и в мониторе (physmap).
pub var pmm_double_frees: u64 = 0;
pub var pmm_free_calls: u64 = 0;
pub var pmm_alloc_calls: u64 = 0;
var pmm_df_reported: u64 = 0; // анти-спам: печатаем первые 16

extern var _kernel_start: anyopaque;
extern var _kernel_end: anyopaque;

pub fn init(mbi_ptr: u64) void {
    // 1. Mark all memory as reserved initially
    @memset(&bitmap, 0xFF);

    if (mbi_ptr != 0) {
        const parser = multiboot2.Parser.init(mbi_ptr);

        // 2. Parse basic memory info tag if present
        if (parser.findTag(4)) |tag_addr| {
            const mem_tag: *const multiboot2.BasicMemTag = @ptrFromInt(tag_addr);
            total_ram_bytes = @as(u64, mem_tag.mem_upper) * 1024 + 1024 * 1024;
        }

        // 3. Parse memory map tag (type 6) — mark usable regions as free
        if (parser.findTag(6)) |tag_addr| {
            const mmap_tag: *const multiboot2.MmapTag = @ptrFromInt(tag_addr);
            const entries = mmap_tag.getEntries();

            for (entries) |entry| {
                if (entry.entry_type == 1) {
                    var addr = entry.addr;
                    const end_addr = entry.addr + entry.len;
                    addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

                    while (addr + PAGE_SIZE <= end_addr) : (addr += PAGE_SIZE) {
                        if (addr < MAX_MEM_SUPPORTED) {
                            freePageInternal(addr);
                            usable_pages += 1;
                        }
                    }
                }
            }
        }
    } else {
        // PVH direct boot (QEMU -kernel, ELF note) — карты памяти нет.
        // v0.20.0 (CDD №12 p1): RAM-размер из CMOS (QEMU заполняет 0x34/0x35
        // выше 16МБ): CachyOS-rootfs (45МБ initrd + ld.so-маппинги 90МБ+)
        // в старом кэпе 128МБ не помещался → PMM-истощение. Гард: кламп в
        // [128МБ, 4ГБ] (мусорный CMOS → прежняя консервативная модель).
        var detected = hal.cmosRamSize();
        if (detected < 128 * 1024 * 1024 or detected > MAX_MEM_SUPPORTED) {
            detected = 128 * 1024 * 1024; // fallback: гипотеза TCG/KVM ≥128МБ
        }
        total_ram_bytes = detected & ~(PAGE_SIZE - 1);
        var addr: u64 = 2 * 1024 * 1024;
        while (addr < total_ram_bytes) : (addr += PAGE_SIZE) {
            freePageInternal(addr);
            usable_pages += 1;
        }
    }

    // 4. Protect the first 1MB (BIOS, VGA, early tables)
    var addr: u64 = 0;
    while (addr < 0x100000) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 5. Protect the kernel image
    const k_start: u64 = 0x100000;
    const k_end = @intFromPtr(&_kernel_end);
    const k_end_aligned = (k_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    addr = k_start;
    while (addr < k_end_aligned) : (addr += PAGE_SIZE) {
        setPageInternal(addr);
    }

    // 6. Protect the Multiboot2 info structure (при PVH: mbi==0 — пропускаем)
    if (mbi_ptr != 0) {
        const mbi_header: *const multiboot2.InfoHeader = @ptrFromInt(mbi_ptr);
        const mbi_size = mbi_header.total_size;
        const mbi_end = (mbi_ptr + mbi_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        addr = mbi_ptr & ~(PAGE_SIZE - 1);
        while (addr < mbi_end) : (addr += PAGE_SIZE) {
            if (addr < MAX_MEM_SUPPORTED) {
                setPageInternal(addr);
            }
        }
    }

    // allocated_pages will be incremented on each allocPage() call
    allocated_pages = 0;
    next_free_hint = 0;
}

pub fn allocPage() ?u64 {
    pmm_alloc_calls += 1;
    // Start from the next-fit hint instead of always scanning from 0
    var i: u64 = next_free_hint;
    var wrapped = false;
    while (true) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            if (watch_pa != 0 and i * PAGE_SIZE == watch_pa) {
                const sched = @import("scheduler.zig");
                hal.Serial.puts("[PM-REISSUE] pa=0x");
                hal.Serial.putHex(watch_pa);
                hal.Serial.puts(" task=");
                hal.Serial.putDecimal(@as(u64, sched.current_task_id));
                hal.Serial.puts("\n");
            }
            setPageInternal(i * PAGE_SIZE);
            allocated_pages += 1;
            next_free_hint = i + 1; // Next scan starts after this page
            if (next_free_hint >= MAX_PAGES) next_free_hint = 0;
            return i * PAGE_SIZE;
        }
        i += 1;
        if (i >= MAX_PAGES) {
            if (wrapped) return null; // Full scan done, no free pages
            i = 0;
            wrapped = true;
        }
    }
}

pub fn freePage(addr: u64) void {
    pmm_free_calls += 1;
    // p5-forensics: ловушка poisoner-free (живой кадр уходит в PMM)
    if (watch_pa != 0 and addr == watch_pa) {
        const sched = @import("scheduler.zig");
        hal.Serial.puts("[PM-FREE] pa=0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts(" task=");
        hal.Serial.putDecimal(@as(u64, sched.current_task_id));
        hal.Serial.puts("\n");
    }
    // v6 FIX (Bug #7): Boundary check — addr >= 4GB causes OOB bitmap access
    if (addr >= MAX_MEM_SUPPORTED) {
        hal.Serial.puts("[PMM] ERROR: freePage addr out of range: 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts("\n");
        return;
    }
    // v6: Check alignment — must be page-aligned
    if (addr % PAGE_SIZE != 0) {
        hal.Serial.puts("[PMM] ERROR: freePage addr not page-aligned: 0x");
        hal.Serial.putHex(addr);
        hal.Serial.puts("\n");
        return;
    }
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0) {
        bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        if (allocated_pages > 0) allocated_pages -= 1;
        // Update hint to point near freed page for better locality
        if (page_idx < next_free_hint) {
            next_free_hint = page_idx;
        }
    } else {
        // CDD №12 p10: DOUBLE-FREE — кадр УЖЕ свободен. Раньше молчал:
        // двойное владение (регион-реестр + PTE-скан, два VA, два слота)
        // не детектировалось, а next-fit ГАРАНТИРОВАЛ мгновенный перевыдач
        // этого кадра второй стороне → физ-алиасинг → порча структур.
        pmm_double_frees += 1;
        if (pmm_df_reported < 16) {
            pmm_df_reported += 1;
            hal.Serial.puts("[PMM] DOUBLE-FREE 0x");
            hal.Serial.putHex(addr);
            hal.Serial.puts(" (#");
            hal.Serial.putDecimal(pmm_double_frees);
            hal.Serial.puts(")\n");
        }
    }
}

fn setPageInternal(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

fn freePageInternal(addr: u64) void {
    const page_idx = addr / PAGE_SIZE;
    const byte_idx = page_idx / 8;
    const bit_idx: u3 = @intCast(page_idx % 8);
    bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
}

/// Allocate N contiguous page-aligned physical pages.
/// Returns the physical address of the first page, or null if not enough
/// contiguous free pages are available.
pub fn allocContiguousPages(count: u64) ?u64 {
    if (count == 0) return null;
    if (count > MAX_PAGES) return null;

    // Scan for a run of `count` consecutive free pages
    var run_start: u64 = 0;
    var run_len: u64 = 0;
    var i: u64 = 0;
    while (i < MAX_PAGES) : (i += 1) {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) {
            // Free page
            if (run_len == 0) run_start = i;
            run_len += 1;
            if (run_len >= count) {
                // Found a contiguous run — mark all as allocated
                if (watch_pa != 0 and watch_pa >= run_start * PAGE_SIZE and
                    watch_pa < (run_start + count) * PAGE_SIZE)
                {
                    const sched = @import("scheduler.zig");
                    hal.Serial.puts("[PM-REISSUE-C] pa=0x");
                    hal.Serial.putHex(watch_pa);
                    hal.Serial.puts(" base=0x");
                    hal.Serial.putHex(run_start * PAGE_SIZE);
                    hal.Serial.puts(" n=");
                    hal.Serial.putDecimal(count);
                    hal.Serial.puts(" task=");
                    hal.Serial.putDecimal(@as(u64, sched.current_task_id));
                    hal.Serial.puts("\n");
                }
                var j: u64 = run_start;
                while (j < run_start + count) : (j += 1) {
                    setPageInternal(j * PAGE_SIZE);
                    allocated_pages += 1;
                }
                next_free_hint = run_start + count;
                if (next_free_hint >= MAX_PAGES) next_free_hint = 0;
                return run_start * PAGE_SIZE;
            }
        } else {
            // Allocated page — reset run
            run_len = 0;
        }
    }
    return null; // No contiguous run found
}

/// Free N contiguous pages starting at the given physical address
pub fn freeContiguousPages(addr: u64, count: u64) void {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        freePage(addr + i * PAGE_SIZE);
    }
}

/// v0.10.0: Зарезервировать физ. диапазон [start, end) — пометить страницы
/// занятыми, чтобы PMM не раздал их под ядро/user-образы. Используется для
/// initrd (PVH: QEMU кладёт его высоко в RAM — вне fallback-окна 2..128МБ,
/// но при -m 128M или иных конфигурациях диапазон может пересечься).
pub fn reserveRange(start: u64, end: u64) void {
    var addr = start & ~(PAGE_SIZE - 1);
    while (addr + PAGE_SIZE <= end) : (addr += PAGE_SIZE) {
        if (addr < MAX_MEM_SUPPORTED) {
            if ((bitmap[addr / PAGE_SIZE / 8] & (@as(u8, 1) << @as(u3, @intCast(addr / PAGE_SIZE % 8)))) == 0) {
                setPageInternal(addr);
                usable_pages -= 1;
            }
        }
    }
}

/// v0.10.0: Выделить N физически последовательных страниц и ОБНУЛИТЬ их
/// (allocContiguousPages не гарантирует нулей — а PE-образы и TEB/PEB
/// обязаны стартовать с чистых страниц).
pub fn allocContiguousZeroed(count: u64) ?u64 {
    const base = allocContiguousPages(count) orelse return null;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const page: [*]volatile u8 = @ptrFromInt(base + i * PAGE_SIZE);
        @memset(page[0..PAGE_SIZE], 0);
    }
    return base;
}

pub fn getStats() struct { total_kb: u64, usable_pages: u64, allocated_pages: u64 } {
    return .{
        .total_kb = total_ram_bytes / 1024,
        .usable_pages = usable_pages,
        .allocated_pages = allocated_pages,
    };
}
