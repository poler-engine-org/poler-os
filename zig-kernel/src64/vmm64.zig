// ============================================================================
// POLER-OS Virtual Memory Manager — x86_64
// ============================================================================

const pmm = @import("pmm64.zig");
const hal = @import("hal.zig");

pub const PTE_PRESENT: u64 = 0x01;
pub const PTE_WRITABLE: u64 = 0x02;
pub const PTE_USER: u64 = 0x04;
pub const PTE_WRITE_THROUGH: u64 = 0x08;
pub const PTE_CACHE_DISABLE: u64 = 0x10;
pub const PTE_ACCESSED: u64 = 0x20;
pub const PTE_DIRTY: u64 = 0x40;
pub const PTE_HUGE: u64 = 0x80;
pub const PTE_GLOBAL: u64 = 0x100;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;

pub const PAGE_SIZE: u64 = 4096;

pub const VmmError = error{
    OutOfMemory,
    InvalidAddress,
    AlreadyMapped,
};

var pml4_phys: u64 = 0;

pub fn init() void {
    pml4_phys = hal.readCr3() & 0x000FFFFFFFFFF000;
    hal.Serial.puts("[VMM] Virtual Memory Manager initialized, PML4 at ");
    hal.Serial.putHex(pml4_phys);
    hal.Serial.puts("\n");
}

fn getOrCreateTable(table_phys: u64, index: usize, is_user: bool) !u64 {
    const table: [*]volatile u64 = @ptrFromInt(table_phys);
    const entry = table[index];

    if (entry & PTE_PRESENT != 0) {
        if (entry & PTE_HUGE != 0) {
            return VmmError.AlreadyMapped;
        }
        // v0.7.0 FIX: If the existing entry doesn't have PTE_USER but we need it
        // (e.g., kernel entry copied to user PML4 without PTE_USER, then user
        // mapping wants to use the same PDPT), add PTE_USER to the entry.
        // This allows Ring 3 to traverse through this page table level.
        if (is_user and (entry & PTE_USER == 0)) {
            table[index] = entry | PTE_USER;
        }
        return entry & 0x000FFFFFFFFFF000;
    }

    const new_table_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const ptr: [*]volatile u64 = @ptrFromInt(new_table_phys);
    @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);

    // Page table entries: only set PTE_USER if this is a user mapping.
    // Kernel page tables should NOT have the User bit — this prevents
    // Ring 3 code from reading kernel memory.
    var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
    if (is_user) pte_flags |= PTE_USER;
    table[index] = new_table_phys | pte_flags;
    return new_table_phys;
}

/// Check if a page table (512 entries) is entirely empty
fn isTableEmpty(table_phys: u64) bool {
    const table: [*]const volatile u64 = @ptrFromInt(table_phys);
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        if (table[i] & PTE_PRESENT != 0) return false;
    }
    return true;
}

pub fn mapPage(virt: u64, phys: u64, flags: u64) !void {
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    // Determine if this is a user-space mapping.
    // If PTE_USER is set in flags, all intermediate page tables must also
    // have PTE_USER — otherwise Ring 3 can't traverse the page tables.
    // If PTE_USER is NOT set (kernel mapping), intermediate tables also
    // should NOT have PTE_USER — this prevents Ring 3 from accessing kernel memory.
    const is_user = (flags & PTE_USER) != 0;

    // v6 FIX (Bug #6): Track pages allocated during table creation
    // so we can free them on failure
    var allocated_pages: [3]?u64 = .{ null, null, null };

    // PDPT table
    const pml4: [*]volatile u64 = @ptrFromInt(pml4_phys);
    const pdpt_phys: u64 = blk: {
        if (pml4[pml4_idx] & PTE_PRESENT != 0) {
            break :blk pml4[pml4_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse return VmmError.OutOfMemory;
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        // Only set PTE_USER on intermediate tables for user mappings
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pml4[pml4_idx] = page | pte_flags;
        allocated_pages[0] = page;
        break :blk page;
    };

    // PD table
    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    const pd_phys: u64 = blk: {
        if (pdpt[pdpt_idx] & PTE_PRESENT != 0) {
            break :blk pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse {
            // v6 FIX: Free already-allocated PDPT page on failure
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pdpt[pdpt_idx] = page | pte_flags;
        allocated_pages[1] = page;
        break :blk page;
    };

    // PT table
    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    const pt_phys: u64 = blk: {
        if (pd[pd_idx] & PTE_PRESENT != 0) {
            break :blk pd[pd_idx] & 0x000FFFFFFFFFF000;
        }
        const page = pmm.allocPage() orelse {
            // v6 FIX: Free already-allocated pages on failure
            if (allocated_pages[1]) |p| { pmm.freePage(p); pdpt[pdpt_idx] = 0; }
            if (allocated_pages[0]) |p| { pmm.freePage(p); pml4[pml4_idx] = 0; }
            return VmmError.OutOfMemory;
        };
        const ptr: [*]volatile u64 = @ptrFromInt(page);
        @memset(@as([*]volatile u8, @ptrCast(ptr))[0..PAGE_SIZE], 0);
        var pte_flags: u64 = PTE_PRESENT | PTE_WRITABLE;
        if (is_user) pte_flags |= PTE_USER;
        pd[pd_idx] = page | pte_flags;
        allocated_pages[2] = page;
        break :blk page;
    };

    // Check if the PTE is already occupied — refuse to silently overwrite
    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    if (pt[pt_idx] & PTE_PRESENT != 0) {
        // v6 FIX: Free newly allocated page tables since we didn't need them
        // (They might be shared with other mappings, so only free if we just allocated them)
        // Actually, we should NOT free them here — other entries might already exist.
        // Just return the error; the allocated tables will be reused or freed later by unmapPage.
        return VmmError.AlreadyMapped;
    }

    pt[pt_idx] = phys | flags | PTE_PRESENT;

    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );
}

/// v0.7.0: Create a new PML4 for a user process.
/// Copies kernel PML4 entries so the kernel remains mapped in the user
/// address space (needed for syscall entry, ISR handling, etc.).
///
/// CRITICAL SECURITY: Kernel PML4 entries are copied WITHOUT the PTE_USER bit.
/// This means Ring 3 code cannot access kernel memory — any attempt causes a
/// page fault. Ring 0 code (during syscall/interrupt handling) can still
/// access kernel pages because CPL=0 overrides the User/Supervisor check.
///
/// Returns the physical address of the new PML4.
pub fn createUserPML4() !u64 {
    const new_pml4_phys = pmm.allocPage() orelse return VmmError.OutOfMemory;
    const new_pml4: [*]volatile u64 = @ptrFromInt(new_pml4_phys);
    @memset(@as([*]volatile u8, @ptrCast(new_pml4))[0..PAGE_SIZE], 0);

    // Copy all non-zero PML4 entries from kernel (shared kernel mapping)
    // but STRIP the PTE_USER bit from kernel entries — this enforces
    // kernel/user isolation: Ring 3 cannot access kernel pages.
    const kernel_pml4: [*]const volatile u64 = @ptrFromInt(pml4_phys);
    for (0..512) |i| {
        const entry = kernel_pml4[i];
        if (entry & PTE_PRESENT != 0) {
            // Remove PTE_USER from kernel mappings — Ring 3 can't read kernel
            new_pml4[i] = entry & ~PTE_USER;
        }
    }

    hal.Serial.puts("[VMM] Created user PML4 at ");
    hal.Serial.putHex(new_pml4_phys);
    hal.Serial.puts(" (kernel entries WITHOUT User bit)\n");

    return new_pml4_phys;
}

/// v6 FIX (Bug #9): unmapPage now returns error instead of silently
/// ignoring misaligned addresses. Caller should handle the error.
pub fn unmapPage(virt: u64) VmmError!void {
    if (virt % PAGE_SIZE != 0) {
        hal.Serial.puts("[VMM] ERROR: unmapPage misaligned address: 0x");
        hal.Serial.putHex(virt);
        hal.Serial.puts("\n");
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const pml4: [*]volatile u64 = @ptrFromInt(pml4_phys);
    if (pml4[pml4_idx] & PTE_PRESENT == 0) return;
    const pdpt_phys = pml4[pml4_idx] & 0x000FFFFFFFFFF000;

    const pdpt: [*]volatile u64 = @ptrFromInt(pdpt_phys);
    if (pdpt[pdpt_idx] & PTE_PRESENT == 0) return;
    const pd_phys = pdpt[pdpt_idx] & 0x000FFFFFFFFFF000;

    const pd: [*]volatile u64 = @ptrFromInt(pd_phys);
    if (pd[pd_idx] & PTE_PRESENT == 0) return;
    const pt_phys = pd[pd_idx] & 0x000FFFFFFFFFF000;

    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    pt[pt_idx] = 0;

    asm volatile ("invlpg (%[virt])"
        :
        : [virt] "r" (virt),
        : "memory"
    );

    // Free empty page tables back to PMM (walk up from PT → PD → PDPT)
    if (isTableEmpty(pt_phys)) {
        pmm.freePage(pt_phys);
        pd[pd_idx] = 0;

        if (isTableEmpty(pd_phys)) {
            pmm.freePage(pd_phys);
            pdpt[pdpt_idx] = 0;

            if (isTableEmpty(pdpt_phys)) {
                pmm.freePage(pdpt_phys);
                pml4[pml4_idx] = 0;
            }
        }
    }
}

/// v0.7.0: Map a page in a SPECIFIC PML4 (not the global kernel PML4).
/// Used for user-space mappings that should only be accessible from
/// the user process's page tables (with PTE_USER set).
///
/// This function creates the full 4-level page table hierarchy
/// (PML4 → PDPT → PD → PT) in the target PML4, with PTE_USER on
/// all intermediate tables so Ring 3 can traverse them.
pub fn mapPageInPML4(target_pml4_phys: u64, virt: u64, phys: u64, flags: u64) !void {
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        return VmmError.InvalidAddress;
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const is_user = (flags & PTE_USER) != 0;

    // Walk/create PML4 → PDPT → PD → PT in the target PML4

    // PDPT
    const pdpt_phys = try getOrCreateTable(target_pml4_phys, pml4_idx, is_user);

    // PD
    const pd_phys = try getOrCreateTable(pdpt_phys, pdpt_idx, is_user);

    // PT
    const pt_phys = try getOrCreateTable(pd_phys, pd_idx, is_user);

    // Set the actual page table entry
    const pt: [*]volatile u64 = @ptrFromInt(pt_phys);
    if (pt[pt_idx] & PTE_PRESENT != 0) {
        return VmmError.AlreadyMapped;
    }
    pt[pt_idx] = phys | flags | PTE_PRESENT;

    // No invlpg needed — this PML4 is not the active CR3 yet
}

// ─── v0.11.0 (CDD-цикл №2): валидация user-указателей из ядра ──────────────

/// Identity-чтение 64-бит из физ. адреса (0-4ГБ — диапазон identity-маппинга
/// из boot64.S; ОЗУ QEMU -m 256M целиком ниже). null = вне identity.
inline fn physReadQ(pa: u64) ?u64 {
    if (pa >= 0x100000000 or pa % 8 != 0) return null;
    const p: *const volatile u64 = @ptrFromInt(pa);
    return p.*;
}

/// Leaf-флаги PTE для va в таблицах УКАЗАННОГО PML4 (walk 4 уровней через
/// identity, поддержка 4K/2M/1G-листьев). Возвращает листовую запись
/// (PTE/PDE/PDPTE) с её битами — caller проверяет PRESENT/USER/WRITABLE.
/// null = путь не present.
///
/// Назначение (win32_api): ядро ВАЛИДИРУЕТ user-указатель ДО разыменования —
/// мусорный аргумент из Ring 3 не должен вызывать #PF в ядре (паника всего
/// ядра), а указатель на kernel-VA (leaf без USER-бита) — пробиваться в
/// supervisor-память через syscall (security: Ring 3 обязан мочь получить к
/// странице доступ сам, иначе это не его память).
pub fn userLeafFlags(target_pml4: u64, va: u64) ?u64 {
    const pml4e = physReadQ(target_pml4 + 8 * ((va >> 39) & 0x1FF)) orelse return null;
    if (pml4e & PTE_PRESENT == 0) return null;
    const pdpte = physReadQ((pml4e & 0x000FFFFFFFFFF000) + 8 * ((va >> 30) & 0x1FF)) orelse return null;
    if (pdpte & PTE_PRESENT == 0) return null;
    if (pdpte & PTE_HUGE != 0) return pdpte; // 1GB-лист
    const pde = physReadQ((pdpte & 0x000FFFFFFFFFF000) + 8 * ((va >> 21) & 0x1FF)) orelse return null;
    if (pde & PTE_PRESENT == 0) return null;
    if (pde & PTE_HUGE != 0) return pde; // 2MB-лист
    const pte = physReadQ((pde & 0x000FFFFFFFFFF000) + 8 * ((va >> 12) & 0x1FF)) orelse return null;
    if (pte & PTE_PRESENT == 0) return null;
    return pte; // 4KB-лист
}
