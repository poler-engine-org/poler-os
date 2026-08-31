// ============================================================================
// POLER-OS Win32 API — kernel-проводка (v0.11.0, CDD-цикл №2)
// ============================================================================
//
// ТОНКИЙ слой между hal (syscall #6) и ЧИСТОЙ семантикой win32_crt.zig:
// устанавливает Ops-инъекцию (installOps) с НАСТОЯЩИМИ платформенными
// примитивами:
//   validate_read/write — walk таблиц PML4 процесса через identity
//                         (vmm.userLeafFlags): USER-бит обязателен (иначе
//                         Ring 3 не мог бы сам тронуть страницу — security),
//                         для записи ещё и WRITABLE. Мусорный указатель из
//                         приложения → отказ, а НЕ #PF-паника ядра.
//   map_user            — PMM-страницы + vmm.mapPageInPML4 (RW+USER+NX) в
//                         heap-регионы процесса (block-heap + VirtualAlloc).
//   read_tsc            — hal.readMsr(0x10) (IA32_TSC).
//   write_console       — hal.Serial (текст приложения попадает в консоль ОС).
//   log                 — hal.Serial ([WIN32]/[CDD]-трейс).
//   exit                — exitCallback (scheduler kill) + hlt.
//
// Вся семантика (dispatch по именам, block-heap, GetProcAddress, ленивые
// CRT-структуры) живёт в win32_crt.zig и покрыта нативными тестами; здесь —
// только платформенные примитивы, покрытие через QEMU E2E.
//
// ⚠ Инвариант (см. шапку win32_crt.zig): прямой доступ к user-VA валиден в
// syscall-контексте (CR3 = PML4 процесса). Все вызовы идут через hal case 6.
// ============================================================================

const std = @import("std");
const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const win32 = @import("win32_stubs.zig");
const crt = @import("win32_crt.zig");

pub const PAGE_SIZE: u64 = 4096;

/// Длина одного validate-диапазона ограничена (мегабайтные memset из мусорных
/// аргументов не должны крутить walk миллионы итераций).
const MAX_VALIDATE_LEN: u64 = 64 * 1024 * 1024;

// ─── Установка Ops (kernelMain, после инициализации hal/vmm/pmm) ────────────

pub fn installOps() void {
    crt.ops = .{
        .validate_read = kValidateRead,
        .validate_write = kValidateWrite,
        .map_user = kMapUser,
        .read_tsc = kReadTsc,
        .write_console = kWriteConsole,
        .log = kLog,
        .exit = kExit,
    };
}

// ─── Точка входа syscall #6 (hal.win32SyscallCallback) ──────────────────────

pub fn syscallDispatch(entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    return crt.syscallDispatch(entry_id, a1, a2, a3, a4);
}

// ─── Платформенные примитивы (kernel) ───────────────────────────────────────

/// Walk таблиц PML4 процесса: каждая страница диапазона обязана быть present
/// и USER (иначе это не память приложения — kernel-VA/подделка → отказ).
/// Постраничная гранулярность: диапазон может пересекать границы страниц.
fn validateRange(va: u64, len: u64, want_write: bool) bool {
    const c = (crt.ctx orelse return false);
    if (len == 0) return true;
    if (len > MAX_VALIDATE_LEN) return false;
    if (va < 0x1000) return false; // NULL-страница — не бывает user-данных

    var off: u64 = 0;
    while (off < len) {
        const p = va + off;
        const leaf = vmm.userLeafFlags(c.pml4, p) orelse return false;
        if (leaf & vmm.PTE_USER == 0) return false; // security: supervisor-VA
        if (want_write and (leaf & vmm.PTE_WRITABLE == 0)) return false;
        off += PAGE_SIZE - (p & (PAGE_SIZE - 1)); // до конца текущей страницы
    }
    return true;
}

fn kValidateRead(va: u64, len: u64) bool {
    return validateRange(va, len, false);
}

fn kValidateWrite(va: u64, len: u64) bool {
    return validateRange(va, len, true);
}

/// Выделить и замапить страницы heap-региона [va, va+bytes): PMM (обнулённые)
/// + VMM (RW+USER+NX) в PML4 процесса. va обязан быть page-aligned
/// (вызывают только kmalloc/virtualAlloc с выровненными курсорами).
fn kMapUser(va: u64, bytes: u64) bool {
    const c = (crt.ctx orelse return false);
    if (va % PAGE_SIZE != 0 or bytes == 0 or bytes > MAX_VALIDATE_LEN) return false;
    const pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const pa = pmm.allocContiguousZeroed(1) orelse return false;
        vmm.mapPageInPML4(c.pml4, va + i * PAGE_SIZE, pa, vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE) catch return false;
    }
    return true;
}

fn kReadTsc() u64 {
    return hal.readMsr(0x10); // IA32_TSC
}

fn kWriteConsole(s: []const u8) void {
    hal.Serial.puts(s);
}

fn kLog(s: []const u8) void {
    hal.Serial.puts(s);
}

/// Завершение PE-процесса: exitCallback (планировщик пометит задачу Killed),
/// дальше hlt до вытеснения. Возврата нет — syscall-обработчик не вернётся.
fn kExit(code: u64) void {
    hal.Serial.puts("[WIN32] ExitProcess(");
    hal.Serial.putHex(code);
    hal.Serial.puts(") — PE-процесс завершился штатно\n");
    if (hal.exitCallback) |cb| cb();
    while (true) {
        asm volatile ("hlt");
    }
}
