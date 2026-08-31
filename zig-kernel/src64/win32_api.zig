// ============================================================================
// POLER-OS Win32 API — реализации для CDD-цикла №1 (v0.10.0)
// ============================================================================
//
// Реальные реализации импортов, вызываемых PE-приложением из Ring 3 через
// syscall-трамплины стабов (win32_stubs.zig, StubKind.impl). Диспетчер —
// syscall #6 «win32_call»: rdi=entry_id, rsi/rsi/rdx/r10/r9 = Win64-аргументы.
//
// Реализовано в v0.10.0 (спека CDD-цикла №1 — топ-3 по плану владельца):
//   KERNEL32.dll!GetStdHandle    — псевдо-хэндлы std streams
//   KERNEL32.dll!GetCommandLineA — указатель на ANSI-строку из params-стр.
//   KERNEL32.dll!GetCommandLineW — указатель на UTF-16LE из params-стр.
//   KERNEL32.dll!VirtualAlloc    — НАСТОЯЩИЙ bump-аллокатор user-страниц
//                                   (PMM + VMM.mapPageInPML4, RW+NX)
//   KERNEL32.dll!ExitProcess     — чистое завершение задачи
//
// Всё остальное остаётся trap-стабами (int3 → CDD-лог → rax=0 → приложение
// живёт) — реализации добавляются по мере падений, см. E2E-лог цепочки.
//
// Контекст одиночный (один PE-процесс на CDD-цикл): ctx заполняет main64
// при peload. Модуль kernel-only (hal/pmm/vmm) — покрытие через QEMU E2E.
// ============================================================================

const std = @import("std");
const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const win32 = @import("win32_stubs.zig");

pub const PAGE_SIZE: u64 = 4096;

/// Контекст активного PE-процесса (заполняется cmd_peload в main64).
pub const Context = struct {
    pml4: u64, // PML4 процесса (для VirtualAlloc-маппингов)
    image_base: u64, // база образа (GetModuleHandle)
    cmdline_a: u64, // user-VA ANSI-командной строки
    cmdline_w: u64, // user-VA UTF-16LE-командной строки
    heap_base: u64, // база VirtualAlloc-региона
    heap_limit: u64,
    heap_cursor: u64,
    allocs: usize, // число VirtualAlloc-выделений
};

pub var ctx: ?Context = null;

/// Статистика CDD: сколько вызовов прошло через syscall-трамплины.
pub var implemented_calls: usize = 0;

/// Псевдо-хэндлы std-потоков (ненулевые, различимые в логах/отчётах).
const FAKE_STDIN: u64 = 0x0000_0000_F000_0001;
const FAKE_STDOUT: u64 = 0x0000_0000_F000_0002;
const FAKE_STDERR: u64 = 0x0000_0000_F000_0003;

// ─── Диспетчер syscall #6 ───────────────────────────────────────────────────

/// Точка входа из hal.zig (win32SyscallCallback): arg-порядок совпадает с
/// syscall-конвенцией трамплина (rsi=arg1, rdx=arg2, r10=arg3, r9=arg4).
pub fn syscallDispatch(entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    const disp = win32.activeDispatcher() orelse return 0;
    return dispatch(disp, entry_id, a1, a2, a3, a4);
}

/// Диспетчер по entry_id реестра стабов: имя → реализация.
/// DLL-имена сравниваются case-insensitive; api-ms-win-crt-* — UCRT-
/// обёртки (curl.exe зовёт exit/_exit через них, а не ExitProcess).
pub fn dispatch(disp: *win32.Dispatcher, entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 {
    if (entry_id >= disp.count) return 0;
    const e = &disp.entries[@intCast(entry_id)];
    const name = switch (e.func) {
        .by_name => |n| n,
        .by_ordinal => return 0, // ординал-импорты не реализованы в v0.10
    };

    var ret: u64 = 0;
    if (std.ascii.eqlIgnoreCase(e.dll, "KERNEL32.dll")) {
        if (std.mem.eql(u8, name, "GetStdHandle")) {
            ret = getStdHandle(a1);
        } else if (std.mem.eql(u8, name, "GetCommandLineA")) {
            ret = getCommandLineA();
        } else if (std.mem.eql(u8, name, "GetCommandLineW")) {
            ret = getCommandLineW();
        } else if (std.mem.eql(u8, name, "VirtualAlloc")) {
            ret = virtualAlloc(a1, a2, a3, a4);
        } else if (std.mem.eql(u8, name, "ExitProcess")) {
            return exitProcess(a1); // не возвращает
        } else if (std.mem.eql(u8, name, "GetModuleHandleA") or std.mem.eql(u8, name, "GetModuleHandleW")) {
            ret = getModuleHandle();
        } else if (std.mem.eql(u8, name, "Sleep")) {
            ret = 0; // CDD-упрощение: без задержки (yield сделает планировщик)
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-stdio-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "__acrt_iob_func")) {
            // stdin/stdout/stderr FILE-массив: буфер в user-хипе
            // (структура FILE опакова — следующий CDD-цикл)
            ret = virtualAlloc(0, 3 * 80, 0x1000, 4);
        } else if (std.mem.eql(u8, name, "__p__fmode") or std.mem.eql(u8, name, "__p__commode")) {
            // int* __p__fmode()/__p__commode(): CRT ЗАПИСЫВАЕТ туда дефолт
            // → валидная user-память обязательна (NULL = #PF у приложения)
            ret = virtualAlloc(0, 8, 0x1000, 4);
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-runtime-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "exit") or std.mem.eql(u8, name, "_exit")) {
            return exitProcess(a1);
        }
        if (std.mem.eql(u8, name, "abort")) {
            return exitProcess(3); // abort() → выход по SIGABRT-коду
        }
        // __p___argc/__p___argv/_errno — указатели, CRT пишет/читает значение
        if (std.mem.eql(u8, name, "__p___argc") or
            std.mem.eql(u8, name, "__p___argv") or
            std.mem.eql(u8, name, "_errno"))
        {
            ret = virtualAlloc(0, 32, 0x1000, 4); // нулевой блок: argc=0, argv=NULL, errno=0
        }
        // сеттеры/инициализаторы: 0 = успех, CRT продолжает
        else if (std.mem.eql(u8, name, "_crt_atexit") or
            std.mem.eql(u8, name, "_set_app_type") or
            std.mem.eql(u8, name, "_set_invalid_parameter_handler") or
            std.mem.eql(u8, name, "_initialize_onexit_table") or
            std.mem.eql(u8, name, "_register_onexit_function") or
            std.mem.eql(u8, name, "_configure_narrow_argv") or
            std.mem.eql(u8, name, "_initialize_narrow_environment") or
            std.mem.eql(u8, name, "_initterm") or
            std.mem.eql(u8, name, "_initterm_e") or
            std.mem.eql(u8, name, "_cexit") or
            std.mem.eql(u8, name, "_seh_filter_exe"))
        {
            ret = 0;
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-heap-l1-1-0.dll")) {
        // UCRT-хип поверх нашего VirtualAlloc-региона
        if (std.mem.eql(u8, name, "malloc") or std.mem.eql(u8, name, "calloc")) {
            const want: u64 = if (std.mem.eql(u8, name, "calloc")) a1 * a2 else a1;
            if (want == 0) {
                ret = virtualAlloc(0, 16, 0x1000, 4); // malloc(0) ≠ NULL по конвенции
            } else {
                ret = virtualAlloc(0, want, 0x1000, 4);
            }
        } else if (std.mem.eql(u8, name, "free")) {
            ret = 0; // no-op: утечки допустимы в CDD-цикле №1 (страницы задачи умрут вместе с ней)
        } else if (std.mem.eql(u8, name, "_set_new_mode")) {
            ret = 0;
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-locale-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "_configthreadlocale")) {
            ret = 0; // «C»-локаль по умолчанию — индивидуальные не нужны
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else if (std.ascii.eqlIgnoreCase(e.dll, "api-ms-win-crt-environment-l1-1-0.dll")) {
        if (std.mem.eql(u8, name, "__p__environ")) {
            // char*** __p__environ(): CRT ЗАПИСЫВАЕТ туда таблицу окружения
            // → нулевой блок (пустое окружение, корректный NULL-терминатор)
            ret = virtualAlloc(0, 32, 0x1000, 4);
        } else if (std.mem.eql(u8, name, "getenv")) {
            ret = 0; // NULL = переменная не найдена (безопасный возврат)
        } else {
            logUnimplemented(e, name);
            return 0;
        }
    } else {
        logUnimplemented(e, name);
        return 0;
    }

    // Лог первого вызова каждой реализованной функции (CDD-трейс)
    e.hits += 1;
    if (e.hits == 1) {
        hal.Serial.puts("[WIN32] ");
        hal.Serial.puts(e.dll);
        hal.Serial.puts("!");
        hal.Serial.puts(name);
        hal.Serial.puts(" — OK, ret=");
        hal.Serial.putHex(ret);
        hal.Serial.puts("\n");
    }
    implemented_calls += 1;
    return ret;
}

fn logUnimplemented(e: *win32.StubEntry, name: []const u8) void {
    // сюда попадаем, только если реализованный стаб не найден в таблице
    // имён (расхождение реестра и API-уровня — баг проводки, не CDD-кейс)
    hal.Serial.puts("[WIN32] WARN: ");
    hal.Serial.puts(e.dll);
    hal.Serial.puts("!");
    hal.Serial.puts(name);
    hal.Serial.puts(" пришёл syscall'ом, но реализации нет\n");
}

/// GetModuleHandleA/W(lpModuleName): NULL → база образа; имя → тоже база
/// (CDD-прагматика: GetProcAddress на ней вернёт 0 → увидим в цепочке).
fn getModuleHandle() u64 {
    return if (ctx) |c| c.image_base else 0;
}

// ─── Реализации ─────────────────────────────────────────────────────────────

/// GetStdHandle(nStdHandle): STD_INPUT(-11)/STD_OUTPUT(-10)/STD_ERROR(-12).
/// Возвращает различимые ненулевые псевдо-хэндлы; 0 при неверном аргументе.
fn getStdHandle(n_std: u64) u64 {
    return switch (n_std & 0xFFFFFFFF) {
        0xFFFFFFF5 => FAKE_STDIN, // (DWORD)-11
        0xFFFFFFF6 => FAKE_STDOUT, // (DWORD)-10
        0xFFFFFFF4 => FAKE_STDERR, // (DWORD)-12
        else => 0, // INVALID_HANDLE_VALUE semantics не нужен CDD-циклу №1
    };
}

/// GetCommandLineA(): user-VA ANSI-строки из params-страницы процесса.
fn getCommandLineA() u64 {
    return if (ctx) |c| c.cmdline_a else 0;
}

/// GetCommandLineW(): user-VA UTF-16LE-строки.
fn getCommandLineW() u64 {
    return if (ctx) |c| c.cmdline_w else 0;
}

/// VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
/// bump-аллокатор user-страниц в контексте процесса (PMM + VMM).
/// lpAddress=NULL → курсор; иначе commit по адресу внутри хипа региона.
/// Права всегда RW+NX+USER (flProtect игнорируем — v0.10).
fn virtualAlloc(lp_address: u64, dw_size: u64, alloc_type: u64, protect: u64) u64 {
    _ = protect;
    if (dw_size == 0 or dw_size > 64 * 1024 * 1024) return 0;
    // MEM_COMMIT=0x1000, MEM_RESERVE=0x2000 — поддерживаем оба/вместе
    if (alloc_type & 0x3000 == 0) return 0;

    const c = &(ctx orelse return 0);
    const pages = (dw_size + PAGE_SIZE - 1) / PAGE_SIZE;

    var base: u64 = 0;
    if (lp_address == 0) {
        base = (c.heap_cursor + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    } else {
        // фикс-адрес: только выровненный и внутри нашего региона
        if (lp_address % PAGE_SIZE != 0) return 0;
        if (lp_address < c.heap_base or lp_address + pages * PAGE_SIZE > c.heap_limit) return 0;
        base = lp_address;
    }
    if (base + pages * PAGE_SIZE > c.heap_limit) return 0; // OOM процесса

    // Выделить и замаппить страницы (по одной: PMM contiguous не обязателен)
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const pa = pmm.allocContiguousZeroed(1) orelse return 0;
        vmm.mapPageInPML4(c.pml4, base + i * PAGE_SIZE, pa, vmm.PTE_USER | vmm.PTE_WRITABLE | vmm.PTE_NO_EXECUTE) catch return 0;
    }

    if (base + pages * PAGE_SIZE > c.heap_cursor) {
        c.heap_cursor = base + pages * PAGE_SIZE;
    }
    c.allocs += 1;
    return base;
}

/// ExitProcess(exitCode): чистое завершение PE-задачи.
/// Возврата нет: задача помечена Killed, hlt до вытеснения планировщиком.
fn exitProcess(code: u64) u64 {
    hal.Serial.puts("[WIN32] ExitProcess(0x");
    hal.Serial.putHex(code);
    hal.Serial.puts(") — PE-процесс завершился штатно\n");
    if (hal.exitCallback) |cb| cb();
    while (true) {
        asm volatile ("hlt");
    }
}
