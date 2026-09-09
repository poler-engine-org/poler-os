// ============================================================================
// POLER-OS HAL (Hardware Abstraction Layer) — x86_64
// ============================================================================
// ISR stubs: isr64.S (assembly) → isr_common_handler() (this file)

// Timer tick callback — registered by scheduler at init
// Breaks circular dependency: hal.zig ↔ scheduler.zig
pub var timerTickCallback: ?*const fn (u64) callconv(.C) u64 = null;

// Multi-pool hardware entropy callbacks (Spec §1-2)
pub var irq_entropy_sink: ?*const fn (u64) void = null; // IRQ pool (APIC timer / hardware interrupt intervals)
pub var bio_entropy_sink: ?*const fn (u64) void = null; // Bio pool (keystroke interval bio-dynamics)
/// v0.16.0 (CDD №7): IRQ Network Worker — pollRx() + TCP-таймеры из тика
/// APIC-таймера (retрансмиты/keep-alive/ACKи при молчащем Ring 3).
/// Обнуляется до NULL; main64 вешает virtio_net.pollRx после init драйвера.
pub var net_irq_sink: ?*const fn () void = null;
/// v0.17.0 (CDD №8): virtio-blk IRQ (вектор 49) — пробуждение ждущих запросов
/// (поллинг в waitForCompletion остаётся как fallback — IRQ ускоряет обмен).
pub var blk_irq_sink: ?*const fn () callconv(.C) void = null;

// Simple spinlock for protecting shared resources (e.g. serial output)
pub var serial_lock: u32 = 0;

pub fn spinLock(lock: *u32) void {
    while (@atomicRmw(u32, lock, .Xchg, 1, .acquire) != 0) {
        asm volatile ("pause");
    }
}

pub fn spinUnlock(lock: *u32) void {
    _ = @atomicRmw(u32, lock, .Xchg, 0, .release);
}
// ============================================================================

// No std import — freestanding kernel

// ============================================================================
// CPU INSTRUCTIONS
// ============================================================================

pub fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outw(port: u16, val: u16) void {
    asm volatile ("outw %[val], %[port]"
        :
        : [val] "{ax}" (val),
          [port] "{dx}" (port),
    );
}

pub fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "{dx}" (port),
    );
}

// ─── v0.16.0 (CDD №7): CMOS RTC — реальное wall-clock время ───────────────

/// Чтение регистра MC146818 (index-порт 0x70, data-порт 0x71).
fn rtcReg(reg: u8) u8 {
    outb(0x70, reg);
    return inb(0x71);
}

/// v0.20.0 (CDD №12 p1): общий RAM-размер из CMOS (PVH-бут без MB2-карты).
/// QEMU/Bochs заполняет: 0x34/0x35 — память ВЫШЕ 16МБ в 64КБ-единицах
/// ((ram_size-16МБ)/64КБ); 0x30/0x31 — выше 1МБ в КБ (кэп 63МБ).
/// Возврат: байты RAM (0 — CMOS пуст/мусор).
pub fn cmosRamSize() u64 {
    const ext16_hi = rtcReg(0x35);
    const ext16_lo = rtcReg(0x34);
    const ext16: u64 = (@as(u64, ext16_hi) << 8) | ext16_lo;
    if (ext16 != 0) {
        // 16МБ + N×64КБ (QEMU -m 512M → 16 + 496МБ)
        return 16 * 1024 * 1024 + ext16 * 64 * 1024;
    }
    // малый RAM: 1МБ + N КБ (кэп 64МБ)
    const ext_hi = rtcReg(0x31);
    const ext_lo = rtcReg(0x30);
    const ext_kb: u64 = (@as(u64, ext_hi) << 8) | ext_lo;
    if (ext_kb != 0) {
        return 1024 * 1024 + ext_kb * 1024;
    }
    return 0;
}

fn bcdToBin(v: u8) u8 {
    return (v & 0x0F) + (v >> 4) * 10;
}

/// Дней от Unix-эпохи до даты (алгоритм Howard Hinnant days_from_civil).
fn daysFromCivil(y: i64, m: u32, d: u32) i64 {
    const yy: i64 = if (m <= 2) y - 1 else y;
    const era: i64 = @divFloor(yy, 400);
    const yoe: i64 = yy - era * 400; // [0, 399]
    const mp: i64 = @mod(@as(i64, m) + 9, 12); // [0, 11]
    const doy: i64 = @divFloor(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// Wall-clock время (Unix-секунды UTC) из CMOS RTC. QEMU подаёт время
/// хоста — TLS-верификация (notBefore/notAfter сертификатов) требует
/// живую дату: фиксированный 2026-01-01 из v0.12 давал «not yet valid (9)»
/// на свежевыпущенных сертификатах example.com. Фолбэк при битом RTC — 0
/// (вызывающие деградируют на прежнюю статику).
pub fn rtcUnixTime() u64 {
    // 1) дождаться конца update-in-progress (бит 7 регистра A)
    var guard: u32 = 0;
    while (guard < 200_000) : (guard += 1) {
        outb(0x70, 0x0A);
        if (inb(0x71) & 0x80 == 0) break;
    }
    // 2) стабильное чтение: два прохода обязаны совпасть (тикающая секунда)
    var tries: u32 = 0;
    while (tries < 4) : (tries += 1) {
        const sec = rtcReg(0x00);
        const min = rtcReg(0x02);
        const hour = rtcReg(0x04);
        const day = rtcReg(0x07);
        const mon = rtcReg(0x08);
        const year = rtcReg(0x09);
        const cent = rtcReg(0x32);
        const stb = rtcReg(0x0B);
        if (rtcReg(0x00) != sec) continue; // секунда тикнула — перечитаем

        const binary = stb & 0x04 != 0;
        const bcd = struct {
            fn f(v: u8, bin: bool) u32 {
                return if (bin) v else bcdToBin(v);
            }
        }.f;
        var h: u32 = bcd(hour & 0x7F, binary);
        if (stb & 0x02 == 0) { // 12-часовой режим: бит 0x80 = PM
            if (hour & 0x80 != 0) {
                h = if (h == 12) 12 else h + 12;
            } else if (h == 12) {
                h = 0;
            }
        }
        const s: u32 = bcd(sec, binary);
        const mi: u32 = bcd(min, binary);
        const d: u32 = bcd(day, binary);
        const mo: u32 = bcd(mon, binary);
        const yr: u32 = bcd(year, binary);
        const cy: u32 = bcd(cent, binary);
        const full_year: i64 = @as(i64, cy) * 100 + @as(i64, yr);
        if (mo < 1 or mo > 12 or d < 1 or d > 31 or s > 59 or mi > 59 or h > 23) continue;
        if (full_year < 2000 or full_year > 2100) continue; // битый century
        const days = daysFromCivil(full_year, mo, d);
        const unix: i64 = days * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + @as(i64, s);
        return @intCast(@max(unix, 0));
    }
    return 0; // RTC не читается — вызывающие деградируют на статику
}

pub fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

pub fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

pub fn cli() void {
    asm volatile ("cli");
}

pub fn sti() void {
    asm volatile ("sti");
}

/// v0.17.0-fix (CDD №8 p5): чтение IF — крит-секции должны СОХРАНЯТЬ
/// состояние прерываний, а не безусловно sti() (урок: heap-аллокатор
/// из IRQ-обработчика (timer→net-worker→kmalloc) возвращался с IF=1 —
/// pop-фаза ISR шла с открытыми прерываниями → вложенный тик сохранял
/// tasks[Y].rsp кадром на ЧУЖОМ стеке (WARN «rsp вне», застой curl).
pub fn interruptsEnabled() bool {
    const f: u64 = asm volatile ("pushfq; popq %[out]"
        : [out] "=r" (-> u64),
    );
    return (f & 0x200) != 0;
}

pub fn hlt() void {
    asm volatile ("hlt");
}

pub fn ltr(selector: u16) void {
    asm volatile ("ltr %[sel]"
        :
        : [sel] "{ax}" (selector),
    );
}

pub fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[val]"
        : [val] "=r" (-> u64),
    );
}

pub fn writeCr3(val: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (val),
        : "memory"
    );
}

pub fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub fn writeMsr(msr: u32, val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(val))),
          [high] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

// ============================================================================
// MSR Constants
// ============================================================================

pub const MSR = struct {
    pub const EFER = 0xC0000080;
    pub const STAR = 0xC0000081;
    pub const LSTAR = 0xC0000082;
    pub const CSTAR = 0xC0000083;
    pub const SFMASK = 0xC0000084;
    pub const FS_BASE = 0xC0000100;
    pub const GS_BASE = 0xC0000101;
    pub const KERNEL_GS_BASE = 0xC0000102;
};

pub const EFER = struct {
    pub const SCE = 1 << 0;  // System Call Extensions
    pub const LME = 1 << 8;  // Long Mode Enable
    pub const LMA = 1 << 10; // Long Mode Active
    pub const NXE = 1 << 11; // No-Execute Enable
};

// ============================================================================
// GDT (Global Descriptor Table)
// ============================================================================

pub const GDT = struct {
    pub const Entry = packed struct {
        limit_low: u16,
        base_low: u24,
        type: u4,
        s: u1,
        dpl: u2,
        p: u1,
        limit_high: u4,
        avl: u1,
        l: u1,
        d: u1,
        g: u1,
        base_high: u8,
    };

    pub const Ptr = packed struct {
        limit: u16,
        base: u64,
    };

    pub const TSSDesc = packed struct {
        low: u64,
        high: u64,
    };

    pub const NUM_ENTRIES = 7; // null + kcode + kdata + ucode + udata + tss_low + tss_high

    var entries: [NUM_ENTRIES]u64 = undefined;
    var ptr: Ptr = undefined;

    pub fn init() void {
        Serial.puts("[GDT] entries address: ");
        Serial.putHex(@intFromPtr(&entries));
        Serial.puts("\n");

        // Entry 0: Null
        entries[0] = 0;

        // Entry 1: 64-bit Kernel Code (ring 0) — matches GRUB's CS=0x08
        entries[1] = 0x00209A0000000000;

        // Entry 2: 64-bit Kernel Data (ring 0) — matches GRUB's DS=0x10
        // SYSCALL loads SS = STAR[47:32]+8 = 0x08+8 = 0x10 ✓
        entries[2] = 0x0000920000000000;

        // v0.10.0 CRITICAL FIX — классическая раскладка для SYSRET:
        // SYSRET: CS = STAR[63:48]+16, SS = STAR[63:48]+8 (ОБЕ от STAR[63:48]!).
        // STAR[63:48]=0x10 → sysret CS=0x20, SS=0x18. Значит:
        //   entry 3 (0x18) ОБЯЗАН быть User DATA,
        //   entry 4 (0x20) ОБЯЗАН быть User CODE.
        // (До фикса было наоборот → sysret грузил CS=0x23=DATA и SS=0x1B=CODE;
        //  первый же iretq из Ring-3 int3 ловил #GP(0x20) — селектор данных в CS.)

        // Entry 3: 64-bit User Data (ring 3) — sysretq SS = 0x18|3 = 0x1B
        entries[3] = 0x0000F20000000000;

        // Entry 4: 64-bit User Code (ring 3) — sysretq CS = 0x20|3 = 0x23
        entries[4] = 0x0020FA0000000000;

        // Entries 5-6: TSS (filled by setTSS)
        entries[5] = 0;
        entries[6] = 0;

        // Load our GDT — GRUB's selectors (0x08, 0x10) are compatible
        var gdt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u64) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        gdt_ptr[0] = @truncate(limit);
        gdt_ptr[1] = @truncate(limit >> 8);
        gdt_ptr[2] = @truncate(base);
        gdt_ptr[3] = @truncate(base >> 8);
        gdt_ptr[4] = @truncate(base >> 16);
        gdt_ptr[5] = @truncate(base >> 24);
        gdt_ptr[6] = @truncate(base >> 32);
        gdt_ptr[7] = @truncate(base >> 40);
        gdt_ptr[8] = @truncate(base >> 48);
        gdt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lgdt (%[p])"
            :
            : [p] "r" (@intFromPtr(&gdt_ptr)),
        );

        // DON'T reload segment registers — GRUB already set them correctly
        // and our GDT layout matches GRUB's (0x08=code, 0x10=data).
        // Reloading DS/SS with 0x10 is safe but unnecessary.
    }

    pub fn setTSS(cpu: u32, base: u64, limit: u64) void {
        _ = cpu;
        const entry_idx: usize = 5; // TSS starts at entry 5

        const base_low = base & 0xFFFFFF;
        const base_mid = (base >> 24) & 0xFF;
        const base_high = (base >> 32) & 0xFFFFFFFF;

        // TSS low 8 bytes
        entries[entry_idx] = (limit & 0xFFFF) |
            ((base_low & 0xFFFFFF) << 16) |
            (0x89 << 40) | // Present, TSS type
            ((limit >> 16) << 48) |
            (@as(u64, base_mid) << 56);

        // TSS high 8 bytes
        entries[entry_idx + 1] = base_high;
    }
};

// ============================================================================
// IDT (Interrupt Descriptor Table)
// ============================================================================

pub const InterruptFrame = packed struct {
    r15: u64, r14: u64, r13: u64, r12: u64,
    r11: u64, r10: u64, r9: u64, r8: u64,
    rdi: u64, rsi: u64, rbp: u64,
    rdx: u64, rcx: u64, rbx: u64, rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64, cs: u64, rflags: u64, rsp: u64, ss: u64,
};

const GateType = enum(u4) {
    interrupt = 0xE,
    trap = 0xF,
};

pub const IDT = struct {
    pub const NUM_ENTRIES = 256;

    pub var entries: [NUM_ENTRIES]u128 = undefined;
    var ptr: packed struct { limit: u16, base: u64 } = undefined;

    // ISR stub table — linker-provided bounds of .rodata.isr_table section
    // LLD may resolve isr_stub_table to the wrong address, so we use
    // linker symbols __isr_table_start / __isr_table_end instead.
    pub extern const __isr_table_start: u8;
    pub extern const __isr_table_end: u8;

    pub fn init() void {
        // Read the ISR table from the linker-defined section bounds
        const table_start: u64 = @intFromPtr(&__isr_table_start);
        const table_end: u64 = @intFromPtr(&__isr_table_end);
        const num_entries = (table_end - table_start) / 8;

        for (0..num_entries) |i| {
            const ptr_arr: [*]const u64 = @ptrFromInt(table_start);
            const handler: u64 = ptr_arr[i];
            if (handler > 0x100000 and i < 50) { // v0.17.0 (CDD №8): 50 = векторы 0..49 (49 = virtio-blk IRQ)
                const dpl: u8 = if (i == 3) 3 else 0;
                // v0.7.0: Use IST1 for Double Fault (vector 8)
                const ist: u3 = if (i == 8) 1 else 0;
                setGate(@intCast(i), .interrupt, handler, 0x08, dpl, ist);
            }
        }

        // Load IDT using raw 10-byte descriptor (2 bytes limit + 8 bytes base)
        var idt_ptr: [10]u8 = undefined;
        const limit: u16 = @intCast(@sizeOf(u128) * NUM_ENTRIES - 1);
        const base: u64 = @intFromPtr(&entries);
        // Little-endian: limit (2 bytes) then base (8 bytes)
        idt_ptr[0] = @truncate(limit);
        idt_ptr[1] = @truncate(limit >> 8);
        idt_ptr[2] = @truncate(base);
        idt_ptr[3] = @truncate(base >> 8);
        idt_ptr[4] = @truncate(base >> 16);
        idt_ptr[5] = @truncate(base >> 24);
        idt_ptr[6] = @truncate(base >> 32);
        idt_ptr[7] = @truncate(base >> 40);
        idt_ptr[8] = @truncate(base >> 48);
        idt_ptr[9] = @truncate(base >> 56);
        asm volatile ("lidt (%[p])"
            :
            : [p] "r" (@intFromPtr(&idt_ptr)),
        );
    }

    fn setGate(vector: u8, gate_type: GateType, handler: u64, selector: u16, dpl: u8, ist: u3) void {
        const low: u64 =
            (handler & 0x0000FFFF) | // Offset low
            (@as(u64, selector) << 16) | // Selector
            (@as(u64, ist) << 32) | // IST (v0.7.0: IST1 for #DF)
            (@as(u64, @intFromEnum(gate_type)) << 40) | // Type
            (@as(u64, dpl) << 45) | // DPL
            (@as(u64, 1) << 47) | // Present
            ((handler >> 16) & 0xFFFF) << 48; // Offset mid

        const high: u64 = handler >> 32; // Offset high

        entries[vector] = (@as(u128, high) << 64) | @as(u128, low);
    }
};

/// Idle loop for after a user-mode fault.
/// When a user process causes a CPU exception (e.g., page fault, GP fault),
/// the exception handler kills the task and redirects IRETQ here.
/// This function simply halts the CPU and waits for the next interrupt
/// (APIC timer tick), which will trigger the scheduler to pick a Ready task.
pub fn idle_after_fault() callconv(.C) noreturn {
    while (true) {
        hlt();
    }
}

// ============================================================================
// ISR Common Handler — called from isr64.S isr_common
// ============================================================================

// CDD №12 p12: ПОЛНЫЙ FPU-КОНТЕКСТ ЗАДАЧИ (x87 + MXCSR + XMM + YMM).
//
// p11 закрыл XMM-калечение через exception/syscall-пути, НО остались ТРИ
// ДЫРЫ (все — источники флаки-порчи guest-состояния):
//   (1) ГЛОБАЛЬНОСТЬ буферов: паркуясь в futex/epoll hlt-loop (глубина
//       syscall-хендлера), задача A возобновляется и восстанавливает ЧУЖОЙ
//       XMM — syscall задачи B перезаписал общий .bss-буфер за время парка
//       (эмпирика p11: «futex-парковки всё равно теряют XMM»).
//   (2) schedule() НЕ сохранял FPU ВООБЩЕ: задача, вытесненная в userspace
//       посреди векторного кода, продолжала после iretq с регистрами ДРУГОЙ
//       задачи (AVX включён: XCR0=0x207 + QEMU -cpu max, v3-сборки CachyOS
//       юзают YMM0-15 в горячих циклах llvmpipe!).
//   (3) IRQ-путь (вектор >= 32) не сохранял FPU → прерывание mid-memset
//       ядерного Zig-каскада калечило живой XMM-скретч обработчика.
//
// РЕШЕНИЕ — ЕДИНЫЙ fpuSave/fpuRestore с XSAVE (маска 0x7: x87|SSE|AVX,
// область 832Б = 512 legacy + 64 header + 256 YMM, выравнивание 64):
//   • SYSCALL-путь: СТЕК-ЛОКАЛ на kstack владельца — переживает парковку
//     (контент лежит на стеке ЗАДАЧИ, не в глобале), per-nesting;
//   • EXCEPTION-путь: стек-локал кадра — вложенность #PF-в-#PF безопасна
//     (каждое вхождение = свой кадр; p11-допущение «IF=0 ⇒ нет вложенности»
//     ошибочно: IF=0 блокирует только МАСКИРУЕМЫЕ прерывания, не #PF!);
//   • IRQ-путь: вход — сейв в Task.fpu прерываемого (ДО любого SSE-кода
//     хендлера, включая структурные копии), хвост — реставр Task.fpu
//     задачи-АДРЕСАТА iretq (свич и не-свич — единая формула).
// Нулевой слот: XSTATE_BV=0 → XRSTOR выставляет INIT-состояние (FCW=0x037F,
// MXCSR=0x1F80, XMM/YMM=0) — каноника для новорождённых задач/glibc.
// Fallback без XSAVE (CPU без AVX): movups XMM0-15 в первые 256Б той же
// области (раскладка кадра kstack НЕ меняется — asm-пути не тронуты).
// Известный остаток: Zig-вызовы R15-детекторов в asm-хвосте (редкий
// already-poison путь) могут калечить FPU ПОСЛЕ реставра — состояние и так
// отравлено, детокция дороже.

/// Размер XSAVE-области (x87|SSE|AVX): 512 legacy + 64 header + 256 YMM.
pub const FPU_AREA_SIZE: usize = 832;

comptime {
    // p12-ФИКС4: $104 в rep stosq (fpuSave) = FPU_AREA_SIZE/8 qword'ов.
    if (FPU_AREA_SIZE != 832) @compileError("FPU_AREA_SIZE изменился — обнови $104 в rep stosq fpuSave!");
}

/// XSAVE доступен (boot64.S включил OSXSAVE+XCR0=0x207 при наличии AVX).
/// Детект в initSyscalls; false → movups-фолбэк (SSE-only).
pub var xsave_enabled: bool = false;

/// CDD №12 p12-БИСЕКТ: гейт IRQ-пути FPU (вход-сейв/хвост-реставр).
/// true = полный p12; false = IRQ-путь выключен (изоляция подозреваемого).
pub var p12_irq_fpu: bool = true;

/// CDD №12 p12-ТРИПВАЙР: слот [top-176] задачи (ISR-кадр r15). Пишет
/// магику арматура (registerKstack), pollит handleIRQ-вход. Появление
/// 0xAAAA = поимка коррупции: дамп контекста прерываемого (RIP кадра =
/// вероятный писатель!) + halt для сбора краш-лога e2e.
pub var p12_watch_addr: u64 = 0;
pub var p12_watch_magic: u64 = 0x5A12C0DE_5A12C0DE;
pub var p12_watch_hits: u32 = 0;

/// Сейв полного FPU-контекста (x87+MXCSR+XMM+YMM) в 832Б-область.
/// Слот обязан быть 64Б-выровнен (xsave с AVX-компонентой).
pub inline fn fpuSave(slot: *[FPU_AREA_SIZE]u8) void {
    if (xsave_enabled) {
        // CDD №12 p12-ФИКС (host-репро xsave-test): XSAVE пишет ТОЛЬКО
        // non-init компоненты (XINUSE-оптимизация) — биты/образы init-
        // компонент ОСТАЮТСЯ как есть в памяти (Zig-Debug 0xAA-фон /
        // стейл прошлого вытеснения) ⇒ XRSTOR читает мусорный FCW/MXCSR/
        // FSW → #GP(0). Зануление ДО xsave: init-компоненты получают
        // нулевой образ + BV-бит 0 (честный INIT на реставре) — ровно
        // дизайн XSAVE. Эмпирика без этого: #GP @ xrstor на ПЕРВОМ
        // syscall (init-FPU) в zig_syscall_handler.
        // p12-ФИКС4: зануление ТОЛЬКО GPR (rep stosq) — @memset
        // компилируется в SSE-бродкаст (movd/pshufd XMM0 + movdqu) и
        // ЗАТИРАЕТ XMM0 ДО xsave ⇒ сейв всегда нулевой ⇒ рестарт-стор
        // #PF пишет нули на JIT-страницу (11 нулевых байт — корень
        // p12-регрессии; эмпирика Run A/fix3: краш @989 syscall сразу
        // после mprotect-RX; дизассембл memset @0x23f880).
        asm volatile (
            \\cld
            \\xor %eax, %eax
            \\mov $104, %ecx
            \\mov %[p], %rdi
            \\rep stosq
            :
            : [p] "r" (@as([*]u8, slot))
            : "rax", "rcx", "rdi", "memory"
        );
        asm volatile (
            \\mov $7, %eax
            \\xor %edx, %edx
            \\xsave (%[p])
            :
            : [p] "r" (@as([*]u8, slot))
            : "rax", "rdx", "memory"
        );
    } else {
        asm volatile (
            \\movups %%xmm0,  0(%[b])
            \\movups %%xmm1,  16(%[b])
            \\movups %%xmm2,  32(%[b])
            \\movups %%xmm3,  48(%[b])
            \\movups %%xmm4,  64(%[b])
            \\movups %%xmm5,  80(%[b])
            \\movups %%xmm6,  96(%[b])
            \\movups %%xmm7,  112(%[b])
            \\movups %%xmm8,  128(%[b])
            \\movups %%xmm9,  144(%[b])
            \\movups %%xmm10, 160(%[b])
            \\movups %%xmm11, 176(%[b])
            \\movups %%xmm12, 192(%[b])
            \\movups %%xmm13, 208(%[b])
            \\movups %%xmm14, 224(%[b])
            \\movups %%xmm15, 240(%[b])
            :
            : [b] "r" (@as([*]u8, slot))
            : "memory"
        );
    }
}

/// Реставр полного FPU-контекста из 832Б-области.
/// XSTATE_BV=0 (нулевой слот) → XRSTOR ставит INIT-состояние компонент.
pub inline fn fpuRestore(slot: *const [FPU_AREA_SIZE]u8) void {
    if (xsave_enabled) {
        asm volatile (
            \\mov $7, %eax
            \\xor %edx, %edx
            \\xrstor (%[p])
            :
            : [p] "r" (@as([*]const u8, slot))
            : "rax", "rdx", "memory"
        );
    } else {
        asm volatile (
            \\movups  0(%[b]), %%xmm0
            \\movups 16(%[b]), %%xmm1
            \\movups 32(%[b]), %%xmm2
            \\movups 48(%[b]), %%xmm3
            \\movups 64(%[b]), %%xmm4
            \\movups 80(%[b]), %%xmm5
            \\movups 96(%[b]), %%xmm6
            \\movups 112(%[b]), %%xmm7
            \\movups 128(%[b]), %%xmm8
            \\movups 144(%[b]), %%xmm9
            \\movups 160(%[b]), %%xmm10
            \\movups 176(%[b]), %%xmm11
            \\movups 192(%[b]), %%xmm12
            \\movups 208(%[b]), %%xmm13
            \\movups 224(%[b]), %%xmm14
            \\movups 240(%[b]), %%xmm15
            :
            : [b] "r" (@as([*]const u8, slot))
            : "memory"
        );
    }
}

/// CDD №12 p12: физический владелец kstack по адресу (скан 8 слотов
/// kstack_lo/hi_tab; task 0 — бут-стек [0x108000,0x10C000)). null = адрес
/// вне всех kstack (IST/#DF/ранний бут — FPU-сейв пропускаем симметрично).
fn kstackOwnerByAddr(addr: u64) ?usize {
    const sched = @import("scheduler.zig");
    var i: usize = 0;
    while (i < sched.MAX_TASKS) : (i += 1) {
        if (sched.kstack_hi_tab[i] != 0 and
            addr >= sched.kstack_lo_tab[i] and addr < sched.kstack_hi_tab[i])
        {
            return i;
        }
    }
    return null;
}

pub export fn isr_common_handler(frame: *InterruptFrame) callconv(.C) *InterruptFrame {
    if (frame.vector < 32) {
        // CDD №12 p12-ФИКС5: ПЕР-ТАСК .bss-СТРОКА (глубина 2) — НЕ стек-локал!
        // Zig-Debug ОБЯЗАН 0xAA-филлить undefined-локаль (SSE-memset:
        // дизассембл mov $0xaa,%esi; mov $0x340,%edx; call memset) — филл
        // затирал XMM0 ДО xsave ⇒ exception-сейв сохранял мусор ⇒ юзер
        // получал отравленный XMM0 (рестарт-стор = яд на JIT-страницу).
        // Строки .bss статически нулевые: филла нет, BV=0 → xrstor INIT.
        // Вне kstack-таблиц (IST/#DF/ранний бут) — fallback-буфер.
        const sched = @import("scheduler.zig");
        const exc_owner = kstackOwnerByAddr(@intFromPtr(frame));
        var exc_slot: *[FPU_AREA_SIZE]u8 = &sched.exc_fpu_fallback;
        var exc_pushed = false;
        if (exc_owner) |o| {
            const d = sched.exc_fpu_depth[o];
            if (d < 2) {
                sched.exc_fpu_depth[o] = d + 1;
                exc_pushed = true;
            }
            exc_slot = &sched.exc_fpu_frame[o][@min(d, @as(u8, 1))];
        }
        fpuSave(exc_slot);
        handleException(frame);
        fpuRestore(exc_slot);
        if (exc_pushed) {
            if (exc_owner) |o| {
                sched.exc_fpu_depth[o] -= 1;
            }
        }
        return frame;
    } else {
        return handleIRQ(frame);
    }
}

pub var tick_count: u64 = 0;

/// CDD №12 p9: счётчик отбраковок FRAME-CONTENT-GUARD (анти-спам-гейт).
pub var p9_guard_drops: u64 = 0;

fn handleIRQ(frame: *InterruptFrame) *InterruptFrame {
    // CDD №12 p12: FPU-СЕЙВ ПРЕРЫВАННОГО КОНТЕКСТА — самое первое заявление
    // (ДО структурной копии `var next_frame = frame` — Zig компилирует её в
    // SSE-movups!). Прерываемый контекст: userspace-задача с живыми XMM/YMM
    // (векторный код v3) ИЛИ ядерный Zig-каскад посреди memset (sti-окно
    // syscall-хендлера — закрытие дыры mid-memset). Владелец — по kstack,
    // на котором физически лежит кадр прерывания (скан 8 слотов).
    var exit_frame_addr: u64 = @intFromPtr(frame);
    const irq_fpu_owner = if (p12_irq_fpu) kstackOwnerByAddr(@intFromPtr(frame)) else null;
    if (irq_fpu_owner) |o| {
        fpuSave(&@import("scheduler.zig").tasks[o].fpu);
    }

    // CDD №12 p12-ТРИПВАЙР: poll слота. 100Гц-гранулярность; поймали
    // 0xAAAA → контекст прерываемого (RIP кадра) = писатель-окрестность.
    // НЕ-магические записи = НОРМА (пуш r15 кадра при каждой преэмпции
    // task-3 из userspace) — печатаем первые 3 (трассировка), не копим.
    if (p12_watch_addr != 0 and p12_watch_hits < 100) {
        const v: u64 = @as(*volatile u64, @ptrFromInt(p12_watch_addr)).*;
        if (v == 0xAAAAAAAAAAAAAAAA) {
            p12_watch_hits = 100; // поймано — больше не pollим
            Serial.puts("[P12-TRIPWIRE] 0xAAAA ПОЙМАН @0x");
            Serial.putHex(p12_watch_addr);
            Serial.puts(" tick=");
            Serial.putDecimal(tick_count);
            Serial.puts(" cur=");
            Serial.putDecimal(@import("scheduler.zig").current_task_id);
            Serial.puts(" in_sys=");
            Serial.putDecimal(@import("scheduler.zig").in_win32_syscall);
            Serial.puts(" frame.rip=0x");
            Serial.putHex(frame.rip);
            Serial.puts(" frame.cs=0x");
            Serial.putHex(frame.cs);
            Serial.puts(" frame.rsp=0x");
            Serial.putHex(frame.rsp);
            Serial.puts(" frame.r15=0x");
            Serial.putHex(frame.r15);
            Serial.puts("\n");
            // p12-ФИКС3-верификация: печатаем и ЖИВЁМ ( фикс обязан
            // исключить появление 0xAAAA; если появился — детектор виден)

        } else if (v != p12_watch_magic and p12_watch_hits < 3) {
            p12_watch_hits += 1;
            Serial.puts("[P12-TRIPWIRE] слот переписан (не магика): val=0x");
            Serial.putHex(v);
            Serial.puts(" от writer-контекста rip=0x");
            Serial.putHex(frame.rip);
            Serial.puts(" cs=0x");
            Serial.putHex(frame.cs);
            Serial.puts(" tick=");
            Serial.putDecimal(tick_count);
            Serial.puts("\n");
        }
    }
    var next_frame = frame;

    // CRITICAL: Send APIC EOI BEFORE scheduler callback.
    // If we don't, the APIC won't deliver the next timer interrupt,
    // and the system hangs after the first context switch.
    if (frame.vector >= 48 and APIC.base_addr != 0) {
        APIC.sendEOI();
    }

    // Also send APIC EOI for PIC vectors if APIC is active
    if (APIC.base_addr != 0 and frame.vector >= 32 and frame.vector < 48) {
        APIC.sendEOI();
    }

    // Send PIC EOI for hardware interrupts (IRQ0-15 = vectors 32-47)
    if (frame.vector >= 32 and frame.vector < 48) {
        PIC.sendEOI(@intCast(frame.vector - 32));
    }

    const irq_tsc = readMsr(0x10);
    if (irq_entropy_sink) |sink| {
        sink(irq_tsc ^ (@as(u64, frame.vector) << 32));
    }

    switch (frame.vector) {
        48 => {
            // APIC Timer tick — scheduler preemption
            tick_count += 1;
            // DEBUG: first tick confirmation
            if (tick_count == 1) {
                Serial.puts("[HAL] First APIC timer tick received!\n");
            }
            // CDD №15 p4: [URIP] — сэмпл user-RIP прерываемого контекста
            // (каждый 100-й тик; только user-кадры cs&3≠0). Ловит СПИН-
            // петли в user-коде БЕЗ syscall'ов: эмпирика p4 — Xwayland
            // 41/41 сэмплов на ld.so+0xF41E = вечный тихий #PF-цикл
            // (demand-zero клал карту в чужое PML4); без URIP фронт
            // невидим (syscall-трейс чист — «процесс работает»).
            if (tick_count % 50 == 0) {
                pageWatch(); // p4-forensics (тротл: 2Гц, только переходы)
            }
            if (tick_count % 100 == 0 and (frame.cs & 0x3) != 0) {
                Serial.puts("[URIP] cur=");
                Serial.putDecimal(@import("scheduler.zig").current_task_id);
                Serial.puts(" rip=0x");
                Serial.putHex(frame.rip);
                Serial.puts("\n");
            }
            if (timerTickCallback) |cb| {
                // v0.13.0-fix (КРИТИЧНО, CDD №4): переключение задач —
                // АТОМАРНАЯ секция. Раньше cb() (schedule) исполнялся с IF=1
                // (тик прерывал syscall-обработчик после его sti()) — и
                // МЕДЛЕННАЯ печать "[SCHED] tick/Switching…" пропускала
                // СЛЕДУЮЩИЙ тик (10мс, serial): вложенный schedule менял
                // current_task_id/TSS.rsp0 ПОСРЕДИ внешнего переключения,
                // а внешний продолжал возвращать СВОЙ кадр → IRETQ в кадр
                // от состояния другого тика → задачи на ЧУЖИХ стеках,
                // tasks[].rsp=0/мусор, kernel-panic @ptrFromInt (лаг v0.12).
                // cli(): вложенный тик ждёт; IRETQ восстановит IF из кадра.
                // Дополнительно: кадр обязан быть ненулевым и 8-выровнен.
                // v0.16.0-fix (CDD №7): IRQ Network Worker — ВНУТРИ атомарной
                // секции (до cb), но НЕ на каждом тике: сервис 10 Гц (каждый
                // 10-й тик) — RTX-бэкофф 200мс/KA 1с дыхают с запасом, а
                // 100-Гц pollRx под TCG отъедал CPU у Ring-3 крипты (сервер
                // успевал FIN до нашего Finished — bad decrypt-подобный обрыв).
                // v0.18.0 (CDD №9, бисект-инструментация): вход тика —
                // сверка кадра против cur/TSS/cks (внутри cli, до nsink).
                // Ловим «кадр на чужом стеке при cur=X» вживую.
                {
                    const sched = @import("scheduler.zig");
                    if (sched.dbg_sched_trace) {
                        Serial.puts("[T] f=0x");
                        Serial.putHex(@intFromPtr(frame));
                        Serial.puts(" cur=");
                        Serial.putDecimal(sched.current_task_id);
                        Serial.puts(" tss=0x");
                        Serial.putHex(tss_rsp0_mirror);
                        Serial.puts(" cks=0x");
                        Serial.putHex(sched.current_kernel_stack);
                        Serial.puts(" fl=");
                        Serial.putDecimal(sched.in_win32_syscall);
                        Serial.puts("\n");
                    }
                }
                cli();
                if (net_irq_sink) |nsink| {
                    if (tick_count % 10 == 0) nsink();
                }
                const next_rsp = cb(@intFromPtr(frame));
                if (next_rsp != 0 and next_rsp & 7 == 0) {
                    // CDD №12 p9: FRAME-CONTENT-GUARD — контент-валидация
                    // кадра ДО переключения. Эмпирика p9run3/7 (R15-POISON
                    // n=1, slot=0x362028 = tasks[2].rsp=STALE-initial
                    // 0x362020): диспетчер выбирал задачу с ПРОТАРЕВШИМ
                    // tasks[].rsp → iretq-каскад «восстанавливал» R15=
                    // 0xAAAAAAAA из Zig-undefined зон кstack → гость
                    // #GP в спискоходе (gamescope+0xC2FB1, r15=0xAAAA).
                    // ЛЕЧЕНИЕ: кадр с мусорным CS/RIP/RSP (content-valid
                    // из sched_resume — kernel 0x08/0x10, user 0x23/0x1B,
                    // канонические RIP/RSP) = НЕ переключаемся — гость не
                    // получает ядовитый регистровый поток.
                    if (@import("sched_resume.zig").frameContentValid(next_rsp)) {
                        next_frame = @ptrFromInt(next_rsp);
                        exit_frame_addr = next_rsp;
                    } else {
                        p9_guard_drops += 1;
                        if (p9_guard_drops <= 8) {
                            Serial.puts("[P9-FRAME-GUARD] кадр 0x");
                            Serial.putHex(next_rsp);
                            Serial.puts(" мусорен (cs=0x");
                            const csp: *volatile u64 = @ptrFromInt(next_rsp + 144);
                            Serial.putHex(csp.*);
                            Serial.puts(" rip=0x");
                            const ripp: *volatile u64 = @ptrFromInt(next_rsp + 136);
                            Serial.putHex(ripp.*);
                            Serial.puts(") — no switch, cur=");
                            Serial.putDecimal(@import("scheduler.zig").current_task_id);
                            Serial.puts("\n");
                        }
                    }
                } else {
                    // 0/мусор = битый кадр (state-расхождение или порча) —
                    // остаёмся в текущем кадре; паники @ptrFromInt нет.
                    Serial.puts("[HAL] tick: rsp=0x");
                    Serial.putHex(next_rsp);
                    Serial.puts(" invalid (frame=0x");
                    Serial.putHex(@intFromPtr(frame));
                    Serial.puts(" cur_task=");
                    Serial.putDecimal(@import("scheduler.zig").current_task_id);
                    Serial.puts(" kstack=0x");
                    Serial.putHex(@import("scheduler.zig").current_kernel_stack);
                    Serial.puts(") — no switch\n");
                }
            }
        },
        33 => {
            // Bio-пул: единственная энтропия — момент нажатия (TSC).
            // ВНИМАНИЕ: port 0x60 читает ТОЛЬКО handleKeyboard — чтение 8042
            // output buffer потребляет сканкод. Кража байта здесь ломала
            // всю клавиатуру (v0.7.2 regression, fixed in v0.7.3).
            if (bio_entropy_sink) |bio_sink| {
                bio_sink(readMsr(0x10));
            }
            handleKeyboard(frame);
        },
        44 => {
            // v0.19.0 (CDD №10 p2): PS/2 мышь (IO-APIC GSI 12 → сюда).
            handleMouse();
        },
        36 => handleSerial(frame),
        49 => {
            // v0.17.0 (CDD №8): virtio-blk — IO-APIC GSI диска маршрутизирован
            // сюда (virtio_blk.zig). APIC EOI уже отправлен выше (вектор ≥ 48).
            if (blk_irq_sink) |bsink| {
                bsink();
            }
        },
        else => {}, // Unknown interrupt — ignore for now
    }
    
    // CDD №12 p12-ФИКС2: FPU-РЕСТАВР АДРЕСАТА IRETQ. Не-свич: владелец
    // входа (сейв→реставр = тождество — тело хендлера могло калечить FPU).
    // Свич: ДИСПЕТЧИРОВАННАЯ задача = schedule()-current_task_id (уже
    // обновлён на next_id до возврата кадра — iretq-авторитет). НЕ kstack-
    // скан кадра: RESUME-SLOT диспетчеризация (installResumeFrame) возвращает
    // кадр из .bss sres.frameSlot — ВНЕ kstack-таблиц → скан давал null →
    // реставр ПРОПУСКАЛСЯ → разбуженная задача продолжала с мусором FPU
    // IRQ-хендлера (эмпирика: 11 нулевых байт в JIT-странице, краш сразу
    // после mprotect-RX паркинга). Гружено ПОСЛЕ всего Zig-кода — после
    // этой точки до iretq калечителей FPU нет.
    if (p12_irq_fpu) {
        if (exit_frame_addr != @intFromPtr(frame)) {
            // свич: кадр сменился (в т.ч. .bss-RESUME-SLOT) — грузим слот
            // ДИСПЕТЧИРОВАННОЙ задачи (последний вход-сейв её вытеснения /
            // нулевой init при рождении).
            const sched = @import("scheduler.zig");
            fpuRestore(&sched.tasks[sched.current_task_id].fpu);
        } else if (irq_fpu_owner) |o| {
            // не-свич: identity — что сейвили на входе, то и грузим.
            fpuRestore(&@import("scheduler.zig").tasks[o].fpu);
        }
    }
    return next_frame;
}

/// CDD №12 p5: владелец кадра исключения по kstack-адресу (как exc_faulter
/// ниже, но доступен ДО печати дампа — demand-zero-путь). Возврат — task_id.
fn halFaulterTask(frame_addr: u64) usize {
    const sched0 = @import("scheduler.zig");
    var fid: usize = 0;
    while (fid < sched0.task_count) : (fid += 1) {
        const kb: u64 = @intFromPtr(&sched0.tasks[fid].kernel_stack);
        if (frame_addr >= kb and frame_addr < kb + sched0.tasks[fid].kernel_stack.len) {
            return fid;
        }
    }
    return sched0.MAX_TASKS; // «не найден»
}

/// CDD №12 p7: дамп 0x40 байта контейнерной структуры (R12/R13/R14/RBX на
/// краше) с модульной атрицбуцией адреса и каждого слота-указателя. Все
/// чтения — ТОЛЬКО после userLeafFlags(PRESENT|USER): рекурсивный #PF в
/// краш-дампе = двойной фолт = потеря всего отчёта (эмпирика p5/p6: лог
/// обрывался на STACK-RET, секции RBP-CHAIN/NODE-DUMP не доходили).
fn dumpContainer(label: []const u8, addr: u64, faulter: usize) void {
    if (addr <= 0x10000 or addr > 0x7FFF_FFFF_FFFF) return;
    const vmm = @import("vmm64.zig");
    const main64 = @import("main64.zig");
    const pml4 = readCr3() & 0x000FFFFFFFFFF000;
    const leaf = vmm.userLeafFlags(pml4, addr) orelse return;
    if (leaf & vmm.PTE_USER == 0) return;
    Serial.puts("C-DUMP [");
    Serial.puts(label);
    Serial.puts("] @0x");
    Serial.putHex(addr);
    if (main64.linuxModuleAt(faulter, addr)) |hit| {
        Serial.puts(" (");
        Serial.puts(hit.name);
        Serial.puts("+0x");
        Serial.putHex(hit.off);
        Serial.puts(")");
    }
    Serial.puts(":");
    // CDD №12 p9: МИСАЛИГН-ТОЛЕРАНТНОЕ ЧТЕНИЕ (эмпирика p9guard: R12
    // =0x…40C — u32-выровненные LLVM-таблицы; выровненный u64-каст
    // паниковал «incorrect alignment» и убивал весь краш-отчёт).
    var k: usize = 0;
    while (k < 8) : (k += 1) {
        Serial.puts(" [+0x");
        Serial.putHex(@intCast(k * 8));
        Serial.puts("]=0x");
        var v64: u64 = 0;
        {
            var b: usize = 0;
            while (b < 8) : (b += 1) {
                const p: *volatile u8 = @ptrFromInt(addr + k * 8 + b);
                v64 |= @as(u64, p.*) << @intCast(b * 8);
            }
        }
        Serial.putHex(v64);
        if (main64.linuxModuleAt(faulter, v64)) |hit2| {
            Serial.puts("(");
            Serial.puts(hit2.name);
            Serial.puts("+0x");
            Serial.putHex(hit2.off);
            Serial.puts(")");
        }
    }
    Serial.puts("\n");
}

// CDD №15 p4: [PF-LOOP] — детектор ТИХОГО вечного #PF-цикла. Эмпирика:
// demand-zero клал карту в ЧУЖОЕ PML4 (реестр по faulter, таблицы по
// current) → страница не появлялась у виновника → фолт молча повторял-
// ся, гость крутился на ОДНОЙ инструкции (URIP 41/41 одного RIP).
// 30 подряд одинаковых (task, cr2) → печать (далее каждая 500-я).
var pfloop_task: usize = 0;
var pfloop_cr2: u64 = 0;
var pfloop_run: u64 = 0;
var pfloop_seen: bool = false;

// ─── CDD №15 p4-forensics: [PAGEWATCH] — хронограф краш-страниц lvp ────────
// Эмпирика run1/run2: пул-заголовок Mesa-слаб-аллокатора (r11≈0x20024079AE8)
// к моменту краша = ЧИСТЫЕ НУЛИ при живом PTE (bump [r11-0x20]=0 → rax=0 →
// #PF [rax+2]); соседний struct (0x2002400320) частично жив (+0x38 рандом).
// Гипотеза: страница ренe-materialized нулём (PTE-drop → demand-zero) ПОСЛЕ
// записи живых данных. Сэмпл 10Гц: pte + 2 ключевых qword КАЖДОЙ страницы;
// печать ТОЛЬКО на изменение (момент обнуления = улика).
var pw_pte0: u64 = 0xDEAD_BEE0;
var pw_q0a: u64 = 0xDEAD_BEE1;
var pw_pte1: u64 = 0xDEAD_BEE2;
var pw_q1a: u64 = 0xDEAD_BEE3;
var pw_first: bool = true;
// p5-forensics v4: сэмплы КАЖДЫЙ вызов (не только при принте) — см. pageWatch
var pw_s0: u64 = 0; // последний СЭМПЛ B/bump
var pw_s1: u64 = 0; // последний СЭМПЛ A/q320
var pw_last: u64 = 0; // тик последнего принта (троттл прогресса)
var pw_dump_last: u64 = 0; // тик последнего [B-DUMP]
/// p5-forensics: счётчик DR0-watchpoint триггеров (до 8, потом разряжение)
var db_events: u64 = 0;

/// p5-forensics: вооруить АППАРАТНЫЕ write-watchpoint'ы (DR0-DR3, 8Б каждый)
/// на 4 qword заголовка чанка slab-аллокатора (base..base+0x20).
/// Ловит записи из ЛЮБОГО режима (юзер-VA + kernel identity) и ЛЮБОГО
/// треда — гонка инициализации/обнуления заголовка станет видимой.
pub fn drArmWriteWatch(addr: u64) void {
    db_events = 0;
    asm volatile ("movq %[a], %%dr0"
        :
        : [a] "r" (addr),
    );
    asm volatile ("movq %[a], %%dr1"
        :
        : [a] "r" (addr + 8),
    );
    asm volatile ("movq %[a], %%dr2"
        :
        : [a] "r" (addr + 16),
    );
    asm volatile ("movq %[a], %%dr3"
        :
        : [a] "r" (addr + 24),
    );
    // DR7: L0-L3=1, RW=01 (write), LEN=11 (8Б) на каждый слот
    // slot i: RW@(16+4i), LEN@(18+4i) → 0xDDDD000F
    asm volatile ("movq $0xDDDD000F, %%rax\n\tmovq %%rax, %%dr7" ::: "rax", "memory");
    asm volatile ("xorq %%rax, %%rax\n\tmovq %%rax, %%dr6" ::: "rax", "memory");
}

/// p5-forensics: DR0-вооружён? (перевооружение только после разряжения)
pub fn drWatchArmed() bool {
    const dr7: u64 = asm volatile ("movq %%dr7, %[v]"
        : [v] "=r" (-> u64),
    );
    return (dr7 & 0x1) != 0;
}

fn pageWatch() void {
    const sched = @import("scheduler.zig");
    var gcr3: u64 = 0;
    var gi: usize = 0;
    while (gi < sched.task_count) : (gi += 1) {
        const t2 = &sched.tasks[gi];
        if (t2.privilege == .User and t2.abi == .linux and
            t2.state != .Killed and t2.cr3 != 0)
        {
            gcr3 = t2.cr3;
            break;
        }
    }
    if (gcr3 == 0) return;
    // p4-forensics: ПОЛНЫЙ raw-walk двух краш-VA (записи всех уровней —
    // huge-детект; qword через huge-aware обходчик)
    const PWV = struct {
        e3: u64 = 0,
        e2: u64 = 0,
        e1: u64 = 0,
        q: u64 = 0xFFFF_FFFF_FFFF_FFFF,
    };
    const walk = struct {
        fn go(cr3: u64, va: u64, qw_off: u64) PWV {
            var r = PWV{};
            const pml4: [*]const volatile u64 = @ptrFromInt(cr3);
            r.e3 = @as(*const volatile u64, &pml4[(va >> 39) & 0x1FF]).*;
            if (r.e3 & 0x1 == 0) return r;
            const pdpt: [*]const volatile u64 = @ptrFromInt(r.e3 & 0x000FFFFFFFFFF000);
            r.e2 = @as(*const volatile u64, &pdpt[(va >> 30) & 0x1FF]).*;
            if (r.e2 & 0x1 == 0) return r;
            if (r.e2 & 0x80 != 0) { // 1GB-huge
                const p: *volatile u64 = @ptrFromInt((r.e2 & 0xFFFFC0000000) + (va & 0x3FFFFFFF) + qw_off);
                r.q = p.*;
                return r;
            }
            const pd: [*]const volatile u64 = @ptrFromInt(r.e2 & 0x000FFFFFFFFFF000);
            r.e1 = @as(*const volatile u64, &pd[(va >> 21) & 0x1FF]).*;
            if (r.e1 & 0x1 == 0) return r;
            if (r.e1 & 0x80 != 0) { // 2MB-huge
                const p: *volatile u64 = @ptrFromInt((r.e1 & 0xFFFFFFE00000) + (va & 0x1FFFFF) + qw_off);
                r.q = p.*;
                return r;
            }
            const pt: [*]const volatile u64 = @ptrFromInt(r.e1 & 0x000FFFFFFFFFF000);
            const leaf = @as(*const volatile u64, &pt[(va >> 12) & 0x1FF]).*;
            r.e1 = leaf; // лист 4K поверх записи PD — печатаем обе? лист тут
            if (leaf & 0x1 == 0) return r;
            const p: *volatile u64 = @ptrFromInt((leaf & 0x000FFFFFFFFFF000) + (va & 0xFFF) + qw_off);
            r.q = p.*;
            return r;
        }
    }.go;
    const a = walk(gcr3, 0x200024003000, 0x230);
    const b = walk(gcr3, 0x200024079000, 0xAC8);
    // p5-forensics: физ-ловушка PMM — вооружаем phys B-страницы (каждый
    // free/alloc этого кадра печатается — poisoner-free + reissue-alloc)
    if (b.e1 & 0x1 != 0) {
        @import("pmm64.zig").watch_pa = b.e1 & 0x000FFFFFFFFFF000;
        // DR0-watchpoint на bump-qword — если ещё не вооружён (DZ-MAT мог
        // успеть раньше — тогда НЕ сбрасываем счётчик триггеров)
        if (!drWatchArmed()) drArmWriteWatch(0x2000_2407_9000 + 0xAC0); // юзер-VA — линейный адрес!
    }
    // p5-forensics v4: СЛЕПАЯ ЗОНА v3 — pw_q* обновлялись ТОЛЬКО при принте;
    // bump мог ЖИТЬ и УМЕРЕТЬ между сэмплами МОЛЧА (print-условия не
    // срабатывали: лист стабилен, zeroed-детектор сравнивал с последним
    // НАПЕЧАТАННЫМ значением = 0). Теперь сэмпл КАЖДЫЙ вызов → pw_s*;
    // деньги-события: лист-переход, 0→живо (рождение), живо→0 (ВАЙП).
    const a_alive = a.q != 0 and a.q != 0xFFFF_FFFF_FFFF_FFFF;
    const b_alive = b.q != 0 and b.q != 0xFFFF_FFFF_FFFF_FFFF;
    const b_born = b_alive and (pw_s0 == 0 or pw_s0 == 0xFFFF_FFFF_FFFF_FFFF);
    const b_dead = !b_alive and (pw_s0 != 0 and pw_s0 != 0xFFFF_FFFF_FFFF_FFFF);
    const a_born = a_alive and (pw_s1 == 0 or pw_s1 == 0xFFFF_FFFF_FFFF_FFFF);
    const a_dead = !a_alive and (pw_s1 != 0 and pw_s1 != 0xFFFF_FFFF_FFFF_FFFF);
    const leaf_change = (a.e1 != pw_pte1) or (b.e1 != pw_pte0);
    const money = leaf_change or b_born or b_dead or a_born or a_dead;
    if (pw_first or money) {
        pw_first = false;
        pw_pte0 = b.e1;
        pw_pte1 = a.e1;
        Serial.puts("[PW] A:pd=0x");
        Serial.putHex(a.e1);
        Serial.puts(" q320=0x");
        Serial.putHex(a.q);
        Serial.puts(" B:leaf=0x");
        Serial.putHex(b.e1);
        Serial.puts(" bump=0x");
        Serial.putHex(b.q);
        if (b_born) Serial.puts(" <<< BORN");
        if (b_dead) Serial.puts(" <<< ZEROED");
        if (a_dead) Serial.puts(" <<< A-DIED");
        Serial.puts(" t=");
        Serial.putDecimal(tick_count / 100);
        Serial.puts("\n");
    }
    // троттл-прогресс живого bump (движение ≠ событие, но видеть жизнь надо)
    if (b_alive and b.q != pw_s0 and !money and tick_count - pw_last >= 20000) {
        Serial.puts("[PW-PROG] bump=0x");
        Serial.putHex(b.q);
        Serial.puts(" t=");
        Serial.putDecimal(tick_count / 100);
        Serial.puts("\n");
    }
    pw_s0 = b.q;
    pw_s1 = a.q;
    pw_last = tick_count;
    // p5-forensics [B-DUMP]: контент-таймлайн структуры slab-аллокатора
    // (base 0x2000_2407_9AC0: +0x00 ?, +0x08 bump, +0x10 freelist, ...)
    // каждые 5000 тиков, если лист жив — рождение/смерть данных по факту.
    if (b.e1 & 0x1 != 0 and tick_count - pw_dump_last >= 5000) {
        pw_dump_last = tick_count;
        const bp = (b.e1 & 0x000FFFFFFFFFF000) + (0xAC8 - 0x8); // base=watch-0x8
        Serial.puts("[B-DUMP] t=");
        Serial.putDecimal(tick_count / 100);
        var qi: usize = 0;
        while (qi < 5) : (qi += 1) {
            const p: *const volatile u64 = @ptrFromInt(bp + qi * 8);
            Serial.puts(" +0x");
            Serial.putHex(@as(u64, qi * 8));
            Serial.puts("=0x");
            Serial.putHex(p.*);
        }
        Serial.puts("\n");
    }
}

fn pfLoopWatch(faulter: usize, cr2: u64) void {
    if (pfloop_seen and faulter == pfloop_task and cr2 == pfloop_cr2) {
        pfloop_run += 1;
    } else {
        pfloop_task = faulter;
        pfloop_cr2 = cr2;
        pfloop_run = 1;
        pfloop_seen = true;
    }
    if (pfloop_run == 30 or (pfloop_run > 30 and pfloop_run % 500 == 0)) {
        Serial.puts("[PF-LOOP] task=");
        Serial.putDecimal(faulter);
        Serial.puts(" cr2=0x");
        Serial.putHex(cr2);
        Serial.puts(" run=");
        Serial.putDecimal(pfloop_run);
        Serial.puts("\n");
    }
}

fn handleException(frame: *InterruptFrame) void {
    // p5-forensics [DB-WRITE]: АППАРАТНЫЙ watchpoint (DR0, write, 8Б) на
    // bump-qword краш-страницы. Ловит ЛЮБУЮ запись — юзер-VA И kernel-
    // identity (PMM-ловушка слепа к identity-записям!). Каждый триггер:
    // RIP писца + записанное значение. write#1 = BORN (bump живой),
    // write#2 = КАЗНЬ (вайп) — и её RIP = ИМЯ УБИЙЦЫ.
    if (frame.vector == 1) {
        const dr6: u64 = asm volatile ("movq %%dr6, %[v]"
            : [v] "=r" (-> u64),
        );
        if (dr6 & 0xF != 0) { // B0-B3 = DR0-DR3 hit
            const ft0 = halFaulterTask(@intFromPtr(frame));
            const slot: u6 = @intCast(@ctz(dr6 & 0xF)); // первый сработавший DR
            const drvar: u64 = switch (slot) {
                0 => asm volatile ("movq %%dr0, %[v]" : [v] "=r" (-> u64)),
                1 => asm volatile ("movq %%dr1, %[v]" : [v] "=r" (-> u64)),
                2 => asm volatile ("movq %%dr2, %[v]" : [v] "=r" (-> u64)),
                else => asm volatile ("movq %%dr3, %[v]" : [v] "=r" (-> u64)),
            };
            const nv: *const volatile u64 = @ptrFromInt(drvar);
            // p5-forensics v6: КОНТРОЛЬНЫЙ ВЫСТРЕЛ — прочитать ДО/ПОСЛЕ
            // invlpg: если значения РАЗНЫЕ → CPU работал через STALE-TLB
            // (PTE говорит P_new, кэш — P_old): источник «записи в пустоту».
            const before_invlpg = nv.*;
            asm volatile ("invlpg (%[virt])"
                :
                : [virt] "r" (drvar & ~@as(u64, 4095)),
                : "memory"
            );
            const after_invlpg = nv.*;
            Serial.puts("[DB-WRITE] task=");
            Serial.putDecimal(ft0);
            Serial.puts(" rip=0x");
            Serial.putHex(frame.rip);
            Serial.puts(" q+");
            Serial.putDecimal(@as(u64, @as(u64, slot) * 8));
            Serial.puts("=0x");
            Serial.putHex(after_invlpg);
            if (before_invlpg != after_invlpg) {
                Serial.puts(" <<< STALE-TLB! was=0x");
                Serial.putHex(before_invlpg);
            }
            Serial.puts(" from_user=");
            Serial.putDecimal(@as(u64, if ((frame.cs & 0x3) != 0) 1 else 0));
            Serial.puts("\n");
            // сброс DR6 + ПЕРЕВООРУЖЕНИЕ (до 16 событий)
            asm volatile ("xorq %%rax, %%rax\n\tmovq %%rax, %%dr6" ::: "rax", "memory");
            if (db_events < 16) {
                db_events += 1;
                asm volatile ("movq $0xDDDD000F, %%rax\n\tmovq %%rax, %%dr7" ::: "rax", "memory"); // rearm
            } else {
                asm volatile ("xorq %%rax, %%rax\n\tmovq %%rax, %%dr7" ::: "rax", "memory");
            }
            return; // trap: инструкция уже завершилась — продолжаем
        }
        // чужой #DB (single-step и пр.) — общий путь ниже
    }

    // v0.10.0 (CDD №1): int3 из стаба импорта — обрабатываем ПЕРВЫМ.
    // Стаб: xor rax,rax; int3; ret — RIP после int3 указывает внутрь стаба;
    // колбэк находит entry по RIP, логирует dll!func, RIP+=1 (skip int3),
    // задача продолжает с rax=0 (дефолт-«не реализовано»).
    if (frame.vector == 3) {
        if (int3Callback) |cb| {
            if (cb(frame)) return;
        }
    }

    // v0.7.0: Differentiate user-mode vs kernel-mode exceptions
    const from_user = (frame.cs & 0x3) != 0;

    // CDD №12 p5: DEMAND-ZERO — #PF(P=0) на lazy-anon/brk-странице гостья:
    // молча выделяем НУЛЕВУЮ физ-страницу с правами региона и ПЕРЕЗАПУСКАЕМ
    // инструкцию (Linux-семантика анонимной памяти: страницы при касании).
    // Хендлер входит с CR3 вины — работаем с таблицами её процесса.
    if (from_user and frame.vector == 14 and (frame.error_code & 0x1) == 0) {
        const cr2_dz: u64 = asm volatile ("movq %%cr2, %[v]"
            : [v] "=r" (-> u64),
        );
        const dz_faulter = halFaulterTask(@intFromPtr(frame));
        pfLoopWatch(dz_faulter, cr2_dz); // CDD №15 p4: тихий цикл?
        // p5-forensics: [DZ-FAULT] — первая запись/чтение watch-страницы:
        // task + ФОЛТЯЩИЙ RIP (какой код тронул страницу) + write-бит.
        if (@import("vmm64.zig").diagWatchOn(cr2_dz & ~@as(u64, 4095))) {
            Serial.puts("[DZ-FAULT] task=");
            Serial.putDecimal(dz_faulter);
            Serial.puts(" rip=0x");
            Serial.putHex(frame.rip);
            Serial.puts(" va=0x");
            Serial.putHex(cr2_dz);
            Serial.puts(" err=0x");
            Serial.putHex(frame.error_code);
            Serial.puts("\n");
        }
        if (@import("main64.zig").linuxDemandZero(dz_faulter, cr2_dz)) {
            return; // гость продолжает — фолта «не было»
        }
    }

    // CDD №12 p7: ДАМП-АТОМАРНОСТЬ — весь краш-отчёт под IF=0. Эмпирика
    // p6/p7-прогонов: печать STACK-RET (медленная, сокет-serial) прерыва-
    // лась таймером (вытеснение кадра каскадом schedule) либо убийством
    // QEMU e2e-скриптом ДО завершения — RBP-CHAIN/NODE-DUMP/модульная
    // атрибуция (СЕКЦИЯ ДЕНЕГ для CDD-диагноза) не доходили до лога.
    // Возврат IF — через rflags кадра (idle_after_fault: 0x202, IF=1).
    if (from_user and frame.vector != 3) {
        cli();
    }

    Serial.puts("\n!!! CPU EXCEPTION !!!\n");
    // CDD №15 p4-forensics: КТО крашит и на КАКОМ CR3 (гипотеза: тред с
    // отдельным PML4 — снапшот-фолбэк? — общая физика сломана)
    {
        const ft = halFaulterTask(@intFromPtr(frame));
        Serial.puts("[EXC] task=");
        Serial.putDecimal(ft);
        Serial.puts(" cr3=0x");
        Serial.putHex(readCr3() & 0x000FFFFFFFFFF000);
        Serial.puts("\n");
    }
    Serial.puts("Vector: ");
    Serial.putHex(frame.vector);
    Serial.puts("\nError Code: ");
    Serial.putHex(frame.error_code);
    // v0.10.0: CR2 — адрес #PF (что именно читали/писали; RIP ≠ CR2 для #PF!)
    if (frame.vector == 14) {
        const cr2: u64 = asm volatile ("movq %%cr2, %[v]"
            : [v] "=r" (-> u64),
        );
        Serial.puts("\nCR2 (fault addr): ");
        Serial.putHex(cr2);
    }
    Serial.puts("\nRIP: ");
    Serial.putHex(frame.rip);
    Serial.puts("\nCS: ");
    Serial.putHex(frame.cs);
    // v0.10.0-debug: регистры из кадра — разбор #PF в user-коде
    Serial.puts("\nRSI: ");
    Serial.putHex(frame.rsi);
    Serial.puts(" RDX: ");
    Serial.putHex(frame.rdx);
    Serial.puts(" RCX: ");
    Serial.putHex(frame.rcx);
    Serial.puts(" RBX: ");
    Serial.putHex(frame.rbx);
    Serial.puts(" RAX: ");
    Serial.putHex(frame.rax);
    Serial.puts("\nRFLAGS: ");
    Serial.putHex(frame.rflags);
    Serial.puts("\nRSP: ");
    Serial.putHex(frame.rsp);
    Serial.puts("\nSS: ");
    Serial.putHex(frame.ss);
    // v0.18.1-бисект: RDI (скрытый контекст error-return-trace — Zig
    // передаёт его регистром; дикая запись returnError = порча корня) +
    // RDI-структура {index, addresses, capacity} + мини-дамп вокруг.
    Serial.puts("\nRDI: ");
    Serial.putHex(frame.rdi);
    if (!from_user and frame.rdi > 0x10000 and frame.rdi < 0x800000) {
        const ctx: *volatile [3]u64 = @ptrFromInt(frame.rdi);
        Serial.puts(" ctx: [idx=0x");
        Serial.putHex(ctx[0]);
        Serial.puts(" ptr=0x");
        Serial.putHex(ctx[1]);
        Serial.puts(" cap=0x");
        Serial.putHex(ctx[2]);
        Serial.puts("]");
    }
    // v0.20.0 (CDD №12 p2): ПОЛНЫЙ регистровый дамп + байты команды (CDD:
    // краш-логи glibc-кода требуют R8-R15 и опкоды fault-инструкции).
    Serial.puts("\nR8: ");
    Serial.putHex(frame.r8);
    Serial.puts(" R9: ");
    Serial.putHex(frame.r9);
    Serial.puts(" R10: ");
    Serial.putHex(frame.r10);
    Serial.puts(" R11: ");
    Serial.putHex(frame.r11);
    Serial.puts(" RBP: ");
    Serial.putHex(frame.rbp);
    Serial.puts("\nR12: ");
    Serial.putHex(frame.r12);
    Serial.puts(" R13: ");
    Serial.putHex(frame.r13);
    Serial.puts(" R14: ");
    Serial.putHex(frame.r14);
    Serial.puts(" R15: ");
    Serial.putHex(frame.r15);
    if (from_user) {
        // 16 байт опкодов НАЧИНАЯ С RIP (fault-инструкция — точный опкод).
        // CDD №12 p5-фикс: старый код печатал только байт по RIP-8 (мусор
        // для разбора) — теперь hex-строка всех байт [RIP, RIP+16).
        // CDD №12 p11: расширение до 96 байт + СЫРОЙ PTE страницы RIP —
        // эмпирика sysharness: краш ИСПОЛНЕНИЯ нулей в свежем RX-JIT-регионе
        // (код, записанный в RW-фазу, «пропал») — PTE (фрейм+флаги) и контент
        // решают спор «записи потеряны vs адрес вызова неверен».
        Serial.puts("\nRIP-bytes[96]: ");
        const vmm2 = @import("vmm64.zig");
        const cr3_base = readCr3() & 0x000FFFFFFFFFF000;
        var k: usize = 0;
        while (k < 96) : (k += 1) {
            const va = frame.rip + k;
            const leaf = vmm2.userLeafFlags(cr3_base, va) orelse break;
            if (leaf & vmm2.PTE_USER == 0) break;
            const pb: *volatile u8 = @ptrFromInt(va);
            Serial.putHexByte(pb.*);
            if ((k & 31) == 31) Serial.puts(" "); // визуальный сепаратор
        }
        // PTE страницы RIP (сырой qword: физфрейм+флаги)
        Serial.puts("\nRIP-PTE: 0x");
        if (vmm2.userLeafRaw(cr3_base, frame.rip & ~@as(u64, 4095))) |pte| {
            Serial.putHex(pte);
        } else {
            Serial.puts("(no-leaf)");
        }
        // CDD №12 p11: сырой дамп [rsp..rsp+0x80) — ret-адрес ВЫЗЫВАЮЩЕГО
        // JIT-функции (лесенка кадров воркера llvmpipe); C++-вызывающий
        // символизируется objdump по [RIP]-модулю из [MMAP]-реестра.
        if (frame.rsp > 0x1000) {
            Serial.puts("\nRSP-RAW: ");
            var q: usize = 0;
            while (q < 16) : (q += 1) {
                const va = frame.rsp + q * 8;
                const leaf = vmm2.userLeafFlags(cr3_base, va) orelse break;
                if (leaf & vmm2.PTE_USER == 0) break;
                const sp: *volatile u64 = @ptrFromInt(va);
                Serial.putHex(sp.*);
                Serial.puts(" ");
            }
        }
    }
    // v0.13.0-fix (диагностика CDD №4): дамп стека юзера — ret-адрес укажет
    // ВЫЗЫВАЮЩЕГО функции NULL-вызова (RIP=0: call reg с reg=0).
    // v0.20.0-fix (CDD №11): ВАЛИДАЦИЯ страницы ПОСЛЕ user-RSP — клон-тред
    // fault-ится на [rsp+8] ВЫШЕ региона стека (эмпирика elf-run: дампер
    // слепо разыменовывал usp[i] → kernel-#PF внутри обработчика → halt).
    // Проба страницы по текущим таблицам (CR3 = PML4 виновника).
    if (from_user and frame.rsp > 0x1000) {
        const vmm = @import("vmm64.zig");
        var i: usize = 0;
        while (i < 12) : (i += 1) {
            const va = frame.rsp + i * 8;
            const leaf = vmm.userLeafFlags(readCr3() & 0x000FFFFFFFFFF000, va) orelse break;
            if (leaf & vmm.PTE_USER == 0) break;
            const usp: *volatile [12]u64 = @ptrFromInt(frame.rsp);
            const v = usp[i];
            if (v >= 0x140000000 and v < 0x1403C0000) {
                Serial.puts("\n  [rsp+");
                Serial.putDecimal(i * 8);
                Serial.puts("] ret=0x");
                Serial.putHex(v);
            }
        }
    }

    // CDD №12 p3: СКАН СТЕКА на ret-адреса (RBP в -O2-коде — обычный
    // регистр, цепочка обрывается; а стек рекурсии СОДЕРЖИТ повторяющиеся
    // ret-адреса — цикл виновников виден по ПОВТОРАМ). Диапазоны: ld.so+либы
    // (0x400_0000_0000+) и образ gamescope (0x1000_0000_0000+, без brk).
    // CDD №12 p4: С МОДУЛЬНОЙ АТРИБУЦИЕЙ — faulter-скан по kstack-диапазонам
    // (ВЛАДЕЛЕЦ кадра) → mmap-реестр его процесса → имя либы+офсет; плюс
    // гистограмма ПОВТОРОВ (цикл рекурсии = повторяющийся ret по счётчику).
    var exc_faulter: usize = 0;
    if (from_user) {
        const sched0 = @import("scheduler.zig");
        const fault_rsp0: u64 = @intFromPtr(frame);
        var fid: usize = 0;
        while (fid < sched0.task_count) : (fid += 1) {
            const kb: u64 = @intFromPtr(&sched0.tasks[fid].kernel_stack);
            if (fault_rsp0 >= kb and fault_rsp0 < kb + sched0.tasks[fid].kernel_stack.len) {
                exc_faulter = fid;
                break;
            }
        }
    }
    if (from_user and frame.rsp > 0x1000) {
        const vmm4 = @import("vmm64.zig");
        const main64 = @import("main64.zig");
        const pml4 = readCr3() & 0x000FFFFFFFFFF000;
        Serial.puts("\nSTACK-RET:");
        // гистограмма повторов ret-адресов
        // CDD №12 p6: 192→1024 слота (кадр _Rb_tree-цепи >1.5КБ локалов;
        // ПЕРВЫЙ код-вказівник от RSP = ближайший caller — порядок важен)
        var hist_addr: [1024]u64 = [_]u64{0} ** 1024;
        var hist_cnt: [1024]u32 = [_]u32{0} ** 1024;
        var hist_n: usize = 0;
        var code_printed: usize = 0;
        var i: usize = 0;
        while (i < 1024) : (i += 1) {
            const va = frame.rsp + i * 8;
            const leaf = vmm4.userLeafFlags(pml4, va) orelse break;
            if (leaf & vmm4.PTE_USER == 0) break;
            const w: *volatile u64 = @ptrFromInt(va);
            const v = w.*;
            const is_ret = (v >= 0x4000_0000_0000 and v < 0x4006_0000_0000) or
                (v >= 0x1000_0000_0000 and v < 0x1000_0040_0000);
            if (is_ret) {
                // CDD №12 p6: первые 32 — с номером слота (порядок = глубина)
                if (code_printed < 32) {
                    Serial.puts(" +0x");
                    Serial.putHex(@intCast(i * 8));
                    Serial.puts(":");
                    Serial.putHex(v);
                    if (main64.linuxModuleAt(exc_faulter, v)) |hit| {
                        Serial.puts("(");
                        Serial.puts(hit.name);
                        Serial.puts("+0x");
                        Serial.putHex(hit.off);
                        Serial.puts(")");
                    }
                    code_printed += 1;
                }
                // повтор → счётчик
                var h: usize = 0;
                while (h < hist_n) : (h += 1) {
                    if (hist_addr[h] == v) {
                        hist_cnt[h] += 1;
                        break;
                    }
                }
                if (h == hist_n and hist_n < hist_addr.len) {
                    hist_addr[hist_n] = v;
                    hist_cnt[hist_n] = 1;
                    hist_n += 1;
                }
            }
        }
        Serial.puts("\n");
        // TOP-повторы (цикл виновников виден по ×N)
        if (hist_n > 0) {
            Serial.puts("STACK-HIST:");
            var h: usize = 0;
            while (h < hist_n and h < 8) : (h += 1) {
                Serial.puts(" ");
                Serial.putHex(hist_addr[h]);
                Serial.puts("x");
                Serial.putDecimal(hist_cnt[h]);
                if (main64.linuxModuleAt(exc_faulter, hist_addr[h])) |hit| {
                    Serial.puts("(");
                    Serial.puts(hit.name);
                    Serial.puts("+0x");
                    Serial.putHex(hit.off);
                    Serial.puts(")");
                }
            }
            Serial.puts("\n");
        }
        // CDD №12 p6: RBP-ЦЕПОЧКА кадров — НАСТОЯЩИЙ backtrace (STACK-RET
        // сканит локальные данные кадра: 192 слота могут быть сплошь
        // указателями-данными; return-адреса сидят на [rbp+8], следующий
        // кадр — на [rbp]). 10 кадров с модульной атрибуцией.
        {
            var rbp: u64 = frame.rbp;
            var frames: usize = 0;
            Serial.puts("RBP-CHAIN:");
            while (frames < 10) : (frames += 1) {
                if (rbp < 0x1000 or rbp > 0x7FFF_FFFF_FFFF) break;
                const leaf0 = vmm4.userLeafFlags(pml4, rbp) orelse break;
                if (leaf0 & vmm4.PTE_USER == 0) break;
                const leaf1 = vmm4.userLeafFlags(pml4, rbp + 8) orelse break;
                if (leaf1 & vmm4.PTE_USER == 0) break;
                // CDD №12 p9: байтовая сборка (мисалигн-толерантно)
                var ret: u64 = 0;
                {
                    var b: usize = 0;
                    while (b < 8) : (b += 1) {
                        const p: *volatile u8 = @ptrFromInt(rbp + 8 + b);
                        ret |= @as(u64, p.*) << @intCast(b * 8);
                    }
                }
                var next: u64 = 0;
                {
                    var b: usize = 0;
                    while (b < 8) : (b += 1) {
                        const p: *volatile u8 = @ptrFromInt(rbp + b);
                        next |= @as(u64, p.*) << @intCast(b * 8);
                    }
                }
                Serial.puts(" ");
                Serial.putHex(ret);
                if (main64.linuxModuleAt(exc_faulter, ret)) |hit| {
                    Serial.puts("(");
                    Serial.puts(hit.name);
                    Serial.puts("+0x");
                    Serial.putHex(hit.off);
                    Serial.puts(")");
                }
                if (next <= rbp or next - rbp > 0x40000) break; // анти-цикл/мусор
                rbp = next;
            }
            Serial.puts("\n");
        }
    }

    // CDD №12 p7: КОНТЕЙНЕРНЫЙ ДАМП R12/R13/R14 — источники итератора.
    // Узел #PF (RDI) лежит в нулевой lazy-странице, но КОНТЕЙНЕР (std::map
    // в .data) — живые данные: его header {parent=ROOT, left, right} и
    // node_count показывают, КТО выдал мусорный итератор. 0x40 байта +
    // модульная атрибуция КАЖДОГО слота (указатели-дети → либа+офсет).
    if (from_user) {
        dumpContainer("R12", frame.r12, exc_faulter);
        dumpContainer("R13", frame.r13, exc_faulter);
        dumpContainer("R14", frame.r14, exc_faulter);
        dumpContainer("RBX", frame.rbx, exc_faulter);
    }

    // CDD №12 p6: ДАМП УЗЛА #PF — [RDI, +0x40) декодировано как
    // _Rb_tree_node_base {color, pad, parent, left, right} + value-слоты:
    // пустое дерево (parent=0, left/right=self) vs живые ссылки.
    if (from_user and frame.vector == 14 and frame.rdi > 0x10000) {
        const vmm4 = @import("vmm64.zig");
        const pml4n = readCr3() & 0x000FFFFFFFFFF000;
        if (vmm4.userLeafFlags(pml4n, frame.rdi) != null) {
            Serial.puts("NODE-DUMP [rdi]: color=0x");
            const wn: *volatile [8]u64 = @ptrFromInt(frame.rdi);
            Serial.putHex(wn[0]);
            Serial.puts(" parent=0x");
            Serial.putHex(wn[1]);
            Serial.puts(" left=0x");
            Serial.putHex(wn[2]);
            Serial.puts(" right=0x");
            Serial.putHex(wn[3]);
            Serial.puts(" val=[0x");
            Serial.putHex(wn[4]);
            Serial.puts(" 0x");
            Serial.putHex(wn[5]);
            Serial.puts(" 0x");
            Serial.putHex(wn[6]);
            Serial.puts(" 0x");
            Serial.putHex(wn[7]);
            Serial.puts("]\n");
        }
    }

    // CDD №12 p4: МОДУЛЬНЫЙ ДАМП — [RIP]/[CR2] → библиотека+офсет из
    // mmap-реестра ВЛАДЕЛЬЦА кадра (изоляция lvp/LLVM device-init: точный
    // модуль краша вместо гадания по диапазонам) + ТОП-5 крупнейших регио-
    // нов + полный дамп (≤64 записи; реже — по ltrace-прогону).
    if (from_user) {
        const main64 = @import("main64.zig");
        Serial.puts("[RIP] module: ");
        if (main64.linuxModuleAt(exc_faulter, frame.rip)) |hit| {
            Serial.puts(hit.name);
            Serial.puts("+0x");
            Serial.putHex(hit.off);
            Serial.puts("\n");
        } else {
            Serial.puts("(unmapped)\n");
        }
        if (frame.vector == 14) {
            const cr2: u64 = asm volatile ("movq %%cr2, %[v]"
                : [v] "=r" (-> u64),
            );
            Serial.puts("[CR2] module: ");
            if (main64.linuxModuleAt(exc_faulter, cr2)) |hit| {
                Serial.puts(hit.name);
                Serial.puts("+0x");
                Serial.putHex(hit.off);
                Serial.puts("\n");
            } else {
                Serial.puts("(unmapped)\n");
            }
        }
        const dumped = main64.linuxDumpRegionTable(exc_faulter, 64);
        Serial.puts("[MMAP] регионов в дампе: ");
        Serial.putDecimal(dumped);
        Serial.puts(" (топ-64 из 512)\n");
    }

    if (from_user) {
        // User-mode exception — kill the offending process instead of kernel panic
        Serial.puts("\n[EXCEPTION] Ring 3 fault! Killing user process.\n");
        // DEBUG (CDD №8): компактный дамп при RIP=0 (урок SYSTEM_INFO-48Б)
        if (frame.rip == 0) {
            const vmm = @import("vmm64.zig");
            const cr3 = readCr3() & 0x000FFFFFFFFFF000;
            Serial.puts("[DBG] RIP=0: ");
            if (vmm.userLeafFlags(cr3, frame.rsp)) |_| {
                const usp: *volatile u64 = @ptrFromInt(frame.rsp);
                Serial.puts("[rsp]=0x");
                Serial.putHex(usp.*);
                if (vmm.userLeafFlags(cr3, frame.rsp + 8)) |_| {
                    Serial.puts(" [rsp+8]=0x");
                    const usp2: *volatile u64 = @ptrFromInt(frame.rsp + 8);
                    Serial.putHex(usp2.*);
                }
            }
            Serial.puts("\n");
        }
        // Kill the task via the exit callback (same mechanism as syscall exit).
        // v0.17.0-fix (CDD №8 p7): если виновник уже убит выше (рассинхрон
        // current) — НЕ зовём exitCallback: он убил бы НЕВИНОВНУЮ current-
        // задачу (эмпирика: curl-main погибал от #PF треда 5).
        var killed_above = false;
        {
            const sched = @import("scheduler.zig");
            const fault_rsp: u64 = @intFromPtr(frame);
            var faulter: usize = 0;
            var fid: usize = 0;
            while (fid < sched.task_count) : (fid += 1) {
                const kb: u64 = @intFromPtr(&sched.tasks[fid].kernel_stack);
                if (fault_rsp >= kb and fault_rsp < kb + sched.tasks[fid].kernel_stack.len) {
                    faulter = fid;
                    break;
                }
            }
            if (faulter != 0 and faulter != sched.current_task_id) {
                Serial.puts("[EXCEPTION] виновник task ");
                Serial.putDecimal(faulter);
                Serial.puts(" (cur=");
                Serial.putDecimal(sched.current_task_id);
                Serial.puts(" — рассинхрон; cur не трогаем)\n");
                sched.killTask(faulter) catch {};
                killed_above = true;
            }
        }
        if (!killed_above) {
            if (exitCallback) |cb| {
                cb();
            }
        }
        // After killing, we can't return to the faulting user code.
        // Modify the interrupt frame to point to a safe idle loop in Ring 0
        // so IRETQ returns to kernel idle code instead of the dead user task.
        // The scheduler will pick a Ready task on the next tick.
        frame.rip = @intFromPtr(&idle_after_fault);
        frame.cs = 0x08; // Kernel code segment
        frame.ss = 0x10; // Kernel data segment
        frame.rflags = 0x202; // IF set
        // Use the idle task's kernel stack for safety
        frame.rsp = 0x10b000; // Boot stack top
        Serial.puts("[EXCEPTION] User process killed. Returning to idle.\n");
    } else {
        // Kernel-mode exception — fatal, halt
        Serial.puts("\n[EXCEPTION] Kernel fault! Halting CPU...\n");
        while (true) {
            cli();
            hlt();
        }
    }
}

fn handleTimer(frame: *InterruptFrame) void {
    _ = frame;
    tick_count += 1;
}

fn handleKeyboard(frame: *InterruptFrame) void {
    _ = frame;
    // v0.7.3: Guard against spurious IRQ1. The 8042 IRQ line is wired to BOTH
    // the PIC and the IO-APIC on i440FX — with both unmasked each scancode
    // caused TWO vector-33 deliveries and the second (empty) inb(0x60) read
    // returned the SAME byte again (QEMU keeps the data register), duplicating
    // every keystroke. Only consume the port when OBF is set and the byte is
    // keyboard (not mouse AUX) data.
    const status = inb(0x64);
    if ((status & 0x01) == 0) return; // OBF clear — nothing to read
    // v0.19.0 (CDD №10 p2): AUX-байт (мышь) — потребляем мышиным путём ПРЯМО
    // (устойчивость: если IRQ12 не доставлен, мышиный байт не блокирует OBF
    // и не глушит клавиатуру).
    if ((status & 0x20) != 0) {
        handleMouse();
        return;
    }

    const scan = inb(0x60);

    // v0.19.0 (CDD №10 p2): evdev /dev/input/event0 — КАЖДЫЙ сканкод
    // становится input_event (нажатие/отпускание/E0-расширенные). Прерывание
    // = interrupt gate (IF=0) — атомарность push'а гарантирована.
    {
        const released = (scan & 0x80) != 0;
        const base = scan & 0x7F;
        if (kbd_extended) {
            const code = evdev.set1ExtToKeyCode(base);
            if (code != 0) {
                evdev_kbd.pushKey(code, if (released) 0 else 1);
                evdev_kbd.pushSyn();
            }
        } else {
            const code = evdev.set1ToKeyCode(base);
            if (code != 0) {
                evdev_kbd.pushKey(code, if (released) 0 else 1);
                evdev_kbd.pushSyn();
            }
        }
    }

    // Debug: raw scancode на serial — ТОЛЬКО нажатия (bit7=release):
    // release-коды (0x9C от sendkey ret) печатались ВНУТРИ строк шелла
    // (гонка [KBD]-лога с печатью «cmdline: …») и ломали E2E-парсинг.
    if (scan != 0xE0 and (scan & 0x80) == 0) {
        Serial.puts("[KBD] scan=0x");
        Serial.putHex(scan);
        Serial.puts("\n");
    }

    // Extended key prefix
    if (scan == 0xE0) {
        kbd_extended = true;
        return;
    }

    // Key release (bit 7 set)
    if (scan & 0x80 != 0) {
        const released = scan & 0x7F;
        if (released == 0x2A or released == 0x36) kbd_shift = false;
        if (released == 0x1D) kbd_ctrl = false;
        if (released == 0x38) kbd_alt = false;
        kbd_extended = false;
        return;
    }

    // Extended key handling
    if (kbd_extended) {
        kbd_extended = false;
        // Arrow keys
        if (scan == 0x48) kbd_push(0x11); // Up
        if (scan == 0x50) kbd_push(0x12); // Down
        if (scan == 0x4B) kbd_push(0x13); // Left
        if (scan == 0x4D) kbd_push(0x14); // Right
        return;
    }

    // Modifier keys
    if (scan == 0x2A or scan == 0x36) { kbd_shift = true; return; }
    if (scan == 0x1D) { kbd_ctrl = true; return; }
    if (scan == 0x38) { kbd_alt = true; return; }

    // Convert scan code to ASCII
    if (scan < 128) {
        if (kbd_ctrl and scan == 0x2E) { kbd_push(0x03); return; } // Ctrl-C
        if (kbd_ctrl and scan == 0x15) { kbd_push(0x18); return; } // Ctrl-X
        if (kbd_ctrl and scan == 0x31) { kbd_push(0x1A); return; } // Ctrl-Z
        const ch = if (kbd_shift) scan_to_ascii_shift[scan] else scan_to_ascii[scan];
        if (ch != 0) {
            kbd_push(ch);
        }
    }
}

// ============================================================================
// v0.19.0 (CDD №10 p2): Evdev — /dev/input/event0 (kbd) + /dev/input/event1 (mouse)
// ============================================================================
const evdev = @import("evdev.zig");

/// Устройства-синглтоны evdev (push из IRQ, read — через Linux-fd слой шага 3).
pub var evdev_kbd: evdev.Evdev = .{};
pub var evdev_mouse: evdev.Evdev = .{};
var mouse_btn_prev: u3 = 0;
var mouse_pkt: [3]u8 = .{0} ** 3;
var mouse_pkt_n: usize = 0;

pub fn initInputEvdev() void {
    evdev.initKeyboard(&evdev_kbd);
    evdev.initMouse(&evdev_mouse);
    Serial.puts("[EVDEV] /dev/input/event0 (PS/2 kbd) + /dev/input/event1 (PS/2 mouse)\n");
}

/// Ожидание OBF с таймаутом (спин — бут-контекст, TCG).
fn waitObf() bool {
    var spins: u32 = 0;
    while (spins < 10_000_000) : (spins += 1) {
        if ((inb(0x64) & 0x01) != 0) return true;
        asm volatile ("pause");
    }
    return false;
}

/// Входной буфер 8042 пуст (контроллер ГОТОВ принять команду) — ОБЯЗАТЕЛЬНО
/// перед КАЖДОЙ записью в 0x64/0x60, иначе команда теряется (эмпирика
/// drm-smoke: потерянный 0xD4-префикс отправил 0xF6 КЛАВИАТУРЕ → reset).
fn waitIbf() void {
    var spins: u32 = 0;
    while (spins < 10_000_000) : (spins += 1) {
        if ((inb(0x64) & 0x02) == 0) return;
        asm volatile ("pause");
    }
}

/// Слить выходной буфер (устаревшие байты) — до 64.
fn flushObf() void {
    var n: usize = 0;
    while (n < 64) : (n += 1) {
        if ((inb(0x64) & 0x01) == 0) return;
        _ = inb(0x60);
    }
}

/// Сохранение IF (cli-окно для атомарных 8042-транзакций).
fn irqSave() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; popq %[f]"
        : [f] "=r" (flags)
        ::
        "memory");
    cli();
    return flags;
}
fn irqRestore(flags: u64) void {
    if (flags & 0x200 != 0) sti(); // IF был включён — восстанавливаем
}

/// Команда aux-устройству (0xD4 + 0x60), ждём ACK 0xFA.
fn auxCmd(cmd: u8) bool {
    waitIbf();
    outb(0x64, 0xD4);
    waitIbf();
    outb(0x60, cmd);
    if (!waitObf()) return false;
    const ack = inb(0x60);
    return ack == 0xFA;
}

/// PS/2 мышь: включить aux-порт, IRQ12 в конфиге 8042, defaults + streaming.
/// false = устройства нет (безопасно — IRQ12 не маршрутизируется).
///
/// АТОМАРНОСТЬ (критично, урок drm-smoke-гонки): ответ контроллера на
/// «read config» (0x20) выглядит как клавиатурный байт (OBF без AUX-бита)
/// → IRQ1/handleKeyboard КРАЛ его из-под waitObf → cfg читался из мусора
/// → запись конфига ПОТЕРЯЛА бит6 (Set2→Set1 translation) → клавиатура
/// сыпала Set2-сырцом («dxx» вместо «drm»). Лечение: cli-окно на всю
/// последовательность + flushObf + waitIbf перед КАЖДОЙ записью + бит6
/// принудительно сохраняется (ядро ожидает Set1-translation).
pub fn initPs2Mouse() bool {
    const flags = irqSave();
    defer irqRestore(flags);

    // 1. Enable auxiliary device (0xA8)
    waitIbf();
    outb(0x64, 0xA8);
    // 2. Controller config: IRQ12 (bit1) + IRQ1 (bit0) вкл, часы вкл
    //    (bit4/5 сняты), translation (bit6) — сохранён и принудительно 1.
    flushObf(); // устаревших байтов нет — ответ 0x20 будет чистым
    waitIbf();
    outb(0x64, 0x20); // read config byte
    if (!waitObf()) return false;
    const cfg = inb(0x60);
    waitIbf();
    outb(0x64, 0x60); // write config byte
    waitIbf();
    outb(0x60, (cfg | 0x03) & ~@as(u8, 0x30) | 0x40);
    // 3. Set defaults (0xF6) — 3-байтный протокол, 100 отсчётов/с
    if (!auxCmd(0xF6)) return false;
    // 4. Enable streaming (0xF4)
    if (!auxCmd(0xF4)) return false;
    return true;
}

/// Обработчик мышиных байтов (IRQ12 → вектор 44; и хвост-путь из IRQ1):
/// 3-байтный пакет (byte0.bit3 = 1 — синхронизация потока) → evdev.
pub fn handleMouse() void {
    const status = inb(0x64);
    if ((status & 0x01) == 0) return;
    if ((status & 0x20) == 0) return; // не AUX — не наш байт
    const b = inb(0x60);
    // resync: первый байт пакета обязан иметь bit3=1 — иначе пропускаем
    if (mouse_pkt_n == 0 and (b & 0x08) == 0) {
        evdev_mouse.dropped += 1;
        return;
    }
    mouse_pkt[mouse_pkt_n] = b;
    mouse_pkt_n += 1;
    if (mouse_pkt_n < 3) return;
    mouse_pkt_n = 0;
    const md = evdev.parseMousePacket(mouse_pkt[0], mouse_pkt[1], mouse_pkt[2]);
    evdev.mousePacketToEvents(&evdev_mouse, md, mouse_btn_prev);
    mouse_btn_prev = evdev.buttonsOf(md);
}

fn handleSerial(frame: *InterruptFrame) void {
    _ = frame;
    // TODO: Serial port interrupt handler
}

// ============================================================================
// PIC (8259 Programmable Interrupt Controller)
// ============================================================================

pub const PIC = struct {
    const PIC1_CMD: u16 = 0x20;
    const PIC1_DATA: u16 = 0x21;
    const PIC2_CMD: u16 = 0xA0;
    const PIC2_DATA: u16 = 0xA1;

    const ICW1_ICW4: u8 = 0x01;
    const ICW1_INIT: u8 = 0x10;
    const ICW4_8086: u8 = 0x01;

    pub fn init() void {
        // Remap PIC: IRQ 0-15 → INT 32-47

        // ICW1: Init + ICW4 needed
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);

        // ICW2: Vector offsets
        outb(PIC1_DATA, 32); // Master: IRQ 0-7 → INT 32-39
        outb(PIC2_DATA, 40); // Slave:  IRQ 8-15 → INT 40-47

        // ICW3: Wiring
        outb(PIC1_DATA, 0x04); // Master: slave on IRQ2
        outb(PIC2_DATA, 0x02); // Slave: identity

        // ICW4: 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        outb(PIC2_DATA, ICW4_8086);

        // Mask ALL PIC interrupts — v0.7.3: the keyboard is routed via the
        // IO-APIC (IRQ1 -> vector 33, see IOAPIC.init) and the timer via the
        // Local APIC (vector 48). Keeping IRQ1 unmasked here as well caused
        // dual delivery of every scancode (PIC + IO-APIC are both wired to the
        // 8042 IRQ line). PIC stays initialized but fully masked.
        outb(PIC1_DATA, 0xFF); // Mask all master lines (keyboard via IO-APIC)
        outb(PIC2_DATA, 0xFF); // Mask all slave
    }

    pub fn sendEOI(irq: u8) void {
        if (irq >= 8) {
            outb(PIC2_CMD, 0x20); // EOI to slave
        }
        outb(PIC1_CMD, 0x20); // EOI to master
    }
};

// ============================================================================
// Programmable Interval Timer (PIT) — Calibration helper
// ============================================================================
pub const PIT = struct {
    const CH2_DATA: u16 = 0x42;
    const CMD: u16 = 0x43;
    const GATE: u16 = 0x61;

    /// Калибровка через PIT channel 2 (метод из OSDev, без побочных IRQ).
    /// Возвращает число APIC-тиков за calibration_ms миллисекунд.
    pub fn calibrateApicTicks(comptime calibration_ms: u32) u32 {
        // PIT работает на 1.193182 MHz
        const pit_freq: u32 = 1193182;
        const pit_count: u32 = pit_freq / (1000 / calibration_ms);

        // Включаем gate PIT ch2, отключаем спикер-выход
        const gate_val = inb(GATE);
        outb(GATE, (gate_val & 0xFC) | 0x01);

        // Mode 0 (one-shot), channel 2, lobyte/hibyte
        outb(CMD, 0b10110000);
        outb(CH2_DATA, @truncate(pit_count));
        outb(CH2_DATA, @truncate(pit_count >> 8));

        // Взводим APIC-таймер на максимум и засекаем сколько он "проедет"
        APIC.writeReg(APIC.REG_TIMER_DIV, APIC.DIV_BY_16);
        APIC.writeReg(APIC.REG_TIMER_INIT, 0xFFFFFFFF);

        // Ждём пока PIT ch2 (OUT, бит 5 порта 0x61) досчитает до 0
        while ((inb(GATE) & 0x20) == 0) {}

        const remaining = APIC.readReg(APIC.REG_TIMER_CURRENT);
        return 0xFFFFFFFF - remaining; // тиков APIC за calibration_ms
    }
};

// ============================================================================
// Local APIC
// Local APIC
// ============================================================================

pub const APIC = struct {
    pub const BASE_MSR = 0x0000001B;
    pub const DEFAULT_PHYS_BASE: u64 = 0xFEE00000;

    pub const REG_ID = 0x020;
    pub const REG_VERSION = 0x030;
    pub const REG_TPR = 0x080;
    pub const REG_EOI = 0x0B0;
    pub const REG_SVR = 0x0F0;
    pub const REG_ICR_LOW = 0x300;
    pub const REG_ICR_HIGH = 0x310;
    pub const REG_LVT_TIMER = 0x320;
    pub const REG_LVT_ERROR = 0x370;
    pub const REG_TIMER_INIT = 0x380;
    pub const REG_TIMER_CURRENT = 0x390;
    pub const REG_TIMER_DIV = 0x3E0;

    pub const SVR_APIC_ENABLE: u32 = 1 << 8;
    pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
    pub const LVT_MASKED: u32 = 1 << 16;
    pub const DIV_BY_16: u32 = 0x03;

    var base_addr: u64 = 0;

    pub fn init() void {
        Serial.puts("[APIC] Reading MSR 0x1B...\n");
        const msr_val = readMsr(BASE_MSR);
        Serial.puts("[APIC] MSR value: ");
        Serial.putHex(msr_val);
        Serial.puts("\n");

        base_addr = msr_val & 0xFFFFFF000;
        Serial.puts("[APIC] Base addr: ");
        Serial.putHex(base_addr);
        Serial.puts("\n");

        // Если APIC глобально выключен — включаем
        if ((msr_val & (1 << 11)) == 0) {
            Serial.puts("[APIC] Enabling APIC...\n");
            writeMsr(BASE_MSR, msr_val | (1 << 11));
        } else {
            Serial.puts("[APIC] APIC already enabled\n");
        }

        // Set Spurious Interrupt Vector Register
        Serial.puts("[APIC] Setting SVR...\n");
        writeReg(REG_SVR, SVR_APIC_ENABLE | 0xFF);

        // Set up timer
        Serial.puts("[APIC] Setting timer...\n");
        writeReg(REG_LVT_TIMER, 48 | LVT_TIMER_PERIODIC); // Vector 48 — avoids PIC IRQ0-15 conflict
        writeReg(REG_TIMER_DIV, DIV_BY_16);

        // Калибровка: считаем сколько APIC-тиков в 10мс, целимся в 100 Гц context-switch
        const ticks_per_10ms = PIT.calibrateApicTicks(10);
        writeReg(REG_TIMER_INIT, ticks_per_10ms);

        // Mask error LVT
        writeReg(REG_LVT_ERROR, LVT_MASKED);
        Serial.puts("[APIC] Timer configured via PIT calibration\n");
    }

    pub fn writeReg(offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        ptr.* = val;
    }

    pub fn readReg(offset: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(base_addr + offset);
        return ptr.*;
    }

    pub fn sendEOI() void {
        writeReg(REG_EOI, 0);
    }

    pub fn getId() u32 {
        return readReg(REG_ID) >> 24;
    }
};

// ============================================================================
// IO-APIC (I/O Advanced Programmable Interrupt Controller)
// ============================================================================
pub const IOAPIC = struct {
    const BASE_ADDR: u64 = 0xFEC00000;
    const REG_SEL: *volatile u32 = @ptrFromInt(BASE_ADDR);
    const REG_WIN: *volatile u32 = @ptrFromInt(BASE_ADDR + 0x10);

    pub fn write(reg: u32, val: u32) void {
        REG_SEL.* = reg;
        REG_WIN.* = val;
    }

    pub fn read(reg: u32) u32 {
        REG_SEL.* = reg;
        return REG_WIN.*;
    }

    pub fn init() void {
        // Redirection table entry for Keyboard (IRQ 1) -> Vector 33
        // 0x12: redirection register for IRQ1 low 32 bits (vector 33, active high, edge triggered)
        // 0x13: redirection register for IRQ1 high 32 bits (destination APIC ID 0)
        write(0x12, 33);
        write(0x13, 0);
        Serial.puts("[IOAPIC] Keyboard redirection configured (IRQ1 -> Vector 33)\n");
        // v0.19.0 (CDD №10 p2): мышь — IRQ12 (GSI 12) → вектор 44.
        // Редирект-таблица: IRQ n → рег-ры 0x10+2n (low) / 0x11+2n (high).
        write(0x28, 44);
        write(0x29, 0);
        Serial.puts("[IOAPIC] Mouse redirection configured (IRQ12 -> Vector 44)\n");
    }
};

// ============================================================================
// PS/2 Keyboard Driver & Buffer
// ============================================================================
var kbd_shift: bool = false;
var kbd_ctrl: bool = false;
var kbd_alt: bool = false;
var kbd_extended: bool = false;

// v0.7.3: CORRECT Set 1 layout. The old table was shifted by one position
// from 0x10 onward (Tab at 0x10 instead of 0x0F), which zeroed 'a'/'s'/'d'
// (scan 0x1E-0x20 mapped to 0) and made Enter map to ']' and Ctrl to '\n'.
const scan_to_ascii = [128]u8{
    // 0x00-0x0F: 0, ESC, 1-9, 0, -, =, Backspace, Tab
    0, 0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', '\t',
    // 0x10-0x1F: q..p, [, ], Enter, LCtrl, a, s
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 'a', 's',
    // 0x20-0x2F: d..l, ;, ', `, LShift, \, z, x, c, v
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
    // 0x30-0x3F: b, n, m, comma, dot, slash, RShift, keypad-*, LAlt, Space
    'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    // 0x40-0x7F: unused in base Set 1
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const scan_to_ascii_shift = [128]u8{
    // 0x00-0x0F
    0, 0x1B, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', '\t',
    // 0x10-0x1F
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 'A', 'S',
    // 0x20-0x2F
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
    // 0x30-0x3F
    'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
    // 0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

var kbd_buffer: [256]u8 = undefined;
var kbd_head: usize = 0;
var kbd_tail: usize = 0;

// v0.7.3: kbd_head/kbd_tail are shared between the IRQ1 handler (producer,
// handleKeyboard → kbd_push) and the shell task (consumer, kbd_poll loop →
// kbd_pop). Plain loads could be cached in a register across the polling
// loop by the compiler (it cannot see async interrupt writes). Atomics are
// also the correct compiler barrier here.
pub fn kbd_push(ch: u8) void {
    const head = @atomicLoad(usize, &kbd_head, .monotonic);
    const tail = @atomicLoad(usize, &kbd_tail, .monotonic);
    const next = (head + 1) % kbd_buffer.len;
    if (next != tail) {
        kbd_buffer[head] = ch;
        @atomicStore(usize, &kbd_head, next, .release);
    }
}

pub fn kbd_pop() u8 {
    const tail = @atomicLoad(usize, &kbd_tail, .monotonic);
    const head = @atomicLoad(usize, &kbd_head, .acquire);
    if (head == tail) return 0;
    const ch = kbd_buffer[tail];
    @atomicStore(usize, &kbd_tail, (tail + 1) % kbd_buffer.len, .release);
    return ch;
}

fn kbd_init() void {
    // Flush pending data from keyboard controller
    while ((inb(0x64) & 0x01) != 0) {
        _ = inb(0x60);
    }

    // Disable keyboard port temporarily during reconfiguration
    outb(0x64, 0xAD);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Read current controller command byte
    outb(0x64, 0x20);
    while ((inb(0x64) & 0x01) == 0) {} // Wait for output buffer full
    var config = inb(0x60);

    // Print initial config for debugging
    Serial.puts("[KBD] Initial controller config: 0x");
    Serial.putHex(config);
    Serial.puts("\n");

    // Set config: enable IRQ1 (bit 0), enable keyboard port (clear bit 4)
    // EXPLICITLY enable translation mode (bit 6 = 0x40)
    // When translation is ON, the PS/2 controller converts
    // Set 2 scancodes from the keyboard into Set 1 before
    // delivering them to us. Our scan_to_ascii table uses Set 1.
    //
    // CRITICAL: Do NOT send 0xF0 0x01 to set scancode set 1 on the keyboard!
    // If translation is ON (bit 6) AND keyboard is in Set 1,
    // the controller's translate_table will mangle the Set 1 codes
    // (double translation). Leave keyboard in default Set 2 and
    // let the controller translate Set 2 → Set 1 for us.
    config |= 0x01;              // Enable IRQ1
    config &= ~@as(u8, 0x10);    // Enable keyboard port (bit 4 clear = enabled)
    config |= 0x40;              // EXPLICITLY enable translation (bit 6)
    // This converts Set 2 scancodes → Set 1 before delivering to port 0x60.
    // QEMU does NOT always have bit 6 set by default — if we don't set it,
    // we get raw Set 2 codes but our scan_to_ascii table is Set 1 = wrong chars!

    // Write command byte back
    outb(0x64, 0x60);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty
    outb(0x60, config);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Re-enable keyboard port
    outb(0x64, 0xAE);
    while ((inb(0x64) & 0x02) != 0) {} // Wait for input buffer empty

    // Reset keyboard (0xFF) — this resets to default Set 2 mode
    outb(0x60, 0xFF);
    // Wait for BAT completion (ACK 0xFA + BAT OK 0xAA)
    var timeout: u32 = 0;
    var got_bat: bool = false;
    while (timeout < 100000) : (timeout += 1) {
        if ((inb(0x64) & 0x01) != 0) {
            const resp = inb(0x60);
            if (resp == 0xAA) {
                got_bat = true;
                break;
            }
            // Consume ACK (0xFA) and keep waiting for BAT (0xAA)
        }
    }
    if (!got_bat) {
        Serial.puts("[KBD] WARNING: Keyboard BAT not received\n");
    }

    // Drain any remaining bytes after reset
    while ((inb(0x64) & 0x01) != 0) {
        _ = inb(0x60);
    }

    // DO NOT send 0xF0 0x01 to set scancode set 1!
    // The PS/2 controller's translation mode (bit 6) already converts
    // Set 2 → Set 1 for us. Setting Set 1 on the keyboard while
    // translation is ON causes double translation = wrong characters.
    // Just leave the keyboard in its default Set 2 mode and let
    // the controller handle the translation.

    kbd_head = 0;
    kbd_tail = 0;
    // Print the final config byte for debugging
    Serial.puts("[KBD] Controller config byte: 0x");
    Serial.putHex(config);
    Serial.puts(" (bit6=translate should be 1)\n");
    Serial.puts("[KBD] Keyboard initialized (Set 2 → Set 1 translation via controller)\n");
}

// Global print and clear screen functions (registered by main kernel)
pub var print_fn: ?*const fn ([]const u8) void = null;
pub var clear_screen_fn: ?*const fn () void = null;

// ============================================================================
// Page Table Flags
// Page table flags
// ============================================================================

pub const PAGE = struct {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NX: u64 = 1 << 63;

    pub const KERNEL_RW: u64 = PRESENT | WRITABLE;
    pub const KERNEL_RX: u64 = PRESENT;
    pub const USER_RW: u64 = PRESENT | WRITABLE | USER;
    pub const USER_RX: u64 = PRESENT | USER;
};

// ============================================================================
// TSS (Task State Segment)
// Task State Segment
// ============================================================================

pub const TSS = packed struct {
    _reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
};

// IST1 stack for Double Fault (#DF, vector 8)
var ist1_stack: [4096]u8 align(16) = undefined;

// TSS.rsp0: пишет ТОЛЬКО диспетчеризация (schedule→setKernelStack) —
// иретк-авторитет. Зеркало ниже экспортировано для isr64.S (Zig не
// экспортирует packed struct): пишется в setKernelStack АТОМАРНО там же
// (IF=0 ISR-контекста) — рассинхрон-иммунный источник syscall-стека.
var tss: TSS = .{
    ._reserved0 = 0,
    .rsp0 = 0,
    .rsp1 = 0,
    .rsp2 = 0,
    ._reserved1 = 0,
    .ist1 = 0,
    .ist2 = 0,
    .ist3 = 0,
    .ist4 = 0,
    .ist5 = 0,
    .ist6 = 0,
    .ist7 = 0,
    ._reserved2 = 0,
    ._reserved3 = 0,
    .iomap_base = 104,
};

/// v0.17.0-fix (CDD №8 p6): зеркало TSS.rsp0 для isr64.S (символ tss —
/// локальный; packed struct не экспортируется) — единый писец: диспетчеризация.
pub export var tss_rsp0_mirror: u64 = 0;

pub fn setKernelStack(stack: u64) void {
    tss.rsp0 = stack;
    tss_rsp0_mirror = stack;
}

/// v0.17.0-fix (CDD №8 p6): kstack-топ ИСПОЛНЯЮЩЕЙ задачи (TSS.rsp0) —
/// тот же источник, что и syscall-вход в isr64.S (callbackDone: кадр
/// колбэка обязан лежать на стеке владельца исполнения).
pub fn getKernelStackTop() u64 {
    return tss.rsp0;
}

// ============================================================================
// Serial Port (для early debug)
// ============================================================================

pub const Serial = struct {
    const COM1: u16 = 0x3F8;

    pub fn init() void {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB
        outb(COM1 + 0, 0x01); // Baud divisor low = 1 → 115200
        outb(COM1 + 1, 0x00); // Baud divisor high = 0
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // Enable RTS/DSR/DTR
    }

    pub fn puts(str: []const u8) void {
        for (str) |ch| {
            if (ch == '\n') {
                while ((inb(COM1 + 5) & 0x20) == 0) {}
                outb(COM1, '\r');
            }
            while ((inb(COM1 + 5) & 0x20) == 0) {}
            outb(COM1, ch);
        }
    }

    pub fn putHex(val: u64) void {
        const hex = "0123456789ABCDEF";
        puts("0x");
        var i: usize = 60;
        while (true) {
            puts(&.{hex[@intCast((val >> @intCast(i)) & 0xF)]});
            if (i == 0) break;
            i -= 4;
        }
    }

    /// CDD №12 p5: hex-байт БЕЗ префикса и ведущих нулей 0x.. — для
    /// RIP-bytes-строки опкодов (плотный дамп fault-инструкции).
    pub fn putHexByte(val: u8) void {
        const hex = "0123456789ABCDEF";
        puts(&.{hex[val >> 4]});
        puts(&.{hex[val & 0xF]});
    }

    pub fn putDecimal(val: u64) void {
        if (val == 0) {
            puts("0");
            return;
        }
        var buf: [20]u8 = undefined;
        var i: usize = 20;
        var temp = val;
        while (temp > 0) {
            i -= 1;
            buf[i] = '0' + @as(u8, @intCast(temp % 10));
            temp /= 10;
        }
        puts(buf[i..20]);
    }
};

pub fn initSyscalls(handler_addr: u64) void {
    // CDD №12 p12: XSAVE-детект (boot64.S уже включил OSXSAVE+XCR0=0x207
    // при AVX; здесь — зеркальная проверка выбора пути fpuSave/Restore).
    {
        const cr4: u64 = asm volatile ("movq %%cr4, %[v]"
            : [v] "=r" (-> u64)
        );
        var eax: u32 = undefined;
        var ebx: u32 = undefined;
        var ecx: u32 = undefined;
        var edx: u32 = undefined;
        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 1)),
        );
        // ECX[26]=XSAVE, ECX[28]=AVX, CR4[18]=OSXSAVE
        xsave_enabled = (cr4 & (@as(u64, 1) << 18)) != 0 and
            (ecx & (@as(u32, 1) << 26)) != 0 and
            (ecx & (@as(u32, 1) << 28)) != 0;
        Serial.puts("[HAL] FPU: xsave=");
        Serial.puts(if (xsave_enabled) "ON" else "OFF");
        Serial.puts("\n");
    }
    // 1. Enable System Call Extensions (SCE) in EFER MSR
    const efer = readMsr(MSR.EFER);
    writeMsr(MSR.EFER, efer | EFER.SCE);

    // 2. Set segment selectors in STAR MSR (0xC0000081)
    const star: u64 = (@as(u64, 0x10) << 48) | (@as(u64, 0x08) << 32);
    writeMsr(MSR.STAR, star);

    // 3. Set entry point in LSTAR MSR (0xC0000082)
    writeMsr(MSR.LSTAR, handler_addr);

    // 4. Set RFLAGS mask in SFMASK MSR (0xC0000084)
    const sfmask: u64 = (1 << 9) | (1 << 10);
    writeMsr(MSR.SFMASK, sfmask);

    Serial.puts("[HAL] Syscall mechanism initialized\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// CDD №12 p4-final: R15-POISON-детект. isr64.S зовёт ЭТО при восстановлении
// R15 из кадра (ISR-выход/iretq и syscall-выход/sysretq), если значение =
// 0xAAAAAAAAAAAAAAAA — паттерн Zig-Debug `undefined`-локалей ядра. Вызов из
// asm-хвоста pop-последовательности: caller-saved (rax/rcx/rdx/rsi/rdi/
// r8-r11) ещё будут перезаписаны НИЖЕЛЕЖАЩИМИ pop'ами — их можно калечить;
// callee-saved (rbx/rbp/r12-r15) обязаны быть нетронутыми здесь (наш
// пролог корректен). Печать — ТОЛЬКО первые 4 раза (анти-спам).
// ═══════════════════════════════════════════════════════════════════════════
var r15_poison_count: u32 = 0; // p12-форензика: лимит печати поднят (см. ниже)

pub export fn r15_poison_report(msg: [*:0]const u8, slot: u64) callconv(.C) void {
    r15_poison_count += 1;
    if (r15_poison_count <= 60) { // p12-форензика: 4 → 60 (EXIT/ENTRY не глушить)
        // ручной strlen (freestanding, std не импортирован в hal)
        var len: usize = 0;
        while (msg[len] != 0) : (len += 1) {}
        Serial.puts(msg[0..len]);
        Serial.putHex(slot);
        Serial.puts(" rip-кадр=0x");
        // слот r15 = slot - 8*1 (r14 сверху? нет: pop r15 снял СВОЙ слот,
        // rsp указывает на r14-слот; r15-слот = slot - 8). RIP-кадр дальше.
        Serial.putHex(slot - 8);
        Serial.puts(" n=");
        Serial.putDecimal(r15_poison_count);
        // CDD №12 p12-ФОРЕНЗИКА: геометрия — чей kstack содержит слот,
        // оффсет от топа (или «вне kstack-ов» = поля Task/другая .bss).
        {
            const sched = @import("scheduler.zig");
            var found = false;
            var i: usize = 0;
            while (i < sched.MAX_TASKS) : (i += 1) {
                if (sched.kstack_hi_tab[i] != 0 and slot >= sched.kstack_lo_tab[i] and slot < sched.kstack_hi_tab[i]) {
                    found = true;
                    Serial.puts(" [GEOM task=");
                    Serial.putDecimal(i);
                    Serial.puts(" top=0x");
                    Serial.putHex(sched.kstack_hi_tab[i]);
                    Serial.puts(" off_from_top=");
                    Serial.putDecimal(sched.kstack_hi_tab[i] - slot);
                    Serial.puts(" taskbase=0x");
                    Serial.putHex(sched.kstack_lo_tab[i]);
                    Serial.puts("]");
                    break;
                }
            }
            if (!found) {
                Serial.puts(" [GEOM: вне kstack-таблиц!]");
                // чей это адрес в .bss? — скан всей tasks[] (поля вокруг kstack)
                var j: usize = 0;
                while (j < sched.MAX_TASKS) : (j += 1) {
                    const lo = sched.kstack_lo_tab[j];
                    if (lo == 0) continue;
                    const tbase = lo - 32; // id/state/priv/rsp до kernel_stack
                    const tend = tbase + 131072 + 864; // kstack + хвост-поля (fpu)
                    if (slot >= tbase and slot < tend) {
                        Serial.puts(" [TASK-STRUCT task=");
                        Serial.putDecimal(j);
                        Serial.puts(" kstack_top=0x");
                        Serial.putHex(lo + 131072);
                        Serial.puts(" slot_minus_top=");
                        Serial.putDecimal(slot - (lo + 131072));
                        Serial.puts("]");
                        break;
                    }
                }
            }
        }
        Serial.puts("\n");
    }
}

// CDD №12 p12-ФИКС3: SYSCALL-FPU — ПЕР-ТАСК .bss-СТРОКА (НЕ стек-локал!).
// ГЕОМЕТРИЧЕСКИЙ КОРЕНЬ p12-регрессии: стек-локал 832Б (and $-64 + sub
// $0x400 + Zig-Debug 0xAA-филлы) растянул кадр обёртки до [top-1168,
// top-128) — верх кадра затирал [top-176, top-128) = GPR-слоты STALE-
// кадра таймер-преэмпции из userspace (R15@top-176!). p11-обёртка была
// тонкой ([top-168, top-128)) — 8Б-зазор хранил R15-слот нетронутым.
// Диспетчеризация stale-кадра (frameContentValid меряет ТОЛЬКО CS/RIP —
// их перезаписал живой каскад ТЕКУЩЕГО syscall!) доставляла юзеру
// R15=0xAAAA → #GP (TRIPWIRE: живой frame.r15=0xAAAA, cs=0x23, in_sys=0;
// EXIT/ENTRY-POISON молчали — доставка минуя syscall-выход).
// СТРОКИ ПЕР-ТАСК: владелец по user_rsp (как syscall_exit_frame);
// парк-безопасность по конструкции (чужие syscall пишут свои строки);
// fallback для владельца вне таблиц (shell — без парковок).
pub export fn zig_syscall_handler(arg1: u64, arg2: u64, arg3: u64, arg4: u64, syscall_num: u64, arg5: u64) callconv(.C) u64 {
    const sched = @import("scheduler.zig");
    const owner = sched.syscallStackOwner(sched.user_rsp);
    var rc: u64 = undefined;
    if (owner != 255 and owner < sched.MAX_TASKS and owner != 0) {
        fpuSave(&sched.syscall_fpu_frame[owner]);
        rc = zig_syscall_handler_inner(arg1, arg2, arg3, arg4, syscall_num, arg5);
        fpuRestore(&sched.syscall_fpu_frame[owner]);
    } else {
        fpuSave(&sched.syscall_fpu_fallback);
        rc = zig_syscall_handler_inner(arg1, arg2, arg3, arg4, syscall_num, arg5);
        fpuRestore(&sched.syscall_fpu_fallback);
    }
    return rc;
}

pub fn zig_syscall_handler_inner(arg1: u64, arg2: u64, arg3: u64, arg4: u64, syscall_num: u64, arg5: u64) callconv(.C) u64 {

    // CDD №12 p7: ВЫХОДНОЙ КАДР В .BSS — СНАПШОТ ПЕРВОЙ ОПЕРАЦИЕЙ (каскад
    // asm уже построен на kstack-топе владельца; транзакция IF=0 — никто
    // не переключил). Далее ЛЮБАЯ порча [top-112, top) не влияет на регист-
    // ровый поток гостя: asm-выход читает регистры из .bss-снапшота.
    {
        const sched7 = @import("scheduler.zig");
        sched7.snapshotExitFrame(sched7.syscallStackOwner(sched7.user_rsp));
        sched7.reportExitPoison();
        // CDD №12 p9: ENTRY-POISON — на ВХОДЕ syscall регистр гостя уже
        // 0xAAAA (доставка СОВЕРШИЛАСЬ после предыдущего выхода; все
        // exit-пути под детекторами и чисты ⇒ яд загружен из user-памяти).
        // Немедленный принт: слоты r15..rbx + user_rsp; предыдущая строка
        // [L]-трейса = syscall-выход-виновник (или пользовательский код).
        {
            const sf = &sched7.syscall_frame;
            if (sf[0] == 0xAAAAAAAAAAAAAAAA or sf[1] == 0xAAAAAAAAAAAAAAAA or
                sf[2] == 0xAAAAAAAAAAAAAAAA or sf[3] == 0xAAAAAAAAAAAAAAAA or
                sf[4] == 0xAAAAAAAAAAAAAAAA or sf[5] == 0xAAAAAAAAAAAAAAAA)
            {
                Serial.puts("[ENTRY-POISON] syscall#=");
                Serial.putDecimal(syscall_num);
                Serial.puts(" ur=0x");
                Serial.putHex(sched7.user_rsp);
                Serial.puts(" r15=0x");
                Serial.putHex(sf[0]);
                Serial.puts(" r14=0x");
                Serial.putHex(sf[1]);
                Serial.puts(" r13=0x");
                Serial.putHex(sf[2]);
                Serial.puts(" r12=0x");
                Serial.putHex(sf[3]);
                Serial.puts(" rbp=0x");
                Serial.putHex(sf[4]);
                Serial.puts(" rbx=0x");
                Serial.putHex(sf[5]);
                Serial.puts("\n");
            }
        }
    }
    // arg3/arg4/arg5 — позиционные rdx/rcx/r9: для syscall №6 это Win64-аргументы

    // v0.18.0 (CDD №9): Linux POSIX-слой. Если текущая задача — Linux-ABI
    // (ELF/Starnix), ВСЕ syscall'ы идут по Linux x86_64 конвенции: номер в
    // RAX (syscall_num), аргументы RDI/RSI/RDX/R10 (позиционные arg1-4);
    // user R8/R9 колбэк читает сам из scheduler.linux_arg5/6 (asm-вход).
    // Win32-задачи не заходят сюда — АБИ решается ДО легаси-свича
    // (Linux SYS_write=1 коллидит с легаси-вектором «print» №1).
    // БИСЕКТ-ИНСТРУМЕНТАЦИЯ: сверка cks против kstack-топа ТЕКУЩЕЙ задачи —
    // вход syscall по несвежему cks = спрей каскада Zig на ЧУЖОЙ kstack
    // (гипотеза корня cks-гонки; лог только при dbg_sched_trace).
    // v2: ГЛАВНОЕ — физический владелец стека каскада (по RСП вызова):
    // чей kstack реально занял syscall-каскад (± небольшой допуск вниз
    // от топа — каскад уходит вглубь от cks-топа).
    {
        const sched = @import("scheduler.zig");
        if (sched.dbg_entry_trace) {
            // v0.18.1-бисект: [E]-трейс — RSP НА ВХОДЕ обработчика (после
            // asm-каскада): сверка с kSleepTask-цепочкой ([RESUME] chain)
            // вычисляет ФАКТИЧЕСКУЮ глубину Zig-каскада (подозрение на
            // 58КБ — переполнение 32КБ kstack).
            const esp: u64 = asm volatile ("movq %%rsp, %[v]"
                : [v] "=r" (-> u64)
            );
            Serial.puts("[E] num=");
            Serial.putDecimal(syscall_num);
            Serial.puts(" sp=0x");
            Serial.putHex(esp);
            Serial.puts("\n");
            const my_top = sched.taskKstackTop(sched.current_task_id);
            if (sched.current_task_id != 0 and sched.current_kernel_stack != my_top) {
                Serial.puts("[SYN!] syscall-вход: cur=");
                Serial.putDecimal(sched.current_task_id);
                Serial.puts(" cks=0x");
                Serial.putHex(sched.current_kernel_stack);
                Serial.puts(" СВОЙ_топ=0x");
                Serial.putHex(my_top);
                Serial.puts(" num=");
                Serial.putDecimal(syscall_num);
                Serial.puts("\n");
            }
            // [S]-трейс: каскад лёг на kstack какой задачи (call-автор по RSP)?
            // Используем RSP вызывающего кадра (asm уже спустил 8 слов + ret):
            const sp: u64 = asm volatile ("movq %%rsp, %[v]"
                : [v] "=r" (-> u64)
            );
            const owner = sched.stackOwner(sp);
            if (owner != sched.current_task_id) {
                Serial.puts("[S!] чужой-стек: cur=");
                Serial.putDecimal(sched.current_task_id);
                Serial.puts(" каскад на kstack=");
                Serial.putDecimal(owner);
                Serial.puts(" num=");
                Serial.putDecimal(syscall_num);
                Serial.puts(" sp=0x");
                Serial.putHex(sp);
                Serial.puts("\n");
            }
        }
    }
    if (taskAbiLinuxCallback) |is_linux| {
        if (is_linux()) {
            if (linuxSyscallCallback) |cb| {
                return cb(syscall_num, arg1, arg2, arg3, arg4);
            }
        }
    }

    // Re-enable interrupts — syscall clears IF via SFMASK, but we need
    // timer interrupts to fire for preemptive scheduling. IF will be
    // restored from R11 on sysretq anyway.
    sti();

    switch (syscall_num) {
        1 => {
            // Syscall 1: Print string
            // arg1 = pointer to string, arg2 = length
            const ptr: [*]const u8 = @ptrFromInt(arg1);
            const len: usize = @intCast(arg2);
            const slice = ptr[0..len];
            if (print_fn) |f| {
                f(slice);
            } else {
                Serial.puts(slice);
            }
            return 0;
        },
        2 => {
            // Syscall 2: Read key (non-blocking)
            return kbd_pop();
        },
        3 => {
            // Syscall 3: Clear screen
            if (clear_screen_fn) |f| {
                f();
            }
            return 0;
        },
        4 => {
            // Syscall 4: Exit — terminate the calling user process
            // arg1 = exit code (unused for now)
            // This sets the current task to Killed state.
            // The scheduler will skip Killed tasks on next tick.
            Serial.puts("[SYSCALL] exit(");
            Serial.putDecimal(arg1);
            Serial.puts(") — killing user process\n");

            // Import scheduler to kill the current task.
            // We can't import scheduler directly (circular dep), so we use
            // a function pointer callback, similar to timerTickCallback.
            if (exitCallback) |cb| {
                cb();
            }
            // The task should never reach here — the scheduler will
            // have marked it as Killed and won't return to it.
            // But just in case, spin forever.
            while (true) {
                asm volatile ("pause");
            }
        },
        5 => {
            // Syscall 5: Yield — voluntarily give up CPU time
            // The scheduler will pick the next Ready task on the next tick.
            // For now, this is a no-op since the APIC timer preempts anyway.
            // In the future, this could trigger an immediate reschedule.
            return 0;
        },
        6 => {
            // Syscall 6: win32_call — CDD-цикл №1 (v0.10.0)
            // Вызывается syscall-трамплином стаба (win32_stubs.zig, .impl):
            //   rdi (arg1)      = entry_id в реестре стабов
            //   rsi (arg2)      = Win64-arg1 (RCX)
            //   rdx (arg3)      = Win64-arg2 (RDX)
            //   r10→rcx (arg4)  = Win64-arg3 (R8)
            //   r9  (arg5, 6-й параметр — читается прямо из регистра) = Win64-arg4
            // Возврат — в RAX приложения (sysretq).
            if (win32SyscallCallback) |cb| {
                return cb(arg1, arg2, arg3, arg4, arg5);
            }
            Serial.puts("[SYSCALL] win32_call: нет win32SyscallCallback\n");
            return 0;
        },
        7 => {
            // Syscall 7: win32_cb_done — v0.12.0 (CDD №3): trampoline
            // Win64-колбэка (InitOnceExecuteOnce) отчитался о завершении:
            //   rdi (arg1) = cookie моста, rsi (arg2) = результат колбэка (RAX).
            // Ядро восстанавливает СОХРАНЁННЫЙ syscall-кадр (win32_api.
            // callbackDone) → asm-попы → sysretq → возврат в точку ПОСЛЕ
            // исходного syscall'а InitOnce с RAX=TRUE/FALSE.
            if (win32CbDoneCallback) |cb| {
                return cb(arg1, arg2);
            }
            Serial.puts("[SYSCALL] win32_cb_done: нет win32CbDoneCallback\n");
            return 0;
        },
        else => {
            Serial.puts("[SYSCALL] Unknown syscall: ");
            Serial.putDecimal(syscall_num);
            Serial.puts("\n");
            return @as(u64, @bitCast(@as(i64, -1)));
        }
    }
}

// Exit callback — registered by scheduler at init to break circular dependency
pub var exitCallback: ?*const fn () callconv(.C) void = null;

// Win32 syscall dispatch — registered by main64 (hal ↔ win32_api circular-dep breaker).
// arg-порядок = syscall-конвенция трамплина: (entry_id, w64arg1, w64arg2, w64arg3, w64arg4).
pub var win32SyscallCallback: ?*const fn (entry_id: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 = null;

// v0.12.0 (CDD №3): syscall #7 — trampoline Win64-колбэка (InitOnce) отчитался:
// (cookie, результат). Возврат попадает в RAX восстановленного исходного syscall'а.
pub var win32CbDoneCallback: ?*const fn (cookie: u64, result: u64) u64 = null;

/// v0.18.0 (CDD №9): Linux POSIX RAX-ABI маршрутизация. Linux-задачи
/// (ELF, Starnix-модель) шлют номер syscall в RAX: hal решает АБИ ДО
/// легаси-свич (Linux SYS_write=1 коллидит с легаси-вектором «print»).
/// Регистрируется из main64 (разрывает цикл hal↔main64/scheduler).
pub var taskAbiLinuxCallback: ?*const fn () callconv(.C) bool = null;
pub var linuxSyscallCallback: ?*const fn (num: u64, a1: u64, a2: u64, a3: u64, a4: u64) u64 = null;

// int3 CDD callback — registered by main64. Вызывается из handleException
// для вектора 3 (#BP) ПЕРВЫМ: если адрес принадлежит стабу win32_stubs,
// обработчик сам логирует имя (первый hit), продвигает RIP (skip int3)
// и возвращает true — задача продолжает работу с rax=0. Возврат false →
// обычный путь (user-kill / kernel-panic).
pub var int3Callback: ?*const fn (frame: *InterruptFrame) bool = null;

// ============================================================================
// HAL Initialization
// ============================================================================

pub fn init() void {
    // 1. Initialize serial port (early debug)
    Serial.init();
    Serial.puts("[HAL] Serial port initialized\n");

    // 2. GDT — Initialize and load our own 64-bit GDT
    GDT.init();
    Serial.puts("[HAL] GDT loaded\n");

    // 3. Initialize IDT (using ISR stubs from isr64.S)
    IDT.init();
    Serial.puts("[HAL] IDT loaded\n");

    // 4. Initialize PIC (remap IRQs)
    PIC.init();
    Serial.puts("[HAL] PIC remapped\n");

    // 5. TSS — Initialize Task State Segment + IST1 for Double Fault
    tss.ist1 = @intFromPtr(&ist1_stack) + ist1_stack.len;
    GDT.setTSS(0, @intFromPtr(&tss), @sizeOf(TSS) - 1);
    ltr(0x28);
    Serial.puts("[HAL] TSS loaded (IST1 for #DF at ");
    Serial.putHex(tss.ist1);
    Serial.puts(")\n");

    // 6. Initialize Local APIC
    APIC.init();
    Serial.puts("[HAL] Local APIC initialized\n");

    // 6.5. Initialize IO-APIC & Keyboard
    IOAPIC.init();
    kbd_init();

    // 7. Enable interrupts!
    sti();
    Serial.puts("[HAL] Interrupts enabled\n");
}

// ============================================================================
// VGA Text Mode Initialization — Program VGA registers for 80x25 text mode
// ============================================================================
//
// Switches VGA from any mode (including VBE graphical) to standard
// 80x25 text mode at 0xB8000. Works from 64-bit long mode without BIOS.
// Based on Linux vgacon, IBM VGA spec, and Rust vga crate.
//
// This is needed because GRUB may leave the VGA controller in graphical
// (VBE) mode. In that state, writing to 0xB8000 has no visible effect —
// the CRTC scans the linear framebuffer, not the text plane.
//
// After calling this, the VGA text buffer at 0xB8000 is active and
// characters written there appear on screen immediately.

pub fn vgaSetTextMode() void {
    // Step 1: Assert synchronous reset on sequencer (disables display)
    vgaWriteIndexed(0x3C4, 0x3C5, 0x00, 0x01);

    // Step 2: Set Miscellaneous Output Register
    // 0x67 = Color I/O, CPU access, 25MHz clock, 400 scan lines
    outb(0x3C2, 0x67);

    // Step 3: Program Sequencer registers
    vgaWriteIndexed(0x3C4, 0x3C5, 0x01, 0x00); // Clocking: 9-dot, screen on
    vgaWriteIndexed(0x3C4, 0x3C5, 0x02, 0x03); // Plane mask: enable planes 0,1
    vgaWriteIndexed(0x3C4, 0x3C5, 0x03, 0x00); // Font: map 0
    vgaWriteIndexed(0x3C4, 0x3C5, 0x04, 0x02); // Memory: odd/even, >64KB

    // De-assert sequencer reset
    vgaWriteIndexed(0x3C4, 0x3C5, 0x00, 0x03);

    // Step 4: Unlock CRTC registers (clear protect bit)
    vgaWriteIndexed(0x3D4, 0x3D5, 0x11, 0x00);

    // Step 5: Program CRTC registers for 80x25 text (720x400, 70Hz)
    const crtc = [_][2]u8{
        .{ 0x00, 0x5F }, // Horizontal Total
        .{ 0x01, 0x4F }, // Horizontal Display End (80 chars)
        .{ 0x02, 0x50 }, // Horizontal Blanking Start
        .{ 0x03, 0x82 }, // Horizontal Blanking End
        .{ 0x04, 0x55 }, // Horizontal Sync Start
        .{ 0x05, 0x81 }, // Horizontal Sync End
        .{ 0x06, 0xBF }, // Vertical Total
        .{ 0x07, 0x1F }, // Overflow
        .{ 0x08, 0x00 }, // Preset Row Scan
        .{ 0x09, 0x4F }, // Maximum Scan Line (16 scanlines/char)
        .{ 0x0A, 0x0D }, // Text Cursor Start
        .{ 0x0B, 0x0E }, // Text Cursor End
        .{ 0x0C, 0x00 }, // Start Address High
        .{ 0x0D, 0x00 }, // Start Address Low
        .{ 0x0E, 0x00 }, // Cursor Location High
        .{ 0x0F, 0x50 }, // Cursor Location Low
        .{ 0x10, 0x9C }, // Vertical Sync Start
        .{ 0x11, 0x8E }, // Vertical Sync End (bit 7=1 re-protects)
        .{ 0x12, 0x8F }, // Vertical Display End (399 = 25*16-1)
        .{ 0x13, 0x28 }, // Offset (40 = 80/2 word mode)
        .{ 0x14, 0x1F }, // Underline Location
        .{ 0x15, 0x96 }, // Vertical Blanking Start
        .{ 0x16, 0xB9 }, // Vertical Blanking End
        .{ 0x17, 0xA3 }, // Mode Control (word mode, sync enabled)
        .{ 0x18, 0xFF }, // Line Compare
    };
    for (&crtc) |reg| {
        vgaWriteIndexed(0x3D4, 0x3D5, reg[0], reg[1]);
    }

    // Step 6: Program Graphics Controller registers
    const gc = [_][2]u8{
        .{ 0x00, 0x00 }, // Set/Reset
        .{ 0x01, 0x00 }, // Enable Set/Reset
        .{ 0x02, 0x00 }, // Color Compare
        .{ 0x03, 0x00 }, // Data Rotate
        .{ 0x04, 0x00 }, // Read Plane Select
        .{ 0x05, 0x10 }, // Graphics Mode: odd/even (text mode)
        .{ 0x06, 0x0E }, // Miscellaneous: TEXT MODE, B8000 mapping
        .{ 0x07, 0x00 }, // Color Don't Care
        .{ 0x08, 0xFF }, // Bit Mask
    };
    for (&gc) |reg| {
        vgaWriteIndexed(0x3CE, 0x3CF, reg[0], reg[1]);
    }

    // Step 7: Blank screen to unlock attribute palette
    _ = inb(0x3DA); // Reset attribute controller flip-flop
    outb(0x3C0, 0x00); // Index 0, blanked (bit 5=0)

    // Step 8: Program Attribute Controller registers
    const ac_palette = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    for (&ac_palette, 0..) |val, idx| {
        outb(0x3C0, @intCast(idx)); // Write index
        outb(0x3C0, val); // Write data
    }
    outb(0x3C0, 0x10); outb(0x3C0, 0x0C); // Mode: text, 9-dot, blink
    outb(0x3C0, 0x11); outb(0x3C0, 0x00); // Overscan: black
    outb(0x3C0, 0x12); outb(0x3C0, 0x0F); // Plane enable: all
    outb(0x3C0, 0x13); outb(0x3C0, 0x08); // Horizontal panning
    outb(0x3C0, 0x14); outb(0x3C0, 0x00); // Color select

    // Step 9: Unblank screen (enable display)
    _ = inb(0x3DA); // Reset flip-flop
    outb(0x3C0, 0x20); // Set bit 5 = enable display

    // Step 10: Initialize DAC palette (16 standard VGA colors)
    outb(0x3C8, 0x00); // DAC write index = 0
    // Standard 16 VGA colors (6-bit RGB: 0x00=0, 0x2A=42, 0x15=21, 0x3F=63)
    const palette = [_][3]u8{
        .{ 0x00, 0x00, 0x00 }, // 0: Black
        .{ 0x00, 0x00, 0x2A }, // 1: Blue
        .{ 0x00, 0x2A, 0x00 }, // 2: Green
        .{ 0x00, 0x2A, 0x2A }, // 3: Cyan
        .{ 0x2A, 0x00, 0x00 }, // 4: Red
        .{ 0x2A, 0x00, 0x2A }, // 5: Magenta
        .{ 0x2A, 0x15, 0x00 }, // 6: Brown
        .{ 0x2A, 0x2A, 0x2A }, // 7: Light Gray
        .{ 0x15, 0x15, 0x15 }, // 8: Dark Gray
        .{ 0x15, 0x15, 0x3F }, // 9: Light Blue
        .{ 0x15, 0x3F, 0x15 }, // 10: Light Green
        .{ 0x15, 0x3F, 0x3F }, // 11: Light Cyan
        .{ 0x3F, 0x15, 0x15 }, // 12: Light Red
        .{ 0x3F, 0x15, 0x3F }, // 13: Light Magenta
        .{ 0x3F, 0x3F, 0x15 }, // 14: Yellow
        .{ 0x3F, 0x3F, 0x3F }, // 15: White
    };
    for (&palette) |color| {
        outb(0x3C9, color[0]); // Red
        outb(0x3C9, color[1]); // Green
        outb(0x3C9, color[2]); // Blue
    }
    outb(0x3C6, 0xFF); // PEL mask

    // Step 11: Clear text buffer at 0xB8000
    const vram: [*]volatile u16 = @ptrFromInt(0xB8000);
    var i: usize = 0;
    while (i < 80 * 25) : (i += 1) {
        vram[i] = 0x0720; // Space (0x20) with light gray on black (0x07)
    }

    // Set cursor to top-left
    vgaWriteIndexed(0x3D4, 0x3D5, 0x0E, 0x00);
    vgaWriteIndexed(0x3D4, 0x3D5, 0x0F, 0x00);

    Serial.puts("[HAL] VGA text mode (80x25) initialized via register programming\n");
}

/// Helper: Write to an indexed VGA register pair
fn vgaWriteIndexed(index_port: u16, data_port: u16, index: u8, value: u8) void {
    outb(index_port, index);
    outb(data_port, value);
}
