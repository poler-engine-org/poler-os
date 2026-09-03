// ═════════════════════════════════════════════════════════════════════════════
// sched_resume.zig — v0.18.1 (CDD №9, residual-fix): ПЕР-ТАСК РЕЗЮМ-КАДР
// SYSCALL В .BSS — ИММУННЫЙ К ЗАТИРАНИЮ КАСКАДАМИ НА KSTACK.
// ═════════════════════════════════════════════════════════════════════════════
//
// RESIDUAL v0.18.0-RC (эмпирика pe-run4/pe-run8, дамп FRAME-GUARD):
//   после kSleepTask-эпилога tasks[].rsp указывал ВГЛУБЬ собственного
//   каскада задачи — на СТАРЫЙ hlt-ISR-кадр, замороженный на kstack во
//   время парковки. Резюм-указатель переживал окно «sysretq → первый
//   тик», но СЛЕДУЮЩИЙ syscall-каскад ТОЙ ЖЕ задачи (спуск с kstack-топа:
//   DNS-буферы, ASCII-строки резолвера, глубокие Zig-цепочки) перезаписы-
//   вал регион — кадр «мусорел» по слотам CS/RIP/RSP/SS (сигнатура дампа:
//   RSP-слот=0x202 — rflags-значение в чужом слоте). frameContentValid
//   отклонял кадр каждый тик → bad_frame_drops накапливал 50 пропусков
//   (0.5с) → FRAME-GUARD убивал ЖИВОЙ тред резолвера curl → HTTP-обмен
//   не завершался. Инвариант «ноль kernel-panic» соблюдался, но треды
//   терялись.
//
// ЛЕЧЕНИЕ (архитектурное, по вектору AGENT_STATE v0.18.1):
//   1. ПРИ ВХОДЕ kSleepTask (каскад ещё жив на топе kstack владельца)
//      снимаем ПОЛНЫЙ InterruptFrame (176Б = 22 слова) в .bss-слот
//      syscall_frame_tab[owner] — память НЕ на стеке → каскады её не
//      затирают. Кадр семантически равен состоянию «после sysretq»:
//      RIP = user-адрес после инструкции syscall, RFLAGS = user, RSP =
//      user, CS=0x23/SS=0x1B (раскладка STAR, hal.zig p6), callee-saved
//      GPR из каскада, RAX=0 (Sleep-return; caller-saved у syscall-ABI
//      не сохраняются — как и в настоящем sysretq-пути).
//   2. В ЭПИЛОГЕ kSleepTask (после снятия будильника) указатель
//      tasks[owner].rsp (и теневая копия shadow_rsp) направляется на
//      .bss-слот: указатель ВСЕГДА валиден по содержимому —FRAME-GUARD
//      не накапливает пропуски. Диспетчеризация из слота легальна:
//      iretq возвращает задачу в user-режим после ЕЁ syscall — сон уже
//      завершён (wake-гвард прошёл), побочных эффектов нет.
//   3. taskRspValid (scheduler.zig) получает whitelist: .bss-слот
//      считается валидным адресом кадра задачи.
//
// МОДУЛЬ ЧИСТЫЙ: не импортирует hal/kernel — тестируется нативно
// (zig build test, addRunArtifact — инвариант v0.9.0: тесты ЗАПУСКАЮТСЯ).
// ═════════════════════════════════════════════════════════════════════════════

/// Число слотов задач = scheduler.MAX_TASKS (8). Дублируется намеренно:
/// модуль не тянет scheduler.zig (hal-цепочка) в нативные тесты.
pub const TASK_SLOTS: usize = 8;

/// InterruptFrame (isr64.S isr_common) = 176 байт = 22 слова.
/// Раскладка (порядок push'ей isr_common; r15 — младший адрес):
///   слово  0..14 : r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi,
///                   rbp, rdx, rcx, rbx, rax
///   слово 15     : vector (48 = APIC-timer)
///   слово 16     : error_code
///   слово 17     : rip     (смещение 136)
///   слово 18     : cs      (смещение 144) — 0x23 = user code (STAR)
///   слово 19     : rflags  (смещение 152)
///   слово 20     : rsp     (смещение 160) — user RSP
///   слово 21     : ss      (смещение 168) — 0x1B = user data (STAR)
pub const FRAME_WORDS: usize = 22;

/// v0.18.1: пер-таск снапшоты syscall-кадра. Заполняет kSleepTask ДО
/// парковки (каскад жив); читает планировщик (tasks[].rsp → слот).
/// export — адреса видны в дампах QEMU-monitor ( символы) при разборе.
/// ⚠ align(16): @alignOf(InterruptFrame) = 16 (packed struct — выравнива-
/// ние его backing-integer); kstack-кадры всегда 16-выровнены (топ
/// 16-выровнен, 176%16=0), а глобал в .bss линкер мог положить на 8-
/// выровненный адрес → @ptrFromInt(*InterruptFrame) в schedule() паниковал
/// «incorrect alignment» (эмпирика pe-run4 v0.18.1-bisect). Ряды 176Б =
/// 11×16 — остаются 16-выровненными.
pub export var syscall_frame_tab: [TASK_SLOTS][FRAME_WORDS]u64 align(16) =
    .{.{0} ** FRAME_WORDS} ** TASK_SLOTS;

/// Адрес .bss-слота резюм-кадра задачи (указатель для tasks[].rsp).
pub fn frameSlot(id: usize) u64 {
    if (id >= TASK_SLOTS) return 0;
    return @intFromPtr(&syscall_frame_tab[id][0]);
}

/// v0.17.0 (CDD №8) — валидность СОДЕРЖИМОГО кадра (InterruptFrame).
/// ПЕРЕНЕСЁНО из scheduler.zig (v0.18.1): функция чистая (volatile-read
/// по слотам 136/144/160) — живёт здесь для нативного тестирования.
/// Guard: CS обязан быть user (0x23/0x1B) или kernel (0x08/0x10),
/// user-RIP/RSP — в каноническом user-диапазоне. Мусор → false:
/// свитч на такой кадр = #GP(RIP=heap) в ядре (эмпирика v0.17, 7-Zip).
pub fn frameContentValid(rsp: u64) bool {
    if (rsp == 0) return false;
    // [rsp+136]=rip, [rsp+144]=cs, [rsp+160]=rsp, [rsp+168]=ss (isr64.S)
    const cs = @as(*volatile u64, @ptrFromInt(rsp + 144)).*;
    if (cs == 0x08 or cs == 0x10) return true; // kernel-задача (shell/idle)
    if (cs != 0x23 and cs != 0x1B) return false; // мусорный CS
    const rip = @as(*volatile u64, @ptrFromInt(rsp + 136)).*;
    if (rip < 0x10000 or rip >= 0x0000_8000_0000_0000) return false;
    const usp = @as(*volatile u64, @ptrFromInt(rsp + 160)).*;
    if (usp < 0x10000 or usp >= 0x0000_8000_0000_0000) return false;
    return true;
}

/// v0.18.1: снять резюм-кадр задачи из ЖИВОГО syscall-каскада.
///
/// Каскад isr64.S syscall_entry — ровно 64 байта под kstack-топом
/// владельца (asm: movq kstack_hi_tab(,%rax,8), %rsp + 8×push):
///   каскад[0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
///   каскад[6]=r11 (USER RFLAGS — кладёт SYSCALL) [7]=rcx (USER RIP)
/// Zig-цепочка kSleepTask живёт НИЖЕ каскада —(region [top-64, top)
/// остаётся нетронутым до sysretq (читать его в любой точке обработчика
/// безопасно; это же свойство использует существующий глобальный
/// syscall_frame-снапшот v0.12.0).
///
/// ur — user-RSP транзакции (scheduler.user_rsp — записан атомарным
/// asm-входом ДО переключения стека; авторитетный признак владельца).
pub fn snapshotSyscallFrame(id: usize, kstack_top: u64, ur: u64) void {
    if (id == 0 or id >= TASK_SLOTS) return; // 0 = idle/boot — не паркуется
    if (kstack_top < 64) return; // мусорный топ — отказ (no-op, не паника)

    const cascade: [*]const volatile u64 = @ptrFromInt(kstack_top - 64);
    const f: *volatile [FRAME_WORDS]u64 = &syscall_frame_tab[id];

    // ── GPR-слоты: соответствие sysretq-семантике выхода ──────────────
    // callee-saved (единственные, чьи значения syscall обязан сохранить):
    f[0] = cascade[0]; // r15
    f[1] = cascade[1]; // r14
    f[2] = cascade[2]; // r13
    f[3] = cascade[3]; // r12
    f[10] = cascade[4]; // rbp
    f[13] = cascade[5]; // rbx
    // r11/rcx у SYSCALL несут RFLAGS/RIP — и iretq-путь (pop GPR), и
    // sysretq-путь оставляют в них ОДНИ И ТЕ ЖЕ значения — консистентно:
    f[4] = cascade[6]; // r11 = user RFLAGS
    f[12] = cascade[7]; // rcx = user RIP
    // caller-saved у syscall-ABI не сохраняются (как в sysretq-пути):
    f[5] = 0; // r10
    f[6] = 0; // r9
    f[7] = 0; // r8
    f[8] = 0; // rdi
    f[9] = 0; // rsi
    f[11] = 0; // rdx
    // RAX: возврат Sleep-транзакции (kSleepTask — void → 0). Диспетчериза-
    // ция из слота редка (wake-гвард + flag-гвард закрывают окна), но даже
    // в ней семантика «сон завершён, код после syscall» корректна:
    f[14] = 0; // rax

    // ── вектор/код ошибки (isr_common их пропускает addq $16) ─────────
    f[15] = 48; // vector = APIC-timer (источник диспетчеризации)
    f[16] = 0; // error_code

    // ── iret-хвост: ТОЧКА ВОЗОБНОВЛЕНИЯ «после syscall» ────────────────
    f[17] = cascade[7]; // rip  = user RIP (после инструкции syscall)
    f[18] = 0x23; // cs   = 64-bit User Code (STAR[63:48]|3, hal.zig p6)
    f[19] = cascade[6]; // rflags = user RFLAGS (IF=1 у живого треда)
    f[20] = ur; // rsp  = user RSP транзакции
    f[21] = 0x1B; // ss   = 64-bit User Data (STAR[63:48]+8|3)
}

// ═════════════════════════════════════════════════════════════════════════════
// Тесты (нативный linux, zig build test — ЗАПУСКАЮТСЯ, инвариант v0.9.0)
// ═════════════════════════════════════════════════════════════════════════════
const std = @import("std");
const t = std.testing;

/// Фейковый syscall-каскад (layout isr64.S) на «kstack-топе».
fn fakeCascade(cascade: *[8]u64) u64 {
    cascade[0] = 0x0000_7000_0010_0015; // r15 (канонический user-адрес)
    cascade[1] = 0x0000_7000_0010_0014; // r14
    cascade[2] = 0x0000_7000_0010_0013; // r13
    cascade[3] = 0x0000_7000_0010_0012; // r12
    cascade[4] = 0x0000_7000_0010_0005; // rbp
    cascade[5] = 0x0000_7000_0010_0003; // rbx
    cascade[6] = 0x202; // r11 = user RFLAGS (IF|резерв)
    cascade[7] = 0x0000_1400_0100_0000; // rcx = user RIP (после syscall)
    return @intFromPtr(cascade) + 64; // «kstack-топ» над каскадом
}

test "frameSlot: стабильные уникальные 16-выровненные адреса .bss-слотов" {
    // ⚠ v0.18.1-фикс: @alignOf(InterruptFrame)=16 (packed) — слот ОБЯЗАН
    // быть 16-выровнен, иначе @ptrFromInt(*InterruptFrame) в schedule()
    // паникует «incorrect alignment» (эмпирика pe-run4).
    const s1 = frameSlot(1);
    const s2 = frameSlot(2);
    try t.expect(s1 != s2);
    try t.expect(s1 % 16 == 0);
    try t.expect(s2 % 16 == 0);
    try t.expect(frameSlot(1) == s1); // детерминизм
    try t.expectEqual(@as(u64, 0), frameSlot(TASK_SLOTS)); // вне таблицы
}

test "snapshotSyscallFrame: раскладка InterruptFrame из syscall-каскада" {
    var cascade: [8]u64 align(16) = undefined;
    const top = fakeCascade(&cascade);
    const ur: u64 = 0x0000_2200_0010_0000; // user RSP (главный стек curl)

    syscall_frame_tab[2] = @splat(0);
    snapshotSyscallFrame(2, top, ur);
    const f = &syscall_frame_tab[2];

    // callee-saved — из каскада
    try t.expectEqual(cascade[0], f[0]); // r15
    try t.expectEqual(cascade[1], f[1]); // r14
    try t.expectEqual(cascade[2], f[2]); // r13
    try t.expectEqual(cascade[3], f[3]); // r12
    try t.expectEqual(cascade[4], f[10]); // rbp
    try t.expectEqual(cascade[5], f[13]); // rbx
    // r11/rcx: user RFLAGS/RIP (семантика SYSCALL)
    try t.expectEqual(cascade[6], f[4]); // r11 = RFLAGS
    try t.expectEqual(cascade[7], f[12]); // rcx = RIP
    // caller-saved + rax = 0
    try t.expectEqual(@as(u64, 0), f[5]); // r10
    try t.expectEqual(@as(u64, 0), f[6]); // r9
    try t.expectEqual(@as(u64, 0), f[7]); // r8
    try t.expectEqual(@as(u64, 0), f[8]); // rdi
    try t.expectEqual(@as(u64, 0), f[9]); // rsi
    try t.expectEqual(@as(u64, 0), f[11]); // rdx
    try t.expectEqual(@as(u64, 0), f[14]); // rax = Sleep-return
    // вектор/код
    try t.expectEqual(@as(u64, 48), f[15]);
    try t.expectEqual(@as(u64, 0), f[16]);
    // iret-хвост — ТОЧКА ВОЗОБНОВЛЕНИЯ
    try t.expectEqual(cascade[7], f[17]); // rip
    try t.expectEqual(@as(u64, 0x23), f[18]); // cs = user code
    try t.expectEqual(cascade[6], f[19]); // rflags
    try t.expectEqual(ur, f[20]); // user RSP
    try t.expectEqual(@as(u64, 0x1B), f[21]); // ss = user data
}

test "snapshotSyscallFrame: кадр проходит frameContentValid (ядро не убьёт)" {
    var cascade: [8]u64 align(16) = undefined;
    const top = fakeCascade(&cascade);
    snapshotSyscallFrame(3, top, 0x0000_2200_0000_F000);
    // Главный инвариант residual-фикса: содержимое слота ВАЛИДНО всегда —
    // каскады на kstack больше не могут «замусорить» резюм-кадр задачи.
    try t.expect(frameContentValid(frameSlot(3)));
}

test "frameContentValid: мусорный CS / kernel-RIP / мусорный RSP отклоняются" {
    var frame: [FRAME_WORDS]u64 = @splat(0);
    frame[18] = 0x2023; // мусорный CS
    try t.expect(!frameContentValid(@intFromPtr(&frame)));

    frame[18] = 0x23; // user CS
    frame[17] = 0x30; // RIP ниже 0x10000 — kernel/нулевой регион
    try t.expect(!frameContentValid(@intFromPtr(&frame)));

    frame[17] = 0x0000_1400_0100_0000; // канонический user RIP
    frame[20] = 0x0000_9000_0000_0000; // RSP выше канонического потолка
    try t.expect(!frameContentValid(@intFromPtr(&frame)));

    frame[20] = 0x0000_2200_0000_F000;
    try t.expect(frameContentValid(@intFromPtr(&frame)));
}

test "frameContentValid: kernel-кадры (CS=0x08/0x10) валидны — parking-кадры hlt" {
    var frame: [FRAME_WORDS]u64 = @splat(0);
    frame[18] = 0x08; // kernel code — кадр парковки hlt-цикла (ring-0)
    frame[17] = 0x0000_0000_0010_8100; // RIP внутри kstack-региона ядра
    try t.expect(frameContentValid(@intFromPtr(&frame)));
    frame[18] = 0x10;
    try t.expect(frameContentValid(@intFromPtr(&frame)));
}

test "snapshotSyscallFrame: id вне таблицы / мусорный топ — no-op без паники" {
    var cascade: [8]u64 align(16) = undefined;
    const top = fakeCascade(&cascade);
    const before = syscall_frame_tab[1];
    snapshotSyscallFrame(0, top, 0x1000); // idle/boot — слот не трогаем
    snapshotSyscallFrame(TASK_SLOTS, top, 0x1000); // вне таблицы
    snapshotSyscallFrame(1, 0, 0x1000); // мусорный топ
    snapshotSyscallFrame(1, 32, 0x1000); // топ < 64 — каскад не влезает
    try t.expectEqualSlices(u64, &before, &syscall_frame_tab[1]);
}
