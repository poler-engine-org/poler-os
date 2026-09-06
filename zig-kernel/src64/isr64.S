// ============================================================================
// POLER-OS isr64.S — x86_64 ISR / IRQ stubs
// ============================================================================
//
// CPU exception stubs (vectors 0-31) and PIC IRQ stubs (vectors 32-47).
// All stubs converge on isr_common which builds an InterruptFrame on the
// stack, calls the Zig handler, then restores state and iretq's.
//
// InterruptFrame layout (must match hal.zig):
//
//   Offset  Field        Who pushes
//   ------  -----------  -------------------------
//   0       r15          isr_common (pushed LAST)
//   8       r14          isr_common
//   16      r13          isr_common
//   24      r12          isr_common
//   32      r11          isr_common
//   40      r10          isr_common
//   48      r9           isr_common
//   56      r8           isr_common
//   64      rdi          isr_common
//   72      rsi          isr_common
//   80      rbp          isr_common
//   88      rdx          isr_common
//   96      rcx          isr_common
//   104     rbx          isr_common
//   112     rax          isr_common (pushed FIRST)
//   120     vector       stub
//   128     error_code   stub (or CPU, or dummy 0)
//   136     rip          CPU
//   144     cs           CPU
//   152     rflags       CPU
//   160     rsp          CPU
//   168     ss           CPU
// ============================================================================

.text
.code64

// CDD №12 p4-final: строка для R15-POISON-детекта (rodata, но близко к коду
// — линкер section .text уже определён выше; кладём в .rodata ниже).

// ============================================================================
//  CPU Exception Stubs  (vectors 0 – 31)
// ============================================================================

// --- Vectors with NO CPU error code (push dummy 0) ---

isr_stub_0:
    pushq $0
    pushq $0
    jmp isr_common

isr_stub_1:
    pushq $0
    pushq $1
    jmp isr_common

isr_stub_2:
    pushq $0
    pushq $2
    jmp isr_common

isr_stub_3:
    pushq $0
    pushq $3
    jmp isr_common

isr_stub_4:
    pushq $0
    pushq $4
    jmp isr_common

isr_stub_5:
    pushq $0
    pushq $5
    jmp isr_common

isr_stub_6:
    pushq $0
    pushq $6
    jmp isr_common

isr_stub_7:
    pushq $0
    pushq $7
    jmp isr_common

// --- Vector 8: #DF Double Fault — CPU pushes error code ---

isr_stub_8:
    pushq $8
    jmp isr_common

isr_stub_9:
    pushq $0
    pushq $9
    jmp isr_common

// --- Vectors with CPU-pushed error code ---

isr_stub_10:
    pushq $10
    jmp isr_common

isr_stub_11:
    pushq $11
    jmp isr_common

isr_stub_12:
    pushq $12
    jmp isr_common

isr_stub_13:
    pushq $13
    jmp isr_common

isr_stub_14:
    pushq $14
    jmp isr_common

// --- Back to no error code ---

isr_stub_15:
    pushq $0
    pushq $15
    jmp isr_common

isr_stub_16:
    pushq $0
    pushq $16
    jmp isr_common

isr_stub_17:                             // #AC — CPU pushes error code
    pushq $17
    jmp isr_common

isr_stub_18:
    pushq $0
    pushq $18
    jmp isr_common

isr_stub_19:
    pushq $0
    pushq $19
    jmp isr_common

isr_stub_20:
    pushq $0
    pushq $20
    jmp isr_common

isr_stub_21:                             // #CP — CPU pushes error code
    pushq $21
    jmp isr_common

isr_stub_22:
    pushq $0
    pushq $22
    jmp isr_common

isr_stub_23:
    pushq $0
    pushq $23
    jmp isr_common

isr_stub_24:
    pushq $0
    pushq $24
    jmp isr_common

isr_stub_25:
    pushq $0
    pushq $25
    jmp isr_common

isr_stub_26:
    pushq $0
    pushq $26
    jmp isr_common

isr_stub_27:
    pushq $0
    pushq $27
    jmp isr_common

isr_stub_28:
    pushq $0
    pushq $28
    jmp isr_common

isr_stub_29:                             // #VC — CPU pushes error code
    pushq $29
    jmp isr_common

isr_stub_30:                             // #SX — CPU pushes error code
    pushq $30
    jmp isr_common

isr_stub_31:
    pushq $0
    pushq $31
    jmp isr_common

// ============================================================================
//  IRQ Stubs  (vectors 32 – 47, PIC remapped)
// ============================================================================

isr_stub_32:
    pushq $0
    pushq $32
    jmp isr_common

isr_stub_33:
    pushq $0
    pushq $33
    jmp isr_common

isr_stub_34:
    pushq $0
    pushq $34
    jmp isr_common

isr_stub_35:
    pushq $0
    pushq $35
    jmp isr_common

isr_stub_36:
    pushq $0
    pushq $36
    jmp isr_common

isr_stub_37:
    pushq $0
    pushq $37
    jmp isr_common

isr_stub_38:
    pushq $0
    pushq $38
    jmp isr_common

isr_stub_39:
    pushq $0
    pushq $39
    jmp isr_common

isr_stub_40:
    pushq $0
    pushq $40
    jmp isr_common

isr_stub_41:
    pushq $0
    pushq $41
    jmp isr_common

isr_stub_42:
    pushq $0
    pushq $42
    jmp isr_common

isr_stub_43:
    pushq $0
    pushq $43
    jmp isr_common

isr_stub_44:
    pushq $0
    pushq $44
    jmp isr_common

isr_stub_45:
    pushq $0
    pushq $45
    jmp isr_common

isr_stub_46:
    pushq $0
    pushq $46
    jmp isr_common

isr_stub_47:
    pushq $0
    pushq $47
    jmp isr_common

// ============================================================================
//  APIC Timer Stub  (vector 48)
// ============================================================================

isr_stub_48:
    pushq $0
    pushq $48
    jmp isr_common

// ============================================================================
//  VirtIO-Blk IRQ Stub  (vector 49) — v0.17.0 (CDD №8)
//  IO-APIC GSI блочного устройства маршрутизируется на вектор 49
//  (virtio_blk.zig: IOAPIC.write(0x10 + gsi*2, 49)), но стаба/гейта не было —
//  доставка в НЕУСТАНОВЛЕННУЮ запись IDT (Present=0) = #GP при ПЕРВОМ же
//  секторе диска (латентно с появления virtio_blk: диск в E2E не монтировался).
// ============================================================================

isr_stub_49:
    pushq $0
    pushq $49
    jmp isr_common

// ============================================================================
//  Common ISR Entry
// ============================================================================

isr_common:
    // Save all general-purpose registers
    // Push order: rax first → r15 last → r15 at lowest address = offset 0
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    // RDI = pointer to InterruptFrame (current RSP)
    movq %rsp, %rdi

    // CDD №12 p4-final (класс p2-R8): 16-байт выравнивание стека ПЕРЕД
    // Zig .C-вызовом. SysV ABI требует RSP%16==0 в точке call: с Ring 3
    // CPU пушит SS/RSP/RFLAGS/RCS/RIP (40Б) + стаб vector/error (16Б) +
    // 14 регисров (112Б) = 168 → RSP≡8 (mod 16) на call — handler входил
    // со СДВИГОМ (movaps-aligned спиллы = #GP). `andq $-16` безопасен:
    // кадр-указатель уже в RDI; возврат handler заменяет RSP целиком
    // (movq %rax,%rsp ниже) — выравнивающий зазор в 0/8Б мёртв.
    movq %rsp, %rax
    andq $-16, %rsp

    // Call Zig handler: isr_common_handler(frame: *InterruptFrame)
    call isr_common_handler

    // RAX contains the return value (the new RSP). Switch stack if context switched.
    movq %rax, %rsp

    // Restore all general-purpose registers
    // CDD №12 p4-final (R15-POISON-детект): pop r15 из ISR-КАДРА на kstack.
    // Гипотеза-лидер 0xAAAA-краша: кадр ИСПОРЧЕН Zig-Debug-локАлями ядра
    // (0xAA-паттерн) → iretq возвращает задачу с R15=0xAAAA → гостевой
    // mov (%r15) → #GP. Детект: pop → cmp → (совпало) — зовём Zig-принтер
    // с указателем слота кадра. БЕЗОПАСНО: все caller-saved (rax/rcx/rdx/
    // rsi/rdi/r8-r11) восстановятся ПОЗДНЕЕ ИЗ КАДРА — call может их
    // калечить сколько угодно; callee-saved Zig-принтер обязан сохранить.
    popq %r15
    cmpq .Laaaa_const(%rip), %r15
    jne .r15_ok_isr
    movq %rsp, %rsi
    leaq .Lr15_msg(%rip), %rdi
    call r15_poison_report
.r15_ok_isr:
    popq %r14
    cmpq .Laaaa_const(%rip), %r14
    jne .r14_ok_isr
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r14_ok_isr:
    popq %r13
    cmpq .Laaaa_const(%rip), %r13
    jne .r13_ok_isr
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r13_ok_isr:
    popq %r12
    cmpq .Laaaa_const(%rip), %r12
    jne .r12_ok_isr
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r12_ok_isr:
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    // Drop vector + error_code (2 x 8 = 16 bytes)
    addq $16, %rsp

    // Return from interrupt
    iretq

// ============================================================================
//  ISR Stub Table — 49 function pointers (vectors 0-48 + 49=vblk, CDD №8)
// ============================================================================

.section .rodata
.balign 8
.Laaaa_const:
    .quad 0xAAAAAAAAAAAAAAAA
.Lr15_msg:
    .asciz "[R15-POISON] кадр kstack испорчен (0xAAAAAAAAAAAAAAAA): slot="
.globl r15_poison_msg
.set r15_poison_msg, .Lr15_msg

.section .rodata.isr_table, "a", @progbits
.balign 8
.globl isr_stub_table
isr_stub_table:    .quad isr_stub_0
    .quad isr_stub_1
    .quad isr_stub_2
    .quad isr_stub_3
    .quad isr_stub_4
    .quad isr_stub_5
    .quad isr_stub_6
    .quad isr_stub_7
    .quad isr_stub_8
    .quad isr_stub_9
    .quad isr_stub_10
    .quad isr_stub_11
    .quad isr_stub_12
    .quad isr_stub_13
    .quad isr_stub_14
    .quad isr_stub_15
    .quad isr_stub_16
    .quad isr_stub_17
    .quad isr_stub_18
    .quad isr_stub_19
    .quad isr_stub_20
    .quad isr_stub_21
    .quad isr_stub_22
    .quad isr_stub_23
    .quad isr_stub_24
    .quad isr_stub_25
    .quad isr_stub_26
    .quad isr_stub_27
    .quad isr_stub_28
    .quad isr_stub_29
    .quad isr_stub_30
    .quad isr_stub_31
    .quad isr_stub_32
    .quad isr_stub_33
    .quad isr_stub_34
    .quad isr_stub_35
    .quad isr_stub_36
    .quad isr_stub_37
    .quad isr_stub_38
    .quad isr_stub_39
    .quad isr_stub_40
    .quad isr_stub_41
    .quad isr_stub_42
    .quad isr_stub_43
    .quad isr_stub_44
    .quad isr_stub_45
    .quad isr_stub_46
    .quad isr_stub_47
    .quad isr_stub_48
    .quad isr_stub_49

// ============================================================================
//  Fast System Call Entry Point (syscall/sysretq)
// ============================================================================

.extern user_rsp
.extern current_kernel_stack
.extern tss_rsp0_mirror           // v0.17.0-fix (CDD №8 p6): зеркало TSS.rsp0 — источник syscall-стека
.extern syscall_frame          // v0.12.0: снапшот кадра (8 слов, .bss)
.extern zig_syscall_handler
.extern r15_poison_report       // CDD №12 p4-final: детект R15=0xAAAA при восстановлении из кадра
.extern ucl_pending            // v0.12.0: мост Win64-колбэка (win32_api)
.extern in_win32_syscall      // v0.13.0: транзакция syscall (schedule-guard)
.extern ucl_rsp
.extern ucl_rip
.extern ucl_rflags
.extern linux_arg5             // v0.18.0 (CDD №9): user R8 — 5-й аргумент Linux-syscall
.extern linux_arg6             // v0.18.0 (CDD №9): user R9 — 6-й аргумент Linux-syscall
// v0.18.0 (CDD №9): PER-TASK SYSCALL STATE — вход по ВЛАДЕЛЬЦУ user-RSP
.extern kstack_lo_tab          // [MAX_TASKS]u64 — низ kstack задачи
.extern kstack_hi_tab          // [MAX_TASKS]u64 — верх kstack (сюда спускаемся)
.extern ustack_hi_tab          // [MAX_TASKS]u64 — верх user-стека (0 = нет)
.extern ustack_lo_tab          // [MAX_TASKS]u64 — низ user-стека
.extern syscall_num_tmp        // времяянка user RAX на время скана
.extern syscall_ret_tmp        // v0.20.0: результат Zig-обработчика (возврат в RAX)
.extern rbx_tmp                // времяянка user RBX на время скана
.extern syscall_exit_frame_ptr // CDD №12 p7: указатель .bss-строки выходного кадра
.extern exit_poison_mask       // CDD №12 p7: битовая маска 0xAAAA-детекторов выхода

.global syscall_entry
syscall_entry:
    // Save user RSP to user_rsp
    movq %rsp, user_rsp(%rip)

    // v0.18.0 (CDD №9, Linux POSIX-фундамент): сохранить user R8/R9 —
    // аргументы №5/№6 Linux x86_64 ABI — ДО затирания R8 номером syscall
    // ниже. АДДИТИВНО: Win32-путь эти значения не читает (R8 перезаписы-
    // вается movq %rax,%r8, R9 в Win64-конвенции — caller-saved/мусор),
    // стек и транзакция НЕ затрагиваются, IF=0 от SYSCALL — атомарно.
    movq %r8, linux_arg5(%rip)
    movq %r9, linux_arg6(%rip)

    // ════════════════════════════════════════════════════════════════
    //  v0.18.0 (CDD №9): PER-TASK SYSCALL STATE — вход по ВЛАДЕЛЬЦУ.
    //
    //  КОРЕНЬ cks-гонки (эмпирика [T]/[S]-трейса): в окнах паркинга
    //  (kSleepTask hlt) cks/current_task_id РАССИНХРОНИЗИРОВАНЫ с реаль-
    //  ным исполнителем: следующий syscall входил ПО cks НА ЧУЖОЙ kstack
    //  → Zig-каскад (DNS-буферы, ASCII-строки) ЗАТИРАЛ замороженные кад-
    //  ры владельца → FRAME-GUARD «кадр мусорен» → каскадный kill жилых
    //  тредов резолвера.
    //
    //  РЕШЕНИЕ: каскад задачи — ТОЛЬКО НА СВОЁМ kstack. Владелец опреде-
    //  ляется ПО USER-RSP (АТОМАРНО: IF=0 от SYSCALL/SFMASK):
    //    1) kernel-задача: syscall из Ring 0 — RSP уже внутри ЕЁ kstack;
    //    2) user-задача/тред: RSP внутри ЕЁ уникального user-стека
    //       (главный 0x22_0000_0000±, треды — VHEAP-выделения: не пере-
    //       секаются; колбэк-стек InitOnce-моста — вне таблиц → честный
    //       cks-fallback: колбэк исполняется ТОЛЬКО при cur=владельце).
    //  Сканируем 8 слотов; промах → cks (легаси-поведение v0.17).
    //  Затираемые на время скана: RAX, RBX → времяянки .bss (восстановим).
    // ════════════════════════════════════════════════════════════════
    movq %rax, syscall_num_tmp(%rip)
    movq %rbx, rbx_tmp(%rip)
    xorl %eax, %eax                      // i = 0
.owner_scan:
    cmpq $8, %rax
    jae .owner_fallback
    // 1) kernel-задача: user_rsp ∈ [kstack_lo_i, kstack_hi_i) ?
    movq kstack_lo_tab(,%rax,8), %rbx
    cmpq user_rsp(%rip), %rbx            // kstack_lo > user_rsp? → мимо
    ja .try_user_stack
    movq kstack_hi_tab(,%rax,8), %rbx
    cmpq user_rsp(%rip), %rbx            // kstack_hi > user_rsp? → HIT
    ja .owner_found
    // 2) user-задача: user_rsp ∈ [ustack_lo_i, ustack_hi_i) ?
.try_user_stack:
    movq ustack_hi_tab(,%rax,8), %rbx
    testq %rbx, %rbx
    jz .owner_next                       // 0 = слот без user-стека
    cmpq user_rsp(%rip), %rbx            // ustack_hi > user_rsp?
    jbe .owner_next
    movq ustack_lo_tab(,%rax,8), %rbx
    cmpq %rbx, user_rsp(%rip)            // user_rsp >= ustack_lo? → HIT
    jae .owner_found
.owner_next:
    incq %rax
    jmp .owner_scan
.owner_found:
    movq kstack_hi_tab(,%rax,8), %rsp    // СВОЙ kstack-топ (атомарно, IF=0)
    jmp .owner_done
.owner_fallback:
    // Промах (колбэк-стек моста / мусорный RSP) — легаси cks: колбэк
    // InitOnce исполняется только при cur=владельце → cks корректен.
    movq current_kernel_stack(%rip), %rsp
.owner_done:
    movq rbx_tmp(%rip), %rbx             // восстановить user RBX
    movq syscall_num_tmp(%rip), %rax     // восстановить user RAX (номер)

    // Теперь мы на СВОЁМ стеке задачи!
    // Push user RIP (RCX) and user RFLAGS (R11)
    pushq %rcx
    pushq %r11

    // Save other general purpose registers to preserve them
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    // Prepare arguments for Zig call conv (.C):
    // RDI (arg1), RSI (arg2), RDX (arg3) are already set.
    // 4th arg is R10, which we move to RCX.
    movq %r10, %rcx
    // 5th arg is RAX (syscall number), which we move to R8.
    movq %rax, %r8

    // v0.12.0 (CDD №3): снапшот спущенного кадра в .bss — 8 слов.
    // IF=0 (SYSCALL маскирует IF через EFER_SFMASK) — атомарно против
    // прерываний: стек ядра под кадром может быть затёрт таймером ПОСЛЕ
    // sti() в обработчике, а syscall_frame — нет. Читает его
    // win32_api.kLaunchCallback (мост InitOnce-колбэка).
    // rax/r11 — scratch (значения уже сохранены push'ами выше).
    leaq syscall_frame(%rip), %r11
    movq 0(%rsp),  %rax
    movq %rax, 0(%r11)         // r15
    movq 8(%rsp),  %rax
    movq %rax, 8(%r11)         // r14
    movq 16(%rsp), %rax
    movq %rax, 16(%r11)        // r13
    movq 24(%rsp), %rax
    movq %rax, 24(%r11)        // r12
    movq 32(%rsp), %rax
    movq %rax, 32(%r11)        // rbp
    movq 40(%rsp), %rax
    movq %rax, 40(%r11)        // rbx
    movq 48(%rsp), %rax
    movq %rax, 48(%r11)        // r11 (user RFLAGS)
    movq 56(%rsp), %rax
    movq %rax, 56(%r11)        // rcx (user RIP после syscall)

    // v0.13.0-fix: транзакция syscall активна — таймерный тик НЕ должен
    // переключать Ring-3 задачу внутри обработки (глобальные user_rsp/
    // current_kernel_stack перезаписал бы чужой контекст — латентная
    // гонка v0.12, взорвалась на 3 Ring-3 задачах: sysretq на чужой стек).
    // IF=0 от SYSCALL — запись атомарна.
    movq $1, in_win32_syscall(%rip)

    // ════════════════════════════════════════════════════════════════
    //  v0.20.0 (CDD №11, glibc-волна): СОХРАНЕНИЕ Linux-ABI регистров.
    //
    //  x86-64 syscall ABI: ядро возвращает пользователю с НЕИЗМЕННЫМИ
    //  RDI/RSI/RDX/R10/R8/R9 (калечатся только RCX/R11/RAX). Zig-обработчик
    //  (.C-конвенция) свободно калечит АРГУМЕНТНЫЕ регистры — glibc
    //  ПОЛАГАЕТСЯ на сохранность (эмпирика: _dl_early_allocate держал
    //  номер syscall в ESI через brk(0)→brk(new): мусор в ESI = дикий
    //  syscall = #PF в __libc_setup_tls). Win32-код не замечал баг:
    //  MSVC-ABI считает RCX/RDX/R8/R9 volatile.
    //
    //  Пуш ПОСЛЕ снапшота syscall_frame (смещения снапшота не трогаем).
    // ════════════════════════════════════════════════════════════════
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %r10
    pushq %r8
    pushq %r9

    // Call Zig syscall handler
    call zig_syscall_handler

    // Результат — в .bss времяянку (RAX обязан вернуться пользователю),
    // затем восстановить аргументные регистры
    movq %rax, syscall_ret_tmp(%rip)

    // ══════════════════════════════════════════════════════════════════
    //  CDD №12 p7: ВЫХОДНОЙ КАДР ИЗ .BSS — pop-каскад kstack ЗАМЕНЁН.
    //
    //  ЭМПИРИКА (p7run6..9, детерминированная ×3): [R15-POISON] — слот
    //  каскада [top-8] содержит 0xAAAAAAAAAAAAAAAA на pop-е → гость
    //  получает R14/R15=0xAAAA → #GP (mov rbp,[r14], R14=0xAAAA...
    //  = non-canonical). Слоты на kstack-топе затираются путями, НЕ
    //  наблюдаемыми TCG-плагинами (8.4M событий, ноль на слоте) и
    //  Z2-watchpoint — единственные непрослеживаемые записи = C-helper
    //  push-и (interrupt entry). ЛЕЧЕНИЕ ПО КОНСТРУКЦИИ: zig-вход
    //  снапшотит все 14 слов [top-112, top) в .bss-строку владельца
    //  (snapshotExitFrame, scheduler.zig); ЗДЕСЬ читаем регистры из
    //  .bss — kstack-топ больше НЕ источник регистрового потока.
    //  RAX = указатель строки (скретч; ret в ret_tmp — хвост перезагрузит).
    //  Детекторы 0xAAAA — дешёвые биты exit_poison_mask (отчёт — из
    //  следующего zig-входа; C-call здесь калечил бы восстановленные).
    // ══════════════════════════════════════════════════════════════════
    movq syscall_exit_frame_ptr(%rip), %rax
    testq %rax, %rax
    jz .exit_pop_fallback

    cmpq $0, ucl_pending(%rip)
    jne .ucl_launch_flagged

    movq 0x00(%rax), %r9
    movq 0x08(%rax), %r8      // НАСТОЯЩИЙ user R8 (snapshot из linux_arg5)
    movq 0x10(%rax), %r10
    movq 0x18(%rax), %rdx
    movq 0x20(%rax), %rsi
    movq 0x28(%rax), %rdi
    movq 0x30(%rax), %r15
    cmpq .Laaaa_const(%rip), %r15
    jne 1f
    orq $1, exit_poison_mask(%rip)
1:  movq 0x38(%rax), %r14
    cmpq .Laaaa_const(%rip), %r14
    jne 2f
    orq $2, exit_poison_mask(%rip)
2:  movq 0x40(%rax), %r13
    cmpq .Laaaa_const(%rip), %r13
    jne 3f
    orq $4, exit_poison_mask(%rip)
3:  movq 0x48(%rax), %r12
    cmpq .Laaaa_const(%rip), %r12
    jne 4f
    orq $8, exit_poison_mask(%rip)
4:  movq 0x50(%rax), %rbp
    movq 0x58(%rax), %rbx
    movq 0x60(%rax), %r11     // user RFLAGS
    movq 0x68(%rax), %rcx     // user RIP
    jmp .exit_frame_done

    // ─── fallback: снапшота нет (shell-контекст / ранний бут) ───────
.exit_pop_fallback:
    popq %r9
    popq %r8
    movq linux_arg5(%rip), %r8
    popq %r10
    popq %rdx
    popq %rsi
    popq %rdi
    movq syscall_ret_tmp(%rip), %rax
    cmpq $0, ucl_pending(%rip)
    jne .ucl_launch_flagged

    // v0.16.0-fix (CDD №7, застрявшие CV-треды): сброс флага транзакции
    // ПЕРЕНЕСЁН за pop'ы — раньше окно «flag=0 до sysretq» (~12 инструкций,
    // IF=1 после sti() обработчика) позволяло тику ПЕРЕКЛЮЧИТЬ задачу
    // посреди выхода: кадр сохранялся, задача замораживалась в середине
    // pop-последовательности, а ГЛОБАЛЬНЫЕ (cks) оставались от владельца
    // последнего свитча → следующий syscall читал ЧУЖОЙ kstack (WARN
    // «вне собственного стека» → вечная парковка треда → deadlock curl).
    // Теперь pop'ы идут под flag=1 (тик честно ждёт в guard-пути и
    // возвращается в ту же точку), окно сужено до mov+sysretq (~2 такта).
    // Проверка колбэка осталась под flag=1: .ucl_launch уводит в Ring 3
    // (мост сам управляет транзакцией).
    cmpq $0, ucl_pending(%rip)
    jne .ucl_launch_flagged

    // Restore general purpose registers
    // CDD №12 p4-final: R15-POISON-детект и на syscall-выходе (pop r15
    // из каскада kstack-топа) — тот же класс порчи кадра.
    popq %r15
    cmpq .Laaaa_const(%rip), %r15
    jne .r15_ok_sys
    movq %rsp, %rsi
    leaq .Lr15_msg(%rip), %rdi
    call r15_poison_report
.r15_ok_sys:
    popq %r14
    cmpq .Laaaa_const(%rip), %r14
    jne .r14_ok_sys
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r14_ok_sys:
    popq %r13
    cmpq .Laaaa_const(%rip), %r13
    jne .r13_ok_sys
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r13_ok_sys:
    popq %r12
    cmpq .Laaaa_const(%rip), %r12
    jne .r12_ok_sys
    movq %rsp, %rsi
    movabs $.Lr15_msg, %rdi
    call r15_poison_report
.r12_ok_sys:
    popq %rbp
    popq %rbx

    // Restore r11 and rcx
    popq %r11
    popq %rcx
    jmp .exit_frame_done

.exit_frame_done:

    // Транзакция завершена. v0.16.0-fix: user_rsp снимается в РЕГИСТР
    // под flag=1 (чужой syscall не перезапишет глобал, пока мы владельцы),
    // хвост атомарен cli-ом (тик не встанет кадром на user-стеке);
    // sysretq восстановит IF из R11 (user-RFLAGS, IF=1).
    // CDD №12 p4-final (класс p2-R8, КОРЕНЬ clobber): СКРЕЧ — RAX, НЕ R10!
    // Linux x86-64 ABI: ядро обязан сохранить пользователю ВСЕ регистры
    // кроме RCX/R11/RAX. Старый код «movq user_rsp,%r10; mov %r10,%rsp»
    // возвращал пользователя с R10=user_rsp — КАЛЕЧЕНИЕ user-R10 на
    // КАЖДОМ syscall (у sysretq нет других мёртвых регистров: RCX=RIP,
    // R11=RFLAGS, RAX=результат). RAX свободен ДВАЖДЫ: результат уже
    // можно положить в syscall_ret_tmp и вернуть в конце.
    // CDD №12 p4-fix2: ret_tmp УЖЕ хранит результат (сохранён сразу после
    // call zig_syscall_handler) — НИКАКИХ перезаписей RAX в хвосте: любые
    // промежуточные затирания (детекты!) не должны попадать в ret_tmp.
    movq user_rsp(%rip), %rax
    cli
    movq $0, in_win32_syscall(%rip)
    movq %rax, %rsp
    movq syscall_ret_tmp(%rip), %rax

    // Return to Ring 3
    sysretq

.ucl_launch_flagged:
    // Флаг поднят — сбрасываем ПЕРЕД уходом в колбэк (Ring 3): колбэк
    // превентивен (тики диспетчируют резолвер/TLS-тред), его собственные
    // syscall'ы поднимут флег заново на входе. Окно до sysretq — 3 команды,
    // user_rsp здесь не читается (используется dedicated cb-стек).
    movq $0, in_win32_syscall(%rip)
    jmp .ucl_launch

.ucl_launch:
    // Кадр НЕ поднимаем (pop'ы пропущены): он уже скопирован в
    // CallbackState (win32_api). Уходим в Ring 3 на LAUNCHER моста:
    //   RCX → RIP (sysretq), R11 → RFLAGS (user), RSP → dedicated-стек.
    // sysretq здесь оставляет SS/CS из STAR — тот же путь, что обычный
    // возврат (проверен E2E v0.10+).
    // ⚠ v0.12.0-fix: редирект ОДНОРАЗОВЫЙ — сбрасываем флаг ЗДЕСЬ.
    // Раньше ucl_pending чистился только в callbackDone (syscall #7),
    // но колбэк ДО добирания до trampoline зовёт syscall #6 (calloc/…)
    // и КАЖДЫЙ возврат из него снова уводил в launcher — бесконечный
    // перезапуск колбэка (E2E: 60 запусков, 0 завершений).
    movq ucl_rsp(%rip), %rsp
    movq ucl_rip(%rip), %rcx
    movq ucl_rflags(%rip), %r11
    movq $0, ucl_pending(%rip)
    xorl %eax, %eax
    sysretq


// ============================================================================
//  v0.17.0 (CDD №8 p5-lite): per-task asm-вход (kstack_tops[owner] +
//  syscall-скретчи) отложен в v0.18-бэклог — эмпирика сессии: рассинхрон
//  current в окнах паркинга надёжно ловится Zig-защитами (SAVE-GUARD
//  отказ + FRAME-HEAL из тени + heap IF-фикс) без хрупких изменений
//  семантики asm-входа/выхода. Уроки задокументированы в AGENT_STATE.md.
// ============================================================================
