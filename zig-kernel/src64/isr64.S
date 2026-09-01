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

    // Call Zig handler: isr_common_handler(frame: *InterruptFrame)
    call isr_common_handler

    // RAX contains the return value (the new RSP). Switch stack if context switched.
    movq %rax, %rsp

    // Restore all general-purpose registers
    popq %r15
    popq %r14
    popq %r13
    popq %r12
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
//  ISR Stub Table — 48 function pointers (vectors 0-47)
// ============================================================================

.section .rodata.isr_table, "a", @progbits
.balign 8
.globl isr_stub_table
isr_stub_table:
    .quad isr_stub_0
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

// ============================================================================
//  Fast System Call Entry Point (syscall/sysretq)
// ============================================================================

.extern user_rsp
.extern current_kernel_stack
.extern syscall_frame          // v0.12.0: снапшот кадра (8 слов, .bss)
.extern zig_syscall_handler
.extern ucl_pending            // v0.12.0: мост Win64-колбэка (win32_api)
.extern ucl_rsp
.extern ucl_rip
.extern ucl_rflags

.global syscall_entry
syscall_entry:
    // Save user RSP to user_rsp
    movq %rsp, user_rsp(%rip)

    // Load kernel RSP of the active task
    movq current_kernel_stack(%rip), %rsp

    // Now we are on the kernel stack!
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

    // Call Zig syscall handler
    call zig_syscall_handler

    // v0.12.0 (CDD №3): запуск Win64-колбэка? (InitOnceExecuteOnce:
    // обработчик сохранил кадр в CallbackState и заполнил ucl_*)
    cmpq $0, ucl_pending(%rip)
    jne .ucl_launch

    // Restore general purpose registers
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx

    // Restore r11 and rcx
    popq %r11
    popq %rcx

    // Switch back to user RSP
    movq user_rsp(%rip), %rsp

    // Return to Ring 3
    sysretq

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

