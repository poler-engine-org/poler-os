// ============================================================================
// POLER-OS AP Trampoline — boot_smp.S
// ============================================================================
//
// This is the AP (Application Processor) startup trampoline code.
// It is copied to physical address 0x8000 at boot time by the BSP.
// Each AP starts executing here in 16-bit real mode after SIPI.
//
// The trampoline:
//   1. Switches from 16-bit real mode → 32-bit protected mode
//   2. Enables PAE + Long Mode via CR4 + EFER
//   3. Loads CR3 (page tables from BSP)
//   4. Enables paging
//   5. Far jumps to 64-bit code
//   6. Loads GDT, IDT from trampoline data
//   7. Sets up stack
//   8. Calls ap_entry_zig()
//
// IMPORTANT: Both lgdt instructions read the GDT pointer from the
// trampoline data area at a FIXED offset (0x8000 + AP_DATA_OFFSET + GDT_PTR_OFF).
// The BSP fills in this data before sending SIPI. This avoids the bug where
// assembly-time computed addresses for lgdt were incorrect after relocation.
//
// GDT layout (kernel's GDT, shared by BSP and all APs):
//   0x00: Null
//   0x08: 64-bit Code (ring 0)
//   0x10: 64-bit Data (ring 0)
//   0x18: User Data (ring 3)
//   0x20: User Code (ring 3)
//   0x28: 32-bit Code (ring 0) ← used for 16→32 transition on AP
//   0x30: 32-bit Data (ring 0) ← used for 32-bit data segments on AP
//   0x38: TSS low
//   0x40: TSS high
//
// Data layout at 0x8100 (AP_DATA_OFFSET = 0x100):
//   Offset  Size  Field
//   0x00    10    GDT pointer (2-byte limit + 8-byte base) — kernel's GDT64
//   0x0A    10    IDT pointer (2-byte limit + 8-byte base)
//   0x14    4     Padding (alignment)
//   0x18    8     CR3 (PML4 physical address)
//   0x20    8     Entry point (ap_entry_zig address)
//   0x28    8     PerCpu structure address (for GSBASE)
//   0x30    4     CPU ID
//   0x34    4     Padding
//   0x38    8     Stack top
// ============================================================================

.set AP_DATA_OFFSET, 0x100

.set CR0_PE, 0x00000001
.set CR0_PG, 0x80000000
.set CR4_PAE, 0x00000020

.set MSR_EFER, 0xC0000080
.set EFER_LME, 0x00000100
.set EFER_NXE, 0x00000800

// Data offsets within ApTrampolineData (extern struct, C layout)
// gdt_ptr: 10 bytes at 0x00
// idt_ptr: 10 bytes at 0x0A
// padding: 6 bytes at 0x14 (alignment to 8-byte boundary for u64)
// cr3:     8 bytes at 0x18
// entry64: 8 bytes at 0x20
// percpu:  8 bytes at 0x28
// cpu_id:  4 bytes at 0x30
// padding: 4 bytes at 0x34
// stack_top: 8 bytes at 0x38
.set GDT_PTR_OFF, 0x00
.set IDT_PTR_OFF, 0x0A
.set CR3_OFF,     0x18
.set ENTRY64_OFF, 0x20
.set PERCPU_OFF,  0x28
.set CPUID_OFF,   0x30
.set STACKTOP_OFF,0x38

// Selectors for 32-bit protected mode (SMP AP trampoline)
.set SEL_CODE32,  0x28    // 32-bit Code segment (GDT entry 5)
.set SEL_DATA32,  0x30    // 32-bit Data segment (GDT entry 6)

// Selectors for 64-bit long mode
.set SEL_CODE64,  0x08    // 64-bit Code segment (GDT entry 1)
.set SEL_DATA64,  0x10    // 64-bit Data segment (GDT entry 2)

.section .text.ap_trampoline, "ax", @progbits
.code16

.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:
    // ========================================================================
    // 16-bit Real Mode Entry Point
    // ========================================================================
    // We arrive here after SIPI. CS:IP = 0x0800:0x0000 (SIPI vector=8).
    // We need to switch to 64-bit long mode.

    // Disable interrupts
    cli

    // Load a known data segment
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    // ========================================================================
    // Switch to 32-bit Protected Mode
    // ========================================================================

    // Enable A20 line (should already be enabled by BIOS/GRUB, but be safe)
    inb $0x92, %al
    orb $0x02, %al
    outb %al, $0x92

    // Load kernel's GDT pointer from trampoline data area.
    // FIXED: Use hardcoded offset (0x8000 + AP_DATA_OFFSET + GDT_PTR_OFF = 0x8100)
    // instead of assembly-time computed address that was broken after relocation.
    //
    // In 16-bit real mode, lgdt reads a 6-byte pseudo-descriptor (2-byte limit + 4-byte base).
    // The data area has a 10-byte pseudo-descriptor (2-byte limit + 8-byte base) from sgdt.
    // The 16-bit lgdt reads bytes 0-5 (limit + lower 32 bits of base), which is correct
    // since the kernel's GDT is below 4GB (identity-mapped at ~1MB).
    lgdt (0x8000 + AP_DATA_OFFSET + GDT_PTR_OFF)

    // Enable protected mode (CR0.PE)
    movl %cr0, %eax
    orl $CR0_PE, %eax
    movl %eax, %cr0

    // Far jump to 32-bit code using 32-bit code selector (0x28)
    ljmpl $SEL_CODE32, $(ap_pm32_entry - ap_trampoline_start + 0x8000)

.code32
ap_pm32_entry:
    // ========================================================================
    // 32-bit Protected Mode
    // ========================================================================

    // Load 32-bit data segments (selector 0x30 = 32-bit Data)
    movw $SEL_DATA32, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    // ========================================================================
    // Set up identity-mapped page tables for 64-bit long mode
    // We use the BSP's page tables (read from trampoline data)
    // ========================================================================

    // Read CR3 from trampoline data area
    movl $(0x8000 + AP_DATA_OFFSET + CR3_OFF), %ebx
    movl (%ebx), %eax
    movl %eax, %cr3

    // Enable PAE (CR4.PAE)
    movl %cr4, %eax
    orl $CR4_PAE, %eax
    movl %eax, %cr4

    // Enable Long Mode (EFER.LME)
    movl $MSR_EFER, %ecx
    rdmsr
    orl $EFER_LME, %eax
    orl $EFER_NXE, %eax
    wrmsr

    // Enable paging (CR0.PG)
    movl %cr0, %eax
    orl $CR0_PG, %eax
    movl %eax, %cr0

    // Reload GDT64 from trampoline data (same GDT, now with 64-bit entries accessible)
    // In 32-bit mode, lgdt reads 6 bytes (2-byte limit + 4-byte base) — correct for <4GB
    lgdt (0x8000 + AP_DATA_OFFSET + GDT_PTR_OFF)

    // Far jump to 64-bit code using 64-bit code selector (0x08)
    ljmpl $SEL_CODE64, $(ap_lm64_entry - ap_trampoline_start + 0x8000)

.code64
ap_lm64_entry:
    // ========================================================================
    // 64-bit Long Mode!
    // ========================================================================

    // Load 64-bit data segments (selector 0x10 = 64-bit Data)
    movw $SEL_DATA64, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    // Load IDT from trampoline data
    lidt (0x8000 + AP_DATA_OFFSET + IDT_PTR_OFF)

    // Load stack from trampoline data
    movq (0x8000 + AP_DATA_OFFSET + STACKTOP_OFF), %rsp

    // Enable SSE (required for Zig)
    movq %cr0, %rax
    andq $-5, %rax         // Clear EM (bit 2)
    orq $0x2, %rax         // Set MP (bit 1)
    movq %rax, %cr0

    movq %cr4, %rax
    orq $0x600, %rax       // OSFXSR + OSXMMEXCPT
    movq %rax, %cr4

    // v0.20.0 (CDD №12 p1): AVX + OSXSAVE + XCR0 на AP (как в BSP).
    // EBX CPUID clobber'ит — сохраняем (контракт трэшпола AP-трамплина).
    pushq %rbx
    mov $1, %eax
    xor %ecx, %ecx
    cpuid
    test $(1 << 26), %ecx         // XSAVE?
    jz 2f
    test $(1 << 28), %ecx         // AVX?
    jz 2f
    movq %cr4, %rax
    orq $(1 << 18), %rax          // OSXSAVE
    movq %rax, %cr4
    xor %ecx, %ecx
    mov $0x207, %eax              // XCR0: x87|SSE|AVX
    xor %edx, %edx
    xsetbv
2:
    popq %rbx

    // Set GSBASE for per-CPU data
    movq (0x8000 + AP_DATA_OFFSET + PERCPU_OFF), %rdi
    movl $0xC0000101, %ecx         // IA32_GS_BASE MSR
    movl %edi, %eax
    shrq $32, %rdi
    movl %edi, %edx
    wrmsr

    // Also set KERNEL_GS_BASE
    movq (0x8000 + AP_DATA_OFFSET + PERCPU_OFF), %rdi
    movl $0xC0000102, %ecx         // IA32_KERNEL_GS_BASE MSR
    movl %edi, %eax
    shrq $32, %rdi
    movl %edi, %edx
    wrmsr

    // Call ap_entry_zig() — no arguments (it reads from trampoline data)
    movq (0x8000 + AP_DATA_OFFSET + ENTRY64_OFF), %rax
    call *%rax

    // Should never return, but just in case
.halt_loop:
    cli
    hlt
    jmp .halt_loop

ap_trampoline_end:

// Mark end of trampoline — no embedded GDT32 needed anymore!
// The kernel's GDT (with 32-bit entries at 0x28/0x30) is used instead.
