// ============================================================================
// POLER-OS boot64.S — Multiboot2 → Long Mode (64-bit)
// ============================================================================
//
// Boot sequence:
//   1. Multiboot2 header (for GRUB)
//   2. Verify Multiboot2 magic (0x36D76289)
//   3. Identity-mapped PML4 (4-level paging)
//   4. Enable PAE + Long Mode via CR4 + EFER
//   5. Load CR3 (PML4)
//   6. Enable paging (CR0.PG)
//   7. Far jump to 64-bit code
//   8. Setup GDT64
//   9. Call poler_kernel_main() in Zig
// ============================================================================

.set MB2_MAGIC,          0xE85250D6   // Multiboot2 header magic
.set MB2_BOOTLOADER_MAGIC, 0x36D76289 // Значение в EAX при загрузке
.set MB2_ARCHITECTURE,   0            // 0 = x86 (protected mode)

.set CR0_PE,             0x00000001
.set CR0_PG,             0x80000000
.set CR4_PAE,            0x00000020
.set CR4_PSE,            0x00000010

.set MSR_EFER,           0xC0000080
.set EFER_LME,           0x00000100
.set EFER_NXE,           0x00000800

// KERNEL_BASE removed — flat identity-mapped kernel for now

// ============================================================================
// Multiboot2 Header
// ============================================================================
.section .multiboot2, "a", @progbits
.balign 8
mb2_header_start:
    .long MB2_MAGIC                                    // magic
    .long MB2_ARCHITECTURE                             // architecture
    .long mb2_header_end - mb2_header_start            // header length
    .long -(MB2_MAGIC + MB2_ARCHITECTURE + (mb2_header_end - mb2_header_start))  // checksum

    // Framebuffer Request Tag (type = 5) — DISABLED for v0.7.x
    // Using VGA text mode (80x25) for reliable terminal output.
    // Graphical framebuffer will be re-enabled in v0.8.0 with proper rendering.
    //
    // .balign 8
    // .word 5                  // type
    // .word 0                  // flags (0 = required)
    // .long 20                 // size
    // .long 1024               // preferred width
    // .long 768                // preferred height
    // .long 32                 // preferred depth

    // End tag
    .balign 8
    .word 0                  // type = end
    .word 0                  // flags
    .long 8                  // size
mb2_header_end:

// ============================================================================
// 32-bit Entry Points (Multiboot2 и PVH)
// ============================================================================
.section .text.boot32, "ax", @progbits
.global pvh_entry
.global _start
.code32

// PVH-точка входа (QEMU >=11 `-kernel`, Xen PVH). Вход: 32-bit protected
// mode, paging off, flat segments. Multiboot2-магии нет: EAX = 0 → «PVH».
// EBX НЕ зануляем: QEMU-PVH кладёт туда физ. адрес hvm_start_info — v0.9.0
// ядро парсит его (initrd-модули, cmdline). MB2-парсер при magic=0 не
// активируется (гейт have_mb2 в main64.zig), мусор не читается.
pvh_entry:
    cli
    xorl %eax, %eax          // magic = 0 → PVH-ветка в poler_kernel_main
    // EBX = paddr(hvm_start_info) — проходит через r13d → RSI (2-й аргумент)
    jmp _start

_start:
    // Сохраняем Multiboot2 info в регистры (EBP = magic, EBX = MBI)
    movl %eax, %ebp

    // ========================================================================
    // Early Serial Init (COM1 = 0x3F8) — для debug output ещё до Zig
    // ========================================================================
    movw $0x3F8, %dx
    movb $0x00, %al
    outb %al, %dx          // 0x3F8+1: Disable interrupts
    incw %dx               // 0x3F9
    outb %al, %dx
    movw $0x3FB, %dx
    movb $0x80, %al        // 0x3FB: Enable DLAB
    outb %al, %dx
    movw $0x3F8, %dx
    movb $0x01, %al        // 0x3F8: Divisor low = 1 (115200 baud)
    outb %al, %dx
    movw $0x3F9, %dx
    movb $0x00, %al        // 0x3F9: Divisor high = 0
    outb %al, %dx
    movw $0x3FB, %dx
    movb $0x03, %al        // 0x3FB: 8N1
    outb %al, %dx
    movw $0x3FA, %dx
    movb $0xC7, %al        // 0x3FA: Enable FIFO
    outb %al, %dx
    movw $0x3FC, %dx
    movb $0x0B, %al        // 0x3FC: RTS/DSR/DTR
    outb %al, %dx

    // Output 'A' to serial — we're alive!
    movw $0x3F8, %dx
    movb $'A', %al
    outb %al, %dx

    // Проверяем Multiboot2 magic (из сохранённого регистра EBP).
    // EBP==0 → PVH-загрузка (информации загрузчика нет, но грузимся),
    // EBP==MB2_BOOTLOADER_MAGIC → обычный GRUB-путь, иначе — hang.
    cmpl $MB2_BOOTLOADER_MAGIC, %ebp
    je 1f
    testl %ebp, %ebp
    jz 1f
    jmp .hang
1:
    // Output 'C' (magic OK)
    movb $'C', %al
    outb %al, %dx

    // Временно отключаем прерывания
    cli

    // Загружаем GDT32 (нужен для far jump)
    lgdt gdt32_ptr

    // Переключаемся на 32-bit code segment
    ljmpl $0x08, $.setup_paging

.setup_paging:
    // Теперь в protected mode с нашим GDT
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    // Настраиваем стек (32KB, ниже 1MB)
    movl $0x0007C00, %esp

    // ========================================================================
    // Создаём Identity-mapped Page Tables
    // PML4[0] → PDPT[0] → PD[0..3] (4 entries = 4GB identity map, 2MB pages)
    // ========================================================================

    // Очищаем страницу для PML4 (4KB at pml4_addr)
    movl $pml4_addr, %edi
    xorl %eax, %eax
    movl $1024, %ecx          // 1024 * 4 bytes = 4KB
    rep stosl

    // Очищаем PDPT
    movl $pdpt_addr, %edi
    xorl %eax, %eax
    movl $1024, %ecx
    rep stosl

    // Очищаем PD (4 pages для 4GB mapping)
    movl $pd_addr, %edi
    xorl %eax, %eax
    movl $4096, %ecx          // 4 pages * 1024 = 4096 dwords = 16KB
    rep stosl

    // PML4[0] → PDPT (present + writable)
    // v0.10.0 SECURITY FIX: USER-бит снят со всей identity-цепочки
    // (PML4[0], PDPT[0..3], листовые 2МБ). CPL=0 игнорирует U/S — ядро
    // работает как раньше; Ring 3 больше не видит 0–4ГБ через ОБЩИЕ
    // таблицы: пользовательский PML4 (копия из createUserPML4) получает
    // USER только на своём экземпляре PML4[0] (getOrCreateTable при
    // маппинге user-VA ≥4ГБ), но PDPT[0..3] ниже остаются supervisor —
    // traversal из Ring 3 блокируется на PDPT. Без этого фикса маппинг
    // user-страниц в PML4[0] открывал Ring 3 ВСЁ ядро.
    movl $pdpt_addr, %eax
    orl $0x03, %eax           // Present + Writable (NO User)
    movl %eax, pml4_addr

    // PDPT: 4 entries pointing to 4 PD pages
    // Each PD page maps 1GB (512 entries × 2MB)
    movl $pd_addr, %eax
    orl $0x03, %eax           // Present + Writable (NO User)
    movl %eax, pdpt_addr           // PDPT[0] → PD0 (0-1GB)
    addl $0x1000, %eax
    movl %eax, pdpt_addr + 8       // PDPT[1] → PD1 (1-2GB)
    addl $0x1000, %eax
    movl %eax, pdpt_addr + 16      // PDPT[2] → PD2 (2-3GB)
    addl $0x1000, %eax
    movl %eax, pdpt_addr + 24      // PDPT[3] → PD3 (3-4GB)

    // PD: заполняем ALL 2048 entries (4 pages × 512) с 2MB huge pages
    // Это маппит 0-4GB identity-mapped
    // v0.10.0: 0x83 = Present + Writable + PageSize (2MB), БЕЗ User (см. фикс выше)
    movl $pd_addr, %edi
    movl $0x83, %eax          // Present + Writable + PageSize(2MB), start at 0
    movl $2048, %ecx          // 2048 entries = 4GB (2048 * 2MB)
.fill_pd_loop:
    movl %eax, (%edi)
    addl $0x00200000, %eax    // Next 2MB
    addl $8, %edi             // Next PD entry
    loop .fill_pd_loop

    // ========================================================================
    // Включаем PAE (CR4.PAE)
    // ========================================================================
    movl %cr4, %eax
    orl $CR4_PAE, %eax
    orl $CR4_PSE, %eax        // Page Size Extension
    movl %eax, %cr4

    // ========================================================================
    // Включаем Long Mode (EFER.LME)
    // ========================================================================
    movl $MSR_EFER, %ecx
    rdmsr
    orl $EFER_LME, %eax
    orl $EFER_NXE, %eax       // No-Execute Enable
    wrmsr

    // ========================================================================
    // Загружаем CR3 (PML4 base)
    // ========================================================================
    movl $pml4_addr, %eax
    movl %eax, %cr3

    // ========================================================================
    // Включаем Paging (CR0.PG)
    // ========================================================================
    movl %cr0, %eax
    orl $CR0_PG, %eax
    movl %eax, %cr0

    // ========================================================================
    // Far jump в 64-bit код!
    // Загружаем GDT64 и прыгаем
    // ========================================================================
    lgdt gdt64_ptr
    ljmpl $0x08, $.long_mode_entry

// ============================================================================
// 64-bit Entry Point
// ============================================================================
.section .text.boot64, "ax", @progbits
.code64

.long_mode_entry:
    // Перезагружаем сегменты для 64-bit
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    // Настраиваем 64-bit стек (16KB)
    movq $stack_top, %rsp

    // Включаем SSE (требуется для Zig SSE-оптимизированного кода)
    movq %cr0, %rax
    andq $-5, %rax         // Очищаем EM (bit 2) ($-5 = ~0x4)
    orq $0x2, %rax         // Устанавливаем MP (bit 1)
    movq %rax, %cr0

    movq %cr4, %rax
    orq $0x600, %rax       // Устанавливаем OSFXSR (bit 9) и OSXMMEXCPT (bit 10)
    movq %rax, %cr4

    // Сохраняем Multiboot2 info в extended регистры до очистки BSS
    movl %ebp, %r12d     // magic
    movl %ebx, %r13d     // mbi pointer

    // Обнуляем BSS (для Zig)
    movq $bss_start, %rdi
    movq $bss_end, %rcx
    subq %rdi, %rcx
    xorq %rax, %rax
    rep stosb

    // Передаем Multiboot2 info в аргументы для Zig (magic -> edi, mbi -> rsi)
    movl %r12d, %edi
    movl %r13d, %esi

    // Вызываем Zig kernel main
    call poler_kernel_main

    // Если вернулись — зависаем
.hang64:
    cli
    hlt
    jmp .hang64

// ============================================================================
// 32-bit hang (при ошибке)
// ============================================================================
.code32
.hang:
    cli
    hlt
    jmp .hang



// ============================================================================
// GDT32 (для перехода protected → long)
// ============================================================================
.section .rodata.gdt32, "a", @progbits
.balign 16
gdt32_start:
    .quad 0x0000000000000000     // 0x00: Null descriptor
    .quad 0x00CF9A000000FFFF     // 0x08: 32-bit Code (0-4GB, ring 0)
    .quad 0x00CF92000000FFFF     // 0x10: 32-bit Data (0-4GB, ring 0)
gdt32_end:

gdt32_ptr:
    .word gdt32_end - gdt32_start - 1   // limit
    .long gdt32_start                     // base

// ============================================================================
// GDT64 (для long mode)
// ============================================================================
.section .rodata.gdt64
.balign 16
gdt64_start:
    .quad 0x0000000000000000     // 0x00: Null descriptor
    .quad 0x00209A0000000000     // 0x08: 64-bit Code (Long mode, ring 0)
    .quad 0x0000920000000000     // 0x10: 64-bit Data (ring 0)
    .quad 0x0000F20000000000     // 0x18: 64-bit Data (User, ring 3)
    .quad 0x0020FA0000000000     // 0x20: 64-bit Code (User, ring 3)
    // TSS будет добавлен динамически из Zig
gdt64_end:

gdt64_ptr:
    .word gdt64_end - gdt64_start - 1   // limit
    .quad gdt64_start                     // base (64-bit!)



// BSS markers (defined by linker script)

// ============================================================================
// PVH ELF Note — QEMU>=11 принимает 64-bit ELF в -kernel только при наличии
// ноты: name "Linux\0", type 18 = XEN_ELFNOTE_PHYS32_ENTRY,
// desc = 32-битный ФИЗИЧЕСКИЙ адрес точки входа (vaddr==paddr → символ уже
// физический). Секция SHT_NOTE ловится линкер-скриптом в PT_NOTE (:note).
// ============================================================================
.section .note.pvh, "a", @note
.align 4
    .long 6                      /* namesz: "Linux\0" (6 байт с NUL)   */
    .long 4                      /* descsz: u32 entry address          */
    .long 18                     /* type: XEN_ELFNOTE_PHYS32_ENTRY     */
    .asciz "Linux"
    .balign 4
    .long pvh_entry              /* desc: 32-bit physical entry        */
    .balign 4
