/* POLER-OS Linker Script — x86_64 (flat identity-mapped)
 *
 * Physical address = virtual address = 0x100000 (1MB mark)
 * Higher-half will be added when PMM/VMM is more mature.
 *                                                                          */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    boot    PT_LOAD FLAGS(7);           /* RWX — boot code (32→64 transition) */
    text    PT_LOAD FLAGS(5);           /* RX — kernel code */
    rodata  PT_LOAD FLAGS(4);           /* R  — read-only data */
    data    PT_LOAD FLAGS(6);           /* RW — data + bss */
    note    PT_NOTE FLAGS(4);           /* R  — PVH ELF note (QEMU≥11 -kernel) */
}

SECTIONS
{
    /* Физический адрес = виртуальный адрес = 1MB */
    . = 0x100000;

    /* ========================================================================
     * Boot section — 32-bit entry, page tables, GDT
     * ======================================================================== */
    .multiboot2 ALIGN(8) : {
        *(.multiboot2)
    } :boot

    .text.boot32 ALIGN(4K) : {
        *(.text.boot32)
    } :boot

    .rodata.gdt32 ALIGN(16) : {
        *(.rodata.gdt32)
    } :boot

    .rodata.gdt64 ALIGN(16) : {
        *(.rodata.gdt64)
    } :boot

    .bss.boot ALIGN(4K) : {
        pml4_addr = .; . += 4096;
        pdpt_addr = .; . += 4096;
        pd_addr   = .; . += 16384;
        stack_bottom = .; . += 16384;
        stack_top = .;
        *(.bss.boot)
    } :boot

    /* ========================================================================
     * PVH ELF Note — байты эмитит boot64.S (секция .note.pvh, SHT_NOTE),
     * сюда попадает input-секция и уходит в PT_NOTE-сегмент. Данные
     * команды в самом скрипте (LONG/ASCII) lld не поддерживает — поэтому
     * ассемблер. Vaddr==Paddr → значение pvh_entry = физический адрес.
     * ======================================================================== */
    .note.pvh ALIGN(4) : {
        *(.note.pvh)
    } :note

    _kernel_start = .;

    /* Text section */
    .text ALIGN(4K) : {
        *(.text.boot64)
        *(.text .text.*)
    } :text

    /* ISR stub pointer table — must be in read-only data, NOT code */
    .rodata.isr_table ALIGN(16) : {
        __isr_table_start = .;
        *(.rodata.isr_table)
        __isr_table_end = .;
    } :rodata

    /* Read-only data */
    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    } :rodata

    /* Data section */
    .data ALIGN(4K) : {
        *(.data .data.*)
    } :data

    /* BSS */
    .bss ALIGN(4K) : {
        bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        bss_end = .;
    } :data

    _kernel_end = .;

    /* ========================================================================
     * Discard unnecessary sections
     * ======================================================================== */
    /DISCARD/ : {
        *(.comment)
        *(.note.gnu*)
        *(.eh_frame*)
        *(.gnu.hash)
    }
}
