const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize: std.builtin.OptimizeMode = .Debug;

    // ═══ 32-bit Kernel Build (legacy) ════════════════════════════════════
    const kernel32_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel32 = b.addExecutable(.{
        .name = "poler-os32",
        .root_source_file = b.path("src/main32.zig"),
        .target = kernel32_target,
        .optimize = optimize,
    });

    kernel32.setLinkerScript(b.path("src/linker32.ld"));
    kernel32.link_gc_sections = false;
    kernel32.addAssemblyFile(b.path("src/boot32.S"));
    kernel32.addAssemblyFile(b.path("src/isr32.S"));
    b.installArtifact(kernel32);

    // ═══ 64-bit Kernel Build (POLER-OS v0.6.0) ═════════════════════════
    const kernel64_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel64 = b.addExecutable(.{
        .name = "poler-os64",
        .root_source_file = b.path("src64/main64.zig"),
        .target = kernel64_target,
        .optimize = optimize,
    });

    kernel64.setLinkerScript(b.path("src64/linker64.ld"));
    kernel64.link_gc_sections = false;
    kernel64.addAssemblyFile(b.path("src64/boot64.S"));
    kernel64.addAssemblyFile(b.path("src64/isr64.S"));
    b.installArtifact(kernel64);

    // ═══ Run 32-bit kernel in QEMU ═══════════════════════════════════════
    const run32_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os32",
        "-m", "128M",
        "-serial", "stdio",
        "-no-reboot",
    });
    run32_cmd.step.dependOn(b.getInstallStep());

    const run32_step = b.step("run32", "Run 32-bit kernel in QEMU");
    run32_step.dependOn(&run32_cmd.step);

    // ═══ Run 64-bit kernel in QEMU ═══════════════════════════════════════
    const run64_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-serial", "stdio",
        "-no-reboot",
    });
    run64_cmd.step.dependOn(b.getInstallStep());

    const run64_step = b.step("run64", "Run 64-bit kernel in QEMU");
    run64_step.dependOn(&run64_cmd.step);

    // ═══ Run 64-bit kernel headless (serial only) ═════════════════════════
    const run64_headless_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-nographic",
        "-no-reboot",
    });
    run64_headless_cmd.step.dependOn(b.getInstallStep());

    const run64_headless_step = b.step("run64-headless", "Run 64-bit kernel headless (serial only)");
    run64_headless_step.dependOn(&run64_headless_cmd.step);

    // ═══ Run 64-bit kernel with virtio-blk disk ═════════════════════════
    const run64_blk_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-serial", "stdio",
        "-no-reboot",
        "-drive", "file=disk.img,if=virtio,format=raw",
    });
    run64_blk_cmd.step.dependOn(b.getInstallStep());

    const run64_blk_step = b.step("run64-blk", "Run 64-bit kernel in QEMU with virtio-blk disk");
    run64_blk_step.dependOn(&run64_blk_cmd.step);

    // ═══ Run 64-bit kernel headless with virtio-blk ═════════════════════
    const run64_blk_headless_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/poler-os64",
        "-m", "256M",
        "-nographic",
        "-no-reboot",
        "-drive", "file=disk.img,if=virtio,format=raw",
    });
    run64_blk_headless_cmd.step.dependOn(b.getInstallStep());

    const run64_blk_headless_step = b.step("run64-blk-headless", "Run 64-bit kernel headless with virtio-blk");
    run64_blk_headless_step.dependOn(&run64_blk_headless_cmd.step);

    // ═══ Run from ISO (CDROM boot) ══════════════════════════════════════
    const run64_iso_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-cdrom", "poler-os64.iso",
        "-m", "256M",
        "-serial", "stdio",
        "-vga", "std",
        "-no-reboot",
    });
    run64_iso_cmd.step.dependOn(b.getInstallStep());

    const run64_iso_step = b.step("run64-iso", "Run POLER-OS from ISO in QEMU");
    run64_iso_step.dependOn(&run64_iso_cmd.step);

    // ═══ Run from ISO with virtio-blk disk ══════════════════════════════
    const run64_iso_blk_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-cdrom", "poler-os64.iso",
        "-m", "256M",
        "-serial", "stdio",
        "-vga", "std",
        "-no-reboot",
        "-drive", "file=disk.img,if=virtio,format=raw",
    });
    run64_iso_blk_cmd.step.dependOn(b.getInstallStep());

    const run64_iso_blk_step = b.step("run64-iso-blk", "Run POLER-OS from ISO in QEMU with virtio-blk");
    run64_iso_blk_step.dependOn(&run64_iso_blk_cmd.step);

    // ═══ POLER Core Tests (native x86_64 linux) ════════════════════════════
    // ⚠ Инвариант (урок v0.9.0): тесты обязаны ЗАПУСКАТЬСЯ (addRunArtifact),
    // а не только компилироваться. Зависимость только от Step.Compile даёт
    // «зелёный» build при падающем/паникующем тест-бинарнике — панки
    // (@alignCast, SIGABRT, #GP) не ловились вообще.
    const test_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .gnu,
    });

    // 32-bit (legacy) POLER core tests
    const poler_core32_tests = b.addTest(.{
        .root_source_file = b.path("src/poler_core.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit POLER core tests (v8.1)
    const poler_core64_tests = b.addTest(.{
        .root_source_file = b.path("src64/poler_core.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit RSA-OAEP tests (BigInt, SHA-256, MGF1, OAEP, CascadeCipher)
    const rsa_oaep64_tests = b.addTest(.{
        .root_source_file = b.path("src64/rsa_oaep.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit PUF tests (hardware entropy binding: extractor, enrollment,
    // anti-clone, live pool — см. docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md)
    const puf64_tests = b.addTest(.{
        .root_source_file = b.path("src64/puf.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit PE/COFF parser tests (Crash-Driven Development, v0.9.0):
    // парсинг реального PE64 (testdata/curl.exe — 274 импорта из 22 DLL)
    const pe64_tests = b.addTest(.{
        .root_source_file = b.path("src64/pe.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit Win32 stub dispatcher tests: полный CDD-цикл — генерация стабов,
    // патч IAT, вызов импорта через слот, фиксация имени функции
    const win32_stubs_tests = b.addTest(.{
        .root_source_file = b.path("src64/win32_stubs.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit PE loader tests (v0.10.0, CDD №1): посекционный Ring-3 маппинг
    // curl.exe на фейковом физ-аллокаторе (LoaderOps-инъекция) + TEB/PEB
    const pe_loader_tests = b.addTest(.{
        .root_source_file = b.path("src64/pe_loader.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit Win32/CRT semantic core tests (v0.11.0, CDD №2): block-heap
    // (malloc/calloc/realloc), GetProcAddress-резолв, QPF/QPC, консольные
    // структуры, ленивые argc/argv/iob — всё через Ops-инъекцию
    const win32_crt_tests = b.addTest(.{
        .root_source_file = b.path("src64/win32_crt.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit Enrollment-Gate tests (v0.12.0, CDD №3): CPUID-отпечаток,
    // identity-свёртка (puf.extractIdentity), вердикты anti-clone (спека §4)
    const enroll_gate_tests = b.addTest(.{
        .root_source_file = b.path("src64/enroll_gate.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // 64-bit VirtIO-Net tests (v0.14.0, CDD №5): Ethernet/ARP/IPv4/TCP/DNS
    // билдеры + чексуммы RFC 1071 + парсеры — байтовая семантика стека
    const virtio_net_tests = b.addTest(.{
        .root_source_file = b.path("src64/virtio_net.zig"),
        .target = test_target,
        .optimize = .Debug,
    });

    // ЗАПУСК тестов (не только компиляция!): паника/сигнал бинарника = красный build
    const run_poler_core32_tests = b.addRunArtifact(poler_core32_tests);
    const run_poler_core64_tests = b.addRunArtifact(poler_core64_tests);
    const run_rsa_oaep64_tests = b.addRunArtifact(rsa_oaep64_tests);
    const run_puf64_tests = b.addRunArtifact(puf64_tests);
    const run_pe64_tests = b.addRunArtifact(pe64_tests);
    const run_win32_stubs_tests = b.addRunArtifact(win32_stubs_tests);
    const run_pe_loader_tests = b.addRunArtifact(pe_loader_tests);
    const run_win32_crt_tests = b.addRunArtifact(win32_crt_tests);
    const run_enroll_gate_tests = b.addRunArtifact(enroll_gate_tests);
    const run_virtio_net_tests = b.addRunArtifact(virtio_net_tests);

    const test_step = b.step("test", "Run all POLER unit tests (32-bit core + 64-bit core + RSA-OAEP + PUF + PE/COFF + Win32 stubs + PE loader + Win32/CRT core + Enrollment-Gate)");
    test_step.dependOn(&run_poler_core32_tests.step);
    test_step.dependOn(&run_poler_core64_tests.step);
    test_step.dependOn(&run_rsa_oaep64_tests.step);
    test_step.dependOn(&run_puf64_tests.step);
    test_step.dependOn(&run_pe64_tests.step);
    test_step.dependOn(&run_win32_stubs_tests.step);
    test_step.dependOn(&run_pe_loader_tests.step);
    test_step.dependOn(&run_win32_crt_tests.step);
    test_step.dependOn(&run_enroll_gate_tests.step);
    test_step.dependOn(&run_virtio_net_tests.step);

    // ═══ Build ISO step ══════════════════════════════════════════════════
    const iso_cp_cmd = b.addSystemCommand(&.{
        "cp", "zig-out/bin/poler-os64", "iso/boot/poler-os64",
    });
    iso_cp_cmd.step.dependOn(b.getInstallStep());

    // Use environment variable GRUB_MKRESCUE if set, otherwise default
    const iso_grub_cmd = b.addSystemCommand(&.{
        "grub-mkrescue", "-o", "poler-os64.iso", "iso",
    });
    iso_grub_cmd.step.dependOn(&iso_cp_cmd.step);

    const iso_step = b.step("iso", "Build POLER-OS bootable ISO");
    iso_step.dependOn(&iso_grub_cmd.step);
}
