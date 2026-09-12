const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize: std.builtin.OptimizeMode = .Debug;

    // ═══ 32-bit Kernel Build (legacy) ════════════════════════════════════
    const kernel32_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel32_mod = b.createModule(.{
        .root_source_file = b.path("src/main32.zig"),
        .target = kernel32_target,
        .optimize = optimize,
    });
    kernel32_mod.addAssemblyFile(b.path("src/boot32.S"));
    kernel32_mod.addAssemblyFile(b.path("src/isr32.S"));

    const kernel32 = b.addExecutable(.{
        .name = "poler-os32",
        .root_module = kernel32_mod,
        .use_llvm = true,
    });

    kernel32.setLinkerScript(b.path("src/linker32.ld"));
    kernel32.link_gc_sections = false;
    b.installArtifact(kernel32);

    // ═══ 64-bit Kernel Build (POLER-OS v0.6.0) ═════════════════════════
    const kernel64_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel64_mod = b.createModule(.{
        .root_source_file = b.path("src64/main64.zig"),
        .target = kernel64_target,
        .optimize = optimize,
    });
    kernel64_mod.addAssemblyFile(b.path("src64/boot64.S"));
    kernel64_mod.addAssemblyFile(b.path("src64/isr64.S"));

    const kernel64 = b.addExecutable(.{
        .name = "poler-os64",
        .root_module = kernel64_mod,
        .use_llvm = true,
    });

    kernel64.setLinkerScript(b.path("src64/linker64.ld"));
    kernel64.link_gc_sections = false;
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

    const addPolerTest = struct {
        fn make(build_ctx: *std.Build, path: []const u8, t_target: std.Build.ResolvedTarget, opt: std.builtin.OptimizeMode) *std.Build.Step.Compile {
            const mod = build_ctx.createModule(.{
                .root_source_file = build_ctx.path(path),
                .target = t_target,
                .optimize = opt,
            });
            return build_ctx.addTest(.{
                .root_module = mod,
                .use_llvm = true,
            });
        }
    }.make;

    // 32-bit (legacy) POLER core tests
    const poler_core32_tests = addPolerTest(b, "src/poler_core.zig", test_target, .Debug);

    // 64-bit POLER core tests (v8.1)
    const poler_core64_tests = addPolerTest(b, "src64/poler_core.zig", test_target, .Debug);

    // 64-bit RSA-OAEP tests (BigInt, SHA-256, MGF1, OAEP, CascadeCipher)
    const rsa_oaep64_tests = addPolerTest(b, "src64/rsa_oaep.zig", test_target, .ReleaseFast);

    // 64-bit PUF tests (hardware entropy binding: extractor, enrollment,
    // anti-clone, live pool — см. docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md)
    const puf64_tests = addPolerTest(b, "src64/puf.zig", test_target, .Debug);

    // 64-bit PE/COFF parser tests (Crash-Driven Development, v0.9.0):
    // парсинг реального PE64 (testdata/curl.exe — 274 импорта из 22 DLL)
    const pe64_tests = addPolerTest(b, "src64/pe.zig", test_target, .Debug);

    // 64-bit Win32 stub dispatcher tests: полный CDD-цикл — генерация стабов,
    // патч IAT, вызов импорта через слот, фиксация имени функции
    const win32_stubs_tests = addPolerTest(b, "src64/win32_stubs.zig", test_target, .Debug);

    // 64-bit PE loader tests (v0.10.0): маппинг секций в user-VA,
    // Zero-VMM трансляции, page-table изоляция, проверка entry point
    const pe_loader_tests = addPolerTest(b, "src64/pe_loader.zig", test_target, .Debug);

    // 64-bit Win32 / CRT core integration tests (v0.10.0, CDD №8):
    // TLS (_tls_index=0), PEB/TEB (%gs:0x30 / %gs:0x60), handle table,
    // HeapCreate / HeapAlloc (8B align), CRT __acrt_iob_func, GetModuleHandleA
    const win32_crt_tests = addPolerTest(b, "src64/win32_crt.zig", test_target, .Debug);

    // 64-bit Enrollment-Gate integration tests (v0.12.0, CDD №9):
    // сквозной конвейер PUF → keywrap → RSA-OAEP → CascadeCipher → HMAC-SHA256
    const enroll_gate_tests = addPolerTest(b, "src64/enroll_gate.zig", test_target, .Debug);

    // 64-bit VirtIO-Net packet & checksum tests (v0.15.0, CDD №9.5):
    // RFC 1071 IP-чексуммы, ARP, IPv4, UDP/DHCP, DNS wire-format билдеры
    const virtio_net_tests = addPolerTest(b, "src64/virtio_net.zig", test_target, .Debug);

    // 64-bit Linux POSIX ABI syscall tests (v0.20.0, CDD №11 p1):
    // sys_write (stdout/stderr), sys_exit/sys_exit_group (status code, 127 = ld.so fail),
    // sys_brk (интервалы кучи), user-space memory boundary validation (USER_VA_CEILING)
    const linux_syscalls_tests = addPolerTest(b, "src64/linux_syscalls.zig", test_target, .Debug);

    // 64-bit Scheduler Resume-Frame tests (v0.20.0, CDD №11 p1):
    // snapshot/install кадров возврата из syscall, Win32/Linux ABI изоляция
    const sched_resume_tests = addPolerTest(b, "src64/scheduler.zig", test_target, .Debug);

    // 64-bit DRM/KMS tests (v0.19.0, CDD №10 p1): UAPI-совместимость ioctl-
    // номеров/раскладок (якоря libdrm), dumb-буферный жизненный цикл,
    // fbdev, апертура mmap, WC/PAT-семантика — DrmOps-инъекция
    const drm_kms_tests = addPolerTest(b, "src64/drm_kms.zig", test_target, .Debug);

    // 64-bit VirtIO-GPU tests (v0.19.0, CDD №10 p1): PCI-probe (modern/
    // legacy), virtio-1.0 capability-парсинг (гостильные листы), 2D-команды
    // байт-в-байт — PciCfg-инъекция с fake конфиг-пространством
    const virtio_gpu_tests = addPolerTest(b, "src64/virtio_gpu.zig", test_target, .Debug);

    // 64-bit Evdev tests (v0.19.0, CDD №10 p2): UAPI input_event 24Б,
    // ioctl-якоря libevdev, FIFO-очередь, read-семантика (EAGAIN/EINVAL),
    // переполнение-дроп, PS/2 Set1→KEY-таблица, мышиные пакеты
    const evdev_tests = addPolerTest(b, "src64/evdev.zig", test_target, .Debug);

    // 64-bit VFS tests (v0.20.0, CDD №12 p1): CPIO-initrd RO, tmpfs RAM overlay,
    // symlink-резолв (относительные, абсолютные, многошаговые, циклические ELOOP)
    const vfs_tests = addPolerTest(b, "src64/vfs.zig", test_target, .Debug);

    // 64-bit ELF loader tests (v0.20.0, CDD №11 p1): Linux-ABI ELF64
    const elf_loader_tests = addPolerTest(b, "src64/elf_loader.zig", test_target, .Debug);
    // v0.20.0 (CDD №13): Нативный SquashFS v4 парсер + Live Orchestrator
    const squashfs_tests = addPolerTest(b, "src64/squashfs.zig", test_target, .Debug);
    const live_orchestrator_tests = addPolerTest(b, "src64/live_orchestrator.zig", test_target, .Debug);

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
    const run_linux_syscalls_tests = b.addRunArtifact(linux_syscalls_tests);
    const run_sched_resume_tests = b.addRunArtifact(sched_resume_tests);
    const run_drm_kms_tests = b.addRunArtifact(drm_kms_tests);
    const run_virtio_gpu_tests = b.addRunArtifact(virtio_gpu_tests);
    const run_evdev_tests = b.addRunArtifact(evdev_tests);
    const run_vfs_tests = b.addRunArtifact(vfs_tests);
    const run_elf_loader_tests = b.addRunArtifact(elf_loader_tests);
    const run_squashfs_tests = b.addRunArtifact(squashfs_tests);
    const run_live_orchestrator_tests = b.addRunArtifact(live_orchestrator_tests);

    const test_step = b.step("test", "Run all POLER unit tests (32-bit core + 64-bit core + RSA-OAEP + PUF + PE/COFF + Win32 stubs + PE loader + Win32/CRT core + Enrollment-Gate + SquashFS + Live Orchestrator)");
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
    test_step.dependOn(&run_linux_syscalls_tests.step);
    test_step.dependOn(&run_sched_resume_tests.step);
    test_step.dependOn(&run_drm_kms_tests.step);
    test_step.dependOn(&run_virtio_gpu_tests.step);
    test_step.dependOn(&run_evdev_tests.step);
    test_step.dependOn(&run_vfs_tests.step);
    test_step.dependOn(&run_elf_loader_tests.step);
    test_step.dependOn(&run_squashfs_tests.step);
    test_step.dependOn(&run_live_orchestrator_tests.step);

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
