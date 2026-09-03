// ============================================================================
// POLER-OS virtio_gpu.zig — VirtIO-GPU драйвер: probe + caps + 2D-команды
// (v0.19.0, CDD №10, шаг 1)
// ============================================================================
//
// VirtIO-GPU — виртуальная GPU QEMU (-device virtio-gpu-pci): 2D-движок
// (scanout + host-copy) для вывода кадров и аппаратный курсор. Устройство
// — VIRTIO 1.0 PCI (нет legacy-эры: GPU появился ПОСЛЕ переходного периода):
//   vendor 0x1AF4, device 0x1050 (= 0x1040 + VIRTIO_ID_GPU 16),
//   конфигурация — через PCI capability list (common/notify/device cfg).
//
// МОДЕЛЬ: probe/парсинг/билдеры команд — ЧИСТЫЕ (нативные тесты через
// PciCfg-инъекцию: fake конфиг-пространство в памяти теста); MMIO-доступ
// и vring-отправка — за BAR-адресами, выдаваемыми probe'ом ядру (main64).
//
// UAPI-СОВМЕСТИМОСТЬ: структуры = дословные раскладки
// include/uapi/linux/virtio_gpu.h (хост-ABI байто-в-байт).
//
// Инвариант CDD №10: враждебный PCI-config (cap-циклы, мусорные указатели)
// НЕ вешает ядро — лимит итераций + проверка границ смещений.
// ============================================================================

const std = @import("std");
const testing = std.testing;

// ─── Идентификаторы VirtIO (virtio_ids.h / virtio_pci.h) ───────────────────

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// VIRTIO_ID_GPU: subsystem-device у legacy; 0x1040+тип — у modern.
pub const VIRTIO_ID_GPU: u16 = 16;
/// Modern-диапазон: device_id = 0x1040 + тип устройства.
pub const VIRTIO_MODERN_BASE: u16 = 0x1040;
/// VirtIO-GPU modern PCI device id (0x1040 + 16).
pub const VIRTIO_GPU_MODERN_DEV: u16 = 0x1050;
/// Legacy-диапазон (0x1000..0x103F), тип — в subsystem (reg 0x2E).
pub const VIRTIO_LEGACY_MIN: u16 = 0x1000;
pub const VIRTIO_LEGACY_MAX: u16 = 0x103F;

// ─── PCI-конфигурация (инъекция: ядро → pci.zig, тесты → fake-пространство) ─

pub const PciCfg = struct {
    read8: *const fn (bus: u8, slot: u8, func: u8, off: u8) u8,
    read16: *const fn (bus: u8, slot: u8, func: u8, off: u8) u16,
    read32: *const fn (bus: u8, slot: u8, func: u8, off: u8) u32,
};

/// Результат probe: PCI-координаты GPU + BAR'ы для MMIO.
pub const GpuProbe = struct {
    bus: u8,
    slot: u8,
    func: u8,
    device_id: u16,
    modern: bool, // true = 0x1050 (caps), false = legacy (BAR0 I/O)
    bars: [6]u32 = .{0} ** 6, // сырые значения BAR0..BAR5

    /// MMIO-адрес BAR (identity): 0 = не мапнут/I/O-пространство.
    pub fn barAddr(self: *const GpuProbe, idx: u3) u64 {
        const v = self.bars[idx];
        if (v & 1 != 0) return 0; // I/O BAR — не MMIO
        if (v == 0) return 0;
        const base64: u64 = if (v & (1 << 2) != 0 and idx < 5)
            // 64-bit BAR: старшая половина в следующем BAR
            (@as(u64, v & 0xFFFF_FFF0) | (@as(u64, self.bars[@intCast(idx + 1)]) << 32))
        else
            (v & 0xFFFF_FFF0);
        return base64;
    }
};

/// Поиск VirtIO-GPU на шине 0 (слоты 0..31). Совпадение:
///   modern: vendor 0x1AF4 + device 0x1050;
///   legacy: vendor 0x1AF4 + device 0x1000..0x103F + subsystem 16 (0x2E).
/// null = устройства нет (норма для -vga std).
pub fn probe(cfg: PciCfg) ?GpuProbe {
    var slot: u8 = 0;
    while (slot < 32) : (slot += 1) {
        const vendor = cfg.read16(0, slot, 0, 0x00);
        if (vendor != VIRTIO_VENDOR_ID) continue;
        const dev = cfg.read16(0, slot, 0, 0x02);

        var modern = false;
        var hit = false;
        if (dev == VIRTIO_GPU_MODERN_DEV) {
            modern = true;
            hit = true;
        } else if (dev >= VIRTIO_LEGACY_MIN and dev <= VIRTIO_LEGACY_MAX) {
            // v0.14.0-урок pci.zig: subsystem DEVICE id — на 0x2E (НЕ 0x2C)
            const subsystem = cfg.read16(0, slot, 0, 0x2E);
            if (subsystem == VIRTIO_ID_GPU) {
                modern = false;
                hit = true;
            }
        }
        if (!hit) continue;

        var g = GpuProbe{
            .bus = 0,
            .slot = slot,
            .func = 0,
            .device_id = dev,
            .modern = modern,
        };
        var bar: u8 = 0;
        while (bar < 6) : (bar += 1) {
            g.bars[bar] = cfg.read32(0, slot, 0, 0x10 + bar * 4);
        }
        return g;
    }
    return null;
}

// ─── VirtIO 1.0 PCI capabilities (virtio_pci.h) ────────────────────────────

pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

/// Максимум распознаваемых capability (гостильный cap-лист).
pub const MAX_CAPS: usize = 8;
/// Лимит итераций cap-цепочки (защита от циклов next → сам).
pub const MAX_CAP_WALK: usize = 32;
/// Размер virtio_pci_cap (vndr, next, len, cfg_type, bar, pad[3], off, len).
pub const VIRTIO_PCI_CAP_SIZE: u32 = 16;

pub const VirtioCap = struct {
    cfg_type: u8 = 0, // 1 common / 2 notify / 3 isr / 4 device
    bar: u8 = 0,
    offset: u32 = 0, // смещение внутри BAR
    length: u32 = 0, // длина поля
    notify_off_multiplier: u32 = 0, // только notify-cap (+4Б к 16)
};

/// Статусный бит «есть capability list» (reg 0x06, bit 4).
pub const PCI_STATUS_CAP_LIST: u16 = 0x10;

/// Разбор cap-листа устройства. Возвращает число распознанных virtio-cap.
/// Читает: reg 0x34 (указатель на первый cap, u8, word-aligned),
/// каждый vendor-cap (id=9): cfg_type/bar/offset/length (+multiplier).
/// Гостильные листы (next-циклы, выход за 256Б) — обрезаются лимитом.
pub fn parseCaps(cfg: PciCfg, dev: GpuProbe, out: *[MAX_CAPS]VirtioCap) usize {
    @memset(out, .{});
    const status = cfg.read16(dev.bus, dev.slot, dev.func, 0x06);
    if (status & PCI_STATUS_CAP_LIST == 0) return 0;

    var cap_off: u16 = cfg.read8(dev.bus, dev.slot, dev.func, 0x34) & 0xFC;
    var found: usize = 0;
    var steps: usize = 0;
    while (cap_off != 0 and cap_off < 0x100 and steps < MAX_CAP_WALK) {
        steps += 1;
        const vndr = cfg.read8(dev.bus, dev.slot, dev.func, @intCast(cap_off));
        const next = cfg.read8(dev.bus, dev.slot, dev.func, @intCast(cap_off + 1));
        if (vndr == 0x09) { // PCI_CAP_ID_VNDR — virtio vendor-specific
            const cap_len = cfg.read8(dev.bus, dev.slot, dev.func, @intCast(cap_off + 2));
            const cfg_type = cfg.read8(dev.bus, dev.slot, dev.func, @intCast(cap_off + 3));
            if (cfg_type >= VIRTIO_PCI_CAP_COMMON_CFG and cfg_type <= VIRTIO_PCI_CAP_PCI_CFG) {
                if (found < MAX_CAPS and cap_len >= VIRTIO_PCI_CAP_SIZE) {
                    out[found] = .{
                        .cfg_type = cfg_type,
                        .bar = cfg.read8(dev.bus, dev.slot, dev.func, @intCast(cap_off + 4)),
                        .offset = cfg.read32(dev.bus, dev.slot, dev.func, @intCast(cap_off + 8)),
                        .length = cfg.read32(dev.bus, dev.slot, dev.func, @intCast(cap_off + 12)),
                        .notify_off_multiplier = if (cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG and cap_len >= 20)
                            cfg.read32(dev.bus, dev.slot, dev.func, @intCast(cap_off + 16))
                        else
                            0,
                    };
                    found += 1;
                }
            }
        }
        if (next == 0 or next == 0xFF) break;
        cap_off = next & 0xFC;
    }
    return found;
}

// ─── UAPI-структуры virtio-gpu (include/uapi/linux/virtio_gpu.h) ───────────

/// struct virtio_gpu_ctrl_hdr (24Б): все команды и ответы.
pub const CtrlHdr = extern struct {
    type_: u32 = 0,
    flags: u32 = 0,
    fence_id: u64 = 0,
    ctx_id: u32 = 0,
    padding: u32 = 0,
};

/// Команды virtio-gpu 2D (VIRTIO_GPU_CMD_*).
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const CMD_MOVE_CURSOR: u32 = 0x0301;

/// Ответы (VIRTIO_GPU_RESP_*).
pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const RESP_ERR_INVALID_PARAMETER: u32 = 0x1200;
pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;

/// struct virtio_gpu_box (16Б) — прямоугольник.
pub const Box = extern struct {
    x: u32 = 0,
    y: u32 = 0,
    w: u32 = 0,
    h: u32 = 0,
};

/// struct virtio_gpu_resource_create_2d (40Б).
pub const ResourceCreate2d = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    format: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
};

/// struct virtio_gpu_set_scanout (48Б).
pub const SetScanout = extern struct {
    hdr: CtrlHdr = .{},
    x: u32 = 0,
    y: u32 = 0,
    w: u32 = 0,
    h: u32 = 0,
    scanout_id: u32 = 0,
    resource_id: u32 = 0,
};

/// struct virtio_gpu_resource_flush (40Б).
pub const ResourceFlush = extern struct {
    hdr: CtrlHdr = .{},
    x: u32 = 0,
    y: u32 = 0,
    w: u32 = 0,
    h: u32 = 0,
};

/// struct virtio_gpu_transfer_to_host_2d (56Б).
pub const TransferToHost2d = extern struct {
    hdr: CtrlHdr = .{},
    x: u32 = 0,
    y: u32 = 0,
    w: u32 = 0,
    h: u32 = 0,
    offset: u64 = 0,
    resource_id: u32 = 0,
    padding: u32 = 0,
};

/// struct virtio_gpu_resource_attach_backing (36Б; entries — отдельные
/// дескрипторы vring: массив virtio_gpu_mem_entry).
pub const AttachBacking = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    nr_entries: u32 = 0,
    padding: u32 = 0,
};

/// struct virtio_gpu_mem_entry (16Б) — гостевая страница backing'а.
pub const MemEntry = extern struct {
    addr: u64 = 0,
    length: u32 = 0,
    padding: u32 = 0,
};

/// struct virtio_gpu_display_one (24Б).
pub const DisplayOne = extern struct {
    r: Box = .{},
    enabled: u32 = 0,
    flags: u32 = 0,
};

/// VIRTIO_GPU_MAX_SCANOUTS = 16.
pub const MAX_SCANOUTS: usize = 16;

/// struct virtio_gpu_resp_display_info (408Б).
pub const RespDisplayInfo = extern struct {
    hdr: CtrlHdr = .{},
    pmodes: [MAX_SCANOUTS]DisplayOne = [_]DisplayOne{.{}} ** MAX_SCANOUTS,
};

// ─── Форматы пикселей (virtio-gpu spec) ────────────────────────────────────

/// VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: байты в памяти [B,G,R,X] —
/// эквивалент DRM_FORMAT_XRGB8888 (fourcc XR24 little-endian).
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const FORMAT_B8G8R8A8_UNORM: u32 = 1;
/// VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM ↔ DRM_FORMAT_ABGR8888.
pub const FORMAT_R8G8B8A8_UNORM: u32 = 5;

// ─── Билдеры команд (заполнение UAPI-структур для vring) ───────────────────

pub fn cmdGetDisplayInfo() CtrlHdr {
    return .{ .type_ = CMD_GET_DISPLAY_INFO };
}

pub fn cmdResourceCreate2d(resource_id: u32, width: u32, height: u32) ResourceCreate2d {
    return .{
        .hdr = .{ .type_ = CMD_RESOURCE_CREATE_2D },
        .resource_id = resource_id,
        .format = FORMAT_B8G8R8X8_UNORM,
        .width = width,
        .height = height,
    };
}

pub fn cmdSetScanout(scanout_id: u32, resource_id: u32, w: u32, h: u32) SetScanout {
    return .{
        .hdr = .{ .type_ = CMD_SET_SCANOUT },
        .x = 0,
        .y = 0,
        .w = w,
        .h = h,
        .scanout_id = scanout_id,
        .resource_id = resource_id,
    };
}

pub fn cmdTransferToHost2d(resource_id: u32, x: u32, y: u32, w: u32, h: u32, offset: u64) TransferToHost2d {
    return .{
        .hdr = .{ .type_ = CMD_TRANSFER_TO_HOST_2D },
        .x = x,
        .y = y,
        .w = w,
        .h = h,
        .offset = offset,
        .resource_id = resource_id,
    };
}

pub fn cmdResourceFlush(x: u32, y: u32, w: u32, h: u32) ResourceFlush {
    return .{
        .hdr = .{ .type_ = CMD_RESOURCE_FLUSH },
        .x = x,
        .y = y,
        .w = w,
        .h = h,
    };
}

pub fn cmdAttachBacking(resource_id: u32, nr_entries: u32) AttachBacking {
    return .{
        .hdr = .{ .type_ = CMD_RESOURCE_ATTACH_BACKING },
        .resource_id = resource_id,
        .nr_entries = nr_entries,
    };
}

/// Первый ВКЛЮЧЁННЫЙ scanout из RESP_OK_DISPLAY_INFO (главный дисплей).
/// null = все выключены (headless QEMU: -display none без scanout).
pub fn primaryScanout(resp: *const RespDisplayInfo) ?DisplayOne {
    for (&resp.pmodes) |pm| {
        if (pm.enabled != 0) return pm;
    }
    return null;
}

// ============================================================================
//  Нативные тесты (fake PCI-пространство в памяти)
// ============================================================================

/// Fake PCI: 256Б конфиг-пространства на слот (bus 0).
const FakePci = struct {
    slots: [32][256]u8 = .{.{0} ** 256} ** 32,

    fn wr16(self: *FakePci, slot: u8, off: u8, val: u16) void {
        std.mem.writeInt(u16, self.slots[slot][off..][0..2], val, .little);
    }
    fn wr32(self: *FakePci, slot: u8, off: u8, val: u32) void {
        std.mem.writeInt(u32, self.slots[slot][off..][0..4], val, .little);
    }
    fn wr8(self: *FakePci, slot: u8, off: u8, val: u8) void {
        self.slots[slot][off] = val;
    }
    /// Положить virtio vendor-cap в слот по смещению; notify-cap получает
    /// cap_len=20 и multiplier (реальная раскладка virtio_pci_notify_cap).
    fn putCap(self: *FakePci, slot: u8, cap_off: u8, cfg_type: u8, bar: u8, offset: u32, length: u32, next: u8) void {
        const is_notify = cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG;
        const cap_len: u8 = if (is_notify) 20 else 16;
        self.wr8(slot, cap_off, 9); // PCI_CAP_ID_VNDR
        self.wr8(slot, cap_off + 1, next);
        self.wr8(slot, cap_off + 2, cap_len);
        self.wr8(slot, cap_off + 3, cfg_type);
        self.wr8(slot, cap_off + 4, bar);
        self.wr32(slot, cap_off + 8, offset);
        self.wr32(slot, cap_off + 12, length);
        if (is_notify) self.wr32(slot, cap_off + 16, 4); // notify_off_multiplier
    }
};

var g_pci: ?*FakePci = null;

fn fakeRead8(bus: u8, slot: u8, func: u8, off: u8) u8 {
    _ = bus;
    _ = func;
    return g_pci.?.slots[slot][off];
}
fn fakeRead16(bus: u8, slot: u8, func: u8, off: u8) u16 {
    _ = bus;
    _ = func;
    return std.mem.readInt(u16, g_pci.?.slots[slot][off..][0..2], .little);
}
fn fakeRead32(bus: u8, slot: u8, func: u8, off: u8) u32 {
    _ = bus;
    _ = func;
    return std.mem.readInt(u32, g_pci.?.slots[slot][off..][0..4], .little);
}

fn fakeCfg() PciCfg {
    return .{ .read8 = fakeRead8, .read16 = fakeRead16, .read32 = fakeRead32 };
}

fn pciSetup() !*FakePci {
    const p = try testing.allocator.create(FakePci);
    p.* = .{};
    g_pci = p;
    return p;
}
fn pciTeardown(p: *FakePci) void {
    g_pci = null;
    testing.allocator.destroy(p);
}

/// Собрать modern virtio-gpu в слоте: vendor/device/BAR'ы/cap-лист.
fn buildModernGpu(p: *FakePci, slot: u8) void {
    p.wr16(slot, 0x00, VIRTIO_VENDOR_ID);
    p.wr16(slot, 0x02, VIRTIO_GPU_MODERN_DEV);
    p.wr16(slot, 0x06, PCI_STATUS_CAP_LIST); // cap-лист есть
    p.wr8(slot, 0x34, 0x40); // первый cap @ 0x40
    // BAR4 — MMIO 64-bit @ 0xF000_0000 (common cfg), BAR5 — старшая половина
    p.wr32(slot, 0x10, 0); // BAR0 пуст
    p.wr32(slot, 0x20, 0xF000_0004); // BAR4: 64-bit MMIO (flags bit2+bit3?)
    p.wr32(slot, 0x24, 0x0000_0000); // BAR5: hi
    // caps: common(1)@0x40 → notify(2)@0x50 (len 20) → device(4)@0x70
    p.putCap(slot, 0x40, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0x0000, 56, 0x50);
    p.putCap(slot, 0x50, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x1000, 4, 0x70);
    p.putCap(slot, 0x70, VIRTIO_PCI_CAP_DEVICE_CFG, 5, 0x0000, 408, 0x00);
}

// ─── Тесты: probe ──────────────────────────────────────────────────────────

test "gpu: probe — modern 0x1050 находится; BAR'ы прочитаны" {
    const p = try pciSetup();
    defer pciTeardown(p);
    buildModernGpu(p, 3);

    const g = probe(fakeCfg()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 3), g.slot);
    try testing.expectEqual(VIRTIO_GPU_MODERN_DEV, g.device_id);
    try testing.expect(g.modern);
    // BAR4 = 0xF000_0004 → база 0xF000_0000 (биты флагов срезаны)
    try testing.expectEqual(@as(u64, 0xF000_0000), g.barAddr(4));
}

test "gpu: probe — legacy 0x1000+subsystem16; net (subsys1) НЕ совпадает" {
    const p = try pciSetup();
    defer pciTeardown(p);
    // legacy virtio-gpu в слоте 5
    p.wr16(5, 0x00, VIRTIO_VENDOR_ID);
    p.wr16(5, 0x02, 0x1000);
    p.wr16(5, 0x2E, VIRTIO_ID_GPU); // subsystem = 16 (GPU)
    p.wr32(5, 0x10, 0xC001); // BAR0: I/O-пространство

    const g = probe(fakeCfg()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 5), g.slot);
    try testing.expect(!g.modern);
    try testing.expectEqual(@as(u64, 0), g.barAddr(0)); // I/O BAR — не MMIO

    // virtio-NET (subsystem 1) в слоте 7 — probe НЕ должен совпасть
    @memset(&p.slots[7], 0);
    p.wr16(7, 0x00, VIRTIO_VENDOR_ID);
    p.wr16(7, 0x02, 0x1000);
    p.wr16(7, 0x2E, 1); // VIRTIO_ID_NETWORK
    // (слот 5 всё ещё GPU — уберём его, оставив только net)
    @memset(&p.slots[5], 0);
    try testing.expect(probe(fakeCfg()) == null);
}

test "gpu: probe — пустая шина / чужой vendor → null" {
    const p = try pciSetup();
    defer pciTeardown(p);
    try testing.expect(probe(fakeCfg()) == null);

    // VGA-совместимый контроллер (0x1234 QEMU std) — не virtio
    p.wr16(2, 0x00, 0x1234);
    p.wr16(2, 0x02, 0x1111);
    try testing.expect(probe(fakeCfg()) == null);
}

// ─── Тесты: capability-парсинг ─────────────────────────────────────────────

test "gpu: parseCaps — common/notify/device из cap-листа" {
    const p = try pciSetup();
    defer pciTeardown(p);
    buildModernGpu(p, 3);
    const g = probe(fakeCfg()).?;

    var caps: [MAX_CAPS]VirtioCap = undefined;
    const n = parseCaps(fakeCfg(), g, &caps);
    try testing.expectEqual(@as(usize, 3), n);

    // common cfg: BAR4 +0, 56Б
    try testing.expectEqual(VIRTIO_PCI_CAP_COMMON_CFG, caps[0].cfg_type);
    try testing.expectEqual(@as(u8, 4), caps[0].bar);
    try testing.expectEqual(@as(u32, 0), caps[0].offset);
    try testing.expectEqual(@as(u32, 56), caps[0].length);
    // notify: BAR4 +0x1000, 4Б, multiplier 4
    try testing.expectEqual(VIRTIO_PCI_CAP_NOTIFY_CFG, caps[1].cfg_type);
    try testing.expectEqual(@as(u32, 0x1000), caps[1].offset);
    try testing.expectEqual(@as(u32, 4), caps[1].notify_off_multiplier);
    // device cfg (display): BAR5 +0, 408Б
    try testing.expectEqual(VIRTIO_PCI_CAP_DEVICE_CFG, caps[2].cfg_type);
    try testing.expectEqual(@as(u8, 5), caps[2].bar);
    try testing.expectEqual(@as(u32, 408), caps[2].length);
}

test "gpu: parseCaps — cap-лист без статуса/циклы — безопасное завершение" {
    const p = try pciSetup();
    defer pciTeardown(p);
    buildModernGpu(p, 3);
    const g = probe(fakeCfg()).?;

    // нет флага cap-list → 0 caps
    p.wr16(3, 0x06, 0);
    var caps: [MAX_CAPS]VirtioCap = undefined;
    try testing.expectEqual(@as(usize, 0), parseCaps(fakeCfg(), g, &caps));

    // цикл: cap@0x40 next→0x50, cap@0x50 next→0x40 — лимит итераций
    p.wr16(3, 0x06, PCI_STATUS_CAP_LIST);
    p.wr8(3, 0x41, 0x50);
    p.wr8(3, 0x51, 0x40);
    const n = parseCaps(fakeCfg(), g, &caps);
    try testing.expect(n <= MAX_CAPS); // не зависло, лимит сработал

    // мусорный указатель cap_off=0xFC+ — выход из цикла
    p.wr8(3, 0x34, 0xFC);
    try testing.expect(parseCaps(fakeCfg(), g, &caps) >= 0);
}

// ─── Тесты: UAPI-раскладки и билдеры ───────────────────────────────────────

test "gpu: UAPI-размеры структур virtio-gpu (хост-ABI)" {
    try testing.expectEqual(@as(usize, 24), @sizeOf(CtrlHdr));
    try testing.expectEqual(@as(usize, 16), @sizeOf(Box));
    try testing.expectEqual(@as(usize, 40), @sizeOf(ResourceCreate2d));
    try testing.expectEqual(@as(usize, 48), @sizeOf(SetScanout));
    try testing.expectEqual(@as(usize, 40), @sizeOf(ResourceFlush));
    try testing.expectEqual(@as(usize, 56), @sizeOf(TransferToHost2d));
    try testing.expectEqual(@as(usize, 40), @sizeOf(AttachBacking)); // 36 + хвостовое выравнивание 8 (как в C: hdr содержит u64)
    try testing.expectEqual(@as(usize, 16), @sizeOf(MemEntry));
    try testing.expectEqual(@as(usize, 24), @sizeOf(DisplayOne));
    try testing.expectEqual(@as(usize, 408), @sizeOf(RespDisplayInfo));
}

test "gpu: билдеры команд — поля и сериализация байт-в-байт" {
    // RESOURCE_CREATE_2D: ресурс 7, 640×480, формат XRGB8888 (2)
    const rc = cmdResourceCreate2d(7, 640, 480);
    try testing.expectEqual(CMD_RESOURCE_CREATE_2D, rc.hdr.type_);
    try testing.expectEqual(@as(u32, 7), rc.resource_id);
    try testing.expectEqual(FORMAT_B8G8R8X8_UNORM, rc.format);
    try testing.expectEqual(@as(u32, 640), rc.width);
    var buf: [@sizeOf(ResourceCreate2d)]u8 = undefined;
    @memcpy(&buf, std.mem.asBytes(&rc));
    // resource_id @24 (после hdr), format @28, width @32, height @36
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, buf[24..28], .little));
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, buf[28..32], .little));
    try testing.expectEqual(@as(u32, 640), std.mem.readInt(u32, buf[32..36], .little));
    try testing.expectEqual(@as(u32, 480), std.mem.readInt(u32, buf[36..40], .little));

    // SET_SCANOUT: scanout 0 ← ресурс 7, 640×480
    const ss = cmdSetScanout(0, 7, 640, 480);
    try testing.expectEqual(CMD_SET_SCANOUT, ss.hdr.type_);
    try testing.expectEqual(@as(u32, 640), ss.w);
    try testing.expectEqual(@as(u32, 0), ss.scanout_id);

    // TRANSFER_TO_HOST_2D: строчка (0,16,640,4) ресурса 7, offset 4096
    const tr = cmdTransferToHost2d(7, 0, 16, 640, 4, 4096);
    try testing.expectEqual(CMD_TRANSFER_TO_HOST_2D, tr.hdr.type_);
    try testing.expectEqual(@as(u64, 4096), tr.offset);
    var tbuf: [@sizeOf(TransferToHost2d)]u8 = undefined;
    @memcpy(&tbuf, std.mem.asBytes(&tr));
    // w @32, h @36, offset @40, resource_id @48
    try testing.expectEqual(@as(u32, 640), std.mem.readInt(u32, tbuf[32..36], .little));
    try testing.expectEqual(@as(u64, 4096), std.mem.readInt(u64, tbuf[40..48], .little));
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, tbuf[48..52], .little));

    // RESOURCE_FLUSH: весь кадр
    const fl = cmdResourceFlush(0, 0, 640, 480);
    try testing.expectEqual(CMD_RESOURCE_FLUSH, fl.hdr.type_);
    try testing.expectEqual(@as(u32, 480), fl.h);

    // ATTACH_BACKING: ресурс 7, 1 запись (guest-страница)
    const ab = cmdAttachBacking(7, 1);
    try testing.expectEqual(CMD_RESOURCE_ATTACH_BACKING, ab.hdr.type_);
    try testing.expectEqual(@as(u32, 1), ab.nr_entries);
    const entry = MemEntry{ .addr = 0x5000_1000, .length = 4096 };
    try testing.expectEqual(@as(u64, 0x5000_1000), entry.addr);

    // GET_DISPLAY_INFO: голый hdr
    try testing.expectEqual(CMD_GET_DISPLAY_INFO, cmdGetDisplayInfo().type_);
}

test "gpu: primaryScanout — первый включённый; headless → null" {
    var resp = RespDisplayInfo{};
    resp.hdr.type_ = RESP_OK_DISPLAY_INFO;
    try testing.expect(primaryScanout(&resp) == null); // все выключены

    resp.pmodes[0] = .{ .r = .{ .x = 0, .y = 0, .w = 1280, .h = 720 }, .enabled = 1 };
    resp.pmodes[1] = .{ .r = .{ .x = 0, .y = 0, .w = 800, .h = 600 }, .enabled = 1 };
    const pm = primaryScanout(&resp).?;
    try testing.expectEqual(@as(u32, 1280), pm.r.w);
    try testing.expectEqual(@as(u32, 720), pm.r.h);

    // выключенный первый, включённый второй → берётся второй
    resp.pmodes[0].enabled = 0;
    const pm2 = primaryScanout(&resp).?;
    try testing.expectEqual(@as(u32, 800), pm2.r.w);
}

test "gpu: форматы — B8G8R8X8_UNORM=2 ↔ DRM XRGB8888-семантика" {
    // virtio перечисляет от старшего байта: B8G8R8X8 = память [B,G,R,X]
    // little-endian u32 = 0xXXRRGGBB — это именно DRM_FORMAT_XRGB8888.
    try testing.expectEqual(@as(u32, 2), FORMAT_B8G8R8X8_UNORM);
    try testing.expectEqual(@as(u32, 1), FORMAT_B8G8R8A8_UNORM);
    try testing.expectEqual(@as(u32, 5), FORMAT_R8G8B8A8_UNORM);
}
