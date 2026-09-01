// ============================================================================
// POLER-OS PCI Bus Driver — x86_64
// ============================================================================
// PCI configuration space access, device enumeration, and VirtIO device
// discovery.  Extracted from the original drivers/virtio.zig and adapted
// for the 64-bit kernel's HAL-based I/O.
// ============================================================================

const hal = @import("hal.zig");

// ============================================================================
// PCI Configuration Space Access
// ============================================================================

const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

pub fn pciRead32(bus: u8, slot: u8, func: u8, offset: u8) u32 {
    const addr = (@as(u32, 1) << 31) |
        (@as(u32, bus) << 16) |
        (@as(u32, slot) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    hal.outl(PCI_CONFIG_ADDR, addr);
    return hal.inl(PCI_CONFIG_DATA);
}

pub fn pciWrite32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) void {
    const addr = (@as(u32, 1) << 31) |
        (@as(u32, bus) << 16) |
        (@as(u32, slot) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    hal.outl(PCI_CONFIG_ADDR, addr);
    hal.outl(PCI_CONFIG_DATA, val);
}

pub fn pciRead16(bus: u8, slot: u8, func: u8, offset: u8) u16 {
    const val = pciRead32(bus, slot, func, offset);
    return @truncate(val >> (8 * (@as(u5, @truncate(offset)) & 2)));
}

pub fn pciRead8(bus: u8, slot: u8, func: u8, offset: u8) u8 {
    const val = pciRead32(bus, slot, func, offset);
    return @truncate(val >> (8 * (@as(u32, offset) & 3)));
}

pub fn pciWrite16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) void {
    const addr = (@as(u32, 1) << 31) |
        (@as(u32, bus) << 16) |
        (@as(u32, slot) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    hal.outl(PCI_CONFIG_ADDR, addr);
    // Read-modify-write for 16-bit within 32-bit register
    const old = hal.inl(PCI_CONFIG_DATA);
    const shift_raw = 8 * (@as(u5, @truncate(offset)) & 2);
    const shift: u5 = @intCast(shift_raw);
    const mask: u32 = @shlExact(@as(u32, 0xFFFF), shift);
    const new = (old & ~mask) | (@as(u32, val) << shift);
    hal.outl(PCI_CONFIG_ADDR, addr);
    hal.outl(PCI_CONFIG_DATA, new);
}

// ============================================================================
// PCI Device Information
// ============================================================================

pub const PciDeviceInfo = struct {
    bus: u8,
    slot: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    io_base: u16,
    irq: u8,
    header_type: u8,
};

// ============================================================================
// PCI Device Enumeration
// ============================================================================

const MAX_PCI_DEVICES: usize = 32;
var found_devices: [MAX_PCI_DEVICES]PciDeviceInfo = undefined;
var device_count: usize = 0;

/// Scan the entire PCI bus and cache discovered devices.
pub fn scan() void {
    device_count = 0;

    hal.Serial.puts("[PCI] Scanning PCI bus...\n");

    var bus: u8 = 0;
    while (bus < 1) : (bus += 1) { // Scan bus 0 only for now
        var slot: u8 = 0;
        while (slot < 32) : (slot += 1) {
            const vendor = pciRead16(bus, slot, 0, 0);
            if (vendor == 0xFFFF) continue;

            const device_id = pciRead16(bus, slot, 0, 2);
            const class_code: u8 = @truncate(pciRead32(bus, slot, 0, 8) >> 24);
            const subclass: u8 = @truncate(pciRead32(bus, slot, 0, 8) >> 16);
            const prog_if: u8 = @truncate(pciRead32(bus, slot, 0, 8) >> 8);
            const header_type: u8 = @truncate(pciRead32(bus, slot, 0, 0x0C) >> 16);

            // Get I/O or Memory base from BAR0
            const bar0 = pciRead32(bus, slot, 0, 0x10);
            const io_base: u16 = if ((bar0 & 1) != 0)
                @truncate(bar0 & 0xFFFC)
            else
                @truncate((bar0 >> 4) & 0xFFF0); // Memory-mapped BAR: bits [31:4], lower 16 for compatibility

            // Get IRQ
            const irq: u8 = @truncate(pciRead32(bus, slot, 0, 0x3C));

            if (device_count < MAX_PCI_DEVICES) {
                found_devices[device_count] = PciDeviceInfo{
                    .bus = bus,
                    .slot = slot,
                    .func = 0,
                    .vendor_id = vendor,
                    .device_id = device_id,
                    .class_code = class_code,
                    .subclass = subclass,
                    .prog_if = prog_if,
                    .io_base = io_base,
                    .irq = irq,
                    .header_type = header_type,
                };
                device_count += 1;

                hal.Serial.puts("[PCI] ");
                hal.Serial.putHex(bus);
                hal.Serial.puts(":");
                hal.Serial.putHex(slot);
                hal.Serial.puts(" vendor=0x");
                hal.Serial.putHex(vendor);
                hal.Serial.puts(" device=0x");
                hal.Serial.putHex(device_id);
                hal.Serial.puts(" class=0x");
                hal.Serial.putHex(class_code);
                hal.Serial.puts(" io=0x");
                hal.Serial.putHex(io_base);
                hal.Serial.puts(" irq=");
                hal.Serial.putHex(irq);
                hal.Serial.puts("\n");
            }
        }
    }

    hal.Serial.puts("[PCI] Found ");
    hal.Serial.putHex(device_count);
    hal.Serial.puts(" PCI devices\n");
}

/// Find a VirtIO block device among the scanned devices.
/// VirtIO legacy devices: vendor 0x1AF4, device ID 0x1000-0x103F.
/// The subsystem ID (offset 0x2E — НЕ 0x2C, там subsystem VENDOR!)
/// identifies the device type (2 = block).
/// v0.14.0-fix: читали 0x2C → subsystem_vendor (0x1AF4) → всегда мисматч.
pub fn findVirtioBlk() ?PciDeviceInfo {
    for (0..device_count) |i| {
        const dev = found_devices[i];
        if (dev.vendor_id == 0x1AF4 and
            dev.device_id >= 0x1000 and
            dev.device_id <= 0x103F)
        {
            const subsystem_id = pciRead16(dev.bus, dev.slot, dev.func, 0x2E);
            if (subsystem_id == 2) { // VIRTIO_ID_BLOCK
                return dev;
            }
        }
    }
    return null;
}

/// Find any VirtIO device (by subsystem type).
/// v0.14.0-fix: subsystem DEVICE id на 0x2E (0x2C = subsystem vendor).
pub fn findVirtioDevice(subsystem_type: u16) ?PciDeviceInfo {
    for (0..device_count) |i| {
        const dev = found_devices[i];
        if (dev.vendor_id == 0x1AF4 and
            dev.device_id >= 0x1000 and
            dev.device_id <= 0x103F)
        {
            const subsystem_id = pciRead16(dev.bus, dev.slot, dev.func, 0x2E);
            if (subsystem_id == subsystem_type) {
                return dev;
            }
        }
    }
    return null;
}

/// Enable a PCI device: set Bus Master and I/O space bits in the command register.
pub fn enableDevice(bus: u8, slot: u8, func: u8) void {
    const cmd = pciRead16(bus, slot, func, 0x04);
    // Set Bus Master (bit 2), I/O Space (bit 0), Memory Space (bit 1)
    const new_cmd = cmd | 0x07;
    pciWrite16(bus, slot, func, 0x04, new_cmd);

    hal.Serial.puts("[PCI] Enabled device at ");
    hal.Serial.putHex(bus);
    hal.Serial.puts(":");
    hal.Serial.putHex(slot);
    hal.Serial.puts(" cmd=0x");
    hal.Serial.putHex(new_cmd);
    hal.Serial.puts("\n");
}

/// Get the number of discovered PCI devices.
pub fn getDeviceCount() usize {
    return device_count;
}

/// Get a discovered PCI device by index.
pub fn getDevice(index: usize) ?PciDeviceInfo {
    if (index >= device_count) return null;
    return found_devices[index];
}
