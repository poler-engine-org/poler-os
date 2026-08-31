// ============================================================================
// POLER-OS VirtIO Block Device Driver — x86_64
// ============================================================================
// Phase 2: virtio-blk driver with split virtqueues, polling I/O.
//
// Key fixes vs initial version:
//   - FIXED: Contiguous virtqueue allocation (desc+avail+used must be contiguous)
//   - FIXED: PFN register uses proper 32-bit value
//   - FIXED: DMA buffers use identity mapping (phys==virt) — previously
//     used VMM before VMM init, corrupting page tables → timeout
//   - Separate DMA slots for req header / data / status
//   - Correct avail/used ring access via pointer arithmetic (offset +4)
//   - pause instruction in polling loop
//   - Memory barriers at all critical points
// ============================================================================

const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const pci = @import("pci.zig");

// Bus entropy callback — registered by kernel to feed BusPool (DMA/PCIe timing)
pub var bus_entropy_sink: ?*const fn (u64) void = null;

// ============================================================================
// VirtIO PCI Register Offsets (Legacy / Transitional)
// ============================================================================

const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_ISR: u16 = 0x13;
const VIRTIO_PCI_CONFIG: u16 = 0x14;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_FAILED: u8 = 128;

const VIRTIO_DESC_F_NEXT: u16 = 1;
const VIRTIO_DESC_F_WRITE: u16 = 2;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// VirtIO-blk feature bits
const VIRTIO_BLK_F_SIZE_MAX: u32 = 1 << 1;
const VIRTIO_BLK_F_SEG_MAX: u32 = 1 << 2;
const VIRTIO_BLK_F_BLK_SIZE: u32 = 1 << 6;
const VIRTIO_BLK_F_RO: u32 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

// ============================================================================
// VirtQueue Data Structures
// ============================================================================

const VirtQueueDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

const VirtQueueAvail = extern struct {
    flags: u16,
    idx: u16,
    // ring: [QUEUE_SIZE]u16 follows at offset 4
    // used_event: u16 follows after ring
};

const VirtQueueUsedElem = extern struct {
    id: u32,
    len: u32,
};

const VirtQueueUsed = extern struct {
    flags: u16,
    idx: u16,
    // ring: [QUEUE_SIZE]VirtQueueUsedElem follows at offset 4
    // avail_event: u16 follows after ring
};

const QUEUE_SIZE: u16 = 256;

const DESC_TABLE_SIZE: u32 = QUEUE_SIZE * 16; // 4096 = 1 page
const AVAIL_RING_SIZE: u32 = 4 + QUEUE_SIZE * 2 + 2; // 514
const USED_RING_SIZE: u32 = 4 + QUEUE_SIZE * 8 + 2; // 2050

// Page-aligned sizes for VirtIO layout
const DESC_PAGES: u32 = (DESC_TABLE_SIZE + 4095) / 4096; // 1
const AVAIL_PAGES: u32 = (AVAIL_RING_SIZE + 4095) / 4096; // 1
const USED_PAGES: u32 = (USED_RING_SIZE + 4095) / 4096; // 1
const VQ_TOTAL_PAGES: u32 = DESC_PAGES + AVAIL_PAGES + USED_PAGES; // 3

const VirtBlkReqHeader = extern struct {
    type: u32,
    reserved: u32,
    sector: u64,
};

const VirtBlkConfig = extern struct {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry_cylinders: u16,
    geometry_heads: u8,
    geometry_sectors: u8,
    blk_size: u32,
};

// ============================================================================
// DMA Slot — pre-allocated buffers for I/O operations
// ============================================================================

const NUM_DMA_SLOTS = 4;

const DmaSlot = struct {
    req_phys: u64,
    req_virt: u64,
    data_phys: u64,
    data_virt: u64,
    status_phys: u64,
    status_virt: u64,
    in_use: bool,
};

// ============================================================================
// Global VirtIO-Blk State
// ============================================================================

pub const VblkError = error{
    NoDevice,
    InitFailed,
    ReadFailed,
    WriteFailed,
    NoDmaSlot,
    Timeout,
};

var vblk_state: struct {
    initialized: bool = false,
    io_base: u16 = 0,
    irq: u8 = 0,
    pci_dev: ?pci.PciDeviceInfo = null,
    config: VirtBlkConfig = undefined,
    features: u32 = 0,
    is_read_only: bool = false,

    // Queue state (using virtual addresses for access, physical for DMA)
    // All three structures are contiguous in physical memory starting at vq_phys
    vq_phys: u64 = 0, // Base physical address of the virtqueue
    vq_virt: u64 = 0, // Base virtual address of the virtqueue

    desc_phys: u64 = 0,
    desc_virt: u64 = 0,
    avail_phys: u64 = 0,
    avail_virt: u64 = 0,
    used_phys: u64 = 0,
    used_virt: u64 = 0,
    free_head: u16 = 0,
    num_free: u16 = QUEUE_SIZE,
    last_used_idx: u16 = 0,

    // DMA slots
    dma_slots: [NUM_DMA_SLOTS]DmaSlot = undefined,
} = .{};

// ============================================================================
// I/O Register Access
// ============================================================================

fn read8(offset: u16) u8 {
    return hal.inb(vblk_state.io_base + offset);
}

fn read16(offset: u16) u16 {
    return hal.inw(vblk_state.io_base + offset);
}

fn read32(offset: u16) u32 {
    return hal.inl(vblk_state.io_base + offset);
}

fn write8(offset: u16, val: u8) void {
    hal.outb(vblk_state.io_base + offset, val);
}

fn write16(offset: u16, val: u16) void {
    hal.outw(vblk_state.io_base + offset, val);
}

fn write32(offset: u16, val: u32) void {
    hal.outl(vblk_state.io_base + offset, val);
}

// ============================================================================
// Descriptor Table Access
// ============================================================================

fn getDesc(idx: u16) *volatile VirtQueueDesc {
    const ptr: [*]volatile VirtQueueDesc = @ptrFromInt(@as(usize, @intCast(vblk_state.desc_virt)));
    return &ptr[idx];
}

fn getAvail() *volatile VirtQueueAvail {
    return @ptrFromInt(@as(usize, @intCast(vblk_state.avail_virt)));
}

fn getUsed() *volatile VirtQueueUsed {
    return @ptrFromInt(@as(usize, @intCast(vblk_state.used_virt)));
}

// ============================================================================
// Descriptor Chain Management
// ============================================================================

fn allocDescChain(count: u16) ?u16 {
    if (vblk_state.num_free < count) return null;

    const head = vblk_state.free_head;
    var current = head;
    var i: u16 = 0;
    while (i < count - 1) : (i += 1) {
        var desc = getDesc(current);
        desc.flags = VIRTIO_DESC_F_NEXT;
        current = desc.next;
    }
    // Last descriptor: no F_NEXT
    getDesc(current).flags = 0;

    vblk_state.free_head = getDesc(current).next;
    vblk_state.num_free -= count;

    return head;
}

fn freeDescChain(head: u16) void {
    var current = head;
    while (true) {
        const desc = getDesc(current);
        const flags = desc.flags;
        const next = desc.next;

        desc.* = .{
            .addr = 0,
            .len = 0,
            .flags = 0,
            .next = vblk_state.free_head,
        };
        vblk_state.free_head = current;
        vblk_state.num_free += 1;

        if ((flags & VIRTIO_DESC_F_NEXT) == 0) break;
        current = next;
    }
}

// ============================================================================
// DMA Slot Management
// ============================================================================

fn allocDmaSlot() ?*DmaSlot {
    for (&vblk_state.dma_slots) |*slot| {
        if (!slot.in_use) {
            slot.in_use = true;
            return slot;
        }
    }
    return null;
}

fn freeDmaSlot(slot: *DmaSlot) void {
    slot.in_use = false;
}

// ============================================================================
// VirtQueue Operations
// ============================================================================

fn submitChain(head: u16) void {
    const avail = getAvail();
    const idx = avail.idx;
    // Ring starts at offset 4 (after flags + idx)
    const ring_ptr: [*]volatile u16 = @ptrFromInt(@as(usize, @intCast(vblk_state.avail_virt)) + 4);
    ring_ptr[idx % QUEUE_SIZE] = head;
    // Memory barrier before updating idx
    asm volatile ("" ::: "memory");
    avail.idx = idx + 1;
    asm volatile ("" ::: "memory");
    // Notify device
    write16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
}

fn waitForCompletion(timeout_ticks: u64) ?u32 {
    var ticks: u64 = 0;
    while (ticks < timeout_ticks) : (ticks += 1) {
        const used = getUsed();
        if (vblk_state.last_used_idx != used.idx) {
            const ring_ptr: [*]volatile VirtQueueUsedElem = @ptrFromInt(@as(usize, @intCast(vblk_state.used_virt)) + 4);
            const used_elem = ring_ptr[vblk_state.last_used_idx % QUEUE_SIZE];
            vblk_state.last_used_idx += 1;
            return used_elem.id;
        }
        asm volatile ("pause");
    }
    return null;
}

// ============================================================================
// Memory Helper: allocate page and map it via VMM
// ============================================================================

// NOTE: allocAndMapPage() removed — it was using VMM before VMM was
// initialized, which caused the DMA timeout bug.  DMA slots now use
// identity-mapped physical addresses directly in setupDmaSlots().

// ============================================================================
// Initialization
// ============================================================================

pub fn init() VblkError!void {
    const dev = pci.findVirtioBlk() orelse {
        hal.Serial.puts("[VBLK] No virtio-blk device found\n");
        return VblkError.NoDevice;
    };

    vblk_state.pci_dev = dev;
    vblk_state.io_base = dev.io_base;
    vblk_state.irq = dev.irq;

    if (vblk_state.io_base == 0) {
        hal.Serial.puts("[VBLK] ERROR: No I/O base address\n");
        return VblkError.InitFailed;
    }

    hal.Serial.puts("[VBLK] Found at bus=");
    hal.Serial.putHex(dev.bus);
    hal.Serial.puts(" slot=");
    hal.Serial.putHex(dev.slot);
    hal.Serial.puts(" I/O=0x");
    hal.Serial.putHex(vblk_state.io_base);
    hal.Serial.puts(" IRQ=");
    hal.Serial.putHex(dev.irq);
    hal.Serial.puts("\n");

    // Enable PCI device (Bus Master + I/O space)
    pci.enableDevice(dev.bus, dev.slot, dev.func);
    hal.Serial.puts("[VBLK] PCI device enabled\n");

    // Step 1: Reset device
    write8(VIRTIO_PCI_STATUS, 0);

    // Step 2: Acknowledge device
    write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

    // Step 3: We know how to drive this device
    write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    // Step 4: Negotiate features
    const host_features = read32(VIRTIO_PCI_HOST_FEATURES);
    hal.Serial.puts("[VBLK] Host features: 0x");
    hal.Serial.putHex(host_features);
    hal.Serial.puts("\n");

    var guest_features: u32 = 0;
    if (host_features & VIRTIO_BLK_F_SIZE_MAX != 0) guest_features |= VIRTIO_BLK_F_SIZE_MAX;
    if (host_features & VIRTIO_BLK_F_SEG_MAX != 0) guest_features |= VIRTIO_BLK_F_SEG_MAX;
    if (host_features & VIRTIO_BLK_F_BLK_SIZE != 0) guest_features |= VIRTIO_BLK_F_BLK_SIZE;
    if (host_features & VIRTIO_BLK_F_FLUSH != 0) guest_features |= VIRTIO_BLK_F_FLUSH;
    // Do NOT accept VIRTIO_BLK_F_RO — we want write support

    // Check if device is read-only
    if (host_features & VIRTIO_BLK_F_RO != 0) {
        vblk_state.is_read_only = true;
        hal.Serial.puts("[VBLK] Device is read-only\n");
        // Accept the read-only feature since the device insists
        guest_features |= VIRTIO_BLK_F_RO;
    }

    vblk_state.features = guest_features;
    write32(VIRTIO_PCI_GUEST_FEATURES, guest_features);

    // Step 5: Set FEATURES_OK
    write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

    // Step 6: Verify FEATURES_OK
    const status = read8(VIRTIO_PCI_STATUS);
    if ((status & VIRTIO_STATUS_FEATURES_OK) == 0) {
        hal.Serial.puts("[VBLK] ERROR: Feature negotiation failed\n");
        return VblkError.InitFailed;
    }
    hal.Serial.puts("[VBLK] Features negotiated OK\n");

    // Step 7: Read device configuration
    readBlkConfig();
    hal.Serial.puts("[VBLK] Capacity: ");
    hal.Serial.putHex(vblk_state.config.capacity);
    hal.Serial.puts(" sectors (");
    hal.Serial.putHex(vblk_state.config.capacity * 512 / 1024);
    hal.Serial.puts(" KB)\n");

    // Step 8: Set up virtqueue (queue 0 = request queue)
    try setupQueue(0);

    // Step 9: Set up DMA slots
    try setupDmaSlots();

    // Step 10: Configure IOAPIC for IRQ
    if (vblk_state.irq != 0 and vblk_state.irq != 0xFF) {
        // IOAPIC redirection for virtio IRQ -> Vector 49
        hal.IOAPIC.write(0x10 + vblk_state.irq * 2, 49); // low: vector 49
        hal.IOAPIC.write(0x10 + vblk_state.irq * 2 + 1, 0); // high: APIC ID 0
        hal.Serial.puts("[VBLK] IO-APIC configured: GSI=");
        hal.Serial.putHex(vblk_state.irq);
        hal.Serial.puts(" -> Vector 49\n");
    }

    // Step 11: DRIVER_OK — device is now live
    write8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    vblk_state.initialized = true;
    hal.Serial.puts("[VBLK] Initialization complete!\n");
}

fn readBlkConfig() void {
    const config_offset = VIRTIO_PCI_CONFIG;
    var buf: [@sizeOf(VirtBlkConfig)]u8 align(4) = undefined;

    var i: u16 = 0;
    while (i < @sizeOf(VirtBlkConfig)) : (i += 4) {
        const val = read32(config_offset + i);
        @as(*u32, @ptrCast(@alignCast(&buf[i]))).* = val;
    }

    vblk_state.config = @as(*VirtBlkConfig, @ptrCast(@alignCast(&buf[0]))).*;
}

fn setupQueue(queue_idx: u16) VblkError!void {
    // Select the queue
    write16(VIRTIO_PCI_QUEUE_SEL, queue_idx);

    // Read maximum queue size
    const max_size = read16(VIRTIO_PCI_QUEUE_NUM);
    hal.Serial.puts("[VBLK] Queue size: ");
    hal.Serial.putHex(max_size);
    hal.Serial.puts("\n");

    if (max_size == 0) {
        hal.Serial.puts("[VBLK] Queue not available\n");
        return VblkError.InitFailed;
    }

    // Use min(QUEUE_SIZE, max_size)
    const actual_size: u16 = if (QUEUE_SIZE <= max_size) QUEUE_SIZE else max_size;
    _ = actual_size;

    // ========================================================================
    // FIXED: Allocate CONTIGUOUS physical pages for the virtqueue
    //
    // VirtIO Legacy requires: desc_table → avail_ring → used_ring to be
    // contiguous in physical memory, starting at the page specified by PFN.
    // The device calculates:
    //   avail_ring = PFN*4096 + align_page(desc_table_size)
    //   used_ring  = PFN*4096 + align_page(desc_table_size) + align_page(avail_ring_size)
    // ========================================================================

    // Allocate 3 contiguous pages
    const vq_base = pmm.allocContiguousPages(VQ_TOTAL_PAGES) orelse {
        hal.Serial.puts("[VBLK] ERROR: Failed to allocate contiguous pages for virtqueue\n");
        return VblkError.InitFailed;
    };

    vblk_state.vq_phys = vq_base;
    vblk_state.vq_virt = vq_base; // Identity-mapped in low memory (< 4GB)

    // Calculate offsets within the contiguous block
    const desc_offset: u64 = 0;
    const avail_offset: u64 = DESC_PAGES * 4096;
    const used_offset: u64 = (DESC_PAGES + AVAIL_PAGES) * 4096;

    vblk_state.desc_phys = vq_base + desc_offset;
    vblk_state.desc_virt = vq_base + desc_offset;
    vblk_state.avail_phys = vq_base + avail_offset;
    vblk_state.avail_virt = vq_base + avail_offset;
    vblk_state.used_phys = vq_base + used_offset;
    vblk_state.used_virt = vq_base + used_offset;

    hal.Serial.puts("[VBLK] Contiguous VQ allocation: base=0x");
    hal.Serial.putHex(vq_base);
    hal.Serial.puts(" desc=0x");
    hal.Serial.putHex(vblk_state.desc_phys);
    hal.Serial.puts(" avail=0x");
    hal.Serial.putHex(vblk_state.avail_phys);
    hal.Serial.puts(" used=0x");
    hal.Serial.putHex(vblk_state.used_phys);
    hal.Serial.puts("\n");

    // Zero the entire virtqueue area
    const vq_ptr: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(vblk_state.vq_virt)));
    @memset(vq_ptr[0 .. VQ_TOTAL_PAGES * 4096], 0);

    // Initialize free descriptor list
    vblk_state.free_head = 0;
    vblk_state.num_free = QUEUE_SIZE;
    vblk_state.last_used_idx = 0;

    for (0..QUEUE_SIZE - 1) |i| {
        getDesc(@intCast(i)).next = @intCast(i + 1);
    }
    getDesc(QUEUE_SIZE - 1).next = 0;

    // Register the queue with the device
    write16(VIRTIO_PCI_QUEUE_NUM, QUEUE_SIZE);
    // FIXED: Write page frame number of the descriptor table base
    // PFN = physical_address >> 12 (must fit in 32 bits for Legacy mode)
    // Guard: if phys >= 4GB, VirtIO Legacy cannot address it — abort init
    if (vblk_state.desc_phys >= 0x100000000) {
        hal.Serial.puts("[VBLK] ERROR: desc_phys >= 4GB, VirtIO Legacy cannot address it!\n");
        return error.NoDmaSlot;
    }
    const pfn: u32 = @intCast(vblk_state.desc_phys >> 12);
    write32(VIRTIO_PCI_QUEUE_PFN, pfn);

    hal.Serial.puts("[VBLK] Virtqueue configured (PFN=0x");
    hal.Serial.putHex(pfn);
    hal.Serial.puts(" desc @ 0x");
    hal.Serial.putHex(vblk_state.desc_phys);
    hal.Serial.puts(")\n");
}

fn setupDmaSlots() VblkError!void {
    // FIXED: Use identity-mapped physical addresses for DMA slots.
    //
    // Previously this used VMM-mapped addresses at 0x200001000+, but VMM
    // was not initialized at this point, causing mapPage() to silently
    // corrupt page tables (pml4_phys was 0, writing to IVT area).  This was
    // the root cause of the virtio-blk read timeout: descriptors contained
    // garbage addresses that the device could not DMA to.
    //
    // Since PMM returns page-aligned physical addresses below 4GB (the
    // bootloader identity-maps the first 4GB), we can simply use
    // phys == virt for all DMA buffers.

    for (&vblk_state.dma_slots, 0..) |*slot, i| {
        // Request header: 1 page (page-aligned, below 4GB)
        const req_phys = pmm.allocPage() orelse return VblkError.InitFailed;
        // Data buffer: 1 page (up to 4096 bytes = 8 sectors)
        const data_phys = pmm.allocPage() orelse {
            pmm.freePage(req_phys);
            return VblkError.InitFailed;
        };

        // Status byte: reuse end of req page (offset 4090, well past the
        // 16-byte VirtBlkReqHeader and leaving room for the data buffer)
        const status_phys = req_phys + 4090;

        // Identity-mapped: virtual address == physical address
        // This works because the bootloader maps the first 4GB 1:1
        const req_virt = req_phys;
        const data_virt = data_phys;
        const status_virt = status_phys;

        // Zero the pages
        const req_ptr: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(req_virt)));
        @memset(req_ptr[0..4096], 0);
        const data_ptr: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(data_virt)));
        @memset(data_ptr[0..4096], 0);

        slot.* = DmaSlot{
            .req_phys = req_phys,
            .req_virt = req_virt,
            .data_phys = data_phys,
            .data_virt = data_virt,
            .status_phys = status_phys,
            .status_virt = status_virt,
            .in_use = false,
        };

        hal.Serial.puts("[VBLK] DMA slot ");
        hal.Serial.putHex(i);
        hal.Serial.puts(": req=0x");
        hal.Serial.putHex(req_phys);
        hal.Serial.puts(" data=0x");
        hal.Serial.putHex(data_phys);
        hal.Serial.puts("\n");
    }

    hal.Serial.puts("[VBLK] DMA slots initialized (identity-mapped)\n");
}

// ============================================================================
// Block Read/Write Operations
// ============================================================================

/// Read sectors from the block device into a buffer.
/// The buffer can be in any accessible memory — data is DMA'd into a
/// dedicated DMA slot first, then copied to the caller's buffer.
pub fn readSectors(sector: u64, num_sectors: u32, buffer: []u8) VblkError!void {
    if (!vblk_state.initialized) return VblkError.NoDevice;

    const slot = allocDmaSlot() orelse return VblkError.NoDmaSlot;
    defer freeDmaSlot(slot);

    // Validate: max 8 sectors per DMA slot (4096 / 512)
    if (num_sectors > 8) return VblkError.ReadFailed;

    // Set up request header
    const req: *volatile VirtBlkReqHeader = @ptrFromInt(@as(usize, @intCast(slot.req_virt)));
    req.type = VIRTIO_BLK_T_IN;
    req.reserved = 0;
    req.sector = sector;

    const data_phys = slot.data_phys;
    const data_len: u32 = num_sectors * 512;

    // Allocate descriptor chain: req(out) → data(in) → status(in)
    const head = allocDescChain(3) orelse return VblkError.NoDmaSlot;

    // Descriptor 0: request header (device-readable)
    var desc0 = getDesc(head);
    desc0.addr = slot.req_phys;
    desc0.len = @sizeOf(VirtBlkReqHeader);
    desc0.flags = VIRTIO_DESC_F_NEXT;

    // Descriptor 1: data buffer (device-writable for read)
    const desc1_idx = desc0.next;
    var desc1 = getDesc(desc1_idx);
    desc1.addr = data_phys;
    desc1.len = data_len;
    desc1.flags = VIRTIO_DESC_F_NEXT | VIRTIO_DESC_F_WRITE;

    // Descriptor 2: status byte (device-writable)
    const desc2_idx = desc1.next;
    var desc2 = getDesc(desc2_idx);
    desc2.addr = slot.status_phys;
    desc2.len = 1;
    desc2.flags = VIRTIO_DESC_F_WRITE;

    // Set status to pending
    const status_ptr: *volatile u8 = @ptrFromInt(@as(usize, @intCast(slot.status_virt)));
    status_ptr.* = 0xFF;

    // Submit and wait
    submitChain(head);

    hal.Serial.puts("[VBLK-READ] Submitted: sector=");
    hal.Serial.putHex(sector);
    hal.Serial.puts(" n=");
    hal.Serial.putHex(num_sectors);
    hal.Serial.puts(" head=");
    hal.Serial.putHex(head);
    hal.Serial.puts(" data_phys=0x");
    hal.Serial.putHex(data_phys);
    hal.Serial.puts("\n");

    const t_start = hal.readMsr(0x10); // TSC start for Bus Pool entropy
    const completed = waitForCompletion(50_000_000) orelse {
        // Debug: dump virtqueue state on timeout
        const used_dbg = getUsed();
        hal.Serial.puts("[VBLK-READ] TIMEOUT! used.idx=");
        hal.Serial.putHex(used_dbg.idx);
        hal.Serial.puts(" last_used=");
        hal.Serial.putHex(vblk_state.last_used_idx);
        hal.Serial.puts(" avail.idx=");
        hal.Serial.putHex(getAvail().idx);
        hal.Serial.puts("\n");
        const isr = read8(VIRTIO_PCI_ISR);
        hal.Serial.puts("[VBLK-READ] ISR=0x");
        hal.Serial.putHex(isr);
        hal.Serial.puts(" dev_status=0x");
        hal.Serial.putHex(read8(VIRTIO_PCI_STATUS));
        hal.Serial.puts("\n");
        hal.Serial.puts("[VBLK-READ] PFN=0x");
        hal.Serial.putHex(@as(u32, @truncate(vblk_state.desc_phys >> 12)));
        hal.Serial.puts(" vq_base=0x");
        hal.Serial.putHex(vblk_state.vq_phys);
        hal.Serial.puts("\n");
        freeDescChain(head);
        return VblkError.Timeout;
    };
    const t_end = hal.readMsr(0x10); // TSC end
    if (bus_entropy_sink) |sink| {
        sink(t_end -% t_start ^ (@as(u64, sector) << 32));
    }

    _ = completed;

    // Check status
    if (status_ptr.* != VIRTIO_BLK_S_OK) {
        hal.Serial.puts("[VBLK-READ] Status error: ");
        hal.Serial.putHex(status_ptr.*);
        hal.Serial.puts("\n");
        freeDescChain(head);
        return VblkError.ReadFailed;
    }

    // Copy data from DMA buffer to user buffer
    const dma_data: [*]const u8 = @ptrFromInt(@as(usize, @intCast(slot.data_virt)));
    for (0..data_len) |i| {
        buffer[i] = dma_data[i];
    }

    freeDescChain(head);
}

/// Write sectors from a buffer to the block device.
pub fn writeSectors(sector: u64, num_sectors: u32, buffer: []const u8) VblkError!void {
    if (!vblk_state.initialized) return VblkError.NoDevice;
    if (vblk_state.is_read_only) return VblkError.WriteFailed;

    const slot = allocDmaSlot() orelse return VblkError.NoDmaSlot;
    defer freeDmaSlot(slot);

    // Validate: max 8 sectors per DMA slot
    if (num_sectors > 8) return VblkError.WriteFailed;

    // Copy data to DMA buffer first
    const data_len: u32 = num_sectors * 512;
    const dma_data: [*]u8 = @ptrFromInt(@as(usize, @intCast(slot.data_virt)));
    for (0..data_len) |i| {
        dma_data[i] = buffer[i];
    }

    // Set up request header
    const req: *volatile VirtBlkReqHeader = @ptrFromInt(@as(usize, @intCast(slot.req_virt)));
    req.type = VIRTIO_BLK_T_OUT;
    req.reserved = 0;
    req.sector = sector;

    // Allocate descriptor chain: req(out) → data(out) → status(in)
    const head = allocDescChain(3) orelse return VblkError.NoDmaSlot;

    var desc0 = getDesc(head);
    desc0.addr = slot.req_phys;
    desc0.len = @sizeOf(VirtBlkReqHeader);
    desc0.flags = VIRTIO_DESC_F_NEXT;

    const desc1_idx = desc0.next;
    var desc1 = getDesc(desc1_idx);
    desc1.addr = slot.data_phys;
    desc1.len = data_len;
    desc1.flags = VIRTIO_DESC_F_NEXT; // Device-readable (not writable)

    const desc2_idx = desc1.next;
    var desc2 = getDesc(desc2_idx);
    desc2.addr = slot.status_phys;
    desc2.len = 1;
    desc2.flags = VIRTIO_DESC_F_WRITE;

    const status_ptr: *volatile u8 = @ptrFromInt(@as(usize, @intCast(slot.status_virt)));
    status_ptr.* = 0xFF;

    submitChain(head);

    hal.Serial.puts("[VBLK-WRITE] Submitted: sector=");
    hal.Serial.putHex(sector);
    hal.Serial.puts(" n=");
    hal.Serial.putHex(num_sectors);
    hal.Serial.puts("\n");

    const t_write_start = hal.readMsr(0x10);
    const completed = waitForCompletion(50_000_000) orelse {
        hal.Serial.puts("[VBLK-WRITE] TIMEOUT!\n");
        freeDescChain(head);
        return VblkError.Timeout;
    };
    const t_write_end = hal.readMsr(0x10);
    if (bus_entropy_sink) |sink| {
        sink(t_write_end -% t_write_start ^ (@as(u64, sector) << 32) ^ 0x57524954); // 'WRIT'
    }

    _ = completed;

    if (status_ptr.* != VIRTIO_BLK_S_OK) {
        hal.Serial.puts("[VBLK-WRITE] Status error: ");
        hal.Serial.putHex(status_ptr.*);
        hal.Serial.puts("\n");
        freeDescChain(head);
        return VblkError.WriteFailed;
    }

    freeDescChain(head);
}

/// Read a single sector
pub fn readSector(sector: u64, buffer: []u8) VblkError!void {
    return readSectors(sector, 1, buffer);
}

/// Write a single sector
pub fn writeSector(sector: u64, buffer: []const u8) VblkError!void {
    return writeSectors(sector, 1, buffer);
}

/// Get device capacity in sectors
pub fn getCapacitySectors() u64 {
    return vblk_state.config.capacity;
}

/// Get device capacity in bytes
pub fn getCapacityBytes() u64 {
    return vblk_state.config.capacity * 512;
}

/// Check if the driver is initialized
pub fn isInitialized() bool {
    return vblk_state.initialized;
}

/// Check if device is read-only
pub fn isReadOnly() bool {
    return vblk_state.is_read_only;
}

/// Handle interrupt from virtio-blk device
pub fn handleIrq() callconv(.C) void {
    const isr = read8(VIRTIO_PCI_ISR);
    if ((isr & 1) != 0) {
        // Queue interrupt — process completed requests
        // In polling mode, this is handled in waitForCompletion
    }
    if ((isr & 2) != 0) {
        // Configuration change
        readBlkConfig();
    }
}
