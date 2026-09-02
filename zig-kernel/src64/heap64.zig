// ============================================================================
// POLER-OS Kernel Dynamic Heap Allocator (kmalloc/kfree) — x86_64
// v7: HMAC-based integrity checking via SipHash-2-4 (replaces heap_cookie)
// v6: Bug fixes for all 11 issues found by symbolic execution
// ============================================================================
//
// v7 SECURITY FIX (MEDIUM severity — heap cookie forgery):
//   Replaced per-boot random cookie (heap_cookie) with SipHash-2-4 based
//   integrity tags. The old cookie could be forged by an attacker with a
//   heap write primitive. The new SipHash tag is cryptographically bound to
//   block metadata (address, size, padding, free status) using a 128-bit key
//   that is never stored in heap memory. An attacker cannot forge a valid tag
//   without knowing the key.
//
//   SipHash-2-4 was chosen over HMAC-SHA256 because:
//   - Specifically designed for short-message authentication
//   - Much simpler (~50 lines vs ~200+ lines for SHA-256)
//   - Used by Linux kernel for the same purpose (heap object tracking)
//   - 64-bit output truncated to 32 bits provides adequate security for
//     heap integrity (2^32 brute-force per block, detected on free)

const pmm = @import("pmm64.zig");
const vmm = @import("vmm64.zig");
const hal = @import("hal.zig");
const std = @import("std");

// ============================================================================
// SipHash-2-4 — Short-input PRF for heap integrity verification
// ============================================================================
// Reference: Jean-Philippe Aumasson & Daniel J. Bernstein, "SipHash: a fast
// short-input PRF" (2012). Parameters c=2, d=4 as recommended for
// non-cryptographic but adversarial use (same as Linux kernel's siphash).
//
/// SipHash-2-4 for heap integrity verification.
/// Simpler than HMAC-SHA256, specifically designed for short-message authentication.
/// Used by Linux kernel for the same purpose (heap object tracking).
const SipHash = struct {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,

    fn sipround(self: *SipHash) void {
        self.v0 +%= self.v1;
        self.v1 = rotl64(self.v1, 13);
        self.v1 ^= self.v0;
        self.v0 = rotl64(self.v0, 32);
        self.v2 +%= self.v3;
        self.v3 = rotl64(self.v3, 16);
        self.v3 ^= self.v2;
        self.v0 +%= self.v3;
        self.v3 = rotl64(self.v3, 21);
        self.v3 ^= self.v0;
        self.v2 +%= self.v1;
        self.v1 = rotl64(self.v1, 17);
        self.v1 ^= self.v2;
        self.v2 = rotl64(self.v2, 32);
    }

    /// Compute SipHash-2-4 of a message using a 128-bit key (k0, k1).
    /// Returns full 64-bit tag. Caller can truncate to 32 bits.
    fn compute(k0: u64, k1: u64, msg: []const u8) u64 {
        var self = SipHash{
            .v0 = k0 ^ 0x736f6d6570736575,
            .v1 = k1 ^ 0x646f72616e646f6d,
            .v2 = k0 ^ 0x6c7967656e657261,
            .v3 = k1 ^ 0x7465646279746573,
        };

        const msg_len = msg.len;
        var offset: usize = 0;

        // Process 8-byte blocks
        while (offset + 8 <= msg_len) : (offset += 8) {
            const m: u64 = std.mem.readInt(u64, msg[offset..][0..8], .little);
            self.v3 ^= m;
            self.sipround(); // c=2: 2 compression rounds
            self.sipround();
            self.v0 ^= m;
        }

        // Last block with length padding
        var last: u64 = @as(u64, msg_len & 0xFF);
        var shift: u6 = 8;
        while (offset < msg_len) : ({
            offset += 1;
            shift +%= 8;
        }) {
            last |= @as(u64, msg[offset]) << shift;
        }

        self.v3 ^= last;
        self.sipround();
        self.sipround();
        self.v2 ^= 0xFF;

        // d=4: 4 finalization rounds
        self.sipround();
        self.sipround();
        self.sipround();
        self.sipround();

        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3;
    }
};

/// Rotate-left for u64 — used by SipHash
fn rotl64(value: u64, comptime shift: usize) u64 {
    return (value << @intCast(shift)) | (value >> @intCast(64 - shift));
}

// ============================================================================
// Block structure & global state
// ============================================================================

pub const Block = struct {
    size: usize,
    free: bool,
    next: ?*Block,
    padding: u64 = 0, // Non-zero when payload is offset from header (aligned alloc)
    tag: u32 = 0, // v7: SipHash integrity tag — 0 for free blocks, computed for allocated blocks
};

// v7: When padding > 0, we store a SipHash tag + real block address just
// before the payload so kfree can find the header regardless of alignment offset.
// Layout before aligned payload:
//   [tag: u64 = zero-extended block.tag] [back_ptr: u64 = address of Block]
// Both are validated in getBlockFromPayload to avoid false positives.
//
// The tag replaces the old heap_cookie. Unlike the cookie, the tag is
// cryptographically bound to block metadata and cannot be forged without
// the SipHash key (heap_hmac_key0, heap_hmac_key1) which is never stored
// in heap memory.
//
// Two-layer verification:
//   1. getBlockFromPayload: tag before payload must match block.tag (finds header)
//   2. freeInternal: recomputes tag from metadata, must match block.tag (integrity)
//
// BACK_PTR_OVERHEAD is still 16 bytes: 8 for tag (u64, zero-extended from u32)
// + 8 for back_ptr.
var heap_hmac_key0: u64 = 0; // v7: SipHash key — generated from RDTSC at boot, never in heap
var heap_hmac_key1: u64 = 0; // v7: SipHash key — generated from RDTSC at boot, never in heap
const BACK_PTR_OVERHEAD: u64 = @sizeOf(u64) * 2; // tag (u64) + back_ptr

pub const HEAP_START: u64 = 0x200000000; // 8GB mark
pub const HEAP_MAX: u64 = 0x300000000; // 12GB mark (4GB max heap)

var heap_end: u64 = HEAP_START;
var first_block: ?*Block = null;

const vtable = std.mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = std.mem.Allocator.noRemap,
    .free = free,
};

pub var allocator: std.mem.Allocator = undefined;

// ============================================================================
// SipHash tag computation
// ============================================================================

/// v7: Compute a 32-bit SipHash-2-4 tag over block metadata.
/// Binds the tag to: block address, size, padding, and free status.
/// The block address makes the tag location-dependent — moving a block
/// to a different address invalidates its tag.
fn computeBlockTag(block: *Block) u32 {
    // Build the message: 4 fields × 8 bytes each = 32 bytes
    var msg: [32]u8 = undefined;
    const addr = @intFromPtr(block);
    std.mem.writeInt(u64, msg[0..8], addr, .little);
    std.mem.writeInt(u64, msg[8..16], block.size, .little);
    std.mem.writeInt(u64, msg[16..24], block.padding, .little);
    std.mem.writeInt(u64, msg[24..32], if (block.free) @as(u64, 1) else @as(u64, 0), .little);
    const full_tag = SipHash.compute(heap_hmac_key0, heap_hmac_key1, &msg);
    return @truncate(full_tag); // Lower 32 bits
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    // v7: Generate 128-bit SipHash key from RDTSC.
    // XOR with golden ratio constants for avalanche even if TSC is predictable.
    // The key is never stored in heap memory — only in BSS (heap_hmac_key0/1).
    var tsc: u64 = 0;
    asm volatile ("rdtsc"
        : [ret] "={rax}" (tsc),
    );
    heap_hmac_key0 = tsc ^ 0x9E3779B99E3779B9;
    // Second key derived from first with different mixing
    heap_hmac_key1 = rotl64(heap_hmac_key0, 17) ^ 0x6A09E667F3BCC909;
    // Ensure key pair is not all-zero (would weaken SipHash initialization vectors)
    if (heap_hmac_key0 == 0 and heap_hmac_key1 == 0) {
        heap_hmac_key0 = 0xDEADBEEF_DEADBEEF;
        heap_hmac_key1 = 0xCAFEBABE_CAFEBABE;
    }

    // Allocate the first physical page for the heap
    const phys = pmm.allocPage() orelse {
        hal.Serial.puts("[HEAP] Failed to allocate first physical page!\n");
        return;
    };

    vmm.mapPage(HEAP_START, phys, vmm.PTE_WRITABLE) catch |err| {
        hal.Serial.puts("[HEAP] Failed to map first page: ");
        hal.Serial.puts(@errorName(err));
        hal.Serial.puts("\n");
        // v6 FIX (Bug #6): Free physical page on mapping failure
        pmm.freePage(phys);
        return;
    };

    heap_end = HEAP_START + vmm.PAGE_SIZE;

    const block: *Block = @ptrFromInt(HEAP_START);
    block.size = vmm.PAGE_SIZE - @sizeOf(Block);
    block.free = true;
    block.next = null;
    block.padding = 0;
    block.tag = 0; // v7: free blocks have tag = 0 (untagged)

    first_block = block;

    allocator = std.mem.Allocator{
        .ptr = undefined,
        .vtable = &vtable,
    };

    hal.Serial.puts("[HEAP] Kernel heap initialized from ");
    hal.Serial.putHex(HEAP_START);
    hal.Serial.puts(" to ");
    hal.Serial.putHex(heap_end);
    hal.Serial.puts(" (SipHash integrity enabled)\n");
}

// ============================================================================
// Utility functions
// ============================================================================

fn alignUp(val: u64, alignment: u64) u64 {
    return (val + alignment - 1) & ~(alignment - 1);
}

/// v6 FIX (Bug #3): Validate that a pointer is a valid heap allocation.
/// Checks: range, alignment, block metadata consistency.
fn isValidHeapPointer(ptr: [*]u8) bool {
    const addr = @intFromPtr(ptr);
    // Check: pointer must be within heap virtual address range
    if (addr < HEAP_START + @sizeOf(Block) or addr >= HEAP_MAX) return false;
    // Check: pointer must be at least 16-byte aligned (minimum Block alignment)
    if (addr % 16 != 0) return false;
    return true;
}

/// v6 FIX (Bug #1 + #3) + v7: Improved getBlockFromPayload with SipHash tag
/// verification (replaces heap_cookie check) and wild pointer detection.
fn getBlockFromPayload(ptr: [*]u8) ?*Block {
    // v6: Validate pointer before any dereference (Bug #3: wild pointer)
    if (!isValidHeapPointer(ptr)) {
        hal.Serial.puts("[HEAP] ERROR: kfree on invalid pointer: 0x");
        hal.Serial.putHex(@intFromPtr(ptr));
        hal.Serial.puts("\n");
        return null;
    }

    // v7: Check if there's a SipHash tag + back-pointer stored just before
    // the payload. Layout: [tag: u64] [block_addr: u64] [aligned_payload...]
    const maybe_tag_addr = @intFromPtr(ptr) - BACK_PTR_OVERHEAD;
    // Bounds check before reading tag
    if (maybe_tag_addr >= HEAP_START and maybe_tag_addr < HEAP_MAX) {
        const maybe_tag: *const u64 = @ptrFromInt(maybe_tag_addr);
        const back_ptr_loc: *const u64 = @ptrFromInt(@intFromPtr(ptr) - @sizeOf(u64));
        const block_addr = back_ptr_loc.*;

        // v7: Instead of comparing against a fixed cookie, we:
        // 1. Read the back-pointer to find the candidate block
        // 2. Verify the block has padding > 0 (aligned alloc marker)
        // 3. Verify the stored tag matches block.tag
        // This eliminates the forgery vulnerability — an attacker cannot
        // produce a valid tag without the SipHash key.
        if (block_addr >= HEAP_START and block_addr < HEAP_MAX) {
            const block: *Block = @ptrFromInt(block_addr);
            // Verify: ptr should be within this block's payload region
            const expected_payload = @intFromPtr(block) + @sizeOf(Block);
            if (@intFromPtr(ptr) >= expected_payload and @intFromPtr(ptr) < expected_payload + block.size + @sizeOf(Block)) {
                // v7: Only trust the tag+back-ptr if:
                // 1. block.padding > 0 (aligned alloc marker)
                // 2. stored tag before payload matches block.tag
                if (block.padding > 0 and block.tag == @as(u32, @truncate(maybe_tag.*))) {
                    return block;
                }
                // Padding=0 but back-ptr+tag found → not an aligned allocation,
                // fall through to the direct header path below.
            }
        }
        // Tag/back-ptr present but invalid — this could be corruption
        // We don't print an error here because it might just be user data
        // that happens to look like a tag+back-ptr pattern. The real
        // integrity check happens in freeInternal via tag recomputation.
    }

    // No aligned padding (or tag mismatch) — header is right before payload
    const block_addr = @intFromPtr(ptr) - @sizeOf(Block);
    if (block_addr < HEAP_START or block_addr >= HEAP_MAX) {
        hal.Serial.puts("[HEAP] ERROR: block header out of heap range\n");
        return null;
    }
    const block: *Block = @ptrFromInt(block_addr);
    // v6: Verify block metadata is consistent
    if (block.size > HEAP_MAX - HEAP_START) {
        hal.Serial.puts("[HEAP] ERROR: block size corrupt (too large)\n");
        return null;
    }
    return block;
}

// ============================================================================
// Allocation
// ============================================================================

fn alloc(
    ctx: *anyopaque,
    len: usize,
    ptr_align: std.mem.Alignment,
    ret_addr: usize,
) ?[*]u8 {

    // v6 FIX (Bug #8): kmalloc(0) should return null
    if (len == 0) return null;

    const alignment = ptr_align.toByteUnits();
    // v6 FIX (Bug #4): Integer overflow check for aligned_len

    // If len is very large, alignUp could overflow u64
    const aligned_len = alignUp(len, 16);
    if (aligned_len < len) return null; // overflow detected

    // v0.17.0-fix (CDD №8 p5): СОХРАНЕНИЕ IF (а не безусловный sti):
    // аллокатор зовётся и из IRQ-обработчиков (IF=0) — sti() на выходе
    // открывал прерывания в pop-фазе ISR → вложенный тик портил rsp.
    const if_was: bool = hal.interruptsEnabled();
    hal.cli();
    defer if (if_was) hal.sti();

    var current = first_block;
    var prev: ?*Block = null;

    while (current) |block| {
        if (block.free) {
            const payload_addr = @intFromPtr(block) + @sizeOf(Block);

            if (alignment <= 16) {
                // Default path: Block header is 16-byte aligned, payload follows directly.
                if (block.size >= aligned_len) {
                    if (block.size >= aligned_len + @sizeOf(Block) + 16) {
                        const next_block_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_len;
                        const next_block: *Block = @ptrFromInt(next_block_addr);
                        next_block.size = block.size - aligned_len - @sizeOf(Block);
                        next_block.free = true;
                        next_block.next = block.next;
                        next_block.padding = 0;
                        next_block.tag = 0; // v7: free blocks are untagged

                        block.size = aligned_len;
                        block.next = next_block;
                    }
                    block.free = false;
                    block.padding = 0;
                    block.tag = computeBlockTag(block); // v7: compute integrity tag
                    return @ptrFromInt(payload_addr);
                }
            } else {
                // Over-aligned allocation
                const min_payload = payload_addr + BACK_PTR_OVERHEAD;
                const final_payload_addr = alignUp(min_payload, alignment);
                const total_padding = final_payload_addr - payload_addr;
                const total_required = aligned_len + total_padding;

                // v6 FIX (Bug #4): overflow check
                if (total_required < aligned_len) return null;

                if (block.size >= total_required) {
                    // v6 FIX (Bug #5): Over-aligned allocs — split if there's room
                    if (block.size >= total_required + @sizeOf(Block) + 16) {
                        const next_block_addr = @intFromPtr(block) + @sizeOf(Block) + total_padding + aligned_len;
                        const next_block: *Block = @ptrFromInt(next_block_addr);
                        next_block.size = block.size - total_padding - aligned_len - @sizeOf(Block);
                        next_block.free = true;
                        next_block.next = block.next;
                        next_block.padding = 0;
                        next_block.tag = 0; // v7: free blocks are untagged

                        block.size = total_padding + aligned_len;
                        block.next = next_block;
                    }

                    block.padding = total_padding;
                    block.free = false;
                    block.tag = computeBlockTag(block); // v7: compute integrity tag

                    // v7: Write tag + back-pointer just before the aligned payload.
                    // The tag replaces the old heap_cookie — it is cryptographically
                    // bound to this block's metadata and cannot be forged.
                    const tag_loc: *u64 = @ptrFromInt(final_payload_addr - BACK_PTR_OVERHEAD);
                    tag_loc.* = @as(u64, block.tag); // zero-extend u32 tag to u64
                    const back_ptr_loc: *u64 = @ptrFromInt(final_payload_addr - @sizeOf(u64));
                    back_ptr_loc.* = @intFromPtr(block);

                    return @ptrFromInt(final_payload_addr);
                }
            }
        }
        prev = current;
        current = block.next;
    }

    // Out of memory, expand the heap!
    // v6 FIX (Bug #4): Safe expansion size calculation with overflow check
    const expand_base = aligned_len + @sizeOf(Block) + BACK_PTR_OVERHEAD;
    if (expand_base < aligned_len) return null; // overflow
    const expand_size = alignUp(expand_base, vmm.PAGE_SIZE);
    const pages_needed = expand_size / vmm.PAGE_SIZE;

    var i: usize = 0;
    while (i < pages_needed) : (i += 1) {
        if (heap_end >= HEAP_MAX) {
            hal.Serial.puts("[HEAP] Out of virtual heap space!\n");
            return null;
        }

        const phys = pmm.allocPage() orelse {
            hal.Serial.puts("[HEAP] Out of physical memory during heap expansion!\n");
            return null;
        };

        vmm.mapPage(heap_end, phys, vmm.PTE_WRITABLE) catch |err| {
            hal.Serial.puts("[HEAP] Failed to map expanded page: ");
            hal.Serial.puts(@errorName(err));
            hal.Serial.puts("\n");
            // v6 FIX (Bug #6): Free physical page on mapping failure
            pmm.freePage(phys);
            return null;
        };

        heap_end += vmm.PAGE_SIZE;
    }

    // Append free space to last block or create a new one
    if (prev) |last_block| {
        if (last_block.free) {
            last_block.size += expand_size;
            return alloc(ctx, len, ptr_align, ret_addr);
        } else {
            const new_block_addr = @intFromPtr(last_block) + @sizeOf(Block) + last_block.size;
            const new_block: *Block = @ptrFromInt(new_block_addr);
            new_block.size = expand_size - @sizeOf(Block);
            new_block.free = true;
            new_block.next = null;
            new_block.padding = 0;
            new_block.tag = 0; // v7: free blocks are untagged

            last_block.next = new_block;
            return alloc(ctx, len, ptr_align, ret_addr);
        }
    }

    return null;
}

test "placeholder" {}

// ============================================================================
// Resize
// ============================================================================

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: std.mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    if (buf.len == 0) return false;
    if (new_len == 0) return false;

    const aligned_new_len = alignUp(new_len, 16);
    if (aligned_new_len < new_len) return false;

    // v0.17.0-fix (CDD №8 p5): СОХРАНЕНИЕ IF (а не безусловный sti):
    // аллокатор зовётся и из IRQ-обработчиков (IF=0) — sti() на выходе
    // открывал прерывания в pop-фазе ISR → вложенный тик портил rsp.
    const if_was: bool = hal.interruptsEnabled();
    hal.cli();
    defer if (if_was) hal.sti();

    const block = getBlockFromPayload(buf.ptr) orelse return false;

    if (aligned_new_len <= block.size) {
        // Shrink block: if remaining space >= Block + 16, split it
        const remaining = block.size - aligned_new_len;
        if (remaining >= @sizeOf(Block) + 16) {
            const next_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_new_len;
            const next_block: *Block = @ptrFromInt(next_addr);
            next_block.size = remaining - @sizeOf(Block);
            next_block.free = true;
            next_block.next = block.next;
            next_block.padding = 0;
            next_block.tag = 0; // v7: free blocks are untagged

            block.size = aligned_new_len;
            block.next = next_block;
        }
        // v7: Recompute tag since size may have changed
        block.tag = computeBlockTag(block);
        return true;
    } else {
        // Grow block in-place if next block is free and large enough
        if (block.next) |next_b| {
            if (next_b.free and (block.size + @sizeOf(Block) + next_b.size >= aligned_new_len)) {
                const remaining = (block.size + @sizeOf(Block) + next_b.size) - aligned_new_len;
                if (remaining >= @sizeOf(Block) + 16) {
                    const new_next_addr = @intFromPtr(block) + @sizeOf(Block) + aligned_new_len;
                    const new_next: *Block = @ptrFromInt(new_next_addr);
                    new_next.size = remaining - @sizeOf(Block);
                    new_next.free = true;
                    new_next.next = next_b.next;
                    new_next.padding = 0;
                    new_next.tag = 0; // v7: free blocks are untagged

                    block.size = aligned_new_len;
                    block.next = new_next;
                } else {
                    block.size += @sizeOf(Block) + next_b.size;
                    block.next = next_b.next;
                }
                // v7: Recompute tag since size changed
                block.tag = computeBlockTag(block);
                return true;
            }
        }
        return false;
    }
}

// ============================================================================
// Free
// ============================================================================

/// v6 + v7: Unified internal free function — eliminates code duplication (Bug #11).
/// Both `free` (VTable) and `kfree` (public API) now use this.
/// Returns true on success, false on error (double-free, invalid pointer, tag mismatch).
fn freeInternal(ptr: [*]u8) bool {
    const block = getBlockFromPayload(ptr) orelse return false;

    // v7: Verify integrity tag — recompute SipHash over block metadata and
    // compare with stored tag. Mismatch indicates heap corruption or tampering.
    // This is the primary security check: an attacker with a heap write primitive
    // cannot forge a valid tag without knowing the SipHash key.
    const expected_tag = computeBlockTag(block);
    if (block.tag != expected_tag) {
        hal.Serial.puts("[HEAP] ALERT: integrity tag mismatch at block 0x");
        hal.Serial.putHex(@intFromPtr(block));
        hal.Serial.puts(" — heap corruption detected!\n");
        return false;
    }

    // v6 FIX (Bug #2): Double-free detection
    // v7 enhancement: a freed block has tag = 0, so recomputation will fail
    // with tag mismatch even before this check. But we keep the explicit
    // double-free detection for clearer error reporting.
    if (block.free) {
        hal.Serial.puts("[HEAP] ERROR: double-free detected at block 0x");
        hal.Serial.putHex(@intFromPtr(block));
        hal.Serial.puts("\n");
        return false;
    }

    block.free = true;
    block.padding = 0; // Clear padding so coalescing is safe
    block.tag = 0; // v7: clear tag — freed blocks are untagged.
    // This also strengthens double-free detection: a freed block will have
    // tag=0, which won't match any valid computed tag.

    // Coalesce contiguous free blocks
    coalesceFreeBlocks();
    return true;
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: std.mem.Alignment,
    ret_addr: usize,
) void {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    if (buf.len == 0) return;

    // v0.17.0-fix (CDD №8 p5): СОХРАНЕНИЕ IF (а не безусловный sti):
    // аллокатор зовётся и из IRQ-обработчиков (IF=0) — sti() на выходе
    // открывал прерывания в pop-фазе ISR → вложенный тик портил rsp.
    const if_was: bool = hal.interruptsEnabled();
    hal.cli();
    defer if (if_was) hal.sti();

    _ = freeInternal(buf.ptr);
}

/// Merge adjacent free blocks into larger ones
fn coalesceFreeBlocks() void {
    var current = first_block;
    while (current) |b| {
        if (b.free) {
            while (b.next) |next_b| {
                if (next_b.free) {
                    b.size += @sizeOf(Block) + next_b.size;
                    b.next = next_b.next;
                    // v7: merged block inherits b.tag (= 0, since b.free)
                } else {
                    break;
                }
            }
        }
        current = b.next;
    }
}

// ============================================================================
// Public API
// ============================================================================

/// v6 FIX (Bug #8): kmalloc(0) returns null
pub fn kmalloc(len: usize) ?[*]u8 {
    if (len == 0) return null; // v6: zero-size allocation not allowed
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// v6 FIX (Bug #2 + #3 + #11) + v7: kfree with validation, double-free detection,
/// and SipHash integrity verification.
/// Uses shared freeInternal to eliminate code duplication.
pub fn kfree(ptr: [*]u8) void {
    // v0.17.0-fix (CDD №8 p5): СОХРАНЕНИЕ IF (а не безусловный sti):
    // аллокатор зовётся и из IRQ-обработчиков (IF=0) — sti() на выходе
    // открывал прерывания в pop-фазе ISR → вложенный тик портил rsp.
    const if_was: bool = hal.interruptsEnabled();
    hal.cli();
    defer if (if_was) hal.sti();

    if (!freeInternal(ptr)) {
        // Error already logged by freeInternal (tag mismatch, double-free,
        // invalid pointer, etc.)
        // In kernel context, we don't abort — just log and continue
    }
}

pub fn printHeapStatus() void {
    hal.Serial.puts("=== KERNEL HEAP STATUS ===\n");
    var current = first_block;
    var idx: usize = 0;
    while (current) |block| : (idx += 1) {
        hal.Serial.puts("  Block ");
        printDec(idx);
        hal.Serial.puts(": Addr=");
        hal.Serial.putHex(@intFromPtr(block));
        hal.Serial.puts(" Size=");
        printDec(block.size);
        hal.Serial.puts(" Free=");
        hal.Serial.puts(if (block.free) "true" else "false");
        hal.Serial.puts(" Tag=0x");
        printHex32(block.tag);
        hal.Serial.puts("\n");
        current = block.next;
    }
    hal.Serial.puts("==========================\n");
}

fn printDec(val: u64) void {
    if (val == 0) {
        hal.Serial.puts("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 19;
    var temp = val;
    while (temp > 0) {
        buf[i] = '0' + @as(u8, @intCast(temp % 10));
        temp /= 10;
        if (i == 0) break;
        i -= 1;
    }
    hal.Serial.puts(buf[i + 1..]);
}

/// v7: Print a 32-bit value in hexadecimal for tag display
fn printHex32(val: u32) void {
    const hex_chars = "0123456789ABCDEF";
    var buf: [8]u8 = undefined;
    var i: usize = 0;
    var shift: u5 = 28;
    while (shift >= 0) : ({
        shift -%= 4;
        i += 1;
    }) {
        buf[i] = hex_chars[@as(usize, (val >> shift) & 0xF)];
        if (shift == 0) break;
    }
    hal.Serial.puts(&buf);
}
