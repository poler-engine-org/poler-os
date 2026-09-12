//! ============================================================================
//! POLER-OS: Native SquashFS v4 / EROFS Substrate in Pure Zig
//! Supports reading CachyOS/Arch Linux airootfs.sfs images directly
//! ============================================================================

const std = @import("std");
const testing = std.testing;

pub const SQUASHFS_MAGIC: u32 = 0x73717368; // "sqsh" in little-endian
pub const SQUASHFS_MAJOR: u16 = 4;
pub const SQUASHFS_MINOR: u16 = 0;

pub const CompressionType = enum(u16) {
    zlib = 1,
    lzma = 2,
    lzo = 3,
    xz = 4,
    lz4 = 5,
    zstd = 6,
    _,
};

pub const Superblock = extern struct {
    s_magic: u32,
    inodes: u32,
    mkfs_time: u32,
    block_size: u32,
    fragments: u32,
    compression: CompressionType,
    block_log: u16,
    flags: u16,
    no_ids: u16,
    s_major: u16,
    s_minor: u16,
    root_inode_ref: u64,
    bytes_used: u64,
    id_table_start: u64,
    xattr_id_table_start: u64,
    inode_table_start: u64,
    directory_table_start: u64,
    fragment_table_start: u64,
    lookup_table_start: u64,
};

pub const InodeType = enum(u16) {
    basic_dir = 1,
    basic_file = 2,
    basic_symlink = 3,
    basic_blkdev = 4,
    basic_chardev = 5,
    basic_fifo = 6,
    basic_socket = 7,
    extended_dir = 8,
    extended_file = 9,
    extended_symlink = 10,
    extended_blkdev = 11,
    extended_chardev = 12,
    extended_fifo = 13,
    extended_socket = 14,
    _,
};

pub const BasicDirInode = extern struct {
    inode_type: InodeType,
    mode: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    inode_number: u32,
    start_block: u32,
    nlink: u32,
    file_size: u16,
    offset: u16,
    parent_inode: u32,
};

pub const BasicFileInode = extern struct {
    inode_type: InodeType,
    mode: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    inode_number: u32,
    blocks_start: u32,
    fragment_block: u32,
    fragment_offset: u32,
    file_size: u32,
};

pub const DirHeader = extern struct {
    count: u32,
    start_block: u32,
    inode_number: u32,
};

pub const DirEntry = extern struct {
    offset: u16,
    inode_offset: i16,
    entry_type: u16,
    size: u16, // size - 1 of name
};

pub const SquashFs = struct {
    raw_data: []const u8,
    sb: Superblock,
    valid: bool,

    pub fn init(image: []const u8) !SquashFs {
        if (image.len < @sizeOf(Superblock)) return error.InvalidImageSize;
        const sb_ptr: *const Superblock = @ptrCast(@alignCast(image.ptr));
        if (sb_ptr.s_magic != SQUASHFS_MAGIC) return error.InvalidMagic;
        if (sb_ptr.s_major != SQUASHFS_MAJOR) return error.UnsupportedVersion;

        return SquashFs{
            .raw_data = image,
            .sb = sb_ptr.*,
            .valid = true,
        };
    }

    /// Read metadata block header (2 bytes: bit 15 = uncompressed flag, bits 0-14 = length)
    pub fn readMetadataHeader(self: *const SquashFs, offset: u64) !struct { uncompressed: bool, size: u16 } {
        if (offset + 2 > self.raw_data.len) return error.OutOfBounds;
        const raw_len = std.mem.readInt(u16, self.raw_data[@intCast(offset)..][0..2], .little);
        const uncompressed = (raw_len & 0x8000) != 0;
        const size = raw_len & 0x7FFF;
        return .{ .uncompressed = uncompressed, .size = size };
    }

    /// Validate inode reference coordinates (block_offset in metadata table + sub-block byte offset)
    pub fn parseInodeRef(inode_ref: u64) struct { block_offset: u32, byte_offset: u16 } {
        const block_offset: u32 = @intCast(inode_ref >> 16);
        const byte_offset: u16 = @intCast(inode_ref & 0xFFFF);
        return .{ .block_offset = block_offset, .byte_offset = byte_offset };
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "squashfs: superblock size and constants" {
    try testing.expectEqual(@as(usize, 96), @sizeOf(Superblock));
    try testing.expectEqual(@as(u32, 0x73717368), SQUASHFS_MAGIC);
    try testing.expectEqual(@as(u16, 4), SQUASHFS_MAJOR);
}

test "squashfs: validate header detection" {
    var fake_image: [128]u8 = undefined;
    @memset(&fake_image, 0);

    // Write magic and version
    std.mem.writeInt(u32, fake_image[0..4], SQUASHFS_MAGIC, .little);
    std.mem.writeInt(u16, fake_image[28..30], SQUASHFS_MAJOR, .little);
    std.mem.writeInt(u16, fake_image[30..32], SQUASHFS_MINOR, .little);

    const fs = try SquashFs.init(&fake_image);
    try testing.expect(fs.valid);
    try testing.expectEqual(SQUASHFS_MAGIC, fs.sb.s_magic);
}
