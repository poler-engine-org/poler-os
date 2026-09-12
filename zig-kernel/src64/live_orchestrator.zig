//! ============================================================================
//! POLER-OS: Native Live Orchestrator & Graphical Session Dispatcher in Pure Zig
//! Manages CachyOS Live-session bootstrap, OverlayFS staging, and Desktop Choices
//! ============================================================================

const std = @import("std");
const testing = std.testing;

pub const DesktopSession = enum {
    kde_plasma_6,
    gnome_47,
    xfce_4,
    gamescope_hdr,
    standalone_wayland,
    posix_shell,

    pub fn displayName(self: DesktopSession) []const u8 {
        return switch (self) {
            .kde_plasma_6 => "KDE Plasma 6 (Wayland / KWin)",
            .gnome_47 => "GNOME 47 (Mutter / Wayland)",
            .xfce_4 => "XFCE 4.18 (Xfwm4 / Desktop)",
            .gamescope_hdr => "Gamescope Steam Deck Compositor",
            .standalone_wayland => "POLER Native Wayland Compositor",
            .posix_shell => "Ring 3 Interactive POSIX Shell",
        };
    }

    pub fn binaryPath(self: DesktopSession) []const u8 {
        return switch (self) {
            .kde_plasma_6 => "bin/compositor",
            .gnome_47 => "usr/bin/gnome-shell",
            .xfce_4 => "usr/bin/xfce4-session",
            .gamescope_hdr => "usr/bin/gamescope",
            .standalone_wayland => "bin/compositor",
            .posix_shell => "bin/sh",
        };
    }
};

pub fn parseSessionName(name: []const u8) ?DesktopSession {
    if (std.mem.eql(u8, name, "plasma") or std.mem.eql(u8, name, "kde") or std.mem.eql(u8, name, "kwin")) {
        return .kde_plasma_6;
    } else if (std.mem.eql(u8, name, "gnome") or std.mem.eql(u8, name, "gdm")) {
        return .gnome_47;
    } else if (std.mem.eql(u8, name, "xfce") or std.mem.eql(u8, name, "xfce4")) {
        return .xfce_4;
    } else if (std.mem.eql(u8, name, "gamescope") or std.mem.eql(u8, name, "steam")) {
        return .gamescope_hdr;
    } else if (std.mem.eql(u8, name, "wayland") or std.mem.eql(u8, name, "compositor")) {
        return .standalone_wayland;
    } else if (std.mem.eql(u8, name, "sh") or std.mem.eql(u8, name, "bash") or std.mem.eql(u8, name, "shell")) {
        return .posix_shell;
    }
    return null;
}

pub const LiveEnvironment = struct {
    pub const DEFAULT_USER = "cachyos";
    pub const DEFAULT_UID: u32 = 1000;
    pub const DEFAULT_GID: u32 = 1000;
    pub const XDG_RUNTIME_DIR = "/run/user/1000";
    pub const WAYLAND_DISPLAY = "wayland-0";

    pub const EnvVar = struct {
        key: []const u8,
        val: []const u8,
    };

    pub fn getSessionEnv() [8]EnvVar {
        return [_]EnvVar{
            .{ .key = "USER", .val = DEFAULT_USER },
            .{ .key = "LOGNAME", .val = DEFAULT_USER },
            .{ .key = "HOME", .val = "/home/cachyos" },
            .{ .key = "XDG_RUNTIME_DIR", .val = XDG_RUNTIME_DIR },
            .{ .key = "WAYLAND_DISPLAY", .val = WAYLAND_DISPLAY },
            .{ .key = "QT_QPA_PLATFORM", .val = "wayland" },
            .{ .key = "GDK_BACKEND", .val = "wayland" },
            .{ .key = "MOZ_ENABLE_WAYLAND", .val = "1" },
        };
    }

    pub fn getRequiredRuntimeDirs() [6][]const u8 {
        return [_][]const u8{
            "/dev",
            "/proc",
            "/sys",
            "/run/user/1000",
            "/tmp",
            "/tmp/.X11-unix",
        };
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "live_orchestrator: desktop session paths and metadata" {
    const plasma = DesktopSession.kde_plasma_6;
    try testing.expectEqualStrings("KDE Plasma 6 (Wayland / KWin)", plasma.displayName());
    try testing.expectEqualStrings("bin/compositor", plasma.binaryPath());

    const gamescope = DesktopSession.gamescope_hdr;
    try testing.expectEqualStrings("Gamescope Steam Deck Compositor", gamescope.displayName());

    const env = LiveEnvironment.getSessionEnv();
    try testing.expectEqualStrings("wayland-0", env[4].val);
    try testing.expectEqualStrings("QT_QPA_PLATFORM", env[5].key);
    try testing.expectEqualStrings("wayland", env[5].val);
}

test "live_orchestrator: parse session names" {
    try testing.expectEqual(DesktopSession.kde_plasma_6, parseSessionName("plasma").?);
    try testing.expectEqual(DesktopSession.kde_plasma_6, parseSessionName("kde").?);
    try testing.expectEqual(DesktopSession.gnome_47, parseSessionName("gnome").?);
    try testing.expectEqual(DesktopSession.xfce_4, parseSessionName("xfce").?);
    try testing.expectEqual(DesktopSession.gamescope_hdr, parseSessionName("gamescope").?);
    try testing.expectEqual(DesktopSession.posix_shell, parseSessionName("sh").?);
    try testing.expect(parseSessionName("invalid_env") == null);
}

test "live_orchestrator: runtime directory list" {
    const dirs = LiveEnvironment.getRequiredRuntimeDirs();
    try testing.expectEqual(@as(usize, 6), dirs.len);
    try testing.expectEqualStrings("/run/user/1000", dirs[3]);
    try testing.expectEqualStrings("/tmp/.X11-unix", dirs[5]);
}
