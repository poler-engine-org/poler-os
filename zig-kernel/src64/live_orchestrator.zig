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
