# POLER-OS Architecture v2: Linux-Compatible Kernel

## Philosophy

> Program/file is a guest, not a host.

POLER-OS is a custom kernel that implements the **Linux system call interface**,
allowing it to run unmodified Linux binaries. The kernel is language-agnostic —
components can be written in C, Rust, Zig, or any language that targets Linux ABI.

**Long-term goal**: Native KDE Plasma and other desktop environments via Wayland
and Qt, running on our kernel without recompilation.

## Why This Approach Works

1. **Don't reinvent the wheel** — Linux has 30+ years of display stack development
   (DRM/KMS → libdrm → Mesa → Wayland → Qt/GTK). We plug into this stack,
   not replace it.

2. **The framebuffer bug goes away** — Instead of writing our own pixel-level
   rendering, we implement DRM/KMS ioctls. The existing `libdrm` + Wayland
   compositor handles all rendering. Proven code, no bugs.

3. **NixOS-inspired composition** — System is assembled from packages, not
   monolithic kernel features. Any component can be swapped.

4. **Language independence** — Since we implement the Linux ABI, we can use
   C libraries (glibc/musl), Rust crates, Zig programs — anything that
   compiles for Linux x86_64.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    User Space (Linux ELF binaries)               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ KDE/Qt   │  │ Wayland  │  │ musl/glibc│  │ Any Linux    │  │
│  │ Plasma   │  │ Sway/    │  │ + libdrm  │  │ ELF binary   │  │
│  │          │  │ KWin     │  │ + Mesa    │  │               │  │
│  └────┬─────┘  └────┬─────┘  └────┬──────┘  └──────┬───────┘  │
│       │              │              │                 │          │
│       └──────────────┴──────────────┴─────────────────┘          │
│                           │ Linux syscalls + /dev/* ioctls       │
╠═══════════════════════════╪═════════════════════════════════════╣
│                    POLER-OS Kernel                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              Linux Syscall Compatibility Layer             │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │  │
│  │  │ Process  │ │ Memory   │ │ File I/O │ │ DRM/KMS     │  │  │
│  │  │ (clone/  │ │ (mmap/   │ │ (openat/ │ │ (ioctl      │  │  │
│  │  │  execve/ │ │  mprotect│ │  read/   │ │  multiplex) │  │  │
│  │  │  wait4)  │ │  /brk)   │ │  write)  │ │             │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │  │
│  │  │ epoll    │ │ net:     │ │ devtmpfs │ │ POLER Core  │  │  │
│  │  │ (event   │ │ AF_UNIX  │ │ /dev/dri │ │ (security/  │  │  │
│  │  │  loop)   │ │ sockets  │ │ /dev/input│ │  intent)    │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              Hardware Abstraction (HAL)                     │  │
│  │  GDT/IDT │ APIC/HPET │ PCI │ VirtIO │ Framebuffer(VBE)   │  │
│  └────────────────────────────────────────────────────────────┘  │
╠═════════════════════════════════════════════════════════════════╣
│                    Hardware (x86_64)                             │
│  CPU(s) │ RAM │ GPU (VBE/DRM) │ Disk │ Network │ Input        │
└─────────────────────────────────────────────────────────────────┘
```

## Phased Implementation Roadmap

### Phase 0: Current State (v0.9.2)
- [x] 64-bit boot (Multiboot2 via GRUB)
- [x] HAL: GDT, IDT, PIC/APIC, ACPI, HPET
- [x] Physical/Virtual memory manager
- [x] Kernel heap
- [x] PCI bus scan
- [x] VirtIO-BLK + FAT32 filesystem
- [x] VBE framebuffer (buggy text rendering)
- [x] Serial console (works perfectly)
- [x] Basic shell
- [x] POLER Core (intent firewall, capabilities)

### Phase 1: Linux Process Model (27 syscalls)
**Goal**: Run a static Linux ELF binary that prints "Hello World"

| Syscall | # | Purpose |
|---------|---|---------|
| `read` | 0 | Read from fd |
| `write` | 1 | Write to fd |
| `openat` | 257 | Open file |
| `close` | 3 | Close fd |
| `fstat` | 5 | File status |
| `lseek` | 8 | Seek in file |
| `mmap` | 9 | Map memory |
| `mprotect` | 10 | Change memory protection |
| `munmap` | 11 | Unmap memory |
| `brk` | 12 | Program break (heap) |
| `rt_sigaction` | 13 | Signal handler |
| `rt_sigprocmask` | 14 | Signal mask |
| `ioctl` | 16 | Device control (KEY: DRM multiplexer) |
| `faccessat` | 21 | Check file access |
| `pipe2` | 293 | Create pipe |
| `clone` | 56 | Create process/thread |
| `execve` | 59 | Execute program |
| `exit` | 60 | Exit process |
| `wait4` | 61 | Wait for child |
| `uname` | 63 | System name |
| `fcntl` | 72 | File control |
| `futex` | 98 | Fast userspace mutex |
| `set_tid_address` | 218 | Thread ID |
| `arch_prctl` | 158 | Architecture-specific |
| `set_robust_list` | 273 | Robust futex list |
| `exit_group` | 231 | Exit all threads |
| `clock_gettime` | 228 | Get time |

**Deliverable**: `a.out` static Linux binary runs on POLER-OS

### Phase 2: DRM/KMS Display (14 ioctls)
**Goal**: Pixels on screen via DRM dumb buffers — NO custom framebuffer rendering

Instead of our buggy put_pixel/draw_char, we implement the DRM ioctl interface
so that `libdrm` handles all rendering through our kernel.

**DRM ioctls (via `ioctl` syscall on `/dev/dri/card0`):**

| Ioctl | Code | Purpose |
|-------|------|---------|
| `DRM_IOCTL_VERSION` | 0x00 | Query driver version |
| `DRM_IOCTL_SET_VERSION` | 0x07 | Set interface version |
| `DRM_IOCTL_GET_CAP` | 0x0C | Query capabilities |
| `DRM_IOCTL_SET_CLIENT_CAP` | 0x0D | Advertise client caps |
| `DRM_IOCTL_SET_MASTER` | 0x1E | Become DRM master |
| `DRM_IOCTL_MODE_GETRESOURCES` | 0xA0 | Enumerate CRTCs/connectors |
| `DRM_IOCTL_MODE_GETCRTC` | 0xA1 | Get CRTC info |
| `DRM_IOCTL_MODE_SETCRTC` | 0xA2 | **Set display mode** |
| `DRM_IOCTL_MODE_GETENCODER` | 0xA6 | Get encoder info |
| `DRM_IOCTL_MODE_GETCONNECTOR` | 0xA7 | Get connector modes |
| `DRM_IOCTL_MODE_ADDFB` | 0xAE | Create framebuffer |
| `DRM_IOCTL_MODE_PAGE_FLIP` | 0xB0 | **Flip display buffer** |
| `DRM_IOCTL_MODE_CREATE_DUMB` | 0xB2 | Allocate dumb buffer |
| `DRM_IOCTL_MODE_MAP_DUMB` | 0xB3 | mmap offset for buffer |

**Kernel subsystems needed:**
- `devtmpfs`: `/dev/dri/card0`, `/dev/input/eventX`
- `mmap` with DRM offset for dumb buffer mapping

**Deliverable**: `modetest` (from libdrm) shows display modes on POLER-OS

### Phase 3: Event Loop + Networking (12 syscalls)
**Goal**: Wayland compositor event loop works

| Syscall | # | Purpose |
|---------|---|---------|
| `socket` | 41 | Create socket (AF_UNIX) |
| `connect` | 42 | Connect socket |
| `bind` | 49 | Bind socket |
| `listen` | 50 | Listen for connections |
| `accept4` | 288 | Accept connection |
| `sendmsg` | 46 | Send message (+ SCM_RIGHTS) |
| `recvmsg` | 47 | Receive message (+ SCM_RIGHTS) |
| `memfd_create` | 319 | Shared memory for Wayland |
| `ftruncate` | 77 | Resize memfd |
| `epoll_create1` | 291 | Create epoll instance |
| `epoll_ctl` | 233 | Control epoll |
| `epoll_wait` | 232 | Wait for events |

**Deliverable**: Weston/Sway starts and shows a desktop

### Phase 4: Input + Compositor (10 syscalls)
**Goal**: Keyboard/mouse work in Wayland compositor

| Syscall | # | Purpose |
|---------|---|---------|
| `signalfd4` | 289 | Signal→fd |
| `timerfd_create` | 283 | Timer→fd |
| `timerfd_settime` | 286 | Arm timer |
| `eventfd2` | 290 | Event notification |
| `getpid` | 39 | Process ID |
| `getuid` | 102 | User ID |
| `getgid` | 104 | Group ID |
| `prctl` | 157 | Process control |
| `getrandom` | 318 | Random bytes |
| `socketpair` | 206 | Socket pair |

**evdev ioctls:**
- `EVIOCGBIT` — query supported event types
- `EVIOCGNAME` — get device name
- `EVIOCGID` — get device ID
- `EVIOCGRAB` — exclusive grab

**Deliverable**: Interactive Wayland desktop with keyboard/mouse

### Phase 5: KDE Plasma (16+ syscalls)
**Goal**: KDE Plasma runs natively

| Syscall | # | Purpose |
|---------|---|---------|
| `inotify_init1` | 294 | File watching |
| `inotify_add_watch` | 254 | Add watch |
| `inotify_rm_watch` | 255 | Remove watch |
| `statx` | 332 | Extended stat |
| `newfstatat` | 262 | Stat at dir |
| `mkdirat` | 258 | Create dirs |
| `unlinkat` | 263 | Delete files |
| `renameat2` | 316 | Rename files |
| `readlinkat` | 267 | Read symlinks |
| `geteuid` | 107 | Effective UID |
| `getcwd` | 79 | Working directory |
| `dup3` | 292 | Duplicate FD |
| `madvise` | 28 | Memory advice |
| `sysinfo` | 99 | System info |
| `sched_getaffinity` | 204 | CPU affinity |
| `sched_setaffinity` | 203 | CPU affinity |

**Deliverable**: KDE Plasma desktop on POLER-OS

## Display Stack: From Framebuffer Bug to DRM

### The Problem (Current)
```
GRUB → VBE framebuffer → Our buggy put_pixel/draw_char → Broken text
```

### The Solution (DRM/KMS Path)
```
GRUB → VBE framebuffer → DRM/KMS ioctls → libdrm → Wayland compositor → Pixels
                                                    (proven code, no bugs)
```

**Key insight**: We DON'T write rendering code. We implement the KERNEL SIDE of DRM.
The USER SPACE side (libdrm, compositor, toolkit) is already written and debugged.

### DRM Dumb Buffer Flow (Simplest Path to Pixels)
```
1. open("/dev/dri/card0")              → get DRM fd
2. DRM_IOCTL_MODE_GETRESOURCES         → find CRTC + connector
3. DRM_IOCTL_MODE_GETCONNECTOR         → get available modes
4. DRM_IOCTL_MODE_CREATE_DUMB          → allocate scanout buffer
5. DRM_IOCTL_MODE_ADDFB                → wrap buffer as framebuffer
6. DRM_IOCTL_MODE_MAP_DUMB + mmap()    → map buffer to userspace
7. Write pixels to mapped buffer        → libdrm does this correctly
8. DRM_IOCTL_MODE_SETCRTC              → display the buffer on screen
9. DRM_IOCTL_MODE_PAGE_FLIP            → double-buffered updates
```

## Kernel Internal Architecture

### Syscall Dispatcher
```zig
// All Linux syscalls route through one entry point
pub fn syscall_dispatch(num: u64, args: [6]u64) u64 {
    return switch (num) {
        0   => sys_read(args),
        1   => sys_write(args),
        9   => sys_mmap(args),
        16  => sys_ioctl(args),     // ← DRM/KMS lives here
        56  => sys_clone(args),
        59  => sys_execve(args),
        232 => sys_epoll_wait(args),
        // ... ~65 total for full KDE support
        else => {
            log.warn("unimplemented syscall: {}", .{num});
            -errno.ENOSYS;
        }
    };
}
```

### DRM Subsystem (inside ioctl handler)
```zig
fn sys_ioctl(args: [6]u64) u64 {
    const fd = args[0];
    const request = args[1];
    const argp = args[2];

    const file = fd_table.get(fd);
    if (file.is_drm) {
        return drm_ioctl(request, argp);  // ← Multiplex DRM commands
    }
    if (file.is_evdev) {
        return evdev_ioctl(request, argp);
    }
    // ... other device types
}

fn drm_ioctl(request: u64, argp: u64) u64 {
    const cmd = request & 0xFF;  // Extract ioctl number
    return switch (cmd) {
        0x00 => drm_version(argp),
        0xA0 => drm_mode_getresources(argp),
        0xA2 => drm_mode_setcrtc(argp),
        0xAE => drm_mode_addfb(argp),
        0xB0 => drm_mode_page_flip(argp),
        0xB2 => drm_mode_create_dumb(argp),
        0xB3 => drm_mode_map_dumb(argp),
        // ...
    };
}
```

### devtmpfs
```
/dev/
├── dri/
│   ├── card0          ← DRM/KMS device (ioctl)
│   └── renderD128     ← GPU render device (future)
├── input/
│   ├── event0         ← Keyboard (evdev)
│   ├── event1         ← Mouse (evdev)
│   └── mice           ← Legacy mouse
├── console            ← VT master
├── tty0               ← Virtual terminal
├── null               ← /dev/null
├── zero               ← /dev/zero
├── urandom            ← /dev/urandom
└── stdin/stdout/stderr ← Standard streams
```

## What About Our Existing Code?

| Component | Status | Future |
|-----------|--------|--------|
| VBE framebuffer | Buggy → Replace | Becomes DRM dumb buffer backend |
| Shell | Works (serial) | Runs as Linux ELF via execve |
| FAT32 + VirtIO | Works | Becomes /dev/vda → ext4/btrfs |
| PCI scan | Works | Used by DRM device detection |
| HAL (GDT/IDT/APIC) | Works | Unchanged — hardware layer |
| POLER Core (intent) | Unique feature | Linux security module (LSM) equivalent |
| Scheduler | Basic | Replaced by Linux-style scheduler |
| VMM/PMM | Works | Extended for mmap/mprotect |

## NixOS-Inspired: System as Composition

Like NixOS, POLER-OS should be **declaratively composable**:

```
poler-os = {
    kernel = self.kernel;           # Our kernel with Linux ABI
    init = busybox + musl;          # PID 1
    display = libdrm + wayland + sway;  # Display stack
    desktop = qt5 + kde-plasma;     # Desktop environment
    security = poler-core;          # Our unique security layer
};
```

Each component is a **pre-built Linux binary** (or compiled from source with musl).
The kernel provides the ABI, the userspace provides the functionality.

## Immediate Next Steps

1. **Implement ELF loader** — Load static Linux ELF binaries
2. **Implement 27 Tier-0 syscalls** — Process lifecycle
3. **Run `hello`** — Static musl binary that writes "Hello World" to stdout
4. **Implement DRM backend** — 14 ioctls for modesetting
5. **Run `modetest`** — First pixels on screen via proven code

This approach kills the framebuffer bug dead: we stop writing rendering code
and let the Linux ecosystem's debugged code do the work.
