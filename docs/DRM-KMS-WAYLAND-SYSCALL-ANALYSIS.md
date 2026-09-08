# Linux DRM/KMS & Wayland Display Stack: Syscall Analysis for Custom Kernel

## Table of Contents
1. [DRM/KMS Ioctl Commands](#1-drmkms-ioctl-commands)
2. [Wayland Compositor Syscalls](#2-wayland-compositor-syscalls)
3. [Qt/KDE Plasma Additional Syscalls](#3-qtkde-plasma-additional-syscalls)
4. [Display Stack Composition](#4-display-stack-composition)
5. [Non-Linux Kernel Compatibility Projects](#5-non-linux-kernel-compatibility-projects)
6. [Minimum Viable Syscall Set](#6-minimum-viable-syscall-set)

---

## 1. DRM/KMS Ioctl Commands

### Key Insight: DRM Uses `ioctl()` on `/dev/dri/cardX` — Not Direct Syscalls

DRM does NOT define its own syscalls. All DRM/KMS operations are multiplexed through a **single syscall**: `ioctl()` (syscall #16 on x86_64) operating on file descriptors opened from `/dev/dri/cardN` (KMS/render) and `/dev/dri/renderD128` (GPU render). The specific operations are selected via ioctl **command numbers**.

### DRM ioctl Encoding

```
Base:  'd' (0x64)
Format: _IO/_IOR/_IOW/_IOWR(DRM_IOCTL_BASE, nr, struct_type)
```

### Complete DRM ioctl Command Table (from `include/uapi/drm/drm.h`)

#### Generic DRM Ioctls (nr 0x00–0x2F)

| Command | Hex | Struct | Purpose | Priority |
|---------|-----|--------|---------|----------|
| `DRM_IOCTL_VERSION` | 0x00 | `drm_version` | Query driver version | **P0 — required** |
| `DRM_IOCTL_GET_UNIQUE` | 0x01 | `drm_unique` | Get bus ID | P3 |
| `DRM_IOCTL_GET_MAGIC` | 0x02 | `drm_auth` | Get auth magic | P2 |
| `DRM_IOCTL_IRQ_BUSID` | 0x03 | `drm_irq_busid` | IRQ bus ID | P3 |
| `DRM_IOCTL_GET_MAP` | 0x04 | `drm_map` | Get map info | P3 |
| `DRM_IOCTL_GET_CLIENT` | 0x05 | `drm_client` | Get client info | P3 |
| `DRM_IOCTL_GET_STATS` | 0x06 | `drm_stats` | Get stats | P3 |
| `DRM_IOCTL_SET_VERSION` | 0x07 | `drm_set_version` | Set interface version | **P0 — required** |
| `DRM_IOCTL_MODESET_CTL` | 0x08 | `drm_modeset_ctl` | Modeset control | P2 |
| `DRM_IOCTL_GEM_CLOSE` | 0x09 | `drm_gem_close` | Close GEM handle | **P1 — needed** |
| `DRM_IOCTL_GEM_FLINK` | 0x0A | `drm_gem_flink` | GEM handle→name | P2 |
| `DRM_IOCTL_GEM_OPEN` | 0x0B | `drm_gem_open` | Open GEM name | P2 |
| `DRM_IOCTL_GET_CAP` | 0x0C | `drm_get_cap` | Query capabilities | **P0 — required** |
| `DRM_IOCTL_SET_CLIENT_CAP` | 0x0D | `drm_set_client_cap` | Advertise client caps | **P0 — required** |
| `DRM_IOCTL_SET_MASTER` | 0x1E | — | Become DRM master | **P0 — required** |
| `DRM_IOCTL_DROP_MASTER` | 0x1F | — | Drop DRM master | P1 |
| `DRM_IOCTL_PRIME_HANDLE_TO_FD` | 0x2D | `drm_prime_handle` | GEM handle→DMA-BUF fd | **P1 — needed** |
| `DRM_IOCTL_PRIME_FD_TO_HANDLE` | 0x2E | `drm_prime_handle` | DMA-BUF fd→GEM handle | **P1 — needed** |

#### KMS Mode-Setting Ioctls (nr 0xA0–0xCE)

| Command | Hex | Struct | Purpose | Priority |
|---------|-----|--------|---------|----------|
| `DRM_IOCTL_MODE_GETRESOURCES` | 0xA0 | `drm_mode_card_res` | Enumerate CRTCs/encoders/connectors | **P0 — required** |
| `DRM_IOCTL_MODE_GETCRTC` | 0xA1 | `drm_mode_crtc` | Get CRTC info | **P0 — required** |
| `DRM_IOCTL_MODE_SETCRTC` | 0xA2 | `drm_mode_crtc` | Set CRTC mode + framebuffer | **P0 — CRITICAL** |
| `DRM_IOCTL_MODE_CURSOR` | 0xA3 | `drm_mode_cursor` | Set cursor (legacy) | P2 |
| `DRM_IOCTL_MODE_GETGAMMA` | 0xA4 | `drm_mode_crtc_lut` | Get gamma LUT | P3 |
| `DRM_IOCTL_MODE_SETGAMMA` | 0xA5 | `drm_mode_crtc_lut` | Set gamma LUT | P3 |
| `DRM_IOCTL_MODE_GETENCODER` | 0xA6 | `drm_mode_get_encoder` | Get encoder info | **P0 — required** |
| `DRM_IOCTL_MODE_GETCONNECTOR` | 0xA7 | `drm_mode_get_connector` | Get connector modes | **P0 — required** |
| `DRM_IOCTL_MODE_GETPROPERTY` | 0xAA | `drm_mode_get_property` | Get KMS property | **P1 — needed** |
| `DRM_IOCTL_MODE_SETPROPERTY` | 0xAB | `drm_mode_connector_set_property` | Set connector property | P2 |
| `DRM_IOCTL_MODE_GETPROPBLOB` | 0xAC | `drm_mode_get_blob` | Get property blob | P2 |
| `DRM_IOCTL_MODE_GETFB` | 0xAD | `drm_mode_fb_cmd` | Get framebuffer info | P3 |
| `DRM_IOCTL_MODE_ADDFB` | 0xAE | `drm_mode_fb_cmd` | Create framebuffer from handle | **P0 — CRITICAL** |
| `DRM_IOCTL_MODE_RMFB` | 0xAF | unsigned int | Destroy framebuffer | **P1 — needed** |
| `DRM_IOCTL_MODE_PAGE_FLIP` | 0xB0 | `drm_mode_crtc_page_flip` | Schedule vblank page flip | **P0 — CRITICAL** |
| `DRM_IOCTL_MODE_DIRTYFB` | 0xB1 | `drm_mode_fb_dirty_cmd` | Mark FB dirty | P3 |
| `DRM_IOCTL_MODE_CREATE_DUMB` | 0xB2 | `drm_mode_create_dumb` | Allocate dumb buffer | **P0 — CRITICAL** |
| `DRM_IOCTL_MODE_MAP_DUMB` | 0xB3 | `drm_mode_map_dumb` | mmap offset for dumb buffer | **P0 — CRITICAL** |
| `DRM_IOCTL_MODE_DESTROY_DUMB` | 0xB4 | `drm_mode_destroy_dumb` | Free dumb buffer | P1 |
| `DRM_IOCTL_MODE_GETPLANERESOURCES` | 0xB5 | `drm_mode_get_plane_res` | Enumerate planes | **P1 — atomic needs** |
| `DRM_IOCTL_MODE_GETPLANE` | 0xB6 | `drm_mode_get_plane` | Get plane info | **P1 — atomic needs** |
| `DRM_IOCTL_MODE_SETPLANE` | 0xB7 | `drm_mode_set_plane` | Set plane config | **P1 — atomic needs** |
| `DRM_IOCTL_MODE_ADDFB2` | 0xB8 | `drm_mode_fb_cmd2` | Create FB with modifiers | **P1 — needed** |
| `DRM_IOCTL_MODE_OBJ_GETPROPERTIES` | 0xB9 | `drm_mode_obj_get_properties` | Get object props | P2 |
| `DRM_IOCTL_MODE_OBJ_SETPROPERTY` | 0xBA | `drm_mode_obj_set_property` | Set object prop | P2 |
| `DRM_IOCTL_MODE_CURSOR2` | 0xBB | `drm_mode_cursor2` | Cursor with hotspot | P2 |
| `DRM_IOCTL_MODE_ATOMIC` | 0xBC | `drm_mode_atomic` | Atomic modeset commit | **P1 — modern path** |
| `DRM_IOCTL_MODE_CREATEPROPBLOB` | 0xBD | `drm_mode_create_blob` | Create property blob | **P1 — atomic needs** |
| `DRM_IOCTL_MODE_DESTROYPROPBLOB` | 0xBE | `drm_mode_destroy_blob` | Destroy property blob | P2 |
| `DRM_IOCTL_MODE_CREATE_LEASE` | 0xC6 | `drm_mode_create_lease` | Lease DRM objects | P2 |
| `DRM_IOCTL_MODE_LIST_LESSEES` | 0xC7 | `drm_mode_list_lessees` | List lessees | P3 |
| `DRM_IOCTL_MODE_GET_LEASE` | 0xC8 | `drm_mode_get_lease` | Get lease | P3 |
| `DRM_IOCTL_MODE_REVOKE_LEASE` | 0xC9 | `drm_mode_revoke_lease` | Revoke lease | P3 |
| `DRM_IOCTL_MODE_GETFB2` | 0xCE | `drm_mode_fb_cmd2` | Get FB2 metadata | P3 |

### Minimum DRM/KMS ioctl Sequence for Modesetting

**Legacy path** (simplest, works everywhere):
```
1. open("/dev/dri/card0", O_RDWR)         → get DRM fd
2. DRM_IOCTL_VERSION                       → verify driver
3. DRM_IOCTL_SET_VERSION                   → set interface version
4. DRM_IOCTL_GET_CAP                       → check capabilities
5. DRM_IOCTL_SET_CLIENT_CAP                → advertise UNIVERSAL_PLANES, etc.
6. DRM_IOCTL_SET_MASTER                    → become DRM master
7. DRM_IOCTL_MODE_GETRESOURCES             → enumerate CRTCs, connectors, encoders
8. DRM_IOCTL_MODE_GETCONNECTOR (×N)        → find connected connector + modes
9. DRM_IOCTL_MODE_GETENCODER (×N)          → find CRTC for encoder
10. DRM_IOCTL_MODE_CREATE_DUMB             → allocate scanout buffer
11. DRM_IOCTL_MODE_ADDFB                   → wrap buffer as framebuffer
12. DRM_IOCTL_MODE_MAP_DUMB + mmap()       → map buffer for CPU writes
13. DRM_IOCTL_MODE_SETCRTC                 → set mode + FB → DISPLAY!
14. DRM_IOCTL_MODE_PAGE_FLIP               → swap FB on vsync (tear-free)
```

**Atomic path** (modern, used by wlroots/Sway):
```
Same 1-8 as above, then:
9.  DRM_IOCTL_MODE_GETPLANERESOURCES       → enumerate planes
10. DRM_IOCTL_MODE_GETPLANE                → get plane details
11. DRM_IOCTL_MODE_GETPROPERTY             → discover properties
12. DRM_IOCTL_MODE_CREATEPROPBLOB          → create mode blob
13. DRM_IOCTL_MODE_CREATE_DUMB             → allocate buffer
14. DRM_IOCTL_MODE_ADDFB2                  → create FB with modifiers
15. DRM_IOCTL_MODE_MAP_DUMB + mmap()       → map buffer
16. DRM_IOCTL_MODE_ATOMIC                  → commit mode + FB + plane
17. DRM_IOCTL_MODE_PAGE_FLIP               → flip on vsync
```

---

## 2. Wayland Compositor Syscalls

### How Wayland Works at the Syscall Level

Wayland uses **Unix domain sockets** (`AF_UNIX`) for all client↔compositor communication. There are no "Wayland syscalls" — it's a protocol over sockets, plus standard Linux IPC.

### Core Syscalls for a Wayland Compositor (e.g., Weston/Sway/wlroots)

#### A. Process/Thread Lifecycle

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `clone` | 56 | Create threads/processes | **P0** |
| `exit` | 60 | Exit thread | **P0** |
| `exit_group` | 231 | Exit process | **P0** |
| `execve` | 59 | Execute program (launching clients) | P1 |
| `wait4` | 61 | Wait for child | P2 |
| `arch_prctl` | 158 | Set thread local storage | **P0** |
| `set_tid_address` | 218 | Thread pointer cleanup | **P0** |
| `futex` | 202 | Mutual exclusion / waiting | **P0** |
| `set_robust_list` | 273 | Robust mutex cleanup | **P0** |

#### B. Memory Management

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `mmap` | 9 | Map memory (DRM buffers, shared memory) | **P0** |
| `munmap` | 11 | Unmap memory | **P0** |
| `mprotect` | 10 | Change memory protections | **P0** |
| `brk` | 12 | Heap management | **P0** |
| `madvise` | 28 | Memory advice | P1 |
| `memfd_create` | 319 | Create anonymous file for buffer sharing | **P0** |
| `shmat`/`shmget`/`shmdt` | — | SysV shared memory (fallback) | P2 |

#### C. File I/O & FD Management

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `openat` | 257 | Open files (`/dev/dri/*`, sockets) | **P0** |
| `close` | 3 | Close file descriptors | **P0** |
| `read` | 0 | Read from FDs | **P0** |
| `write` | 1 | Write to FDs | **P0** |
| `ioctl` | 16 | DRM operations, TTY, evdev | **P0** |
| `fcntl` | 72 | FD flags (CLOEXEC, etc.) | **P0** |
| `dup` / `dup2` / `dup3` | 32/33/292 | Duplicate FDs | P1 |
| `fstat` | 5 | File stat | P1 |
| `newfstatat` | 262 | File stat at dir | P1 |
| `lseek` | 8 | Seek in files | P1 |
| `pread64` / `pwrite64` | 17/18 | Positional I/O | P2 |
| `readv` / `writev` | 19/20 | Scatter-gather I/O | P1 |

#### D. Event Loop (The Heart of a Compositor)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `epoll_create1` | 291 | Create epoll instance | **P0** |
| `epoll_ctl` | 233 | Add/modify/delete FD in epoll | **P0** |
| `epoll_wait` | 232 | Wait for events | **P0** |
| `signalfd4` | 327 | Receive signals as FD events | **P0** |
| `timerfd_create` | 283 | Create timer FD | **P0** |
| `timerfd_settime` | 286 | Arm/disarm timer | **P0** |
| `timerfd_gettime` | 287 | Read timer remaining | P2 |
| `eventfd2` | 290 | Event notification FD | **P1** |
| `pipe2` | 293 | Pipe for signaling | P1 |

#### E. Socket / IPC (Wayland Protocol)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `socket` | 41 | Create AF_UNIX socket | **P0** |
| `bind` | 49 | Bind to $XDG_RUNTIME_DIR/wayland-0 | **P0** |
| `listen` | 50 | Listen for client connections | **P0** |
| `accept4` | 288 | Accept client connection | **P0** |
| `connect` | 42 | Connect to compositor (client side) | **P0** |
| `sendmsg` | 46 | Send Wayland messages + FDs | **P0** |
| `recvmsg` | 47 | Receive Wayland messages + FDs | **P0** |
| `sendto` | 44 | Send data | P2 |
| `recvfrom` | 45 | Receive data | P2 |
| `getsockname` | 51 | Get socket name | P2 |
| `getsockopt` | 55 | Get socket options | P2 |
| `setsockopt` | 54 | Set socket options (CLOEXEC, etc.) | **P1** |
| `shutdown` | 48 | Shutdown socket | P2 |
| `socketpair` | 53 | Create socket pair | P1 |

#### F. Scheduling & Signals

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `rt_sigaction` | 13 | Set signal handler | **P0** |
| `rt_sigprocmask` | 14 | Block/unblock signals | **P0** |
| `rt_sigreturn` | 15 | Return from signal handler | **P0** |
| `sched_setscheduler` | 144 | Set scheduling policy | P2 |
| `sched_getaffinity` | 204 | Get CPU affinity | P2 |
| `sched_setaffinity` | 203 | Set CPU affinity | P2 |
| `nanosleep` | 35 | Sleep | P2 |
| `clock_nanosleep` | 230 | High-res sleep | P2 |

#### G. Time

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `clock_gettime` | 228 | Get time (CLOCK_MONOTONIC for frames) | **P0** |
| `gettimeofday` | 96 | Wall clock time | P1 |
| `clock_getres` | 229 | Clock resolution | P2 |

#### H. TTY / VT (Console Switching)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `ioctl` (VT-specific) | 16 | VT_ACTIVATE, VT_WAITACTIVE, KDSETMODE, KDSETKEY | **P0** (for VT switching) |

Key TTY ioctls:
- `VT_ACTIVATE` — switch to VT
- `VT_WAITACTIVE` — wait for VT switch
- `VT_GETSTATE` — get current VT
- `VT_SETMODE` — set VT mode (SIGUSR1 on switch)
- `KDSETMODE` — KD_GRAPHICS mode (disable text rendering)
- `KDSKBMODE` — K_OFF (disable keyboard input to console)

#### I. Input (evdev via libinput)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `ioctl` (evdev-specific) | 16 | Input device ioctls | **P0** |

Key evdev ioctls:
- `EVIOCGBIT` — get supported event types
- `EVIOCGNAME` — get device name
- `EVIOCGID` — get device ID
- `EVIOCGKEY` — get key state
- `EVIOCGRAB` — exclusive grab
- `EVIOCSABS` / `EVIOCGABS` — absolute axis config

#### J. Buffer Sharing (DMA-BUF)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `ioctl` (DMA-BUF) | 16 | DMA-BUF ioctl on fd | **P1** |

DMA-BUF ioctls:
- `DMA_BUF_IOCTL_SYNC` — CPU access synchronization
- `DMA_BUF_SET_NAME` — name the buffer (debug)

---

## 3. Qt/KDE Plasma Additional Syscalls

Beyond what Wayland/wlroots needs, Qt/QML/KDE requires:

#### A. File System Monitoring

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `inotify_init1` | 294 | Create inotify instance | **P0** for KDE |
| `inotify_add_watch` | 254 | Add file watch | **P0** for KDE |
| `inotify_rm_watch` | 255 | Remove file watch | **P1** for KDE |

Qt uses inotify for:
- QFileSystemWatcher (theme changes, config file changes)
- Plasma's file monitoring (desktop files, configs)
- Font cache invalidation

#### B. Process & Thread Control

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `prctl` | 157 | Process control (PR_SET_NAME, PR_SET_PDEATHSIG, PR_SET_DUMPABLE) | **P0** for KDE |
| `getpid` | 39 | Get process ID | **P0** |
| `gettid` | 186 | Get thread ID | P1 |
| `getuid` | 102 | Get user ID | **P0** |
| `getgid` | 104 | Get group ID | **P0** |
| `geteuid` | 107 | Get effective UID | **P0** |
| `getegid` | 108 | Get effective GID | P1 |
| `getgroups` | 115 | Get supplementary groups | P1 |
| `setsid` | 112 | Create session | P1 |
| `setpgid` | 109 | Set process group | P2 |

#### C. D-Bus / IPC (KDE's session bus)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `socket` (AF_UNIX) | 41 | Connect to D-Bus daemon | **P0** for KDE |
| `connect` | 42 | Connect to `/run/dbus/system_bus_socket` | **P0** for KDE |
| `sendmsg` / `recvmsg` | 46/47 | D-Bus message exchange | **P0** for KDE |

#### D. X11/XWayland Compatibility (Transitional)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `socket` (AF_UNIX) | 41 | Connect to X11 socket | P2 |
| `ioctl` (via libX11) | 16 | X11 protocol | P2 |

#### E. Security / Sandboxing (KDE uses various)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `prctl` (PR_SET_SECCOMP) | 157 | Seccomp filters | P2 |
| `pidfd_open` | 434 | PID file descriptor | P2 |
| `pidfd_send_signal` | 424 | Signal via pidfd | P2 |

#### F. Network (for KDE Connect, etc.)

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `socket` (AF_INET/AF_INET6) | 41 | Network sockets | P2 |
| `bind` / `connect` | 49/42 | Network connections | P2 |

#### G. Additional Qt-Specific

| Syscall | x86_64 # | Purpose | Priority |
|---------|----------|---------|----------|
| `statx` | 332 | Extended file stat | P1 |
| `access` | 21 | Check file access | P1 |
| `faccessat` | 269 | Check access at dir | P1 |
| `uname` | 63 | System name | P1 |
| `sysinfo` | 99 | System info | P2 |
| `getrandom` | 318 | Random bytes (Qt SSL, UUID) | P1 |
| `getcwd` | 79 | Current working directory | P1 |
| `chdir` | 80 | Change directory | P2 |
| `mkdirat` | 258 | Create directories | P1 |
| `unlinkat` | 263 | Remove files | P1 |
| `renameat2` | 316 | Rename files | P1 |
| `readlinkat` | 267 | Read symlink | P1 |
| `umask` | 95 | Set file mode mask | P2 |

---

## 4. Display Stack Composition

### Full Stack Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    USER APPLICATIONS                         │
│   Firefox, KDE Apps, Games, Terminal Emulators              │
└────────────┬────────────────────────────────────────────────┘
             │ Wayland protocol (AF_UNIX socket)
             ▼
┌─────────────────────────────────────────────────────────────┐
│                 WAYLAND COMPOSITOR                           │
│   KWin (KDE), Mutter (GNOME), Sway/wlroots, Weston         │
│                                                              │
│   Responsibilities:                                          │
│   • Accept Wayland client connections                        │
│   • Composite surfaces into final frame                     │
│   • Handle input routing (keyboard/mouse/touch)             │
│   • Perform DRM/KMS modesetting                             │
│   • Page flip for vsync                                     │
└──────┬──────────────┬──────────────┬────────────────────────┘
       │              │              │
       ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────────────┐
│   libdrm    │ │  libinput   │ │  Mesa / GPU driver │
│  (DRM ioctls│ │  (evdev     │ │  (OpenGL/Vulkan)   │
│   wrapper)  │ │   ioctls)   │ │                    │
└──────┬──────┘ └──────┬──────┘ └────────┬───────────┘
       │              │                  │
       ▼              ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    LINUX KERNEL                              │
│                                                              │
│   ┌─────────────┐  ┌──────────┐  ┌─────────────────────┐   │
│   │  DRM/KMS     │  │  evdev   │  │  GPU driver (i915,  │   │
│   │  subsystem   │  │  input   │  │  amdgpu, nouveau)   │   │
│   │              │  │          │  │                     │   │
│   │  /dev/dri/   │  │ /dev/    │  │  /dev/dri/          │   │
│   │  card0       │  │ input/   │  │  renderD128         │   │
│   └──────┬───────┘  └────┬─────┘  └──────────┬──────────┘   │
│          │               │                    │              │
│          ▼               ▼                    ▼              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              HARDWARE (GPU, Display, Input)          │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### NixOS Display Stack (as an example distro)

```
NixOS packages compose like this:

kernel (with DRM/KMS drivers built-in or modules)
  └─> /dev/dri/card0, /dev/dri/renderD128
  
libdrm (userspace ioctl wrapper)
  └─> Used by: Mesa, compositor, XWayland
  
Mesa (OpenGL/Vulkan implementation)
  ├─> libEGL.so       — EGL platform (wayland, drm)
  ├─> libGL.so        — OpenGL
  ├─> libgbm.so       — Generic Buffer Manager (create/allocate scanout buffers)
  ├─> libvulkan.so    — Vulkan
  └─> DRI drivers: i915, amdgpu, radeonsi, nouveau, etc.

libinput (input device handling)
  └─> Reads from /dev/input/eventX via evdev ioctls

Wayland (protocol + libwayland)
  ├─> libwayland-client.so  — Client-side Wayland IPC
  ├─> libwayland-server.so  — Server-side Wayland IPC
  └─> wayland-scanner       — Protocol XML → C code generator

Compositor (picks one):
  ├─> Sway (wlroots-based, tiling)
  ├─> KWin (KDE's compositor)
  ├─> Mutter (GNOME's compositor)
  ├─> Weston (reference compositor)
  └─> Hyprland (wlroots-based, animated)

Toolkit (picks one or more):
  ├─> Qt 6 (QPA: wayland platform plugin)
  ├─> GTK 4 (Wayland backend)
  ├─> SDL2/SDL3 (Wayland video driver)
  └─> GLFW (Wayland backend)

XWayland (optional compatibility)
  └─> XWayland binary (runs as Wayland client, serves X11 apps)
```

### Key Library Dependency Chain for a Minimal Wayland Client

```
wayland-client
  → libwayland-client.so (socket IPC)
  → libc (socket, connect, sendmsg, recvmsg, mmap)
  → /run/user/1000/wayland-0 (Unix domain socket)
```

### Key Library Dependency Chain for a Wayland Compositor

```
compositor (e.g., wlroots-based)
  → libwayland-server.so (socket IPC, event loop)
  → libdrm.so (DRM/KMS ioctls)
  → libgbm.so (buffer allocation via DRM)
  → libEGL.so + libGLESv2/libGL (GPU rendering)
  → libinput.so (evdev input)
  → libudev.so (device enumeration — reads /sys, /dev)
  → libc (all standard syscalls)
```

---

## 5. Non-Linux Kernel Compatibility Projects

### 5.1 FreeBSD Linuxulator

**What**: FreeBSD's Linux binary compatibility layer (not emulation — runs Linux ELF binaries natively on FreeBSD kernel).

**How**: 
- Implements Linux syscall numbers and semantics as a FreeBSD syscall translation layer
- Linux ELF binaries are detected at exec time, routed to the Linuxulator syscall table
- Provides Linux-like `/proc`, `/sys`, and `/dev` filesystems

**DRM/GPU status**: FreeBSD has its own port of the Linux DRM/KMS subsystem using **LinuxKPI** (Linux Kernel Programming Interface), which provides API-compatible implementations of Linux kernel interfaces. This is how FreeBSD runs the same i915, amdgpu, etc. GPU drivers — they're literally the Linux kernel source with thin compatibility shims.

**Wayland status**: FreeBSD can run Wayland compositors (Wayfire, Sway, Hikari) natively. The DRM/KMS stack is ported, so all the ioctl commands work. The Linuxulator is needed only for running Linux ELF binaries.

**Coverage**: ~380 Linux syscalls implemented (as of FreeBSD 14). Missing some newer ones like `pidfd_open`, `landlock`, etc.

**Relevance to your project**: ★★★★★ — The most mature model. FreeBSD proves you can take Linux GPU drivers and make them work on another kernel by implementing the kernel-internal API compatibility layer (LinuxKPI) + the userspace syscall interface (Linuxulator).

### 5.2 Fuchsia / Zircon + Starnix

**What**: Google's Fuchsia OS uses the Zircon microkernel. **Starnix** is a Linux syscall compatibility layer that runs Linux binaries on Fuchsia.

**How**:
- Starnix implements Linux syscalls as a userspace process
- Linux binaries run inside a Starnix "container" that translates Linux syscalls to Zircon primitives
- Not a kernel-level translation — it's a userspace syscall emulator

**DRM/GPU status**: Fuchsia has its own display stack (Scenic, Flatland). It does NOT implement DRM/KMS ioctl compatibility. Linux GPU drivers cannot run on Fuchsia.

**Wayland status**: No Wayland support. Fuchsia uses its own compositor architecture.

**Relevance**: ★★★ — Interesting architectural reference for how to do syscall translation in userspace rather than kernel space, but no display stack compatibility.

### 5.3 SerenityOS

**What**: A from-scratch Unix-like OS with its own kernel, GUI, and userspace.

**How**:
- Implements a POSIX-compatible syscall layer
- Has its own WindowServer (not X11 or Wayland)
- No Linux binary compatibility — everything is compiled natively

**DRM/GPU status**: Has basic VirtIO-GPU support using its own driver model. No DRM/KMS compatibility.

**Relevance**: ★★ — Shows how to build a display stack from scratch, but doesn't do Linux compatibility.

### 5.4 NetBSD Linux Emulation

**What**: Similar to FreeBSD's Linuxulator — runs Linux ELF binaries.

**How**: Syscall translation layer in kernel, similar approach to FreeBSD.

**DRM/GPU status**: NetBSD has ported some DRM drivers but the stack is less complete than FreeBSD's.

**Relevance**: ★★★ — Another reference for syscall translation, but less mature GPU support.

### 5.5 OpenBSD

**What**: Has its own DRM/KMS driver port (independent from FreeBSD's LinuxKPI approach).

**How**: They port individual GPU drivers with manual adaptation rather than a compatibility shim.

**DRM/GPU status**: Working Intel (i915), AMD (amdgpu) support. Runs X11 and Wayland.

**Relevance**: ★★★ — Shows that you can port DRM drivers without a full LinuxKPI, but it's more work per driver.

### 5.6 ReactOS

**What**: Windows NT-compatible OS (not Linux-compatible).

**How**: Implements Win32 syscalls and NT kernel APIs. Can run Windows GUI applications.

**Relevance**: ★ — Architectural reference only; wrong target API.

### 5.7 Redox OS

**What**: Microkernel-based OS written in Rust.

**How**: POSIX-like syscall interface, no Linux binary compatibility.

**DRM/GPU status**: Basic GPU drivers (VirtIO-GPU), no DRM/KMS compatibility.

**Relevance**: ★★ — Shows Rust-based OS architecture.

### Key Takeaway from Compatibility Projects

The **FreeBSD LinuxKPI + Linuxulator** approach is the gold standard for what you're trying to do:
1. **LinuxKPI** = kernel-internal API compatibility (so Linux GPU drivers compile and run on your kernel)
2. **Linuxulator** = userspace syscall compatibility (so Linux ELF binaries run unmodified)
3. Both are needed for a complete display stack

---

## 6. Minimum Viable Syscall Set

### Phase 0: Boot to Userspace (Pre-Display)

These are needed before ANY display work:

| # | Syscall | x86_64 # | Notes |
|---|---------|----------|-------|
| 1 | `read` | 0 | |
| 2 | `write` | 1 | |
| 3 | `openat` | 257 | |
| 4 | `close` | 3 | |
| 5 | `fstat` | 5 | |
| 6 | `lseek` | 8 | |
| 7 | `mmap` | 9 | |
| 8 | `mprotect` | 10 | |
| 9 | `munmap` | 11 | |
| 10 | `brk` | 12 | |
| 11 | `rt_sigaction` | 13 | |
| 12 | `rt_sigprocmask` | 14 | |
| 13 | `ioctl` | 16 | **THE most important syscall for DRM** |
| 14 | `access` / `faccessat` | 21/269 | |
| 15 | `pipe2` | 293 | |
| 16 | `clone` | 56 | |
| 17 | `execve` | 59 | |
| 18 | `exit` | 60 | |
| 19 | `wait4` | 61 | |
| 20 | `uname` | 63 | |
| 21 | `fcntl` | 72 | |
| 22 | `futex` | 202 | |
| 23 | `set_tid_address` | 218 | |
| 24 | `arch_prctl` | 158 | |
| 25 | `set_robust_list` | 273 | |
| 26 | `exit_group` | 231 | |
| 27 | `clock_gettime` | 228 | |

**Total Phase 0: ~27 syscalls**

### Phase 1: "Hello World" Wayland Client (Displays a Colored Rectangle)

A minimal Wayland client needs:
- Connect to compositor socket
- Create a shared memory buffer (via `memfd_create`)
- Send the buffer to the compositor via the Wayland protocol
- Compositing + display happens in the compositor

| # | Syscall | x86_64 # | Notes |
|---|---------|----------|-------|
| 28 | `socket` | 41 | AF_UNIX to connect to compositor |
| 29 | `connect` | 42 | Connect to `$XDG_RUNTIME_DIR/wayland-0` |
| 30 | `sendmsg` | 46 | Send Wayland protocol + FDs |
| 31 | `recvmsg` | 47 | Receive Wayland events |
| 32 | `memfd_create` | 319 | Create shared memory buffer |
| 33 | `ftruncate` | 77 | Size the memfd |
| 34 | `mmap` | 9 | (already counted) Map the memfd for pixel writing |
| 35 | `epoll_create1` | 291 | Event loop |
| 36 | `epoll_ctl` | 233 | Register wayland FD |
| 37 | `epoll_wait` | 232 | Wait for events |

**Additional Phase 1: ~10 new syscalls (37 total)**

But this assumes a compositor is ALREADY RUNNING. For the compositor:

### Phase 2: Minimal Wayland Compositor + DRM/KMS

**Syscalls the compositor adds:**

| # | Syscall | x86_64 # | Notes |
|---|---------|----------|-------|
| 38 | `bind` | 49 | Bind compositor socket |
| 39 | `listen` | 50 | Listen for clients |
| 40 | `accept4` | 288 | Accept client |
| 41 | `signalfd4` | 327 | Signal handling in event loop |
| 42 | `timerfd_create` | 283 | Frame timing |
| 43 | `timerfd_settime` | 286 | Set frame timer |
| 44 | `eventfd2` | 290 | Thread wakeup |
| 45 | `getpid` | 39 | |
| 46 | `getuid` | 102 | |
| 47 | `getgid` | 104 | |
| 48 | `prctl` | 157 | PR_SET_NAME etc. |
| 49 | `getrandom` | 318 | For Wayland protocol |

**Plus DRM ioctl commands (all via `ioctl` syscall #16):**

**Absolute minimum DRM ioctls for modesetting:**
1. `DRM_IOCTL_VERSION` (0x00)
2. `DRM_IOCTL_SET_VERSION` (0x07)
3. `DRM_IOCTL_GET_CAP` (0x0C)
4. `DRM_IOCTL_SET_CLIENT_CAP` (0x0D)
5. `DRM_IOCTL_SET_MASTER` (0x1E)
6. `DRM_IOCTL_MODE_GETRESOURCES` (0xA0)
7. `DRM_IOCTL_MODE_GETCRTC` (0xA1)
8. `DRM_IOCTL_MODE_SETCRTC` (0xA2)
9. `DRM_IOCTL_MODE_GETENCODER` (0xA6)
10. `DRM_IOCTL_MODE_GETCONNECTOR` (0xA7)
11. `DRM_IOCTL_MODE_ADDFB` (0xAE)
12. `DRM_IOCTL_MODE_PAGE_FLIP` (0xB0)
13. `DRM_IOCTL_MODE_CREATE_DUMB` (0xB2)
14. `DRM_IOCTL_MODE_MAP_DUMB` (0xB3)

**Additional for atomic modesetting (modern wlroots path):**
15. `DRM_IOCTL_MODE_GETPLANERESOURCES` (0xB5)
16. `DRM_IOCTL_MODE_GETPLANE` (0xB6)
17. `DRM_IOCTL_MODE_ADDFB2` (0xB8)
18. `DRM_IOCTL_MODE_ATOMIC` (0xBC)
19. `DRM_IOCTL_MODE_CREATEPROPBLOB` (0xBD)
20. `DRM_IOCTL_MODE_GETPROPERTY` (0xAA)

**Additional for DMA-BUF sharing (GPU acceleration):**
21. `DRM_IOCTL_PRIME_HANDLE_TO_FD` (0x2D)
22. `DRM_IOCTL_PRIME_FD_TO_HANDLE` (0x2E)
23. `DRM_IOCTL_GEM_CLOSE` (0x09)

**Additional Phase 2: ~12 new syscalls (49 total) + 14-23 DRM ioctl commands**

### Phase 3: Input (Keyboard/Mouse/Touch)

| # | Syscall | x86_64 # | Notes |
|---|---------|----------|-------|
| 50 | (same `ioctl` #16) | 16 | evdev ioctls for /dev/input/eventX |
| 51 | `read` | 0 | (already counted) Read input events |

**evdev ioctls needed:**
- `EVIOCGBIT` — query supported event types
- `EVIOCGNAME` — get device name
- `EVIOCGID` — get device ID
- `EVIOCGRAB` — exclusive grab

**Additional Phase 3: ~0 new syscalls, ~4 new ioctl commands**

### Phase 4: KDE Plasma / Full Desktop

| # | Syscall | x86_64 # | Notes |
|---|---------|----------|-------|
| 52 | `inotify_init1` | 294 | File watching |
| 53 | `inotify_add_watch` | 254 | Add watch |
| 54 | `inotify_rm_watch` | 255 | Remove watch |
| 55 | `statx` | 332 | Extended stat |
| 56 | `newfstatat` | 262 | Stat at dir |
| 57 | `mkdirat` | 258 | Create dirs |
| 58 | `unlinkat` | 263 | Delete files |
| 59 | `renameat2` | 316 | Rename files |
| 60 | `readlinkat` | 267 | Read symlinks |
| 61 | `geteuid` | 107 | Effective UID |
| 62 | `getcwd` | 79 | Working directory |
| 63 | `dup3` | 292 | Duplicate FD |
| 64 | `sched_getaffinity` | 204 | CPU affinity |
| 65 | `sched_setaffinity` | 203 | CPU affinity |
| 66 | `madvise` | 28 | Memory advice |
| 67 | `sysinfo` | 99 | System info |

**Additional Phase 4: ~16 new syscalls (65+ total)**

---

## Summary: Minimum Viable Path

### "Hello World" Wayland Client → Screen

```
┌─────────────────────────────────────────────────────────┐
│ MINIMUM TO GET A PIXEL ON SCREEN                        │
│                                                         │
│ Syscalls needed: 49                                     │
│ DRM ioctl commands: 14 (legacy) or 20 (atomic)         │
│ evdev ioctl commands: 4                                 │
│                                                         │
│ Key insight: ioctl is the multiplexer for ALL DRM +     │
│ input operations. You need ONE syscall (ioctl) to       │
│ handle hundreds of sub-commands.                        │
│                                                         │
│ Architecture choice:                                    │
│   Option A: Implement Linux syscall ABI                 │
│     → Run unmodified Linux Wayland binaries             │
│     → Need ~49 syscalls + DRM ioctls                    │
│     → Need /dev/dri/* and /dev/input/* filesystems      │
│                                                         │
│   Option B: Implement kernel-internal API compat        │
│     → Port Linux DRM drivers to your kernel             │
│     → Like FreeBSD's LinuxKPI approach                  │
│     → Then implement Linuxulator for userspace          │
│                                                         │
│   Option C: Both (recommended, like FreeBSD)            │
│     → LinuxKPI to reuse Linux GPU drivers               │
│     → Linuxulator to run Linux Wayland binaries         │
│     → Most work, but most compatible                    │
└─────────────────────────────────────────────────────────┘
```

### Priority-Ordered Syscall Implementation List

```
TIER 0 — ABSOLUTELY REQUIRED (27 syscalls):
  read, write, openat, close, fstat, lseek, mmap, mprotect,
  munmap, brk, rt_sigaction, rt_sigprocmask, ioctl, faccessat,
  pipe2, clone, execve, exit, wait4, uname, fcntl, futex,
  set_tid_address, arch_prctl, set_robust_list, exit_group,
  clock_gettime

TIER 1 — WAYLAND COMPOSITOR (12 more = 39 total):
  socket, connect, bind, listen, accept4, sendmsg, recvmsg,
  memfd_create, ftruncate, epoll_create1, epoll_ctl, epoll_wait

TIER 2 — COMPOSITOR OPERATIONAL (10 more = 49 total):
  signalfd4, timerfd_create, timerfd_settime, eventfd2,
  getpid, getuid, getgid, prctl, getrandom, socketpair

TIER 3 — KDE/Qt DESKTOP (16 more = 65 total):
  inotify_init1, inotify_add_watch, inotify_rm_watch,
  statx, newfstatat, mkdirat, unlinkat, renameat2,
  readlinkat, geteuid, getcwd, dup3, madvise,
  sched_getaffinity, sched_setaffinity, sysinfo

TIER 4 — FULL DESKTOP COMFORT (20+ more):
  nanosleep, clock_nanosleep, pread64, pwrite64, readv,
  writev, sendto, recvfrom, shutdown, getsockname,
  getsockopt, setsockopt, setsid, setpgid, gettid,
  getgroups, getegid, chdir, umask, sched_setscheduler
```

### DRM ioctl Priority Implementation List

```
TIER 0 — MINIMUM MODESETTING (14 ioctls):
  DRM_IOCTL_VERSION (0x00)
  DRM_IOCTL_SET_VERSION (0x07)
  DRM_IOCTL_GET_CAP (0x0C)
  DRM_IOCTL_SET_CLIENT_CAP (0x0D)
  DRM_IOCTL_SET_MASTER (0x1E)
  DRM_IOCTL_MODE_GETRESOURCES (0xA0)
  DRM_IOCTL_MODE_GETCRTC (0xA1)
  DRM_IOCTL_MODE_SETCRTC (0xA2)
  DRM_IOCTL_MODE_GETENCODER (0xA6)
  DRM_IOCTL_MODE_GETCONNECTOR (0xA7)
  DRM_IOCTL_MODE_ADDFB (0xAE)
  DRM_IOCTL_MODE_PAGE_FLIP (0xB0)
  DRM_IOCTL_MODE_CREATE_DUMB (0xB2)
  DRM_IOCTL_MODE_MAP_DUMB (0xB3)

TIER 1 — ATOMIC + DMA-BUF (9 more = 23 total):
  DRM_IOCTL_GEM_CLOSE (0x09)
  DRM_IOCTL_PRIME_HANDLE_TO_FD (0x2D)
  DRM_IOCTL_PRIME_FD_TO_HANDLE (0x2E)
  DRM_IOCTL_MODE_GETPROPERTY (0xAA)
  DRM_IOCTL_MODE_GETPLANERESOURCES (0xB5)
  DRM_IOCTL_MODE_GETPLANE (0xB6)
  DRM_IOCTL_MODE_ADDFB2 (0xB8)
  DRM_IOCTL_MODE_ATOMIC (0xBC)
  DRM_IOCTL_MODE_CREATEPROPBLOB (0xBD)

TIER 2 — CURSOR/CLEANUP (6 more):
  DRM_IOCTL_DROP_MASTER (0x1F)
  DRM_IOCTL_MODE_RMFB (0xAF)
  DRM_IOCTL_MODE_DESTROY_DUMB (0xB4)
  DRM_IOCTL_MODE_CURSOR2 (0xBB)
  DRM_IOCTL_MODE_DESTROYPROPBLOB (0xBE)
  DRM_IOCTL_MODE_SETPLANE (0xB7)
```

### Critical Kernel Subsystems Beyond Syscalls

Implementing the syscalls alone isn't enough. Your kernel also needs:

1. **Device filesystem** (`devtmpfs`): Must populate `/dev/dri/card0`, `/dev/dri/renderD128`, `/dev/input/eventX`
2. **TTY/VT subsystem**: For console switching (KD_GRAPHICS mode, VT_SETMODE)
3. **epoll subsystem**: Central to every Wayland compositor's event loop
4. **signalfd/timerfd**: Core to compositor event handling
5. **memfd_create**: Shared memory for Wayland buffer transport
6. **DMA-BUF framework**: Buffer sharing between processes/GPU
7. **mmap with DRM offset**: `DRM_IOCTL_MODE_MAP_DUMB` returns an offset for `mmap(offset=...)` on the DRM fd
8. **Unix domain sockets**: Wayland protocol transport
9. **SCM_RIGHTS**: Passing file descriptors over Unix sockets (for DMA-BUF sharing between compositor and clients)

### The "Cheat Code" Approach

If you want the absolute fastest path to pixels:

1. **Implement the 27 Tier-0 syscalls** (basic POSIX process)
2. **Implement ioctl** with DRM command multiplexing
3. **Implement epoll** (event loop backbone)
4. **Write a simple DRM backend** that:
   - Opens `/dev/dri/card0`
   - Does legacy modesetting (14 DRM ioctls)
   - Creates a dumb buffer, maps it, writes pixels
   - Calls `DRM_IOCTL_MODE_SETCRTC` to display
5. **Skip Wayland entirely** at first — just write raw pixels to the framebuffer via DRM dumb buffers
6. **Then add** the socket/epoll/memfd_create infrastructure for Wayland

This gives you "Hello World on screen" with approximately **30 syscalls and 14 DRM ioctls**.
