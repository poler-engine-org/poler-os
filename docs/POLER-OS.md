# POLER-OS — Permanent Instructions

## READ THIS FIRST in every session. This file is the source of truth.

## PROJECT
- OS: POLER-OS — custom kernel with POLER v8 cryptography
- Language: Zig 0.13.0 (kernel), C (LKM port)
- Target: x86_64 freestanding, GRUB Multiboot2
- GitHub: Kotokvit/poler-os
- Architecture: Linux-compatible kernel (syscall subset + DRM/KMS)

## GIT RULES — CRITICAL
- NEVER use `git push --force`
- ALWAYS `git pull` before `git push`
- ALWAYS `git add <specific_file>` — NEVER `git add .` or `git add -A`
- ALWAYS check `git diff --stat` before commit
- ALWAYS check `git status` before any git operation
- If conflict: `git pull --rebase origin main`, resolve, then push
- NEVER delete folders. If something needs removal, delete specific files only

## ARCHITECTURE DECISIONS
1. Kernel implements Linux syscall subset for running unmodified Linux ELF binaries
2. DRM/KMS (14 ioctls) replaces custom framebuffer rendering
3. 5-phase roadmap: Phase 1 (27 syscalls ELF), Phase 2 (14 DRM ioctls),
   Phase 3 (12 Wayland syscalls), Phase 4 (10 input syscalls), Phase 5 (16+ KDE syscalls)
4. POLER v8 crypto: block cipher (128-bit, 256-bit key, 20 Feistel rounds) + RSA-OAEP
5. NixOS-inspired composition: programs are guests, not hosts

## CURRENT STATE
- Kernel boots in QEMU via GRUB, framebuffer works
- POLER v8 crypto ported to C as Linux Kernel Module (9/9 tests pass)
- LKM source: linux-arch-experiment/poler-lkm/
- RSA-OAEP port to C: PENDING
- Phase 1 syscalls: PENDING
- Arch Linux custom kernel experiment: PENDING

## KEY FILES
- zig-kernel/src64/poler_core.zig — POLER v8 block cipher (1882 lines)
- zig-kernel/src64/rsa_oaep.zig — RSA-OAEP + cascade (2982 lines)
- zig-kernel/src64/framebuffer.zig — Graphene/Thymos pattern driver
- zig-kernel/src64/main64.zig — kernel entry point
- linux-arch-experiment/poler-lkm/poler_core.h — C port of POLER cipher
- linux-arch-experiment/poler-lkm/poler_lkm.c — LKM with /dev/poler
- docs/ARCHITECTURE-v2-LinuxCompat.md — Linux compat architecture doc

## DO NOT
- Do NOT add emojis unless user explicitly asks
- Do NOT use force push
- Do NOT add files with git add -A
- Do NOT overwrite remote state
- Do NOT add artificial ending markers to documents
- Do NOT build web pages when user asks for documents

## COMMUNICATION STYLE
- User speaks Ukrainian/Russian — respond in same language
- Be direct. No fluff, no apologies, no moralizing
- If something is broken — say it's broken, explain why, fix it
- If uncertain — ask, don't assume
