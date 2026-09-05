#!/usr/bin/env python3
"""extract-gs-shaders.py — SPIR-V модули из бинарника gamescope (glslang 0x8000b).
CDD #12 p4: vkprobe2 компилирует РЕАЛЬНЫЕ шейдеры gamescope (host-side ground
truth для lvp pipeline-пути). Извлечённые модули → gs_shaders.h (GS_VS/GS_FS)."""
import struct, sys

data = open(sys.argv[1] if len(sys.argv) > 1 else "cachyos-root/root/usr/bin/gamescope", "rb").read()
magic = struct.pack("<I", 0x07230203)
offs, i = [], 0
while True:
    i = data.find(magic, i)
    if i < 0:
        break
    offs.append(i)
    i += 4
offs.append(len(data))
print(f"{len(offs)-1} embedded SPIR-V modules")
with open("scripts/gs_shaders.h", "w") as f:
    f.write("// gamescope embedded shaders (extracted, glslang generator 0x8000b)\n#include <stdint.h>\n")
    for j, (a, b) in enumerate(zip(offs, offs[1:])):
        blob = data[a:b]
        if len(blob) > 400000:
            continue
        words = len(blob) // 4
        f.write(f"static const uint32_t GS_SH{j}[{words}] = {{\n")
        ws = struct.unpack(f"<{words}I", blob[: words * 4])
        for k in range(0, words, 8):
            f.write("    " + ",".join(f"0x{w:08x}" for w in ws[k : k + 8]) + ",\n")
        f.write("};\n")
print("written scripts/gs_shaders.h")
