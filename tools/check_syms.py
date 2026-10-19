# -*- coding: utf-8 -*-
# 校验补丁里硬编码的那些 GetProcAddress 名字，在真实 DLL 导出表里到底存不存在
from pathlib import Path
import os, struct

ROOT = str(Path(__file__).resolve().parent)
OUT = os.path.join(ROOT, "check_syms.log")
L = []


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def exports(path):
    b = open(path, "rb").read()
    pe = u32(b, 0x3C)
    opt = pe + 24
    magic = u16(b, opt)
    nsec = u16(b, pe + 6)
    ddir = opt + (112 if magic == 0x20B else 96)
    exp_rva = u32(b, ddir + 0)
    exp_size = u32(b, ddir + 4)
    sec_off = pe + 24 + u16(b, pe + 20)
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        secs.append((u32(b, o + 12), u32(b, o + 8), u32(b, o + 20)))

    def r2o(rva):
        for va, vs, pr in secs:
            if va <= rva < va + max(vs, 0x1000):
                return pr + (rva - va)
        return None

    if exp_rva == 0:
        return None, b
    eo = r2o(exp_rva)
    n_names = u32(b, eo + 24)
    names_rva = u32(b, eo + 32)
    no = r2o(names_rva)
    out = []
    for i in range(n_names):
        nr = u32(b, no + i * 4)
        p = r2o(nr)
        out.append(b[p:b.index(b"\x00", p)].decode("latin1"))
    return out, b


WANT = [
    "?utf16@QString@@QEBAPEBGXZ",
]

targets = [
    (str(Path(__file__).resolve().parent / "UNISUnzip_patched" / "Qt5Core.dll"), "Qt5Core.dll"),
    (r"C:\Windows\System32\kernel32.dll", "kernel32.dll"),
]

for path, label in targets:
    L.append("=" * 60)
    L.append("[%s] %s" % (label, path))
    if not os.path.exists(path):
        L.append("  MISSING")
        continue
    exps, _ = exports(path)
    if exps is None:
        L.append("  无导出表")
        continue
    L.append("  导出总数: %d" % len(exps))
    for w in WANT:
        L.append("  EXACT  %-40s -> %s" % (w, "存在" if w in exps else "**不存在**"))
    for kw in ("utf16", "constData", "unicode"):
        hits = [e for e in exps if kw in e]
        L.append("  含 %-10s 的导出 (%d):" % (kw, len(hits)))
        for h in hits[:2]:
            L.append("      " + h)

# kernel32 关键名字
exps32, _ = exports(r"C:\Windows\System32\kernel32.dll")
if exps32:
    L.append("=" * 60)
    L.append("[kernel32 关键导出]")
    for w in ("CreateFileW", "WriteFile", "CloseHandle", "GetTempPathW"):
        L.append("  %-16s -> %s" % (w, "存在" if w in exps32 else "**不存在**"))

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("ok")
