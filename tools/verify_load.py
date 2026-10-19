# -*- coding: utf-8 -*-
# 静态验证：模拟 Windows 加载器的 DLL 搜索，做传递闭包，找出任何缺失依赖
from pathlib import Path
import os, struct, sys

ROOT = str(Path(__file__).resolve().parent)
TARGET = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "UNISUnzip.exe")
OUT = os.path.join(ROOT, "verify_load.log")


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def import_dlls(path):
    try:
        b = open(path, "rb").read()
        e_lfanew = _u32(b, 0x3C)
        if b[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        opt = e_lfanew + 24
        magic = _u16(b, opt)
        nsec = _u16(b, e_lfanew + 6)
        ddir = opt + (112 if magic == 0x20B else 96)
        imp_rva = _u32(b, ddir + 8)
        if imp_rva == 0:
            return []
        sec_off = e_lfanew + 24 + _u16(b, e_lfanew + 20)
        secs = []
        for i in range(nsec):
            o = sec_off + i * 40
            name = b[o:o + 8].rstrip(b"\x00").decode("latin1")
            vsize = _u32(b, o + 8)
            vaddr = _u32(b, o + 12)
            praw = _u32(b, o + 20)
            secs.append((name, vaddr, vsize, praw))

        def rva2off(rva):
            for _, va, vs, pr in secs:
                if va <= rva < va + max(vs, 0x1000):
                    return pr + (rva - va)
            return None

        off = rva2off(imp_rva)
        if off is None:
            return []
        res = []
        while True:
            oft = _u32(b, off)
            name_rva = _u32(b, off + 12)
            if oft == 0 and name_rva == 0:
                break
            no = rva2off(name_rva)
            if no is None:
                break
            nm = b[no:b.index(b"\x00", no)].decode("latin1")
            res.append(nm)
            off += 20
        return res
    except Exception as e:
        return ["<PARSE_ERROR:%s>" % e]


sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
windir = os.environ.get("SystemRoot", r"C:\Windows")
search_dirs = [
    os.path.dirname(os.path.abspath(TARGET)),
    sysdir,
    windir,
]
for pe in os.environ.get("PATH", "").split(os.pathsep):
    pe = pe.strip()
    if pe and os.path.isdir(pe):
        search_dirs.append(pe)

seen = set()
missing = []
resolved = {}
queue = [os.path.basename(TARGET)]
start = os.path.abspath(TARGET)
resolved[queue[0].lower()] = start
files_to_scan = [start]

while files_to_scan:
    cur = files_to_scan.pop()
    for dll in (import_dlls(cur) or []):
        key = dll.lower()
        if key in seen:
            continue
        seen.add(key)
        free = dll.lower()
        # API Set / Extension 虚拟 DLL：由 Windows API Set Schema 解析，磁盘上无实体文件
        if free.startswith("api-ms-") or free.startswith("ext-ms-"):
            resolved[key] = "(API Set 虚拟DLL，由内核解析)"
            continue
        found = None
        for d in search_dirs:
            cand = os.path.join(d, dll)
            if os.path.exists(cand):
                found = cand
                break
        if found:
            resolved[key] = found
            files_to_scan.append(found)
        else:
            missing.append((dll, os.path.basename(cur)))

lines = []
lines.append("TARGET: " + start)
lines.append("search_dirs:")
for d in search_dirs:
    lines.append("  " + d)
lines.append("")
lines.append("direct imports: %d" % len(import_dlls(start) or []))
lines.append("")
lines.append("resolved transitively: %d" % len(resolved))
for k in sorted(resolved):
    lines.append("  OK   %-40s <- %s" % (k, resolved[k]))
lines.append("")
if missing:
    lines.append("!!! MISSING (%d):" % len(missing))
    for d, owner in missing:
        lines.append("  MISS %s   (needed by %s)" % (d, owner))
    lines.append("RESULT: FAIL")
else:
    lines.append("RESULT: PASS - all transitive dependencies resolvable")
open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("ok")
