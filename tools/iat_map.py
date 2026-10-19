# -*- coding: utf-8 -*-
# 把 exe 导入表里每个 IAT 槽的 RVA 映射到 "DLL!函数名"，核对补丁硬编码的 6 个常量
from pathlib import Path
import os, struct

ROOT = str(Path(__file__).resolve().parent)
SRC = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(ROOT, "iat_map.log")


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


b = open(SRC, "rb").read()
pe = u32(b, 0x3C)
opt = pe + 24
magic = u16(b, opt)
nsec = u16(b, pe + 6)
ddir = opt + (112 if magic == 0x20B else 96)
imp_rva = u32(b, ddir + 8)
sec_off = pe + 24 + u16(b, pe + 20)
secs = []
for i in range(nsec):
    o = sec_off + i * 40
    secs.append((b[o:o + 8].rstrip(b"\x00").decode("latin1"), u32(b, o + 12), u32(b, o + 8), u32(b, o + 20)))


def r2o(rva):
    for _, va, vs, pr in secs:
        if va <= rva < va + max(vs, 0x1000):
            return pr + (rva - va)
    return None


L = []
slotmap = {}          # iat_rva -> "dll!func"
o = r2o(imp_rva)
while True:
    oft = u32(b, o + 0)
    name_rva = u32(b, o + 12)
    ft = u32(b, o + 16)
    if oft == 0 and name_rva == 0 and ft == 0:
        break
    no = r2o(name_rva)
    dll = b[no:b.index(b"\x00", no)].decode("latin1") if no else "?"
    thunk = r2o(oft if oft else ft)
    i = 0
    while True:
        ent = u64(b, thunk + i * 8)
        if ent == 0:
            break
        if ent & (1 << 63):
            hint = ent & 0xFFFF
            nm = "<ordinal %d>" % hint
        else:
            np = r2o(ent & 0x7FFFFFFF)
            nm = b[np + 2:b.index(b"\x00", np + 2)].decode("latin1")
        slotmap[ft + i * 8] = "%s!%s" % (dll, nm)
        i += 1
    o += 20

L.append("导入表槽位总数: %d" % len(slotmap))
L.append("")
WANT = {
    0x27240: "?setEchoMode@QLineEdit@@QEAAXW4EchoMode@1@@Z  (Qt5Widgets)",
    0x27010: "?setText@QLineEdit@@QEAAXAEBVQString@@@Z      (Qt5Widgets)",
    0x26080: "GetModuleHandleW                             (kernel32)",
    0x260c0: "GetProcAddress                              (kernel32)",
    0x260b0: "WideCharToMultiByte                         (kernel32)",
    0x26010: "GetSystemTimeAsFileTime                     (kernel32)",
}
L.append("=== 补丁硬编码的 IAT 槽 核对 ===")
for rva, expect in WANT.items():
    got = slotmap.get(rva)
    ok = "??"
    if got:
        fn = got.split("!", 1)[1]
        ok = "OK " if expect.split()[0] == fn else "**不匹配**"
    else:
        ok = "**槽位不存在**"
    L.append("  0x%-6x %s  实际=%s   期望=%s" % (rva, ok, got, expect))
L.append("")
L.append("=== 该 exe 是否导入下述函数（供排查）===")
for kw in ("GetModuleHandleW", "GetProcAddress", "WideCharToMultiByte",
           "GetSystemTimeAsFileTime", "GetTempPathW", "CreateFileW", "WriteFile", "CloseHandle"):
    hits = [k for k, v in slotmap.items() if v.endswith("!" + kw)]
    L.append("  %-26s -> %s" % (kw, ["0x%x  %s" % (h, slotmap[h]) for h in hits] or "未导入"))

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("ok")
