r"""侦查③：dump setWindowTitle 调用点引用的字符串常量，判断标题里有没有文件名。

对 11 个 setWindowTitle 调用点，向前扫 0x60 字节，反汇编，
收集所有 `lea r64, [rip+disp]`，算出目标 RVA，dump 该处的 ASCII/UTF-16 内容。
输出 probe_title_str.log
"""
from pathlib import Path
import struct, os, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_INS_LEA

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = os.path.join(BASE, "build", "UNISUnzip.exe")
OUT = os.path.join(BASE, "probe_title_str.log")
LOG = []


def w(s=""):
    LOG.append(str(s))


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


raw = open(TARGET, "rb").read()
E_LFANEW = u32(raw, 0x3C)
OPT = E_LFANEW + 24
NSEC = u16(raw, E_LFANEW + 6)
SECOFF = OPT + u16(raw, E_LFANEW + 20)
DD = OPT + 112
IMAGE_BASE = u64(raw, OPT + 24)

SECS = []
for i in range(NSEC):
    s = SECOFF + i * 40
    SECS.append((raw[s:s + 8].rstrip(b"\x00").decode("latin-1"),
                 u32(raw, s + 12), u32(raw, s + 8), u32(raw, s + 20), u32(raw, s + 16)))


def rva2off(rva):
    for nm, va, vs, pr, rs in SECS:
        if va <= rva < va + max(vs, rs):
            return pr + (rva - va)
    return None


def sec_of(rva):
    for nm, va, vs, pr, rs in SECS:
        if va <= rva < va + max(vs, rs):
            return nm
    return "?"


def cstr(off, limit=160):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


IMP_OFF = rva2off(u32(raw, DD + 8))
slots = {}
i = 0
while True:
    d = IMP_OFF + i * 20
    oft, namerva, ft = u32(raw, d), u32(raw, d + 12), u32(raw, d + 16)
    if oft == 0 and namerva == 0 and ft == 0:
        break
    noff = rva2off(namerva)
    dll = cstr(noff) if noff else "?"
    toff = rva2off(oft or ft)
    if toff:
        j = 0
        while True:
            t = u64(raw, toff + j * 8)
            if t == 0:
                break
            if not (t >> 63):
                fo = rva2off(t & 0xFFFFFFFF)
                if fo:
                    slots[(dll, cstr(fo + 2))] = ft + j * 8
            j += 1
            if j > 5000:
                break
    i += 1
    if i > 200:
        break

SLOT_WT = slots[("Qt5Widgets.dll", "?setWindowTitle@QWidget@@QEAAXAEBVQString@@@Z")]

text = next(s for s in SECS if s[0] == ".text")
t_nm, t_va, t_vs, t_pr, t_rs = text
body = raw[t_pr:t_pr + t_rs]
t_end = t_va + t_rs

calls = []
p = 0
while True:
    k = body.find(b"\xff\x15", p)
    if k < 0:
        break
    disp = struct.unpack_from("<i", body, k + 2)[0]
    if (t_va + k + 6 + disp) == SLOT_WT:
        calls.append(t_va + k)
    p = k + 1

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

w("=" * 74)
w("setWindowTitle 调用点引用的字符串常量（共 %d 处调用）" % len(calls))
w("=" * 74)

seen_global = {}
for cva in calls:
    w("")
    w("---- 调用点 RVA %#x ----" % cva)
    start = max(t_va, cva - 0x60)
    so = rva2off(start)
    code = raw[so:so + (cva - start) + 8]
    for ins in md.disasm(code, start):
        if ins.id == X86_INS_LEA and ins.operands and ins.operands[1].type == X86_OP_MEM \
                and ins.operands[1].mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + ins.operands[1].mem.disp
            o = rva2off(tgt)
            nm = ins.operands[0].reg
            regname = ins.reg_name(nm) if nm else "?"
            if o is None:
                w("   %#08x  lea %-4s -> %#x  [越界]" % (ins.address, regname, tgt))
                continue
            sec = sec_of(tgt)
            s_ascii = cstr(o, 120)
            s_wide = ""
            if len(s_ascii) >= 3 and all(32 <= ord(c) < 127 for c in s_ascii[:8]):
                pass
            raw16 = raw[o:o + 240]
            try:
                s_wide = raw16.decode("utf-16-le", "ignore")
                s_wide = s_wide.split("\x00")[0]
            except Exception:
                s_wide = ""
            if all(31 < ord(c) < 127 for c in s_wide[:12]) and len(s_wide) > 3:
                shown = "WIDE: %s" % s_wide[:100]
            else:
                shown = "ASCII: %s" % s_ascii[:100]
            w("   %#08x  lea %-4s -> %#08x (%-8s) %s" % (ins.address, regname, tgt, sec, shown))
            seen_global.setdefault(tgt, []).append(shown)

w("")
w("=" * 74)
w("去重后的候选字符串常量")
w("=" * 74)
for tgt in sorted(seen_global):
    w("  %#08x  %s" % (tgt, seen_global[tgt][0][:120]))

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
