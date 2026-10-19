r"""侦查④：在**未打补丁的原版**上分析 QLineEdit::setText 的 10 个调用点，
看每个调用点的 QString 参数是从哪来的（是不是 QFileInfo::fileName / absoluteFilePath 等）。

用原版的原因：原版 IAT 调用点仍是 FF 15，可以完整反查；补丁版已被改成 E8。
输出 probe_settext_src.log
"""
from pathlib import Path
import struct, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_INS_LEA, X86_INS_CALL

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(BASE, "probe_settext_src.log")
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


def cstr(off, limit=140):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


IMP_OFF = rva2off(u32(raw, DD + 8))
slots = {}
rva2name = {}
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
                    nm = cstr(fo + 2)
                    slots[(dll, nm)] = ft + j * 8
                    rva2name[ft + j * 8] = "%s!%s" % (dll.replace(".dll", ""), nm)
            j += 1
            if j > 5000:
                break
    i += 1
    if i > 200:
        break

text = next(s for s in SECS if s[0] == ".text")
_, t_va, t_vs, t_pr, t_rs = text
body = raw[t_pr:t_pr + t_rs]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

PROBE = ["setText@QLineEdit", "fileName@QFileInfo", "absolutePath@QDir",
         "absoluteFilePath@QDir", "completeBaseName@QFileInfo", "baseName@QFileInfo"]
w("=" * 74)
w("原版 %s" % os.path.basename(TARGET))
w("=" * 74)
for p in PROBE:
    for (dll, nm), rva in slots.items():
        if p in nm:
            w("  %-28s %s!%s  IAT=%#x" % (p, dll, nm[:60], rva))

SLOT_SETA = None
for (dll, nm), rva in slots.items():
    if nm == "?setText@QLineEdit@@QEAAXAEBVQString@@@Z":
        SLOT_SETA = rva
if SLOT_SETA is None:
    w("setText 槽未找到")
    open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
    raise SystemExit

calls = []
p = 0
while True:
    k = body.find(b"\xff\x15", p)
    if k < 0:
        break
    disp = struct.unpack_from("<i", body, k + 2)[0]
    if (t_va + k + 6 + disp) == SLOT_SETA:
        calls.append(t_va + k)
    p = k + 1

w("")
w("setText 调用点：%d 处" % len(calls))
for cva in calls:
    w("")
    w("---- setText 调用点 RVA %#x ----" % cva)
    start = max(t_va, cva - 0x70)
    so = rva2off(start)
    insns = list(md.disasm(raw[so:so + (cva - start) + 8], start))
    for ins in insns:
        mark = ""
        if ins.address == cva:
            mark = "   <<< setText"
        note = ""
        if ins.id == X86_INS_LEA and ins.operands and ins.operands[1].type == X86_OP_MEM \
                and ins.operands[1].mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + ins.operands[1].mem.disp
            o = rva2off(tgt)
            sec = sec_of(tgt)
            s = cstr(o, 90) if o is not None else ""
            if sec == ".rdata" and len(s) >= 3:
                note = "   ; %s" % s
            else:
                note = "   ; ->%#x(%s)" % (tgt, sec)
        if ins.id == X86_INS_CALL and ins.operands and ins.operands[0].type == X86_OP_MEM \
                and ins.operands[0].mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + ins.operands[0].mem.disp
            fn = rva2name.get(tgt)
            if fn and "QString" in fn or (fn and "QFileInfo" in fn) or (fn and "QDir" in fn):
                note = "   <<== %s" % fn[:70]
            elif fn:
                note = "   ; %s" % fn[:70]
        w("   %#08x  %-22s %-28s%s%s" % (ins.address,
                                         " ".join("%02x" % x for x in ins.bytes[:8]),
                                         ins.mnemonic + " " + ins.op_str, note, mark))

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
