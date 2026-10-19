# -*- coding: utf-8 -*-
r"""静态数据流：被改写的调用点返回后，调用方是否会读到 RDI/RSI（非易失寄存器）。
若会，则 caveB 破坏 RDI/RSI 的行为必然导致调用方使用垃圾指针 -> 闪退。
"""
from pathlib import Path
import os, struct

ROOT = str(Path(__file__).resolve().parent)
SRC = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(ROOT, "callsite_flow.log")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import sys, traceback as _tb
def _ex(t, v, tb):
    open(os.path.join(ROOT, "callsite_flow_err.log"), "w", encoding="utf-8").write(
        "".join(_tb.format_exception(t, v, tb)))
sys.excepthook = _ex

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

b = open(SRC, "rb").read()
pe = u32(b, 0x3C)
opt = pe + 24
nsec = u16(b, pe + 6)
sec_off = pe + 24 + u16(b, pe + 20)
secs = []
for i in range(nsec):
    o = sec_off + i * 40
    secs.append((b[o:o + 8].rstrip(b"\x00").decode("latin1"), u32(b, o + 12), u32(b, o + 8), u32(b, o + 20)))
text = [s for s in secs if s[0] == ".text"][0]
tva, trs, tro = text[1], text[2], text[3]
code = b[tro:tro + trs]

SETECHO_IAT = 0x27240
SETTEXT_IAT = 0x27010

sites = []
p = 0
while p < len(code) - 6:
    if code[p] == 0xFF and code[p + 1] == 0x15:
        disp = struct.unpack_from("<i", code, p + 2)[0]
        call_rva = tva + p
        tgt = call_rva + 6 + disp
        if tgt in (SETECHO_IAT, SETTEXT_IAT):
            sites.append((call_rva, "setEchoMode" if tgt == SETECHO_IAT else "setText"))
    p += 1

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
insns = list(md.disasm(code, tva))
by_addr = {i.address: k for k, i in enumerate(insns)}


def fam(nm):
    if nm in ("rdi", "edi", "di", "dil"): return "RDI"
    if nm in ("rsi", "esi", "si", "sil"): return "RSI"
    return None


L = []
L.append("被改写的调用点: %d 个（setEchoMode 1 / setText 10 预期）" % len(sites))
L.append("")
risky = 0
for addr, kind in sites:
    k = by_addr.get(addr)
    if k is None:
        L.append("  rva 0x%x  %s  <反汇编未对齐，跳过>" % (addr, kind))
        continue
    hit = {}
    for j in range(k + 1, min(k + 40, len(insns))):
        ins = insns[j]
        reads, writes = ins.regs_access()
        rn = {fam(md.reg_name(r)) for r in reads}
        wn = {fam(md.reg_name(w)) for w in writes}
        rn.discard(None); wn.discard(None)
        for reg in ("RDI", "RSI"):
            if reg in rn and reg not in wn and reg not in hit:
                hit[reg] = "%s %s" % (ins.mnemonic, ins.op_str)
        if len(hit) == 2:
            break
    if hit:
        risky += 1
    L.append("  rva 0x%-6x %-11s 返回后读取: %s" % (
        addr, kind,
        (", ".join("%s(在 '%s')" % (r, v) for r, v in hit.items()) if hit else "无（该点安全）")))

L.append("")
L.append("结论: %d / %d 个调用点在返回后会读取 RDI/RSI" % (risky, len(sites)))
L.append("=> caveB 不保存 RDI/RSI 会直接破坏这些调用方的变量。" if risky else "=> 未发现读后使用，需另找闪退原因")

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("ok")
