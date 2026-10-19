# -*- coding: utf-8 -*-
"""静态校验 v2 补丁产物：PE 结构、调用点重定向、区段内容、反汇编。"""
from pathlib import Path
import struct, os, sys

BASE = str(Path(__file__).resolve().parent)
PATCHED = os.path.join(BASE, "build", "UNISUnzip.exe")
ORIG = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(BASE, "verify_v2.log")

sys.path.insert(0, BASE)
import patch_unis_v2 as V2

IMAGE_BASE = 0x140000000
SEC_VOFF = V2.SEC_VOFF
SEC_SIZE = V2.SEC_SIZE

L = []
def w(m):
    L.append(str(m))
    open(OUT, "w", encoding="utf-8").write("\n".join(L))

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

def parse(path):
    raw = open(path,'rb').read()
    pe = u32(raw,0x3c); opt = pe+24
    ns = u16(raw,pe+6); so = opt+u16(raw,pe+20)
    secs=[]
    for i in range(ns):
        o=so+i*40
        secs.append(dict(name=raw[o:o+8].split(b'\x00')[0].decode('latin1'),
                         vs=u32(raw,o+8), va=u32(raw,o+12),
                         rs=u32(raw,o+16), ro=u32(raw,o+20), ch=u32(raw,o+36)))
    return raw, pe, opt, ns, so, secs

def r2o(raw, secs, rva):
    for s in secs:
        if s['va'] <= rva < s['va']+max(s['vs'], s['rs']):
            return s['ro'] + (rva - s['va'])
    return None

# ---------------- A. 结构比对 ----------------
raw0, pe0, opt0, ns0, so0, secs0 = parse(ORIG)
raw1, pe1, opt1, ns1, so1, secs1 = parse(PATCHED)
w("[A] PE structure")
w("    sections  : %d -> %d  (expect %d -> %d)" % (ns0, ns1, ns0, ns0+1))
w("    SizeOfImage: 0x%x -> 0x%x (expect 0x%x)" % (u32(raw0,opt0+56), u32(raw1,opt1+56), SEC_VOFF+SEC_SIZE))
w("    entry     : 0x%x -> 0x%x" % (u32(raw0,opt0+16), u32(raw1,opt1+16)))
w("    DllChar   : 0x%04x -> 0x%04x" % (u16(raw0,pe0+22+0x46-0x46), u16(raw1,pe1+22)))
last = secs1[-1]
w("    new section: %s va=0x%x vs=0x%x rs=0x%x ro=0x%x ch=0x%x" % (
    last['name'], last['va'], last['vs'], last['rs'], last['ro'], last['ch']))
w("    file size : %d -> %d" % (len(raw0), len(raw1)))
# 新节内容 == 我们生成的 SECTION
sec_bytes = raw1[last['ro']:last['ro']+SEC_SIZE]
w("    section bytes == generated SECTION : %s" % (sec_bytes == V2.SECTION))
# 除新节与调用点外，其余字节必须完全一致
diff = [i for i in range(min(len(raw0), last['ro'])) if raw0[i] != raw1[i]]
w("    changed bytes inside old image: %d" % len(diff))
for i in diff:
    w("      off 0x%06x : %02x -> %02x" % (i, raw0[i], raw1[i]))

# ---------------- B. 调用点 ----------------
text = [s for s in secs1 if s['name'] == '.text'][0]
CAVE_A = IMAGE_BASE + V2.CAVE_A_RVA
CAVE_B = IMAGE_BASE + V2.CAVE_B_RVA
w("[B] call sites")
w("    caveA=0x%x  caveB=0x%x" % (CAVE_A, CAVE_B))
nA = nB = 0
bad = []
p = text['ro']
end = text['ro'] + text['rs'] - 6
while p < end:
    if raw1[p] == 0xE8:
        rel = struct.unpack_from('<i', raw1, p+1)[0]
        call_rva = text['va'] + (p - text['ro'])
        tgt = call_rva + 5 + rel
        if tgt in (V2.CAVE_A_RVA, V2.CAVE_B_RVA):
            nop_ok = (raw1[p+5] == 0x90)
            if tgt == V2.CAVE_A_RVA: nA += 1
            else: nB += 1
            w("    rva 0x%06x -> %s  (nop filler: %s)" % (
                call_rva, 'caveA' if tgt == V2.CAVE_A_RVA else 'caveB', nop_ok))
            if not nop_ok: bad.append(call_rva)
    p += 1
w("    redirected setEchoMode=%d (expect 1)   setText=%d (expect 10)" % (nA, nB))
# 残留的间接调用必须为 0
left = 0
p = text['ro']
while p < end:
    if raw1[p] == 0xFF and raw1[p+1] == 0x15:
        disp = struct.unpack_from('<i', raw1, p+2)[0]
        call_rva = text['va'] + (p - text['ro'])
        if call_rva + 6 + disp in (V2.SETECHO_IAT, V2.SETTEXT_IAT):
            left += 1
            w("    !! leftover indirect call at 0x%06x" % call_rva)
    p += 1
w("    leftover indirect calls: %d (expect 0)" % left)

# ---------------- C. 反汇编 caveA / caveB 入口 ----------------
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
cs = Cs(CS_ARCH_X86, CS_MODE_64)
def dis(rva, n, title):
    w("[C] %s (rva 0x%x)" % (title, rva))
    off = r2o(raw1, secs1, rva)
    for i in cs.disasm(raw1[off:off+80], IMAGE_BASE+rva):
        w("      0x%x  %-22s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
        n -= 1
        if n <= 0: break
dis(V2.CAVE_A_RVA, 8, "caveA head")
dis(V2.CAVE_B_RVA, 10, "caveB head")

# ---------------- D. 结论 ----------------
ok = (ns1 == ns0+1 and u32(raw1,opt1+56) == SEC_VOFF+SEC_SIZE
      and nA == 1 and nB == 10 and left == 0
      and sec_bytes == V2.SECTION and not bad)
w("RESULT: %s" % ("PASS" if ok else "FAIL"))
