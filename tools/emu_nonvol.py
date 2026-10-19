# -*- coding: utf-8 -*-
r"""Win64 ABI 非易失寄存器保留性回归测试。

Win64 约定：RBX, RBP, RDI, RSI, RSP, R12-R15 必须由被调函数保存并恢复。
caveA/caveB 是"冒充" QLineEdit::setEchoMode / setText 的，所以它们对调用方
必须表现得像正常的 C++ 函数——任何非易失寄存器被破坏，调用方后续使用到的
就是垃圾值，典型表现就是"点一下就闪退"。

本测试在进入 cave 前给 8 个非易失寄存器写入哨兵值，返回后逐一比对。
"""
from pathlib import Path
import struct, sys, os

BASE = str(Path(__file__).resolve().parent)
sys.path.insert(0, BASE)
import patch_unis_v2 as V2

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
                               UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RDI,
                               UC_X86_REG_RSI, UC_X86_REG_R12, UC_X86_REG_R13,
                               UC_X86_REG_R14, UC_X86_REG_R15)

OUT = os.path.join(BASE, "emu_nonvol.log")
L = []
def w(m):
    L.append(str(m))
    open(OUT, "w", encoding="utf-8").write("\n".join(L))

import traceback as _tb
sys.excepthook = lambda t, v, tb: w("EXCEPTION:\n" + "".join(_tb.format_exception(t, v, tb)))

w("=== Win64 非易失寄存器保留性测试 ===")

IMAGE = 0x140000000
STUB  = 0x160000000
AUX   = 0x190000000
STACK = 0x170000000
SENTINEL = AUX + 0x4000

S = dict(gmhw=STUB + 0x00, gpa=STUB + 0x10, utf16=STUB + 0x20, cfw=STUB + 0x30,
         wf=STUB + 0x40, ch=STUB + 0x50, gtp=STUB + 0x60, setecho=STUB + 0x70,
         settext=STUB + 0x80, gsyst=STUB + 0x90, wctomb=STUB + 0xA0)

REC_PTR = AUX + 0x0000
SLOT_PATH = AUX + 0x0008
RECBEG = AUX + 0x0100
FOUNDP = AUX + 0x1000
QSTRING = AUX + 0x2000

PW = "TestPass123"
TEMP_W = os.environ.get("TEMP", "C:\\Windows\\Temp").rstrip("\\") + "\\"
FAKE_FILETIME = 0x01DA3F8C12345678

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(IMAGE, 0x90000, UC_PROT_ALL)
mu.mem_map(STUB, 0x2000, UC_PROT_ALL)
mu.mem_map(AUX, 0x5000, UC_PROT_ALL)
mu.mem_map(STACK, 0x20000, UC_PROT_ALL)
mu.mem_write(IMAGE + V2.SEC_VOFF, V2.SECTION)
for a in S.values():
    mu.mem_write(a, b"\xc3")

def wq(a, v): mu.mem_write(a, struct.pack('<Q', v))
def rq(a): return struct.unpack('<Q', mu.mem_read(a, 8))[0]
def wiat(rva, v): wq(IMAGE + rva, v)

wiat(V2.IAT_GMHW, S['gmhw']);   wiat(V2.IAT_GPA, S['gpa'])
wiat(V2.IAT_WCTOMB, S['wctomb']); wiat(V2.IAT_GSYST, S['gsyst'])
wiat(V2.SETECHO_IAT, S['setecho']); wiat(V2.SETTEXT_IAT, S['settext'])

wq(REC_PTR, RECBEG)
wq(SLOT_PATH, 0)
mu.mem_write(FOUNDP, PW.encode('utf-16-le') + b'\x00\x00')
wq(QSTRING, FOUNDP)
mu.mem_write(SENTINEL, b"\x0f\x0b")

NAME_MAP = {
    b"?utf16@QString@@QEBAPEBGXZ": S['utf16'],
    b"CreateFileW": S['cfw'], b"WriteFile": S['wf'],
    b"CloseHandle": S['ch'], b"GetTempPathW": S['gtp'],
}
align_bad = []

def wstr(b, maxlen=64):
    out = bytearray()
    for i in range(0, maxlen, 2):
        if b[i] == 0 and b[i + 1] == 0:
            break
        out += b[i:i + 2]
    return out.decode('utf-16-le', 'replace')

def hook(mu, address, size, ud):
    if address in S.values():
        if mu.reg_read(UC_X86_REG_RSP) % 16 != 8:
            align_bad.append((hex(address), mu.reg_read(UC_X86_REG_RSP) % 16))
        if address == S['gmhw']:
            mu.reg_write(UC_X86_REG_RAX, 0x5000 + len(wstr(bytes(mu.mem_read(mu.reg_read(UC_X86_REG_RCX), 64)))))
        elif address == S['gpa']:
            nm = bytes(mu.mem_read(mu.reg_read(UC_X86_REG_RDX), 64)).split(b'\x00')[0]
            mu.reg_write(UC_X86_REG_RAX, NAME_MAP.get(nm, 0))
        elif address == S['utf16']:
            mu.reg_write(UC_X86_REG_RAX, rq(mu.reg_read(UC_X86_REG_RCX)))
        elif address == S['gsyst']:
            wq(mu.reg_read(UC_X86_REG_RCX), FAKE_FILETIME)
        elif address == S['wctomb']:
            rsp = mu.reg_read(UC_X86_REG_RSP)
            dst = struct.unpack('<Q', mu.mem_read(rsp + 0x28, 8))[0]
            s = bytes(mu.mem_read(mu.reg_read(UC_X86_REG_R8), mu.reg_read(UC_X86_REG_R9) * 2)).decode('utf-16-le')
            b = s.encode('utf-8')
            mu.mem_write(dst, b)
            mu.reg_write(UC_X86_REG_RAX, len(b))
        elif address == S['gtp']:
            rdx = mu.reg_read(UC_X86_REG_RDX)
            mu.mem_write(rdx, TEMP_W.encode('utf-16-le') + b'\x00\x00')
            mu.reg_write(UC_X86_REG_RAX, len(TEMP_W))
        elif address == S['cfw']:
            mu.reg_write(UC_X86_REG_RAX, 0x222)
        elif address == S['wf']:
            mu.reg_write(UC_X86_REG_RAX, 1)
        elif address == S['ch']:
            mu.reg_write(UC_X86_REG_RAX, 1)

mu.hook_add(UC_HOOK_CODE, hook)

NV = [("RBX", UC_X86_REG_RBX, 0xB1B1B1B1B1B1B1B1),
      ("RBP", UC_X86_REG_RBP, 0xB2B2B2B2B2B2B2B2),
      ("RDI", UC_X86_REG_RDI, 0xB3B3B3B3B3B3B3B3),
      ("RSI", UC_X86_REG_RSI, 0xB4B4B4B4B4B4B4B4),
      ("R12", UC_X86_REG_R12, 0xB5B5B5B5B5B5B5B5),
      ("R13", UC_X86_REG_R13, 0xB6B6B6B6B6B6B6B6),
      ("R14", UC_X86_REG_R14, 0xB7B7B7B7B7B7B7B7),
      ("R15", UC_X86_REG_R15, 0xB8B8B8B8B8B8B8B8)]

def call(addr, rcx, rdx, label):
    sp = (STACK + 0x10000) & ~0xF
    sp -= 8
    wq(sp, SENTINEL)
    mu.reg_write(UC_X86_REG_RSP, sp)
    for _, reg, val in NV:
        mu.reg_write(reg, val)
    mu.reg_write(UC_X86_REG_RCX, rcx)
    mu.reg_write(UC_X86_REG_RDX, rdx)
    mu.emu_start(addr, SENTINEL, timeout=5 * 10**6, count=400000)
    bad = []
    for name, reg, val in NV:
        got = mu.reg_read(reg)
        if got != val:
            bad.append("%s: 期望 %#x 实际 %#x" % (name, val, got))
    sp_back = mu.reg_read(UC_X86_REG_RSP)
    # 入口 rsp 指向返回地址；正常 ret 之后 rsp 应等于入口值 + 8
    if sp_back != sp + 8:
        bad.append("RSP 未复原: 入口 %#x 返回 %#x (期望 %#x)" % (sp, sp_back, sp + 8))
    w("[%s] 非易失寄存器检查: %s" % (label, "全部保留 OK" if not bad else "**被破坏**"))
    for b in bad:
        w("      " + b)
    return bad

allbad = []
allbad += call(IMAGE + V2.CAVE_A_RVA, 0xABCDEF, 3, "caveA mode=3 (登记+强制0)")
allbad += call(IMAGE + V2.CAVE_A_RVA, 0x111AAA, 0, "caveA mode=0 (直通)")
allbad += call(IMAGE + V2.CAVE_B_RVA, 0xDEADBEEF, QSTRING, "caveB 未登记控件")
allbad += call(IMAGE + V2.CAVE_B_RVA, 0xABCDEF, QSTRING, "caveB 已登记控件(写日志)")

w("")
w("栈对齐违规: %s" % (align_bad if align_bad else "无"))
w("RESULT: %s" % ("PASS" if (not allbad and not align_bad) else "FAIL"))
w("violations=%d" % (len(allbad) + len(align_bad)))
