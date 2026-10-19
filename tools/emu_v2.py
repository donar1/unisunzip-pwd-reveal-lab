# -*- coding: utf-8 -*-
r"""unicorn 仿真验证 v2 cave 代码：逻辑 + 栈对齐。

判定要点：
  1. 每个外部函数（含 IAT 调用）入口处 RSP % 16 == 8 —— 即调用前 RSP 16 字节对齐（Win64 ABI）
     v1 的补丁在这里是错的，本测试能直接抓出来。
  2. caveA 收到 mode=3 时必须把 mode 改成 0 再下传，并登记控件指针。
  3. caveB 对已登记控件：先调原 setText，再把真实文本写成
     "16位大写十六进制FILETIME \t 密码UTF8 \r\n" 追加到 %TEMP%\UNISUnzip_pwd_log.txt。
  4. 对未登记控件：不得触发任何文件写入。
"""
from pathlib import Path
import struct, sys, os
BASE = str(Path(__file__).resolve().parent)
sys.path.insert(0, BASE)
import patch_unis_v2 as V2

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RCX,
                               UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
                               UC_X86_REG_RAX)

OUT = os.path.join(BASE, "emu_v2.log")
L = []
def w(m):
    L.append(str(m))
    open(OUT, "w", encoding="utf-8").write("\n".join(L))

import traceback as _tb
def _exc_hook(t, v, tb):
    w("EXCEPTION:\n" + "".join(_tb.format_exception(t, v, tb)))
sys.excepthook = _exc_hook
w("=== emu_v2 start ===")

IMAGE = 0x140000000
STUB  = 0x160000000
AUX   = 0x190000000
STACK = 0x170000000
SENTINEL = AUX + 0x4000

S = dict(gmhw=STUB+0x00, gpa=STUB+0x10, utf16=STUB+0x20, cfw=STUB+0x30,
         wf=STUB+0x40, ch=STUB+0x50, gtp=STUB+0x60, setecho=STUB+0x70,
         settext=STUB+0x80, gsyst=STUB+0x90, wctomb=STUB+0xA0)

REC_PTR   = AUX + 0x0000
SLOT_PATH = AUX + 0x0008
SLOT_H    = AUX + 0x0010
RECBEG    = AUX + 0x0100
FOUNDP    = AUX + 0x1000
QSTRING   = AUX + 0x2000
CAPBUF    = AUX + 0x3000

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

# ---- IAT ----
def wiat(rva, v): wq(IMAGE + rva, v)
wiat(V2.IAT_GMHW, S['gmhw'])
wiat(V2.IAT_GPA, S['gpa'])
wiat(V2.IAT_WCTOMB, S['wctomb'])
wiat(V2.IAT_GSYST, S['gsyst'])
wiat(V2.SETECHO_IAT, S['setecho'])
wiat(V2.SETTEXT_IAT, S['settext'])

# ---- aux data ----
wq(REC_PTR, RECBEG)
wq(SLOT_PATH, 0)
wq(SLOT_H, 0)
mu.mem_write(FOUNDP, PW.encode('utf-16-le') + b'\x00\x00')
wq(QSTRING, FOUNDP)
mu.mem_write(SENTINEL, b"\x0f\x0b")

events = []
align_bad = []

NAME_MAP = {
    b"?utf16@QString@@QEBAPEBGXZ": S['utf16'],
    b"CreateFileW": S['cfw'],
    b"WriteFile": S['wf'],
    b"CloseHandle": S['ch'],
    b"GetTempPathW": S['gtp'],
}

def wstr(b, maxlen=64):
    out = bytearray()
    for i in range(0, maxlen, 2):
        if b[i] == 0 and b[i+1] == 0:
            break
        out += b[i:i+2]
    return out.decode('utf-16-le', 'replace')

def hook(mu, address, size, ud):
    if address in S.values():
        rsp = mu.reg_read(UC_X86_REG_RSP)
        if rsp % 16 != 8:
            align_bad.append((hex(address), rsp % 16))
        if address == S['gmhw']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            nm = wstr(bytes(mu.mem_read(rcx, 64)))
            events.append("GetModuleHandleW(%s)" % nm)
            mu.reg_write(UC_X86_REG_RAX, 0x5000 + len(nm))
        elif address == S['gpa']:
            rdx = mu.reg_read(UC_X86_REG_RDX)
            nm = bytes(mu.mem_read(rdx, 64)).split(b'\x00')[0]
            events.append("GetProcAddress(%s)" % nm.decode())
            mu.reg_write(UC_X86_REG_RAX, NAME_MAP.get(nm, 0))
        elif address == S['utf16']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            mu.reg_write(UC_X86_REG_RAX, rq(rcx))
        elif address == S['setecho']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            rdx = mu.reg_read(UC_X86_REG_RDX)
            events.append("ORIG setEchoMode(self=%#x, mode=%d)" % (rcx, rdx))
        elif address == S['settext']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            rdx = mu.reg_read(UC_X86_REG_RDX)
            events.append("ORIG setText(self=%#x, qstr=%#x)" % (rcx, rdx))
        elif address == S['gsyst']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            wq(rcx, FAKE_FILETIME)
        elif address == S['wctomb']:
            rsp = mu.reg_read(UC_X86_REG_RSP)
            r8  = mu.reg_read(UC_X86_REG_R8)
            r9d = mu.reg_read(UC_X86_REG_R9)
            dst = struct.unpack('<Q', mu.mem_read(rsp + 0x28, 8))[0]
            raw = bytes(mu.mem_read(r8, r9d * 2))
            s = raw.decode('utf-16-le')
            b = s.encode('utf-8')
            mu.mem_write(dst, b)
            mu.reg_write(UC_X86_REG_RAX, len(b))
            events.append("WideCharToMultiByte(len=%d) -> %r" % (r9d, s))
        elif address == S['gtp']:
            rdx = mu.reg_read(UC_X86_REG_RDX)
            mu.mem_write(rdx, TEMP_W.encode('utf-16-le') + b'\x00\x00')
            mu.reg_write(UC_X86_REG_RAX, len(TEMP_W))
        elif address == S['cfw']:
            rcx = mu.reg_read(UC_X86_REG_RCX)
            wq(SLOT_PATH, rcx)
            dst = rq(REC_PTR)
            mu.mem_write(dst, struct.pack('<Q', 0x222))
            mu.reg_write(UC_X86_REG_RAX, 0x222)
            events.append("CreateFileW")
        elif address == S['wf']:
            h = mu.reg_read(UC_X86_REG_RCX)
            rdx = mu.reg_read(UC_X86_REG_RDX)
            r8 = mu.reg_read(UC_X86_REG_R8)
            data = bytes(mu.mem_read(rdx, r8))
            dst = rq(REC_PTR)
            mu.mem_write(dst, data)
            wq(REC_PTR, dst + r8)
            r9 = mu.reg_read(UC_X86_REG_R9)
            if r9: mu.mem_write(r9, struct.pack('<I', r8))
            mu.reg_write(UC_X86_REG_RAX, 1)
            events.append("WriteFile(ptr=%#x, %d bytes)" % (rdx, r8))
            events.append("   STAMP  = %#x" % (rq(IMAGE + V2.off['STAMP']),))
            events.append("   LINEBUF= %s" % bytes(mu.mem_read(IMAGE + V2.off['LINEBUF'], 48)).hex(' '))
            events.append("   payload= %r" % data)
        elif address == S['ch']:
            mu.reg_write(UC_X86_REG_RAX, 1)

mu.hook_add(UC_HOOK_CODE, hook)

def call(addr, rcx, rdx):
    sp = (STACK + 0x10000) & ~0xF
    sp -= 8
    wq(sp, SENTINEL)
    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.reg_write(UC_X86_REG_RCX, rcx)
    mu.reg_write(UC_X86_REG_RDX, rdx)
    mu.emu_start(addr, SENTINEL, timeout=5 * 10**6, count=200000)

CAVE_A = IMAGE + V2.CAVE_A_RVA
CAVE_B = IMAGE + V2.CAVE_B_RVA

# ---------- 1. mode=0 不该被登记/改写 ----------
events.clear()
call(CAVE_A, 0x111AAA, 0)
w("[1] caveA(mode=0) events: %s" % events)
t1 = (events == ["ORIG setEchoMode(self=0x111aaa, mode=0)"])

# ---------- 2. mode=3 -> 强制 0 + 登记 ----------
events.clear()
call(CAVE_A, 0xABCDEF, 3)
w("[2] caveA(mode=3) events: %s" % events)
t2 = (events == ["ORIG setEchoMode(self=0xabcdef, mode=0)"])

# ---------- 3. 已登记控件的 setText -> 落盘 ----------
events.clear()
wq(REC_PTR, RECBEG)
call(CAVE_B, 0xABCDEF, QSTRING)
w("[3] caveB(registered) events:")
for e in events: w("      " + e)
path_ptr = rq(SLOT_PATH)
path = bytes(mu.mem_read(path_ptr, 300)).decode('utf-16-le').split('\x00')[0] if path_ptr else "<none>"
written = bytes(mu.mem_read(RECBEG, rq(REC_PTR) - RECBEG))
w("    log path : %r" % path)
w("    line     : %r" % written)
hexpart = written[:16].decode('ascii', 'replace')
tab = written[16:17]
body = written[17:-2]
w("    hexpart=%r tab=%r body=%r" % (hexpart, tab, body))
t3 = (path == TEMP_W + "UNISUnzip_pwd_log.txt"
      and written[16:17] == b"\t"
      and written[-2:] == b"\r\n"
      and body == PW.encode('utf-8')
      and all(c in b"0123456789ABCDEF" for c in written[:16])
      and int(hexpart, 16) == FAKE_FILETIME)

# ---------- 4. 未登记控件 -> 不得写文件 ----------
events.clear()
wq(REC_PTR, RECBEG)
wq(SLOT_PATH, 0)
call(CAVE_B, 0xDEADBEEF, QSTRING)
w("[4] caveB(unregistered) events: %s" % events)
t4 = (events == ["ORIG setText(self=0xdeadbeef, qstr=%#x)" % QSTRING]
      and rq(SLOT_PATH) == 0 and rq(REC_PTR) == RECBEG)

w("[5] stack alignment violations: %s" % (align_bad if align_bad else "none"))
w("RESULT: %s" % ("PASS" if (t1 and t2 and t3 and t4 and not align_bad) else "FAIL"))
w("checks: t1=%s t2=%s t3=%s t4=%s" % (t1, t2, t3, t4))
