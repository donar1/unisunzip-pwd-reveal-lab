r"""侦查⑤：dump 云端查询协议用到的 JSON 键名 + 补齐两个 setText 调用点的上下文。

重点：
  - 0x2db98 是 QJsonObject::value() 的键（查询响应字段名）
  - 0x28232 是某个 setText 的静态文本
  - 0x191a7 / 0x1e882 两个调用点上下文缺失，放宽窗口补上
  - 全 .rdata 里找 md5/hash/pwd/size/name 这类键名
"""
from pathlib import Path
import struct, os, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_INS_CALL

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(BASE, "probe_json.log")
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


def cstr(off, limit=200):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


def looks(s):
    return bool(s) and all(32 <= ord(c) < 127 for c in s)


def dump_window(tag, rva, before=0x100, after=0x400):
    w("")
    w("=" * 74)
    w("%s  窗口 %#x .. %#x" % (tag, rva - before, rva + after))
    w("=" * 74)
    o = rva2off(rva - before)
    if o is None:
        w("  越界")
        return
    blob = raw[o:o + before + after]
    p = 0
    while p < len(blob):
        e = blob.find(b"\x00", p)
        if e < 0:
            break
        s = blob[p:e].decode("latin-1", "replace")
        addr = rva - before + p
        if 2 <= len(s) <= 90 and looks(s):
            mark = "  <<<< " if (rva - before + p) == rva else ""
            w("   %#08x  %s%s" % (addr, s, mark))
        p = e + 1


dump_window("A. 查询响应 JSON 键 (0x2db98)", 0x2db98)
dump_window("B. setText 静态文本 (0x28232)", 0x28232, before=0x80, after=0x180)
dump_window("C. 0x2d670 区域 (ZipInfoDlg / 进度)", 0x2d670, before=0x100, after=0x200)

w("")
w("=" * 74)
w("D. 全 .rdata 中疑似 JSON 键名（短、纯英文小写）")
w("=" * 74)
KW = r"^(md5|sha1|sha256|hash|pwd|password|passwd|name|filename|file_name|file|size|filesize|file_size|sign|signature|token|key|keys|data|code|msg|status|url|type|zip|ext|id|uid|time|ts|nonce|appid|ver)$"
rx = re.compile(KW)
sec = next(s for s in SECS if s[0] == ".rdata")
nm, va, vs, pr, rs = sec
o, end = pr, pr + rs
hits = []
cur = o
while cur < end:
    e = raw.find(b"\x00", cur, cur + 120)
    if e < 0:
        cur += 1
        continue
    s = raw[cur:e].decode("latin-1", "replace")
    if 2 <= len(s) <= 40 and rx.match(s.lower()):
        hits.append((cur - pr + va, s))
    cur = e + 1
for a, s in hits:
    w("   %#08x  %s" % (a, s))
w("   (共 %d 条)" % len(hits))

w("")
w("=" * 74)
w("E. 与「查询密码」相关的字符串及上下文")
w("=" * 74)
for m in re.finditer(rb"[\x20-\x7e]{5,120}", raw):
    s = m.group().decode("latin-1")
    if re.search(r"(?i)querypassword|postquery|password", s):
        off = m.start()
        rva = None
        for n2, va2, vs2, pr2, rs2 in SECS:
            if pr2 <= off < pr2 + rs2:
                rva = va2 + (off - pr2)
                break
        w("   %s   @%s" % (s[:110], ("%#x" % rva) if rva else "?"))

w("")
w("=" * 74)
w("F. 补 0x191a7 / 0x1e882 两个 setText 调用点上下文（窗口 0xc0）")
w("=" * 74)
IMP_OFF = rva2off(u32(raw, DD + 8))
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
                    rva2name[ft + j * 8] = "%s!%s" % (dll.replace(".dll", ""), cstr(fo + 2))
            j += 1
            if j > 5000:
                break
    i += 1
    if i > 200:
        break

text = next(s for s in SECS if s[0] == ".text")
_, t_va, t_vs, t_pr, t_rs = text
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for cva in (0x191a7, 0x1e882):
    w("")
    w("---- setText @ %#x ----" % cva)
    start = cva - 0xc0
    so = rva2off(start)
    for ins in md.disasm(raw[so:so + 0xc0 + 8], start):
        note = ""
        if ins.id == X86_INS_CALL and ins.operands and ins.operands[0].type == X86_OP_MEM \
                and ins.operands[0].mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + ins.operands[0].mem.disp
            fn = rva2name.get(tgt)
            if fn:
                note = "   ; %s" % fn[:70]
        elif ins.id == 30 and ins.operands and ins.operands[1].type == X86_OP_MEM \
                and ins.operands[1].mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + ins.operands[1].mem.disp
            o2 = rva2off(tgt)
            if o2:
                s2 = cstr(o2, 60)
                if s2 and all(32 <= ord(c) < 127 for c in s2):
                    note = "   ; str=%s" % s2
        mark = "   <<< setText" if ins.address == cva else ""
        w("   %#08x  %-26s%s%s" % (ins.address, ins.mnemonic + " " + ins.op_str, note, mark))

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
