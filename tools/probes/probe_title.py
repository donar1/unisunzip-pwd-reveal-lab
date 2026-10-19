r"""静态侦查②：程序是否把「当前压缩包文件名」写进窗口标题 / 显示在某控件里。

做法：
  1. 在 build exe 的导入表里定位 Qt5Widgets!?setWindowTitle@QWidget@@ 的 IAT 槽 RVA
  2. 扫 .text 找所有引用该槽的 FF 15 调用点，反汇编上下文，看标题字符串怎么拼出来的
  3. 顺带列出 Qt5Widgets 里所有「能拿到窗口/顶层窗口/标题」的导出符号（供补丁调用）
输出 probe_title.log
"""
from pathlib import Path
import struct, os, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = os.path.join(BASE, "build", "UNISUnzip.exe")
GREENDIR = os.path.join(BASE, "UNISUnzip_patched")
OUT = os.path.join(BASE, "probe_title.log")

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
SIZE_IMG = u32(raw, OPT + 56)


def rva2off(rva):
    for i in range(NSEC):
        s = SECOFF + i * 40
        va = u32(raw, s + 12)
        vs = u32(raw, s + 8)
        pr = u32(raw, s + 20)
        if va <= rva < va + max(vs, u32(raw, s + 16)):
            return pr + (rva - va)
    return None


def off2rva(off):
    for i in range(NSEC):
        s = SECOFF + i * 40
        va = u32(raw, s + 12)
        pr = u32(raw, s + 20)
        rs = u32(raw, s + 16)
        if pr <= off < pr + rs:
            return va + (off - pr)
    return None


def cstr(off, limit=300):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


# ---------- 导入表：建 (dll, func) -> IAT slot RVA ----------
imp_off = rva2off(u32(raw, DD + 8))
slots = {}
i = 0
while True:
    d = imp_off + i * 20
    oft = u32(raw, d)
    namerva = u32(raw, d + 12)
    ft = u32(raw, d + 16)
    if oft == 0 and namerva == 0 and ft == 0:
        break
    noff = rva2off(namerva)
    dll = cstr(noff) if noff else "?"
    thunk_rva = oft or ft
    toff = rva2off(thunk_rva)
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

w("=" * 72)
w("1. 目标符号的 IAT 槽")
w("=" * 72)
TARGETS = {
    "setWindowTitle": "?setWindowTitle@QWidget@@QEAAXAEBVQString@@@Z",
    "windowTitle": "?windowTitle@QWidget@@QEBA?AVQString@@XZ",
    "window": "?window@QWidget@@QEBAPEAV1@XZ",
    "topLevelWidgets": "?topLevelWidgets@QApplication@@SA?AV?$QList@PEAVQWidget@@@@XZ",
    "arg": "?arg@QString@@QEBA?AV1@AEBV1@H@Z",
    "fileName": "?fileName@QFileInfo@@QEBA?AVQString@@XZ",
}
found = {}
for label, sym in TARGETS.items():
    for (dll, fn), rva in slots.items():
        if fn == sym:
            found[label] = (dll, rva)
            w("  %-16s %s!%s -> IAT RVA %#x" % (label, dll, fn, rva))
if not found:
    w("  (导入表中未命中)")

# ---------- 扫描 .text 中引用这些槽的 FF 15 ----------
text = None
for i in range(NSEC):
    s = SECOFF + i * 40
    nm = cstr(s, 8).rstrip("\x00")
    if nm == ".text":
        text = (u32(raw, s + 20), u32(raw, s + 16), u32(raw, s + 12))
        break
t_off, t_size, t_va = text
body = raw[t_off:t_off + t_size]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

w("")
w("=" * 72)
w("2. setWindowTitle 的调用点（看标题怎么拼出来的）")
w("=" * 72)
if "setWindowTitle" in found:
    slot_rva = found["setWindowTitle"][1]
    calls = []
    p = 0
    while True:
        k = body.find(b"\xff\x15", p)
        if k < 0:
            break
        disp = struct.unpack_from("<i", body, k + 2)[0]
        cur_va = t_va + k
        tgt_rva = cur_va + 6 + disp
        if tgt_rva == slot_rva:
            calls.append(cur_va)
        p = k + 1
    w("  命中 %d 处" % len(calls))
    for cva in calls:
        w("")
        w("  ---- 调用点 RVA %#x ----" % cva)
        start = cva - 0x50
        so = rva2off(start)
        code = raw[so:so + 0x50 + 0x20]
        for ins in md.disasm(code, start):
            mark = "  <= call setWindowTitle" if ins.address == cva else ""
            bs = " ".join("%02x" % b for b in ins.bytes)
            w("     %#08x  %-24s %s %s%s" % (ins.address, bs, ins.mnemonic, ins.op_str, mark))
else:
    w("  未找到 setWindowTitle 槽，跳过")

# 字符串里的标题格式串
w("")
w("=" * 72)
w("3. 可能的标题格式串（含 %1 的模板）")
w("=" * 72)
pats = set()
for m in re.finditer(rb"[\x20-\x7e]{4,120}", raw):
    s = m.group().decode("latin-1")
    if "%1" in s or "%2" in s:
        pats.add(s)
for s in sorted(pats)[:60]:
    w("   %s" % s)
w("   (共 %d 条)" % len(pats))

# ---------- Qt5Widgets 中可用的窗口类符号 ----------
w("")
w("=" * 72)
w("4. Qt5Widgets 中「取窗口 / 标题」可用导出")
w("=" * 72)


def parse_exports(path):
    b = open(path, "rb").read()
    lf = u32(b, 0x3C)
    op = lf + 24
    ns = u16(b, lf + 6)
    so = op + u16(b, lf + 20)
    ddd = op + 112
    eo = None
    er = u32(b, ddd)
    for k in range(ns):
        s = so + k * 40
        va = u32(b, s + 12)
        vs = u32(b, s + 8)
        pr = u32(b, s + 20)
        if va <= er < va + max(vs, u32(b, s + 16)):
            eo = pr + (er - va)
            break
    if eo is None:
        return []
    nn = u32(b, eo + 24)
    nr = u32(b, eo + 32)
    no = None
    for k in range(ns):
        s = so + k * 40
        va = u32(b, s + 12)
        vs = u32(b, s + 8)
        pr = u32(b, s + 20)
        if va <= nr < va + max(vs, u32(b, s + 16)):
            no = pr + (nr - va)
            break
    res = []
    for k in range(min(nn, 100000)):
        r = u32(b, no + k * 4)
        for m in range(ns):
            s = so + m * 40
            va = u32(b, s + 12)
            vs = u32(b, s + 8)
            pr = u32(b, s + 20)
            if va <= r < va + max(vs, u32(b, s + 16)):
                o = pr + (r - va)
                e = b.find(b"\x00", o, o + 400)
                res.append(b[o:e].decode("latin-1", "replace"))
                break
    return res


exps = parse_exports(os.path.join(GREENDIR, "Qt5Widgets.dll"))
QKW = [
    r"\?window@QWidget@@QEBA",
    r"\?windowTitle@QWidget@@QEBA",
    r"\?topLevelWidgets@QApplication",
    r"\?activeWindow@QApplication",
    r"\?setWindowTitle@QWidget",
    r"\?isVisible@QWidget@@QEBA",
    r"\?text@QLineEdit@@QEBA",
    r"\?parentWidget@QWidget@@QEBAPEAV1@XZ",
    r"\?objectName@QObject@@QEBA",
]
for k in QKW:
    rx = re.compile(k)
    hits = sorted({e for e in exps if rx.search(e)})
    w("  %s" % k)
    for h in hits[:8]:
        w("      %s" % h)
    if not hits:
        w("      (无)")

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
