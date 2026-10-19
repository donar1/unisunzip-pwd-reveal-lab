r"""交叉验证：IAT 槽引用统计（含阳性对照 setText/setEchoMode）。

目的：确认「扫 FF 15 找调用点」这套方法有效，从而判断 setWindowTitle 是否真的 0 引用。
顺带统计 QProcess / 7z 相关导入。
输出 probe_iat_ref.log
"""
from pathlib import Path
import struct, os, re

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = os.path.join(BASE, "build", "UNISUnzip.exe")
OUT = os.path.join(BASE, "probe_iat_ref.log")
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
IAT_RVA = u32(raw, DD + 12)
IAT_SIZE = u32(raw, DD + 16)


def rva2off(rva):
    for i in range(NSEC):
        s = SECOFF + i * 40
        va = u32(raw, s + 12)
        vs = u32(raw, s + 8)
        pr = u32(raw, s + 20)
        if va <= rva < va + max(vs, u32(raw, s + 16)):
            return pr + (rva - va)
    return None


def cstr(off, limit=300):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


def parse_imports():
    imp_off = rva2off(u32(raw, DD + 8))
    res = {}
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
                        res[(dll, cstr(fo + 2))] = ft + j * 8
                j += 1
                if j > 5000:
                    break
        i += 1
        if i > 200:
            break
    return res


slots = parse_imports()

text = None
for i in range(NSEC):
    s = SECOFF + i * 40
    nm = cstr(s, 8).rstrip("\x00")
    if nm == ".text":
        text = (u32(raw, s + 20), u32(raw, s + 16), u32(raw, s + 12))
        break
t_off, t_size, t_va = text
body = raw[t_off:t_off + t_size]

# 统计所有 FF 15 的目标 RVA
refs = {}
p = 0
while True:
    k = body.find(b"\xff\x15", p)
    if k < 0:
        break
    disp = struct.unpack_from("<i", body, k + 2)[0]
    tgt = t_va + k + 6 + disp
    refs[tgt] = refs.get(tgt, 0) + 1
    p = k + 1

# 也统计 mov rax,[rip+d] 形式（FF D0 调用前的加载）
movrefs = {}
for pat in [b"\x48\x8b\x05", b"\x4c\x8b\x05", b"\x48\x8b\x0d", b"\x4c\x8b\x0d"]:
    p = 0
    while True:
        k = body.find(pat, p)
        if k < 0:
            break
        disp = struct.unpack_from("<i", body, k + 3)[0]
        tgt = t_va + k + 7 + disp
        movrefs[tgt] = movrefs.get(tgt, 0) + 1
        p = k + 1

w("=" * 72)
w("A. 阳性对照（已知事实：setEchoMode 1 处、setText 10 处）")
w("=" * 72)
CHECK = [
    ("setEchoMode", ("Qt5Widgets.dll", "?setEchoMode@QLineEdit@@QEAAXW4EchoMode@1@@Z")),
    ("setText", ("Qt5Widgets.dll", "?setText@QLineEdit@@QEAAXAEBVQString@@@Z")),
    ("setWindowTitle", ("Qt5Widgets.dll", "?setWindowTitle@QWidget@@QEAAXAEBVQString@@@Z")),
    ("windowTitle", ("Qt5Widgets.dll", "?windowTitle@QWidget@@QEBA?AVQString@@XZ")),
    ("window", ("Qt5Widgets.dll", "?window@QWidget@@QEBAPEAV1@XZ")),
    ("fileName(QFileInfo)", ("Qt5Core.dll", "?fileName@QFileInfo@@QEBA?AVQString@@XZ")),
    ("utf16(QString)", ("Qt5Core.dll", "?utf16@QString@@QEBAPEBGXZ")),
]
for label, key in CHECK:
    rva = slots.get(key)
    if rva is None:
        w("  %-22s 槽不在导入表" % label)
    else:
        w("  %-22s 槽 RVA %#08x   FF15引用 %-4d  MOV引用 %d"
          % (label, rva, refs.get(rva, 0), movrefs.get(rva, 0)))

w("")
w("=" * 72)
w("B. 被 FF15 引用最多的槽（确认扫描没跑偏）")
w("=" * 72)
inv = {}
for (dll, fn), rva in slots.items():
    if rva in refs:
        inv[rva] = "%s!%s" % (dll, fn)
top = sorted(refs.items(), key=lambda x: -x[1])[:25]
w("  FF15 总命中 %d 处，涉及槽 %d 个" % (sum(refs.values()), len(refs)))
for rva, n in top:
    w("    %-4d  %#08x  %s" % (n, rva, inv.get(rva, "<非导入槽/数据>")))

w("")
w("=" * 72)
w("C. QProcess / 7z / 进程启动 相关导入")
w("=" * 72)
KW = ["QProcess", "startDetached", "execute", "CreateProcess", "ShellExecute", "WinExec", "QDesktopServices"]
hit = False
for (dll, fn), rva in slots.items():
    if any(k.lower() in fn.lower() for k in KW):
        hit = True
        w("  %s!%s   FF15=%d" % (dll, fn, refs.get(rva, 0)))
if not hit:
    w("  (无)")

w("")
w("=" * 72)
w("D. Qt5Core 导入中与「文件/路径/模型」相关的符号")
w("=" * 72)
KW2 = ["QFileInfo", "QFile", "QDir", "QStandardPaths", "toUtf8", "fromLocal8Bit",
       "absoluteFilePath", "canonicalFilePath", "exists", "size"]
for (dll, fn), rva in sorted(slots.items()):
    if dll == "Qt5Core.dll" and any(k.lower() in fn.lower() for k in KW2):
        w("  %-70s FF15=%d" % (fn[:70], refs.get(rva, 0)))

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
