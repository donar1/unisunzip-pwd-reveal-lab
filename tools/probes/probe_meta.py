r"""侦查：UNISUnzip 是否具备「记录压缩包路径 + 算 MD5」的条件。

查三条线索：
  A. 导入表 —— 有没有 CryptoAPI(advapi32) / 窗口函数(user32) / 路径函数
  B. 字符串 —— 程序里出现的 md5 / 文件路径 / 云端查询 相关字样
  C. Qt 导出表 —— Qt5Core 里有没有 QCryptographicHash、QFileInfo、QWidget::windowTitle
输出落盘 probe_meta.log，再读。
"""
from pathlib import Path
import struct, os, re

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = os.path.join(BASE, "build", "UNISUnzip.exe")
GREENDIR = os.path.join(BASE, "UNISUnzip_patched")
OUT = os.path.join(BASE, "probe_meta.log")

LOG = []


def w(s=""):
    LOG.append(str(s))


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def rva2off(raw, opt, nsec, secoff, rva):
    for i in range(nsec):
        s = secoff + i * 40
        va = u32(raw, s + 12)
        vs = u32(raw, s + 8)
        pr = u32(raw, s + 20)
        if va <= rva < va + max(vs, u32(raw, s + 16)):
            return pr + (rva - va)
    return None


def cstr(raw, off, limit=200):
    e = raw.find(b"\x00", off, off + limit)
    if e < 0:
        e = off + limit
    return raw[off:e].decode("latin-1", "replace")


def parse_imports(raw):
    e_lfanew = u32(raw, 0x3C)
    opt = e_lfanew + 24
    nsec = u16(raw, e_lfanew + 6)
    secoff = opt + u16(raw, e_lfanew + 20)
    dd = opt + 112
    imp_rva = u32(raw, dd + 8)
    imp_off = rva2off(raw, opt, nsec, secoff, imp_rva)
    res = {}
    if imp_off is None:
        return res
    i = 0
    while True:
        d = imp_off + i * 20
        oft = u32(raw, d)
        name_rva = u32(raw, d + 12)
        first = u32(raw, d + 16)
        if oft == 0 and name_rva == 0 and first == 0:
            break
        noff = rva2off(raw, opt, nsec, secoff, name_rva)
        dll = cstr(raw, noff) if noff else "?"
        thunk_off = rva2off(raw, opt, nsec, secoff, oft or first)
        funcs = []
        if thunk_off:
            j = 0
            while True:
                t = u64(raw, thunk_off + j * 8)
                if t == 0:
                    break
                if not (t >> 63):
                    fo = rva2off(raw, opt, nsec, secoff, t & 0xFFFFFFFF)
                    if fo:
                        funcs.append(cstr(raw, fo + 2))
                j += 1
                if j > 5000:
                    break
        res[dll] = funcs
        i += 1
        if i > 200:
            break
    return res


def parse_exports(path):
    raw = open(path, "rb").read()
    e_lfanew = u32(raw, 0x3C)
    opt = e_lfanew + 24
    nsec = u16(raw, e_lfanew + 6)
    secoff = opt + u16(raw, e_lfanew + 20)
    dd = opt + 112
    exp_rva = u32(raw, dd)
    exp_off = rva2off(raw, opt, nsec, secoff, exp_rva)
    if exp_off is None:
        return []
    nnames = u32(raw, exp_off + 24)
    names_rva = u32(raw, exp_off + 32)
    noff = rva2off(raw, opt, nsec, secoff, names_rva)
    out = []
    if noff is None:
        return out
    for i in range(min(nnames, 200000)):
        r = u32(raw, noff + i * 4)
        o = rva2off(raw, opt, nsec, secoff, r)
        if o:
            out.append(cstr(raw, o))
    return out


def extract_strings(raw, minlen=6):
    res = set()
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, raw):
        res.add(m.group().decode("latin-1"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, raw):
        res.add(m.group().decode("utf-16-le", "replace"))
    return res


# ---------- A. 导入表 ----------
raw = open(TARGET, "rb").read()
w("=" * 70)
w("A. 导入表（build\\UNISUnzip.exe）")
w("=" * 70)
imps = parse_imports(raw)
for dll in sorted(imps):
    w("  [%s] %d funcs" % (dll, len(imps[dll])))

w("")
w("  --- 关键能力探测 ---")
want_dll = ["advapi32", "crypt32", "user32", "shell32", "kernel32", "shlwapi"]
for dll in sorted(imps):
    low = dll.lower()
    for k in want_dll:
        if k in low:
            w("  * %s -> %s" % (dll, ", ".join(imps[dll][:60])))

w("")
w("  --- 函数名含关键词的 ---")
KW = ["md5", "hash", "crypt", "windowtext", "windowtitle", "getwindow",
      "getopen", "getfilename", "openfile", "dragquer", "commandline",
      "searchpath", "getfullpath", "getmodulefilename", "findfirst", "getfilesize"]
for dll in sorted(imps):
    hits = [f for f in imps[dll] if any(k in f.lower() for k in KW)]
    if hits:
        w("  %s:" % dll)
        for h in sorted(set(hits)):
            w("     %s" % h)

# ---------- B. 字符串 ----------
w("")
w("=" * 70)
w("B. 字符串线索")
w("=" * 70)
strs = extract_strings(raw, 6)
PAT = {
    "md5/hash": r"(?i)md5|sha1|sha256|crc32|hash",
    "文件/路径 API 名": r"(?i)windowtitle|getwindowtext|getopenfilename|dragqueryfile|getfullpathname",
    "云端查询": r"(?i)querypassword|postquery|searchpassword|findpassword",
    "文件相关词": r"(?i)\bfile(name|path)\b|\bzipfile\b|\barchives?\b",
    "datetime/ini": r"(?i)valueinfo",
}
for label, pat in PAT.items():
    rx = re.compile(pat)
    hits = sorted({s for s in strs if rx.search(s) and len(s) < 160})
    w("  --- %s : %d 条 ---" % (label, len(hits)))
    for h in hits[:40]:
        w("     %s" % h)

# ---------- C. Qt 导出表 ----------
w("")
w("=" * 70)
w("C. Qt 模块导出符号（能否直接调用）")
w("=" * 70)
QTKW = {
    "QCryptographicHash": r"QCryptographicHash",
    "QFileInfo": r"QFileInfo",
    "QWidget::windowTitle": r"windowTitle",
    "QWidget::window": r"@QWidget@@QEBAPEAVQWidget",
    "QDir/QFile": r"@QFile@@|@QDir@@",
    "QString::fromLocal8Bit": r"fromLocal8Bit",
    "QString::toUtf8": r"toUtf8",
}
for dll in ["Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll"]:
    p = os.path.join(GREENDIR, dll)
    if not os.path.exists(p):
        w("  %s  MISSING" % dll)
        continue
    exps = parse_exports(p)
    w("  --- %s : 导出 %d 个 ---" % (dll, len(exps)))
    for label, pat in QTKW.items():
        rx = re.compile(pat)
        hits = sorted({e for e in exps if rx.search(e)})
        if hits:
            w("     [%s] %d 条，例：" % (label, len(hits)))
            for h in hits[:6]:
                w("        %s" % h)

w("")
w("DONE")

open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written", OUT)
