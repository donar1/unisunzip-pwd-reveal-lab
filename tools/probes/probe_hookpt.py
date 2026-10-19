r"""侦查⑥：确定「文件名 + MD5」的最佳截获点。

候选（按优先级）：
  QJsonDocument::toJson         —— 拿到请求明文 JSON（含 fileName/fileSize/md5）
  QNetworkAccessManager::post   —— 拿到最终请求体（可能已 AES 加密 + base64）
  QCryptographicHash::hash      —— 拿到 MD5 摘要本身
  QByteArray::toBase64/fromBase64、QJsonObject::insert
统计各自 IAT 槽与调用点数量（原版 exe）。
"""
from pathlib import Path
import struct, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = str(Path(__file__).resolve().parent.parent)
TARGET = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
OUT = os.path.join(BASE, "probe_hookpt.log")
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

text = next(s for s in SECS if s[0] == ".text")
_, t_va, t_vs, t_pr, t_rs = text
body = raw[t_pr:t_pr + t_rs]

refs = {}
p = 0
while True:
    k = body.find(b"\xff\x15", p)
    if k < 0:
        break
    disp = struct.unpack_from("<i", body, k + 2)[0]
    tgt = t_va + k + 6 + disp
    refs.setdefault(tgt, []).append(t_va + k)
    p = k + 1

w("=" * 74)
w("A. 网络 / JSON / 哈希 相关导入及其调用点")
w("=" * 74)
GROUPS = {
    "网络发送": ["post@QNetworkAccessManager", "put@QNetworkAccessManager",
                 "sendCustomRequest", "get@QNetworkAccessManager",
                 "@QNetworkRequest@@", "@QNetworkReply@@", "QNetworkReply"],
    "JSON": ["QJsonDocument", "QJsonObject", "QJsonValue", "QJsonArray"],
    "哈希": ["QCryptographicHash"],
    "编码": ["toBase64", "fromBase64", "toHex", "fromHex", "QByteArray"],
}
for g, kws in GROUPS.items():
    w("")
    w("  --- %s ---" % g)
    for (dll, nm), rva in sorted(slots.items()):
        if any(k in nm for k in kws):
            n = len(refs.get(rva, []))
            w("   %-72s IAT=%#08x  calls=%d" % (nm[:72], rva, n))

w("")
w("=" * 74)
w("B. 全部导入里名字含这些关键词的（含调用点）")
w("=" * 74)
for kw in ["toJson", "fromJson", "insert", "toBase64", "fromBase64",
           "QNetworkAccessManager", "QNetworkRequest", "QNetworkReply",
           "QCryptographicHash", "addData", "result@QCryptographicHash"]:
    w("")
    w("  [%s]" % kw)
    found = False
    for (dll, nm), rva in sorted(slots.items()):
        if kw in nm:
            found = True
            w("   %-72s IAT=%#08x calls=%d" % (nm[:72], rva, len(refs.get(rva, []))))
    if not found:
        w("   (无)")

w("")
w("=" * 74)
w("C. Qt5Network.dll 的全部导入（13 个）")
w("=" * 74)
for (dll, nm), rva in sorted(slots.items()):
    if "Network" in dll:
        w("   %-72s calls=%d" % (nm[:72], len(refs.get(rva, []))))

w("")
w("DONE")
open(OUT, "w", encoding="utf-8").write("\n".join(LOG))
print("written")
