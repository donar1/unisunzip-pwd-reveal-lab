# -*- coding: utf-8 -*-
r"""
UNISUnzip 密码显形 + 台账补丁生成器  v2
--------------------------------------------------
目标：让「查找密码」返回的密码在界面上以明文显示（可选中/可复制），
      并把每次被写入密码框的密码追加记录到 %TEMP%\UNISUnzip_pwd_log.txt

实现（新增一个 .unispw 节，位置无关代码，ASLR 安全）：
  caveA  <- 接管 QLineEdit::setEchoMode 调用点
            若传入的 echo mode != Normal：把控件指针登记进环形表，并把 mode 强制改 0(Normal)
  caveB  <- 接管 QLineEdit::setText 调用点
            先执行原 setText；若该控件在登记表里，取出真实文本(UTF-16)
            转 UTF-8 后以 "16位十六进制FILETIME\\t密码\\r\\n" 追加写入日志文件

v2 相对 v1 修正的 5 处缺陷：
  1. 调用点重定向方式错误：原做法把 `FF 15 disp32`(间接调用) 的 disp 指向代码区，
     执行时会取代码字节当函数指针 -> 必崩。改为 `E8 rel32` + 0x90（直接调用，长度不变，无需重定位）。
  2. echo 模式判断错误：原代码只判断 mode==2(Password)，而本程序实际下传的是 3(PasswordEchoOnEdit)
     -> 原来即使不崩也毫无效果。改为 mode != 0 一律强制为 0。
  3. 栈 16 字节对齐错误：原代码在 sub rsp 后 rsp%16==8 就调用外部函数，违反 Win64 ABI，
     Qt 内部使用 SSE 对齐指令时会崩。v2 每个函数入口都精算对齐。
  4. 日志路径不可写：原路径写在 C:\Program Files (x86)\UNISUnzip\ 下，而该 exe 清单为
     asInvoker、目录 ACL 对 Users 只读 -> CreateFileW 必然 ACCESS_DENIED。
     改为运行时 GetTempPathW() 动态取 %TEMP%。
  5. QString::utf16 从错误的模块解析：QString 属于 Qt5Core.dll，原代码却在 Qt5Widgets.dll 里查
     -> GetProcAddress 返回 NULL，永远不记录。改为 Qt5Core.dll。

v2.1 修正（2026-09-21，实测"点查找密码就闪退"定位到）：
  6. **破坏 Win64 非易失寄存器 RDI/RSI**。caveB（以及它调的 resolve_all）把 RDI/RSI 当临时寄存器用，
     却只保存了 RBX/RBP/R12-R15。Win64 ABI 规定 RBX/RBP/RDI/RSI/RSP/R12-R15 必须由被调函数保留，
     而 caveB 是"冒充 QLineEdit::setText"的，调用方完全有权在调用返回后继续使用 RDI/RSI。
     实测该 exe 有 8/11 个被改写的调用点在返回后会读 RDI/RSI（含 0x1e882，正是"查找密码"弹窗
     构造代码，紧邻 setEchoMode 调用点 0x1e89c）-> 拿到垃圾指针立即崩溃。
     修法：caveB 与 resolve_all 各增加 push/pop rdi、rsi（push 后仍为 8 个/5 个，栈对齐不变）。
     回归测试见 emu_nonvol.py（进入前给 8 个非易失寄存器写哨兵，返回后逐一比对）。
"""
from pathlib import Path
import struct, os, sys

IMAGE_BASE = 0x140000000
SEC_VOFF   = 0x7f000          # 新区段 VA（紧跟 .reloc 0x7e000+0xE00 之后）
SEC_SIZE   = 0x2000
DATA_OFF   = 0x1000           # 节内数据区偏移 -> RVA 0x80000
DATA_RVA   = SEC_VOFF + DATA_OFF
SEC_VA     = IMAGE_BASE + SEC_VOFF

# 需要接管的 IAT 槽（由 pe 解析确认）
SETECHO_IAT = 0x27240   # Qt5Widgets: ?setEchoMode@QLineEdit@@QEAAXW4EchoMode@1@@Z
SETTEXT_IAT = 0x27010   # Qt5Widgets: ?setText@QLineEdit@@QEAAXAEBVQString@@@Z
IAT_GMHW    = 0x26080   # kernel32: GetModuleHandleW
IAT_GPA     = 0x260c0   # kernel32: GetProcAddress
IAT_WCTOMB  = 0x260b0   # kernel32: WideCharToMultiByte
IAT_GSYST   = 0x26010   # kernel32: GetSystemTimeAsFileTime

LOG_SUFFIX = "UNISUnzip_pwd_log.txt"

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

# ------------------------------------------------------------------ 数据区
data = bytearray()
off = {}
def put(name, blob, align=8):
    while len(data) % align: data.append(0)
    off[name] = DATA_RVA + len(data)
    data.extend(blob)

put('FN_UTF16', b'\x00'*8)
put('FN_CFW',   b'\x00'*8)
put('FN_WF',    b'\x00'*8)
put('FN_CH',    b'\x00'*8)
put('FN_GTP',   b'\x00'*8)
put('DONE',     b'\x00'*8)
put('PW_IDX',   b'\x00'*8)
put('PW_SET',   b'\x00'*64)
put('STAMP',    b'\x00'*8)
put('LINEBUF',  b'\x00'*1024)
put('LOGPATH',  b'\x00'*640, align=2)
put('STR_QT',   "Qt5Core.dll".encode('utf-16-le') + b'\x00\x00', align=2)
put('STR_K32',  "kernel32.dll".encode('utf-16-le') + b'\x00\x00', align=2)
put('N_UTF16',  b"?utf16@QString@@QEBAPEBGXZ\x00")
put('N_CFW',    b"CreateFileW\x00")
put('N_WF',     b"WriteFile\x00")
put('N_CH',     b"CloseHandle\x00")
put('N_GTP',    b"GetTempPathW\x00")
put('SUFFIX',   LOG_SUFFIX.encode('utf-16-le') + b'\x00\x00', align=2)

def H(name): return "0x%x" % off[name]

# ------------------------------------------------------------------ 代码
SUB_CONST = SEC_VOFF + 7      # get_base 必须是节内第一条指令：lea rax,[rip] 长度 7

asm = """
get_base:
    lea rax, [rip]
    sub rax, {subc}
    ret


caveA:
    mov eax, 0xCAFEA001
    push rbx
    push rbp
    mov rbp, rsp
    sub rsp, 0x28
    mov [rbp - 0x08], rcx
    mov [rbp - 0x10], rdx
    call get_base
    mov rbx, rax
    mov r8, [rbp - 0x10]
    test r8, r8
    je caveA_orig
    lea r9, [rbx + {PW_IDX}]
    mov r10d, [r9]
    lea r11, [rbx + {PW_SET}]
    mov rax, [rbp - 0x08]
    mov [r11 + r10*8], rax
    inc r10d
    and r10d, 7
    mov [r9], r10d
    mov qword ptr [rbp - 0x10], 0
caveA_orig:
    mov rcx, [rbp - 0x08]
    mov rdx, [rbp - 0x10]
    lea rax, [rbx + {SETECHO_IAT}]
    mov rax, [rax]
    call rax
    mov rsp, rbp
    pop rbp
    pop rbx
    ret


caveB:
    mov eax, 0xCAFEB002
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    mov rbp, rsp
    sub rsp, 0x328
    mov [rbp - 0x08], rcx
    mov [rbp - 0x10], rdx
    call get_base
    mov rbx, rax
    mov rcx, [rbp - 0x08]
    mov rdx, [rbp - 0x10]
    lea rax, [rbx + {SETTEXT_IAT}]
    mov rax, [rax]
    call rax
    mov r12, [rbp - 0x08]
    lea r8, [rbx + {PW_SET}]
    xor r9d, r9d
caveB_scan:
    cmp r9d, 8
    jge caveB_done
    mov r13, [r8 + r9*8]
    test r13, r13
    je caveB_next
    cmp r13, r12
    je caveB_found
caveB_next:
    inc r9d
    jmp caveB_scan
caveB_found:
    call resolve_all
    mov rax, [rbx + {FN_UTF16}]
    test rax, rax
    je caveB_done
    mov rcx, [rbp - 0x10]
    call rax
    mov r13, rax
    test r13, r13
    je caveB_done
    xor r14d, r14d
caveB_len:
    movzx eax, word ptr [r13 + r14*2]
    test eax, eax
    je caveB_lend
    inc r14d
    cmp r14d, 0x80
    jb caveB_len
    jmp caveB_done
caveB_lend:
    test r14d, r14d
    je caveB_done
    lea rcx, [rbx + {STAMP}]
    lea rax, [rbx + {IAT_GSYST}]
    mov rax, [rax]
    call rax
    mov r15, [rbx + {STAMP}]
    lea rdi, [rbx + {LINEBUF}]
    xor r12d, r12d
caveB_hex:
    mov rax, r15
    mov ecx, 0x3C
    mov edx, r12d
    shl edx, 2
    sub ecx, edx
    shr rax, cl
    and eax, 0xF
    cmp eax, 0xA
    jb caveB_hexd
    add eax, 0x7
caveB_hexd:
    add eax, 0x30
    mov byte ptr [rdi + r12], al
    inc r12d
    cmp r12d, 0x10
    jb caveB_hex
    mov byte ptr [rdi + 0x10], 0x9
    mov ecx, 0xFDE9
    xor edx, edx
    mov r8, r13
    mov r9d, r14d
    lea r10, [rbx + {LINEBUF}]
    add r10, 0x11
    mov qword ptr [rsp + 0x20], r10
    mov qword ptr [rsp + 0x28], 0x3E8
    mov qword ptr [rsp + 0x30], 0
    mov qword ptr [rsp + 0x38], 0
    lea rax, [rbx + {IAT_WCTOMB}]
    mov rax, [rax]
    call rax
    test eax, eax
    jle caveB_done
    movsxd rdx, eax
    lea rdi, [rbx + {LINEBUF}]
    add rdi, 0x11
    mov byte ptr [rdi + rdx], 0xD
    mov byte ptr [rdi + rdx + 1], 0xA
    add edx, 0x13
    mov r14d, edx
    call open_log
    mov r13, rax
    cmp r13, -1
    je caveB_done
    mov rcx, r13
    lea rdx, [rbx + {LINEBUF}]
    mov r8d, r14d
    lea r9, [rbp - 0x20]
    mov qword ptr [rsp + 0x20], 0
    lea rax, [rbx + {FN_WF}]
    mov rax, [rax]
    call rax
    mov rcx, r13
    lea rax, [rbx + {FN_CH}]
    mov rax, [rax]
    call rax
caveB_done:
    mov rsp, rbp
    pop rsi
    pop rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


open_log:
    mov eax, 0xCAFEC003
    sub rsp, 0x38
    lea rcx, [rbx + {LOGPATH}]
    mov edx, 4
    mov r8d, 1
    xor r9d, r9d
    mov dword ptr [rsp + 0x20], 4
    mov dword ptr [rsp + 0x28], 0x80
    mov qword ptr [rsp + 0x30], 0
    lea rax, [rbx + {FN_CFW}]
    mov rax, [rax]
    call rax
    add rsp, 0x38
    ret


resolve_all:
    mov eax, 0xCAFED004
    push rbx
    push rbp
    push r12
    push rdi
    push rsi
    mov rbp, rsp
    sub rsp, 0x60
    call get_base
    mov rbx, rax
    lea rcx, [rbx + {DONE}]
    mov rax, [rcx]
    test rax, rax
    jnz resolve_ret
    lea rcx, [rbx + {STR_QT}]
    lea rax, [rbx + {IAT_GMHW}]
    mov rax, [rax]
    call rax
    mov [rbp - 0x08], rax
    test rax, rax
    je resolve_fail
    mov rcx, rax
    lea rdx, [rbx + {N_UTF16}]
    lea rax, [rbx + {IAT_GPA}]
    mov rax, [rax]
    call rax
    lea rcx, [rbx + {FN_UTF16}]
    mov [rcx], rax
    lea rcx, [rbx + {STR_K32}]
    lea rax, [rbx + {IAT_GMHW}]
    mov rax, [rax]
    call rax
    mov r12, rax
    test r12, r12
    je resolve_fail
    mov rcx, r12
    lea rdx, [rbx + {N_CFW}]
    lea rax, [rbx + {IAT_GPA}]
    mov rax, [rax]
    call rax
    lea rcx, [rbx + {FN_CFW}]
    mov [rcx], rax
    mov rcx, r12
    lea rdx, [rbx + {N_WF}]
    lea rax, [rbx + {IAT_GPA}]
    mov rax, [rax]
    call rax
    lea rcx, [rbx + {FN_WF}]
    mov [rcx], rax
    mov rcx, r12
    lea rdx, [rbx + {N_CH}]
    lea rax, [rbx + {IAT_GPA}]
    mov rax, [rax]
    call rax
    lea rcx, [rbx + {FN_CH}]
    mov [rcx], rax
    mov rcx, r12
    lea rdx, [rbx + {N_GTP}]
    lea rax, [rbx + {IAT_GPA}]
    mov rax, [rax]
    call rax
    lea rcx, [rbx + {FN_GTP}]
    mov [rcx], rax
    test rax, rax
    je resolve_fail
    mov ecx, 0x104
    lea rdx, [rbx + {LOGPATH}]
    call rax
    test eax, eax
    je resolve_fail
    movsxd r10, eax
    lea rdi, [rbx + {LOGPATH}]
    lea rsi, [rbx + {SUFFIX}]
    xor r11d, r11d
resolve_append:
    mov ax, [rsi + r11*2]
    mov [rdi + r10*2], ax
    test ax, ax
    je resolve_ok
    inc r10
    inc r11d
    jmp resolve_append
resolve_ok:
    lea rcx, [rbx + {DONE}]
    mov qword ptr [rcx], 1
resolve_ret:
    mov rsp, rbp
    pop rsi
    pop rdi
    pop r12
    pop rbp
    pop rbx
    ret
resolve_fail:
    lea rcx, [rbx + {FN_UTF16}]
    mov qword ptr [rcx], 0
    jmp resolve_ret
"""

def fmt():
    d = dict(subc="0x%x" % SUB_CONST,
             SETECHO_IAT="0x%x" % SETECHO_IAT,
             SETTEXT_IAT="0x%x" % SETTEXT_IAT,
             IAT_WCTOMB="0x%x" % IAT_WCTOMB,
             IAT_GSYST="0x%x" % IAT_GSYST,
             IAT_GMHW="0x%x" % IAT_GMHW,
             IAT_GPA="0x%x" % IAT_GPA)
    for k in off: d[k] = H(k)
    return d

MAGIC = {'caveA': 0xCAFEA001, 'caveB': 0xCAFEB002,
         'open_log': 0xCAFEC003, 'resolve_all': 0xCAFED004}

def assemble():
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_INTEL
    text = asm.format(**fmt())
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "asm_dump.txt"), "w", encoding="utf-8") as f:
        f.write(text)
        f.write("\n--- nonascii: %r\n" % [i for i, c in enumerate(text) if ord(c) > 127])
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    ks.syntax = KS_OPT_SYNTAX_INTEL
    cb, n = ks.asm(text, SEC_VA)
    if not cb or n <= 0:
        raise RuntimeError("keystone failed: n=%r" % (n,))
    code = bytes(cb)
    labels = {}
    for name, mg in MAGIC.items():
        pat = b'\xb8' + struct.pack('<I', mg)
        i = code.find(pat)
        if i < 0:
            raise RuntimeError("magic %s not found" % name)
        if code.find(pat, i+1) >= 0:
            raise RuntimeError("magic %s duplicated" % name)
        labels[name] = i            # 节内偏移 == RVA 偏移（节 VA 已按页对齐）
    # 关键立即数 lint：keystone(Intel) 把裸数字当十六进制，必须显式 0x
    from capstone import Cs as _Cs, CS_ARCH_X86 as _A, CS_MODE_64 as _M
    _cs = _Cs(_A, _M)
    seen = set("%s %s" % (ins.mnemonic, ins.op_str) for ins in _cs.disasm(code, SEC_VA))
    must = [
        "and eax, 0xf",
        "cmp eax, 0xa",
        "add eax, 0x30",
        "mov ecx, 0x3c",
        "cmp r12d, 0x10",
        "mov byte ptr [rdi + 0x10], 9",
        "mov ecx, 0xfde9",
        "add r10, 0x11",
        "mov qword ptr [rsp + 0x28], 0x3e8",
        "add rdi, 0x11",
        "add edx, 0x13",
        "cmp r14d, 0x80",
        "mov ecx, 0x104",
        "and r10d, 7",
        "cmp r9d, 8",
        "mov edx, 4",
        "mov r8d, 1",
    ]
    missing = [m for m in must if m not in seen]
    if missing:
        raise RuntimeError("immediate lint failed: %r" % missing)
    return code, labels

def build_section():
    sec = bytearray(CODE)
    if len(sec) > DATA_OFF:
        raise RuntimeError("code too big: %d > %d" % (len(sec), DATA_OFF))
    while len(sec) < DATA_OFF:
        sec.append(0x90)
    sec.extend(data)
    while len(sec) < SEC_SIZE:
        sec.append(0)
    return bytes(sec)

try:
    CODE, LABELS = assemble()
    CAVE_A_RVA = SEC_VOFF + LABELS['caveA']
    CAVE_B_RVA = SEC_VOFF + LABELS['caveB']
    SECTION = build_section()
except Exception:
    import traceback as _tb
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch_v2.log"),
              "w", encoding="utf-8") as _f:
        _f.write("BUILD FAIL:\n" + _tb.format_exc())
    raise

def build_section_legacy():
    sec = bytearray(CODE)
    if len(sec) > DATA_OFF:
        raise RuntimeError("code too big: %d > %d" % (len(sec), DATA_OFF))
    while len(sec) < DATA_OFF:
        sec.append(0x90)
    sec.extend(data)
    while len(sec) < SEC_SIZE:
        sec.append(0)
    return bytes(sec)

def rva_to_off(secs, rva):
    for (name, vsize, voff, rsize, roff, flags) in secs:
        if voff <= rva < voff + rsize:
            return roff + (rva - voff)
    return None

def patch(src, dst):
    raw = bytearray(open(src, 'rb').read())
    e_lfanew = u32(raw, 0x3c)
    opt = e_lfanew + 24
    if u16(raw, opt) != 0x20b:
        raise RuntimeError("not PE32+")
    if u64(raw, opt + 24) != IMAGE_BASE:
        raise RuntimeError("unexpected image base 0x%x" % u64(raw, opt + 24))
    num_sec = u16(raw, e_lfanew + 6)
    sec_off = opt + u16(raw, e_lfanew + 20)
    secs = []
    for i in range(num_sec):
        o = sec_off + i*40
        secs.append((raw[o:o+8].split(b'\x00')[0].decode('latin1'),
                     u32(raw,o+8), u32(raw,o+12), u32(raw,o+16), u32(raw,o+20), u32(raw,o+36)))
    for s in secs:
        if s[0] == '.unispw':
            raise RuntimeError("already patched")
    text = [s for s in secs if s[0] == '.text'][0]
    tname, tvs, tva, trs, tro, tfl = text

    # ---- 重定向调用点： FF 15 disp32 (6B) -> E8 rel32 + 90
    nA = nB = 0
    p = tro
    end = tro + trs - 6
    while p < end:
        if raw[p] == 0xFF and raw[p+1] == 0x15:
            disp = struct.unpack_from('<i', raw, p+2)[0]
            call_rva = tva + (p - tro)
            tgt = call_rva + 6 + disp
            if tgt in (SETECHO_IAT, SETTEXT_IAT):
                cave = CAVE_A_RVA if tgt == SETECHO_IAT else CAVE_B_RVA
                rel = cave - (call_rva + 5)
                if not (-0x80000000 <= rel <= 0x7fffffff):
                    raise RuntimeError("rel32 out of range")
                raw[p] = 0xE8
                struct.pack_into('<i', raw, p+1, rel)
                raw[p+5] = 0x90
                if tgt == SETECHO_IAT: nA += 1
                else: nB += 1
        p += 1
    print("call sites redirected: setEchoMode=%d setText=%d" % (nA, nB))
    if nA != 1 or nB != 10:
        raise RuntimeError("unexpected call-site count (expect 1 / 10)")

    # ---- 追加新节
    while len(raw) % 0x200:
        raw.append(0)
    sec_raw = len(raw)
    raw.extend(SECTION)

    hdr = b'.unispw'.ljust(8, b'\x00')
    hdr += struct.pack('<I', SEC_SIZE)
    hdr += struct.pack('<I', SEC_VOFF)
    hdr += struct.pack('<I', SEC_SIZE)
    hdr += struct.pack('<I', sec_raw)
    hdr += struct.pack('<I', 0) * 2
    hdr += struct.pack('<H', 0) * 2
    hdr += struct.pack('<I', 0xE0000020)
    assert len(hdr) == 40
    raw[sec_off + num_sec*40: sec_off + num_sec*40 + 40] = hdr
    struct.pack_into('<H', raw, e_lfanew + 6, num_sec + 1)
    struct.pack_into('<I', raw, opt + 56, SEC_VOFF + SEC_SIZE)   # SizeOfImage

    with open(dst, 'wb') as f:
        f.write(raw)
    return dict(caveA=CAVE_A_RVA, caveB=CAVE_B_RVA, size=len(raw),
                nA=nA, nB=nB, sec_raw=sec_raw, off=off, labels=LABELS)

if __name__ == '__main__':
    import traceback
    logp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch_v2.log")
    lg = open(logp, "w", encoding="utf-8")
    def L(*a):
        lg.write(" ".join(str(x) for x in a) + "\n"); lg.flush()
    try:
        src = r"C:\Program Files (x86)\UNISUnzip\UNISUnzip.exe"
        dst = str(Path(__file__).resolve().parent / "build" / "UNISUnzip.exe")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        info = patch(src, dst)
        L("code len =", len(CODE))
        L("labels   =", {k: hex(v) for k, v in info['labels'].items()})
        L("caveA_rva =", hex(info['caveA']), " caveB_rva =", hex(info['caveB']))
        L("out      =", dst, info['size'], "bytes")
        L("sec_raw  = 0x%x" % info['sec_raw'])
        L("data off =", {k: hex(v) for k, v in info['off'].items()})
        L("DONE_PATCH_V2")
    except Exception:
        L("FAIL:\n" + traceback.format_exc())
    finally:
        lg.close()
