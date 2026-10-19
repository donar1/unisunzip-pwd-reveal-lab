# UNISUnzip 密码显形实验室

**unisunzip-pwd-reveal-lab** — 一个二进制补丁 + 逆向分析技术研究项目：在无源码条件下，通过 PE 代码洞穴（code cave）注入，接管 Qt `QLineEdit::setEchoMode` / `setText`，使 UNISUnzip「查找密码」功能的显示由圆点变为明文，并将写入密码框的文本落盘到 `%TEMP%\UNISUnzip_pwd_log.txt`。

> A binary-patching & reverse-engineering research project: no source code available, so it takes the PE code-cave injection route to hook Qt's `QLineEdit::setEchoMode`/`setText` in UNISUnzip, turning the "find password" result from dots into plaintext and logging it.

---

## ⚠️ 免责声明 / Disclaimer

**本项目仅供安全研究、逆向工程教学与密码恢复技术演示。**

- 仅可对**您自己拥有或已获得明确授权**的压缩文件使用本技术；
- **不得**用于规避他人数据的访问保护、窃取密码或任何未授权用途；
- 分发规避技术措施的工具在部分司法辖区可能触犯法律（如中国《著作权法》《计算机软件保护条例》相关条款、美国 DMCA 第 1201 条），使用者需自行评估并承担全部责任；
- 作者不对任何滥用行为负责。

**For security research, reverse-engineering education, and password-recovery technique demonstration only. Use only on archives you own or are explicitly authorized to access.**

---

## 技术方案 / How it works

无源码，走「二进制补丁 + 代码洞穴」路线：

1. 在 exe 尾部新增节 `.unispw`（VA `0x7f000`），放置两段注入代码；
2. 将 exe 内 11 处调用点原地改写跳进洞穴：
   - `QLineEdit::setEchoMode`（全 exe 仅 1 处调用，下传值 `3 = PasswordEchoOnEdit`）—— 强制改为 `0 = Normal`；
   - `QLineEdit::setText`（10 处）—— 凡写进密码框的文本追加落盘；
3. 洞穴代码全部使用 RIP/ImageBase 相对寻址，**兼容 ASLR**，无需改重定位表；
4. 日志路径运行时 `GetTempPathW()` 动态获取（目标程序为 `asInvoker`，`Program Files` 对普通用户只读，写死必失败）；
5. 每个函数入口精算 16 字节栈对齐，符合 Win64 ABI（Qt 内含 SSE 对齐指令，错位即崩）。

工程细节与踩坑记录（5 个致命缺陷的定位与修复、keystone 立即数陷阱等）详见 **[docs/writeup.md](docs/writeup.md)**。

## 仓库结构 / Layout

```
unisunzip-pwd-reveal-lab/
├── README.md
├── LICENSE                  # MIT
├── requirements.txt
├── docs/
│   └── writeup.md           # 完整技术 writeup：方案、踩坑、验证
└── tools/
    ├── patch_unis_v2.py     # 核心：PE 补丁生成器（代码洞穴 + 调用点改写）
    ├── verify_v2.py         # 反汇编校验补丁结果（capstone）
    ├── verify_load.py       # 补丁 exe 加载/完整性校验
    ├── emu_v2.py            # Unicorn 仿真：跑洞穴代码，验证钩子逻辑
    ├── emu_nonvol.py        # Unicorn 仿真：非易失路径验证
    ├── iat_map.py           # IAT 映射分析
    ├── callsite_flow.py     # 调用点控制流追踪
    ├── check_syms.py        # Qt DLL 符号解析检查（QString::utf16 在 Qt5Core 而非 Qt5Widgets）
    └── probes/              # 侦查阶段脚本（定位钩子点/IAT 引用/字符串）
        ├── probe_hookpt.py
        ├── probe_iat_ref.py
        ├── probe_json.py
        ├── probe_meta.py
        ├── probe_settext_src.py
        ├── probe_title.py
        └── probe_title_str.py
```

**有意未包含 / Intentionally excluded**：补丁后的二进制、第三方 DLL（Qt / ZMCoreUnZip 等）、便携版打包产物、密码台账 UI 及其数据采集管线 —— 避免分发规避产物与真实凭证。技术路线已在 writeup 中完整说明，可按需自行重建。

## 环境要求 / Requirements

- Python 3.8+
- `pip install -r requirements.txt`（keystone-engine / unicorn / capstone）
- 目标程序 `UNISUnzip.exe`（Qt 5.15 Widgets，PE32+ x64）需自备；补丁输出到 `build/UNISUnzip.exe`

## 使用 / Usage

```bash
# 1. 生成补丁（默认读取 tools/UNISUnzip.exe，输出到 tools/build/UNISUnzip.exe）
python tools/patch_unis_v2.py

# 2. 校验补丁（反汇编比对调用点与洞穴代码）
python tools/verify_v2.py

# 3. 仿真验证钩子逻辑（无需运行目标程序）
python tools/emu_v2.py
```

## 验证 / Verification

- 反汇编校验：11 处调用点改写、洞穴代码字节级比对通过；
- Unicorn 仿真：`setEchoMode(3)` → 强制 `0`、`setText` 落盘路径 `%TEMP%\UNISUnzip_pwd_log.txt`（FILETIME + TAB + 明文 UTF-8）均按预期触发。

完整记录见 [docs/writeup.md](docs/writeup.md)。

## 许可 / License

MIT，见 [LICENSE](LICENSE)。
