# BinaryHammer

A fast, lightweight PE reverse engineering tool for Windows — built for anyone who wants to understand what a binary does, from beginners to experienced analysts.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-C%2B%2B20-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

Load a PE binary (`.exe`, `.dll`, `.sys`) and immediately get a full analysis — no setup, no scripts, no external tools.

On first launch a 4-page onboarding guide walks you through every panel, how to use them, and optional API key setup. Re-open it any time from **Help → About / Help**.

### Analysis & Overview
- **Threat Overview** — 0–100 threat score with colour-coded verdict (Likely Clean / Suspicious / Likely Malicious / Highly Suspicious). Plain-English summary of what the binary does, key findings bullet list, and a "Is This Normal?" table comparing each property to expected ranges. Import behaviour category badges show at a glance what capability groups are present.
- **Security Analysis** — signature-based detection of packers, protectors, anti-debug tricks, and suspicious patterns with per-finding descriptions.
- **YARA** — run custom YARA rules against the loaded binary. Add `yara` to `vcpkg.json` to enable (CMake detects it automatically via `HAVE_YARA`).

### Code Analysis
- **Disassembly** — x86/x64 via Zydis, 4-column table (address / bytes / mnemonic / operands). Click any call or jump to navigate to the target. Toggle **Explain mode** for plain-English annotations on every instruction (e.g. `xor eax, eax` → "Zero out eax"). Add per-instruction comments that persist between sessions.
- **Pseudo Code** — in-process lifter translates disassembly into readable C-like code with syntax highlighting. No external decompiler needed.
- **LLVM IR** — optional LLVM IR lifting panel. Enabled automatically if LLVM is found via vcpkg.
- **Call Graph** — visual call graph for the selected function.
- **Function Explorer** — entry point + all named exports + prologue-discovered functions. Click to disassemble.

### PE Structure
- **Imports** — two views: **By DLL** (tree) and **By Category** (coloured tabs grouping APIs into Networking / File I/O / Process Injection / Anti-Analysis / Persistence / Crypto / Process Mgmt / Memory / System Info / UI). Hover for per-API descriptions and malware context.
- **Exports** — ordinal, RVA, name, forwarder detection.
- **Sections** — entropy-coloured table. Click any row to expand a description card explaining the section's purpose, entropy interpretation, and hash. Highlights W+X (writable + executable) sections.
- **PE Headers** — collapsible DOS / File / Optional header field breakdown with tooltips explaining each field and its malware relevance.
- **Resources** — resource directory tree with type names and counts.

### Utilities
- **Strings** — ASCII and UTF-16LE extraction with live filter. Double-click to jump to the offset in Hex View.
- **Hex View** — full file hex dump, section-coloured, lazy-rendered (handles any file size). Navigate directly from strings or disassembly.
- **Search** — search across strings, imports, and function names.
- **Bookmarks** — save and name any RVA, jump back instantly.
- **Console** — built-in command line with `.info`, `.strings`, `.goto <rva>`, and `.help`.
- **Settings → API Keys** — store optional VirusTotal / MalwareBazaar API keys locally for future threat-intel lookups. Keys never leave your machine. Set up during onboarding or any time after.

---

## Threat Scoring

BinaryHammer's threat score uses context-aware heuristics — indicators are not counted independently when they share a root cause.

| What it detects | Score |
|---|---|
| Very high entropy section (>7.0) | +20 (once, not per section) |
| Packer / installer detected | +20 (capped, not per signature) |
| W+X section (executable + writable) | +18 |
| Full injection triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) | +45 |
| Process hollowing pattern | +38 |
| Keylogger pattern (SetWindowsHookEx + GetAsyncKeyState) | +35 |
| C2/dropper pattern (network + persistence, unpacked only) | +25 |
| Anti-debug cluster (2+ techniques) | +20 |
| Anti-debug APIs (reduced in packer context) | up to +30 |
| High-confidence IOC strings (shellcode, meterpreter, mimikatz…) | up to +30 |
| Cross-process injection APIs | up to +25 |
| TLS callbacks | +10 |
| PE overlay (unpacked only) | +10 |
| RT_VERSION resource | −8 |
| RT_MANIFEST resource | −5 |
| 5+ distinct imported DLLs | −5 |

**Correlated indicators are suppressed**: when a packer is detected, "few imports", "PE overlay", the network+persistence cluster, and anti-debug penalties are reduced or skipped — because those are expected consequences of packing, not independent red flags.

**Verdicts**: Likely Clean (<25) · Suspicious (25–49) · Likely Malicious (50–74) · Highly Suspicious (75+)

> A legitimate NSIS installer like Git's setup typically scores ~30 (Suspicious) — honest, since we can't verify what it unpacks without running it.

---

## Building

### Requirements

- Windows 10/11
- Visual Studio 2022 (C++ Desktop workload)
- CMake 3.28+
- vcpkg (bundled with VS 2022)

### Steps

Open a VS 2022 Developer Command Prompt:

```bat
git clone https://github.com/harryc295/Binary-slammer.git
cd Binary-slammer
cmake -S . -B build
cmake --build build --config Release
.\build\Release\binaryslammer.exe
```

vcpkg handles all dependencies automatically via `vcpkg.json`.

### Linux

Same UI, same codebase — Dear ImGui draws everything itself, so nothing native-themed differs between platforms.

```sh
sudo apt install libgl1-mesa-dev libxrandr-dev libxinerama-dev libxcursor-dev \
  libxi-dev libxext-dev libwayland-dev libxkbcommon-dev wayland-protocols

git clone https://github.com/harryc295/Binary-slammer.git
cd Binary-slammer
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
./build/binaryslammer
```

`zenity` or `kdialog` is used for the native file-open dialog — install whichever your desktop ships with.

### Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `glfw3` | Window + input | Yes |
| `opengl` | Render backend | Yes |
| `zydis` | x86/x64 disassembly | Yes |
| `yara` | YARA rule scanning | Optional — add to vcpkg.json to enable |
| `llvm` | IR lifting panel | Optional — detected automatically |

ImGui (docking branch) is bundled in `incl/`.

---

## Usage

1. Launch `binaryslammer.exe` — the window opens maximised with a custom app icon.
2. A **4-page onboarding guide** appears on first run, covering every panel, workflow, and optional API key setup. Dismiss it and it won't show again; reopen it any time via **Help → About / Help**.
3. **File → Open** (or `Ctrl+O`) to load a PE.
4. The **Overview** panel gives an immediate threat assessment.
5. Use **Function Explorer** to navigate functions — **Disassembly** and **Pseudo Code** update instantly.
6. Toggle **Explain** in the Disassembly toolbar for plain-English instruction annotations.
7. Click any section row in **Sections** to expand its description card.
8. Switch **Imports → By Category** for a behaviour-grouped view of what the binary does.

### Console commands

```
.info                — binary summary (arch, entry point, counts)
.goto <hex_rva>      — scroll hex view to offset
.strings [min_len]   — dump strings to console
.help                — list all commands
```

---

## Panels

| Panel | What it shows |
|-------|--------------|
| Overview | Threat score, verdict, narrative, findings, stats table, category badges |
| Function Explorer | All discovered functions — click to disassemble |
| Disassembly | Address / bytes / mnemonic / operands with Explain mode and comments |
| Pseudo Code | Lifted C-like code for the selected function |
| LLVM IR | LLVM IR output (requires LLVM via vcpkg) |
| Call Graph | Visual call graph for the selected function |
| Imports | DLL tree + category tabs with API descriptions |
| Exports | Ordinal, RVA, name, forwarder info |
| Sections | Entropy table + per-section description cards |
| PE Headers | DOS / File / Optional header field breakdown |
| Resources | Resource directory tree |
| Strings | Filterable ASCII/UTF-16LE table |
| Hex View | Full file hex dump, section-coloured, lazy-rendered |
| Security Analysis | Packer, anti-debug, and suspicious pattern findings |
| YARA | Rule scanning (optional) |
| Search | Search across strings, imports, functions |
| Bookmarks | Named RVA bookmarks |
| Console | Command input and session log |

---

## Architecture

```
src/
├── analysis/
│   ├── import_categories.h   — 11 import behaviour categories + classification
│   ├── overview.h            — threat scoring, narrative, stats computation
│   ├── asm_annotate.h        — plain-English x86/x64 instruction annotations
│   └── security_analyzer.h  — packer/anti-debug signature detection
├── binary/
│   ├── binary.h / .cpp       — PE parser (sections, imports, exports, strings, TLS…)
│   └── disassembler.h / .cpp — Zydis wrapper + instruction metadata
├── decompiler/
│   └── lifter.h / .cpp       — in-process pseudo-code lifter
├── ir/
│   └── ir_lifter.h / .cpp    — LLVM IR lifter (HAVE_LLVM guard)
├── rendering/
│   ├── ui.h / .cpp           — all panels, docking layout, onboarding, file loading
│   ├── app_icon.h            — embedded 32×32 RGBA app icon (orange hammer)
│   ├── nav_state.h           — cross-panel navigation state
│   └── file_prompt.h         — Windows IFileOpenDialog wrapper
├── data/
│   ├── api_descriptions.h    — Win32 API descriptions with malware context
│   ├── api_settings.h        — VirusTotal / MalwareBazaar API key persistence
│   ├── open_url.h             — opens a URL in the system browser (sign-up links)
│   └── section_flags.h       — IMAGE_SCN_* flag descriptions
├── assets/
│   └── icon.ico              — multi-resolution icon (16/32/48px) for the exe
├── logger.h                  — session log → binaryhammer.log
└── main.cpp                  — entry point and window loop
```

---

## License

MIT — see [LICENSE](LICENSE).
