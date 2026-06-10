# BinaryHammer

A fast, lightweight PE reverse engineering tool for Windows — built for malware analysts who want to spend time on decisions, not mechanics.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-C%2B%2B20-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

Load a PE binary and immediately get:

- **Disassembly** — x86/x64 via Zydis, with hover tooltips explaining each instruction. Click any call or jump to navigate to the target.
- **Pseudo-code** — an in-process lifter translates the disassembly into readable C-like code with syntax highlighting. No external decompiler needed.
- **Imports & Exports** — full tree view of every imported function, with malware-relevance tooltips for ~130 common Win32 APIs (`VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`, etc.).
- **Sections** — entropy-colored table (red = packed/encrypted) with per-flag tooltips explaining every `IMAGE_SCN_*` characteristic.
- **Hex View** — lazy-rendered (handles arbitrarily large files), section-colored bytes, hover shows offset/value, navigate directly from strings or disassembly.
- **Strings** — ASCII and UTF-16LE extraction with live filter. Double-click to jump the hex view to that offset.
- **PE Headers** — collapsible DOS / File / Optional header tables with field-level tooltips (what the field means, malware relevance, expected values).
- **Function Explorer** — entry point + all named exports + prologue-scan discovered functions. Click to disassemble and lift.
- **Console** — built-in command line with `.info`, `.strings`, `.goto <rva>`, and `.help`.

---

## Screenshots

> Load a PE, select a function in the explorer, and the disassembly and pseudo-code panels update instantly.

---

## Building

### Requirements

- Windows 10/11
- Visual Studio 2022 (with C++ Desktop workload)
- CMake 3.28+
- vcpkg (bundled with VS 2022 at `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg`)

### Steps

Open a VS 2022 Developer Command Prompt:

```bat
git clone https://github.com/harryc295/binary-slammer.git
cd binary-slammer
cmake -S . -B build
cmake --build build --config Release
.\build\Release\app.exe
```

CMake uses the vcpkg manifest (`vcpkg.json`) to automatically install dependencies — no manual vcpkg install needed.

### Dependencies (auto-installed via vcpkg)

| Package | Purpose |
|---------|---------|
| `glfw3` | Window creation and input |
| `opengl` | Rendering backend |
| `zydis` | x86/x64 disassembly engine |

ImGui (docking branch) is bundled in `incl/`.

---

## Usage

1. Launch `app.exe` — a welcome dialog appears.
2. Click **Load File** or use **File → Open** to pick a PE (`.exe`, `.dll`, `.sys`).
3. The tool parses the binary and auto-disassembles the entry point.
4. Use the **Function Explorer** on the left to switch between functions.
5. The **Disassembly** and **Pseudo Code** panels update for the selected function.
6. Double-click any import name to see its API description. Double-click a string to jump to it in the hex view.

### Console commands

```
.info                  — print binary summary (arch, entry point, section/import counts)
.goto <hex_rva>        — scroll hex view to a file offset
.strings [min_len]     — dump extracted strings to the console
.help                  — list all commands
```

---

## Architecture

```
src/
├── binary/
│   ├── binary.h / .cpp       — PE parser (sections, imports, exports, strings, functions)
│   └── disassembler.h / .cpp — Zydis wrapper, instruction tooltips
├── decompiler/
│   └── lifter.h / .cpp       — in-process pseudo-code lifter (disasm_t → C-like output)
├── data/
│   ├── api_descriptions.h    — ~130 Win32 API descriptions with malware context
│   └── section_flags.h       — IMAGE_SCN_* flag descriptions and tooltips
├── rendering/
│   ├── ui.h / .cpp           — all 10 ImGui panels, docking layout, file loading
│   ├── nav_state.h           — cross-panel navigation (hex offset, disasm RVA)
│   └── file_prompt.h         — Windows IFileOpenDialog wrapper
├── console_handler.h / .cpp  — command parser
├── logger.h                  — session logging to binaryhammer.log
└── main.cpp                  — entry point, window loop
```

The lifter works entirely in-process: Zydis decodes instructions into `disasm_t` structs, the lifter pattern-matches on mnemonics and operands to produce `pseudo_line_t` structs, and the UI renders them with syntax highlighting. No external tools required.

---

## Panels

| Panel | Description |
|-------|-------------|
| Function Explorer | Sorted list of all discovered functions. Click to select. |
| Disassembly | 4-column table: address, bytes, mnemonic (colored), operands. |
| Pseudo Code | Lifted C-like code for the selected function. |
| Hex View | Full file hex dump, section-colored, lazy rendered. |
| Imports | DLL → function tree with API tooltips. |
| Exports | Ordinal, RVA, name, forwarder detection. |
| Sections | VA, sizes, entropy bar, characteristic flags. |
| Strings | Filterable ASCII/UTF-16LE string table. |
| PE Headers | DOS, File, Optional header field breakdown. |
| Console | Command input and session log. |

---

## Roadmap

- [ ] Signature-based pattern matching (YARA integration)
- [ ] Cross-reference (xrefs) view — where is this function called from?
- [ ] Rename functions and add comments (persisted per binary)
- [ ] Import hash (ImpHash) and section hash display
- [ ] Dark/light theme toggle
- [ ] Linux support (file dialog + PE parser already partially ported)

---

## License

MIT — see [LICENSE](LICENSE).
