#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "../binary/binary.h"

struct security_finding_t {
    std::string category;
    std::string title;
    std::string description;
    std::string bypass;
    int severity; // 1=info, 2=warning, 3=critical
};

struct antidebug_entry_t {
    const char *func;
    const char *description;
    const char *bypass;
    int severity;
};

static const antidebug_entry_t k_antidebug_apis[] = {
    {"IsDebuggerPresent",
     "Reads PEB.BeingDebugged flag. Returns non-zero when a debugger is attached.",
     "Patch PEB+2 byte to 0, or hook the function to always return 0.",
     2},
    {"CheckRemoteDebuggerPresent",
     "Queries kernel via NtQueryInformationProcess(ProcessDebugPort) for a remote debugger.",
     "Hook to force *pbDebuggerPresent = FALSE before returning.",
     2},
    {"NtQueryInformationProcess",
     "ProcessDebugPort (class 7) returns non-zero under a debugger. "
     "ProcessDebugFlags (class 0x1F) returns 0 under a debugger.",
     "ScyllaHide plugin; patch the return/out value at call site.",
     3},
    {"ZwQueryInformationProcess",
     "Syscall alias for NtQueryInformationProcess — same anti-debug use.",
     "Same as NtQueryInformationProcess bypass.",
     3},
    {"NtSetInformationThread",
     "ThreadHideFromDebugger (class 0x11) hides a thread from the debugger's thread list.",
     "Hook and no-op calls where InformationClass == 0x11 (ScyllaHide handles this).",
     3},
    {"ZwSetInformationThread",
     "Syscall alias for NtSetInformationThread.",
     "Same as NtSetInformationThread bypass.",
     3},
    {"GetThreadContext",
     "Reads DR0-DR7 hardware debug registers to detect software breakpoints.",
     "Hook GetThreadContext and zero DR0-DR7 in the returned CONTEXT structure.",
     2},
    {"SetThreadContext",
     "May be used to clear debug registers or hijack execution flow.",
     "Monitor calls; ScyllaHide handles common abuse patterns.",
     1},
    {"FindWindowA",
     "Searches for debugger/tool windows by class or title string (e.g. 'x64dbg', 'OLLYDBG').",
     "Hook FindWindowA and return NULL for known debugger window class/title names.",
     2},
    {"FindWindowW",
     "Wide-char version of FindWindowA — same debugger window scan.",
     "Hook FindWindowW and return NULL.",
     2},
    {"GetTickCount",
     "Timing-based anti-debug: measures wall time; large delta implies single-stepping.",
     "Hook to return a monotonically incrementing constant (e.g. +1 per call).",
     1},
    {"GetTickCount64",
     "64-bit timing check variant.",
     "Hook to return constant + small increment.",
     1},
    {"QueryPerformanceCounter",
     "High-resolution timing; single-stepping produces anomalously large deltas.",
     "Hook and return spoofed monotonic values.",
     1},
    {"OutputDebugStringA",
     "GetLastError trick: under no debugger, this sets last error to a specific value.",
     "Hook to suppress or ignore; rarely critical in modern binaries.",
     1},
    {"OutputDebugStringW",
     "Wide-char OutputDebugStringA variant with same error-code trick.",
     "Hook to suppress.",
     1},
    {"CreateToolhelp32Snapshot",
     "Enumerates running processes to detect debugger executables (x64dbg.exe etc.).",
     "Hook to hide debugger process entries from snapshot results.",
     2},
    {"NtQuerySystemInformation",
     "Queries system-wide info; used for VM/sandbox/debugger detection.",
     "Hook and spoof suspicious result fields.",
     2},
    {"SetUnhandledExceptionFilter",
     "Replaces top-level SEH; under a debugger the debugger intercepts exceptions first.",
     "Pass exceptions to the application: Shift+F9 in x64dbg.",
     1},
    {"RaiseException",
     "SEH-based exception trick to detect whether a debugger is handling exceptions.",
     "Pass exceptions to the application in the debugger.",
     1},
};

struct packer_sig_t {
    const char *section_name;
    const char *packer;
    const char *bypass;
    int severity;
};

static const packer_sig_t k_packer_sigs[] = {
    {".vmp0",    "VMProtect",
     "Use an OEP finder with x64dbg; ScyllaHide hides the debugger. "
     "VMProtect entry stubs are a PUSH + CALL into a high-entropy section. "
     "Set a bp on VirtualProtect to catch the unpacking stub, then dump+fix IAT with Scylla.",
     3},
    {".vmp1",    "VMProtect",
     "Same as .vmp0 — this is the second VMProtect section (often the virtualized code).",
     3},
    {".vmp2",    "VMProtect",
     "Third VMProtect section.",
     3},
    {".vmp",     "VMProtect",
     "Generic VMProtect section name.",
     3},
    {".themida", "Themida / WinLicense",
     "OEP hunt via VirtualProtect bp. Dump the unpacked image with Scylla after OEP is reached.",
     3},
    {".winlicen","WinLicense",
     "Same approach as Themida.",
     3},
    {"UPX0",     "UPX Packer",
     "Self-decompressing. Simply run: upx -d binary.exe to recover the original.",
     3},
    {"UPX1",     "UPX Packer",
     "Run: upx -d binary.exe",
     3},
    {"UPX2",     "UPX Packer",
     "UPX stub section.",
     2},
    {".nsp0",    "NSPack",
     "OEP hunt: look for POPAD near end of packed section, then dump+fix IAT with Scylla.",
     2},
    {".nsp1",    "NSPack",
     "NSPack data section.",
     2},
    {".petite",  "Petite Packer",
     "OEP hunt: find POPAD/JMP sequence. Dump and fix IAT with Scylla.",
     2},
    {"petite",   "Petite Packer",
     "Petite stub section.",
     2},
    {".aspack",  "ASPack",
     "OEP hunt via POPAD pattern. Dump with Scylla.",
     2},
    {".adata",   "ASProtect",
     "Use ASProtect-aware unpackers or OEP hunt past the anti-dump code.",
     2},
    {".MPRESS1", "MPRESS",
     "Run mpress -d binary.exe or OEP hunt via breakpoint.",
     2},
    {".MPRESS2", "MPRESS",
     "MPRESS data section.",
     2},
};

inline std::vector<security_finding_t> analyze_security(
        const std::vector<import_t> &imports,
        const std::vector<section_t> &sections)
{
    std::vector<security_finding_t> findings;

    for (const auto &imp : imports) {
        if (imp.by_ordinal) continue;
        for (const auto &e : k_antidebug_apis) {
            if (imp.function == e.func) {
                security_finding_t f;
                f.category    = "Anti-Debug";
                f.title       = std::string("Imports ") + e.func;
                f.description = e.description;
                f.bypass      = e.bypass;
                f.severity    = e.severity;
                findings.push_back(std::move(f));
                break;
            }
        }
    }

    for (const auto &sec : sections) {
        for (const auto &sig : k_packer_sigs) {
            if (sec.name == sig.section_name) {
                security_finding_t f;
                f.category    = sig.packer;
                f.title       = std::string("Section '") + sec.name + "' detected";
                f.description = std::string(sig.packer) + " protection identified by section name '" + sec.name + "'.";
                f.bypass      = sig.bypass;
                f.severity    = sig.severity;
                findings.push_back(std::move(f));
                break;
            }
        }
    }

    return findings;
}
