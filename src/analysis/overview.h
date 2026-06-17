#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include "import_categories.h"
#include "security_analyzer.h"
#include "../binary/binary.h"

// ── Data structures ───────────────────────────────────────────────────────────

struct overview_stat_t {
    std::string label;
    std::string value;
    std::string normal_range;
    std::string note;
    bool ok;
};

struct overview_t {
    int score{};
    std::string verdict;
    std::vector<std::string> findings;
    std::string narrative;
    std::vector<overview_stat_t> stats;
    std::map<import_cat_t, int> cat_counts;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static inline bool str_icontains(const std::string &hay, const char *needle) {
    std::string h = hay, n = needle;
    for (auto &c : h) c = (char)std::tolower((unsigned char)c);
    for (auto &c : n) c = (char)std::tolower((unsigned char)c);
    return h.find(n) != std::string::npos;
}

// ── Main computation ──────────────────────────────────────────────────────────

inline overview_t compute_overview(
        const std::vector<section_t>          &sections,
        const std::vector<import_t>           &imports,
        const std::vector<float>              &entropies,
        const std::vector<security_finding_t> &sec_findings,
        bool                                   is_64bit,
        bool                                   has_overlay,
        const std::vector<uint64_t>           &tls_callbacks,
        const std::vector<string_t>           &strings,
        const std::vector<pe_resource_type_t> &resource_types)
{
    overview_t out;
    int score = 0;

    // ── Category counts (named imports only) ──────────────────────────────────
    for (const auto &imp : imports) {
        if (imp.by_ordinal) continue;
        import_cat_t cat = classify_import(imp.function);
        out.cat_counts[cat]++;
    }

    // Fast import presence check
    auto has_import = [&](const char *fn) -> bool {
        for (const auto &imp : imports)
            if (!imp.by_ordinal && imp.function == fn)
                return true;
        return false;
    };
    // Prefix import check (e.g. "SetWindowsHookEx" matches A/W variants)
    auto has_import_prefix = [&](const char *prefix) -> bool {
        for (const auto &imp : imports)
            if (!imp.by_ordinal && imp.function.rfind(prefix, 0) == 0)
                return true;
        return false;
    };

    // ── Entropy (capped: multiple packed sections = same root cause) ──────────
    bool any_very_high_entropy = false, any_elevated_entropy = false;
    for (size_t i = 0; i < sections.size() && i < entropies.size(); ++i) {
        float e = entropies[i];
        char buf[160];
        if (e > 7.0f) {
            std::snprintf(buf, sizeof(buf),
                "Section '%s' has very high entropy (%.1f/8.0) -- likely packed or encrypted",
                sections[i].name.c_str(), (double)e);
            if (out.findings.size() < 10) out.findings.push_back(buf);
            any_very_high_entropy = true;
        } else if (e >= 6.5f) {
            std::snprintf(buf, sizeof(buf),
                "Section '%s' has elevated entropy (%.1f/8.0) -- may contain compressed data",
                sections[i].name.c_str(), (double)e);
            if (out.findings.size() < 10) out.findings.push_back(buf);
            any_elevated_entropy = true;
        }
    }
    if (any_very_high_entropy)   score += 20;
    else if (any_elevated_entropy) score += 8;

    // ── Packer / installer detection (capped: multiple sigs = same binary) ────
    int antidebug_count = 0, packer_count = 0;
    for (const auto &f : sec_findings) {
        if (f.category == "Anti-Debug") {
            ++antidebug_count;
        } else {
            if (packer_count == 0) {
                char buf[160];
                std::snprintf(buf, sizeof(buf), "Packer/installer detected: %s (%s)",
                              f.category.c_str(), f.title.c_str());
                if (out.findings.size() < 10) out.findings.push_back(buf);
            }
            ++packer_count;
        }
    }
    if (packer_count > 0) score += 20;

    // ── W+X sections (executable AND writable = self-modifying code) ──────────
    {
        bool wx_found = false;
        for (const auto &s : sections) {
            bool exec  = (s.characteristics & 0x20000000u) != 0;
            bool write = (s.characteristics & 0x80000000u) != 0;
            if (exec && write) {
                char buf[128];
                std::snprintf(buf, sizeof(buf),
                    "Section '%s' is executable AND writable -- classic shellcode loader pattern",
                    s.name.c_str());
                if (out.findings.size() < 10) out.findings.push_back(buf);
                wx_found = true;
            }
        }
        if (wx_found) score += 18;
    }

    // ── Import cluster: classic process injection triad ───────────────────────
    {
        int c = (has_import("VirtualAllocEx")    ? 1 : 0)
              + (has_import("WriteProcessMemory") ? 1 : 0)
              + (has_import("CreateRemoteThread") ? 1 : 0);
        if (c == 3) {
            score += 45;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "Injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread");
        } else if (c == 2) {
            score += 22;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "Partial injection capability: 2 of 3 classic injection APIs present");
        }
    }

    // ── Import cluster: process hollowing ─────────────────────────────────────
    {
        bool unmap  = has_import("NtUnmapViewOfSection") || has_import("ZwUnmapViewOfSection");
        bool alloc  = has_import("VirtualAllocEx");
        bool write  = has_import("WriteProcessMemory");
        int c = (int)unmap + (int)alloc + (int)write;
        if (c >= 2) {
            score += 38;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "Process hollowing pattern: section unmapping + remote allocation + memory write");
        }
    }

    // ── Import cluster: keylogger ─────────────────────────────────────────────
    {
        bool hook = has_import_prefix("SetWindowsHookEx");
        bool key  = has_import("GetAsyncKeyState");
        if (hook && key) {
            score += 35;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "Keylogger pattern: SetWindowsHookEx + GetAsyncKeyState");
        }
    }

    // ── Import cluster: network + persistence (C2 dropper) ───────────────────
    {
        bool net     = has_import_prefix("InternetOpen")  || has_import("WSAStartup")
                    || has_import_prefix("WinHttpOpen")   || has_import("URLDownloadToFile");
        bool persist = has_import_prefix("RegCreateKey")  || has_import_prefix("RegSetValueEx")
                    || has_import_prefix("CreateService");
        if (net && persist) {
            score += 25;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "C2/dropper pattern: networking APIs combined with registry or service persistence");
        }
    }

    // ── Import cluster: active anti-debug (multiple techniques together) ──────
    {
        int c = (has_import("IsDebuggerPresent")                                         ? 1 : 0)
              + (has_import("CheckRemoteDebuggerPresent")                                ? 1 : 0)
              + ((has_import("NtQueryInformationProcess")
                  || has_import("ZwQueryInformationProcess"))                            ? 1 : 0)
              + (has_import("GetThreadContext")                                           ? 1 : 0)
              + (has_import("NtSetInformationThread") || has_import("ZwSetInformationThread") ? 1 : 0);
        if (c >= 2) {
            score += 20;
            if (out.findings.size() < 10)
                out.findings.push_back(
                    "Anti-debug cluster: multiple evasion techniques present together");
        }
    }

    // ── Single anti-debug APIs (if not already caught by cluster) ─────────────
    if (antidebug_count > 0) {
        score += std::min(30, antidebug_count * 10);
        char buf[128];
        std::snprintf(buf, sizeof(buf),
            "%d anti-debug API(s) imported -- binary actively resists analysis",
            antidebug_count);
        if (out.findings.size() < 10) out.findings.push_back(buf);
    }

    // ── Process injection (cross-process only, not LoadLibrary/GetProcAddress) ─
    int inj_count = 0;
    {
        auto it = out.cat_counts.find(import_cat_t::ProcessInjection);
        if (it != out.cat_counts.end()) inj_count = it->second;
    }
    if (inj_count > 0) {
        score += std::min(25, inj_count * 8);
        char buf[128];
        std::snprintf(buf, sizeof(buf),
            "%d cross-process manipulation API(s) (e.g. VirtualAllocEx, WriteProcessMemory)",
            inj_count);
        if (out.findings.size() < 10) out.findings.push_back(buf);
    }

    // ── Very few named imports (skip if packer detected -- expected consequence) ──
    int named_count = 0;
    for (const auto &imp : imports)
        if (!imp.by_ordinal) ++named_count;

    if (named_count < 5 && !imports.empty() && packer_count == 0) {
        score += 20;
        if (out.findings.size() < 10)
            out.findings.push_back(
                "Very few named imports -- import table may be obfuscated");
    }

    // ── TLS callbacks ─────────────────────────────────────────────────────────
    if (!tls_callbacks.empty()) {
        score += 10;
        char buf[96];
        std::snprintf(buf, sizeof(buf),
            "%zu TLS callback(s) -- code executes before the entry point",
            tls_callbacks.size());
        if (out.findings.size() < 10) out.findings.push_back(buf);
    }

    // ── PE overlay (skip penalty if packer/installer already detected) ────────
    if (has_overlay && packer_count == 0) {
        score += 10;
        if (out.findings.size() < 10)
            out.findings.push_back(
                "PE overlay present -- data appended after the last section");
    } else if (has_overlay) {
        if (out.findings.size() < 10)
            out.findings.push_back(
                "PE overlay present -- expected for self-extracting installers");
    }

    // ── Low section count ─────────────────────────────────────────────────────
    if (sections.size() < 3) {
        score += 12;
        char buf[96];
        std::snprintf(buf, sizeof(buf),
            "Only %zu PE section(s) -- unusually low, common in packed binaries",
            sections.size());
        if (out.findings.size() < 10) out.findings.push_back(buf);
    }

    // ── String IOC scanning ───────────────────────────────────────────────────
    // Only high-confidence keywords that essentially never appear in legit software
    {
        static const char *k_ioc_keywords[] = {
            "shellcode", "meterpreter", "mimikatz",
            "cobalt strike", "empire", "metasploit",
            "powershell -enc", "powershell -e ", "cmd.exe /c ",
            "WScript.Shell", "bypass amsi",
            nullptr
        };
        int ioc_score = 0;
        for (const auto &s : strings) {
            for (const char **kw = k_ioc_keywords; *kw; ++kw) {
                if (str_icontains(s.value, *kw)) {
                    char buf[160];
                    std::snprintf(buf, sizeof(buf),
                        "Suspicious string: \"%s\" contains '%s'", s.value.c_str(), *kw);
                    if (out.findings.size() < 10) out.findings.push_back(buf);
                    ioc_score += 15;
                    break;
                }
            }
            if (ioc_score >= 30) break; // cap
        }
        score += std::min(30, ioc_score);
    }

    // ── Legitimacy signals (reduce score for common benign indicators) ─────────
    {
        bool has_version_info = false, has_manifest = false;
        for (const auto &rt : resource_types) {
            if (rt.id == 16) has_version_info = true; // RT_VERSION
            if (rt.id == 24) has_manifest     = true; // RT_MANIFEST
        }
        if (has_version_info) score -= 8;
        if (has_manifest)     score -= 5;

        // Many distinct DLLs = diverse legitimate imports
        std::set<std::string> dlls;
        for (const auto &imp : imports)
            if (!imp.by_ordinal && !imp.dll.empty())
                dlls.insert(imp.dll);
        if ((int)dlls.size() >= 5) score -= 5;
    }

    // ── Clamp and verdict ─────────────────────────────────────────────────────
    out.score = std::clamp(score, 0, 100);

    if      (out.score < 25) out.verdict = "Likely Clean";
    else if (out.score < 50) out.verdict = "Suspicious";
    else if (out.score < 75) out.verdict = "Likely Malicious";
    else                     out.verdict = "Highly Suspicious";

    // ── Narrative ─────────────────────────────────────────────────────────────
    {
        auto has_cat = [&](import_cat_t cat) -> int {
            auto ci = out.cat_counts.find(cat);
            return (ci != out.cat_counts.end()) ? ci->second : 0;
        };

        std::string n;
        n += std::string("This is a ") + (is_64bit ? "64" : "32") + "-bit Windows executable.";

        if (packer_count > 0)
            n += " A packer or installer framework was detected, which means the real code may only be visible at runtime.";

        if (has_cat(import_cat_t::Networking) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It imports %d networking API(s).",
                          has_cat(import_cat_t::Networking));
            n += buf;
        }
        if (has_cat(import_cat_t::FileIO) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It performs file I/O (%d API(s)).",
                          has_cat(import_cat_t::FileIO));
            n += buf;
        }
        if (has_cat(import_cat_t::ProcessManagement) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It manages processes or threads (%d API(s)).",
                          has_cat(import_cat_t::ProcessManagement));
            n += buf;
        }
        if (inj_count > 0) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                " It uses %d cross-process manipulation API(s) -- a strong indicator of code injection.",
                inj_count);
            n += buf;
        }
        if (has_cat(import_cat_t::Persistence) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It accesses persistence mechanisms (%d API(s)).",
                          has_cat(import_cat_t::Persistence));
            n += buf;
        }
        if (has_cat(import_cat_t::Crypto) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It uses cryptographic APIs (%d API(s)).",
                          has_cat(import_cat_t::Crypto));
            n += buf;
        }
        if (has_cat(import_cat_t::SystemInfo) > 0) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), " It queries host system information (%d API(s)).",
                          has_cat(import_cat_t::SystemInfo));
            n += buf;
        }
        if (antidebug_count > 0) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                " %d anti-debug technique(s) detected -- the binary tries to resist analysis.",
                antidebug_count);
            n += buf;
        }
        if (any_very_high_entropy)
            n += " One or more sections have very high entropy, consistent with packing or encryption.";

        n += " Overall risk: " + out.verdict + ".";
        out.narrative = std::move(n);
    }

    // ── Stats rows ────────────────────────────────────────────────────────────
    {
        {
            overview_stat_t s;
            s.label        = "Section count";
            s.value        = std::to_string(sections.size());
            s.normal_range = "3-8";
            s.ok           = (sections.size() >= 3 && sections.size() <= 8);
            s.note         = s.ok ? "" : (sections.size() < 3 ? "Very few -- may be packed"
                                                               : "Unusually many sections");
            out.stats.push_back(std::move(s));
        }
        {
            overview_stat_t s;
            s.label        = "Named imports";
            s.value        = std::to_string(named_count);
            s.normal_range = "10-300";
            s.ok           = (named_count >= 10 && named_count <= 300);
            if (named_count < 5 && !imports.empty())
                s.note = "Very few -- may be packed";
            else if (!s.ok && named_count > 300)
                s.note = "Unusually many named imports";
            out.stats.push_back(std::move(s));
        }
        {
            overview_stat_t s;
            s.label        = "Architecture";
            s.value        = is_64bit ? "64-bit" : "32-bit";
            s.normal_range = "any";
            s.ok           = true;
            out.stats.push_back(std::move(s));
        }
        {
            overview_stat_t s;
            s.label        = "TLS callbacks";
            s.value        = std::to_string(tls_callbacks.size());
            s.normal_range = "0";
            s.ok           = tls_callbacks.empty();
            s.note         = tls_callbacks.empty() ? "" : "Pre-entry callbacks detected";
            out.stats.push_back(std::move(s));
        }
        {
            overview_stat_t s;
            s.label        = "PE overlay";
            s.value        = has_overlay ? "Yes" : "No";
            s.normal_range = "No";
            s.ok           = !has_overlay;
            s.note         = has_overlay ? (packer_count > 0 ? "Expected for installers"
                                                             : "Data after last section") : "";
            out.stats.push_back(std::move(s));
        }
        {
            overview_stat_t s;
            s.label        = "Anti-debug APIs";
            s.value        = std::to_string(antidebug_count);
            s.normal_range = "0";
            s.ok           = (antidebug_count == 0);
            s.note         = (antidebug_count > 0) ? "Anti-analysis behaviour" : "";
            out.stats.push_back(std::move(s));
        }
        {
            // W+X sections
            int wx = 0;
            for (const auto &s : sections)
                if ((s.characteristics & 0x20000000u) && (s.characteristics & 0x80000000u))
                    ++wx;
            overview_stat_t s;
            s.label        = "W+X sections";
            s.value        = std::to_string(wx);
            s.normal_range = "0";
            s.ok           = (wx == 0);
            s.note         = (wx > 0) ? "Executable + writable -- self-modifying code" : "";
            out.stats.push_back(std::move(s));
        }
    }

    return out;
}
