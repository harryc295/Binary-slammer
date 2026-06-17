#pragma once
#include <string>
#include <vector>
#include <map>
#include <algorithm>
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
    bool ok;   // true = within normal range, false = unusual
};

struct overview_t {
    int score{};                            // 0-100 threat score
    std::string verdict;                    // "Likely Clean" / "Suspicious" / "Likely Malicious" / "Highly Suspicious"
    std::vector<std::string> findings;     // plain-English bullet points (max ~8)
    std::string narrative;                 // one-paragraph summary
    std::vector<overview_stat_t> stats;    // "is this normal?" rows
    std::map<import_cat_t, int> cat_counts; // category -> import count
};

// ── Main computation ──────────────────────────────────────────────────────────

inline overview_t compute_overview(
        const std::vector<section_t>          &sections,
        const std::vector<import_t>           &imports,
        const std::vector<float>              &entropies,
        const std::vector<security_finding_t> &sec_findings,
        bool                                   is_64bit,
        bool                                   has_overlay,
        const std::vector<uint64_t>           &tls_callbacks)
{
    overview_t out;
    int score = 0;

    // ── Category counts (named imports only) ──────────────────────────────────
    for (const auto &imp : imports) {
        if (imp.by_ordinal) continue;
        import_cat_t cat = classify_import(imp.function);
        out.cat_counts[cat]++;
    }

    // ── Entropy scoring ───────────────────────────────────────────────────────
    for (size_t i = 0; i < sections.size() && i < entropies.size(); ++i) {
        float e = entropies[i];
        char buf[160];
        if (e > 7.0f) {
            score += 20;
            std::snprintf(buf, sizeof(buf),
                "Section '%s' has very high entropy (%.1f/8.0) -- likely packed or encrypted",
                sections[i].name.c_str(), (double)e);
            if (out.findings.size() < 8)
                out.findings.push_back(buf);
        } else if (e >= 6.5f) {
            score += 8;
            std::snprintf(buf, sizeof(buf),
                "Section '%s' has elevated entropy (%.1f/8.0) -- may contain compressed data",
                sections[i].name.c_str(), (double)e);
            if (out.findings.size() < 8)
                out.findings.push_back(buf);
        }
    }

    // ── Security findings: Anti-Debug and packers ─────────────────────────────
    int antidebug_count = 0;
    int packer_count    = 0;
    for (const auto &f : sec_findings) {
        if (f.category == "Anti-Debug") {
            ++antidebug_count;
        } else {
            ++packer_count;
            char buf[160];
            std::snprintf(buf, sizeof(buf), "Packer/protector detected: %s (%s)",
                          f.category.c_str(), f.title.c_str());
            if (out.findings.size() < 8)
                out.findings.push_back(buf);
            score += 30;
        }
    }
    if (antidebug_count > 0) {
        score += std::min(40, antidebug_count * 12);
        char buf[128];
        std::snprintf(buf, sizeof(buf),
            "%d anti-debug API(s) imported -- binary actively resists analysis",
            antidebug_count);
        if (out.findings.size() < 8)
            out.findings.push_back(buf);
    }

    // ── Process injection imports ─────────────────────────────────────────────
    int inj_count = 0;
    {
        auto it = out.cat_counts.find(import_cat_t::ProcessInjection);
        if (it != out.cat_counts.end())
            inj_count = it->second;
    }
    if (inj_count > 0) {
        score += std::min(35, inj_count * 10);
        char buf[128];
        std::snprintf(buf, sizeof(buf),
            "%d process injection API(s) imported (e.g. VirtualAllocEx, WriteProcessMemory)",
            inj_count);
        if (out.findings.size() < 8)
            out.findings.push_back(buf);
    }

    // ── Very few named imports ────────────────────────────────────────────────
    int named_count = 0;
    for (const auto &imp : imports)
        if (!imp.by_ordinal) ++named_count;

    if (named_count < 5 && !imports.empty()) {
        score += 20;
        if (out.findings.size() < 8)
            out.findings.push_back(
                "Very few named imports -- import table may be obfuscated or binary is packed");
    }

    // ── TLS callbacks ─────────────────────────────────────────────────────────
    if (!tls_callbacks.empty()) {
        score += 10;
        char buf[96];
        std::snprintf(buf, sizeof(buf),
            "%zu TLS callback(s) detected -- code executes before entry point",
            tls_callbacks.size());
        if (out.findings.size() < 8)
            out.findings.push_back(buf);
    }

    // ── PE overlay ────────────────────────────────────────────────────────────
    if (has_overlay) {
        score += 10;
        if (out.findings.size() < 8)
            out.findings.push_back(
                "PE overlay present -- data appended after the last section (dropper/self-extractor pattern)");
    }

    // ── Low section count ─────────────────────────────────────────────────────
    if (sections.size() < 3) {
        score += 15;
        char buf[96];
        std::snprintf(buf, sizeof(buf),
            "Only %zu PE section(s) -- unusually low, common in packed binaries",
            sections.size());
        if (out.findings.size() < 8)
            out.findings.push_back(buf);
    }

    // ── Clamp and derive verdict ──────────────────────────────────────────────
    out.score = std::min(score, 100);

    if      (out.score < 20) out.verdict = "Likely Clean";
    else if (out.score < 45) out.verdict = "Suspicious";
    else if (out.score < 70) out.verdict = "Likely Malicious";
    else                     out.verdict = "Highly Suspicious";

    // ── Narrative ─────────────────────────────────────────────────────────────
    {
        auto has_cat = [&](import_cat_t cat) -> int {
            auto ci = out.cat_counts.find(cat);
            return (ci != out.cat_counts.end()) ? ci->second : 0;
        };

        std::string n;
        n += std::string("This is a ") + (is_64bit ? "64" : "32") + "-bit Windows executable.";

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
            std::snprintf(buf, sizeof(buf), " It manages processes/threads (%d API(s)).",
                          has_cat(import_cat_t::ProcessManagement));
            n += buf;
        }
        if (inj_count > 0) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                " It uses %d process injection API(s), a strong indicator of malicious intent.",
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
                " %d anti-debug technique(s) were detected, suggesting deliberate analysis resistance.",
                antidebug_count);
            n += buf;
        }

        bool has_high_entropy = false;
        for (float e : entropies)
            if (e > 7.0f) { has_high_entropy = true; break; }
        if (has_high_entropy)
            n += " One or more sections show very high entropy, consistent with packing or encryption.";

        if (packer_count > 0) {
            char buf[80];
            std::snprintf(buf, sizeof(buf),
                " %d known packer/protector signature(s) were matched.", packer_count);
            n += buf;
        }

        n += " Overall risk: " + out.verdict + ".";
        out.narrative = std::move(n);
    }

    // ── Stats rows ────────────────────────────────────────────────────────────
    {
        // 1. Section count
        {
            overview_stat_t s;
            s.label        = "Section count";
            s.value        = std::to_string(sections.size());
            s.normal_range = "3-8";
            s.ok           = (sections.size() >= 3 && sections.size() <= 8);
            s.note         = s.ok ? "" : (sections.size() < 3
                                          ? "Very few -- may be packed"
                                          : "Unusually many sections");
            out.stats.push_back(std::move(s));
        }

        // 2. Named imports
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

        // 3. Architecture
        {
            overview_stat_t s;
            s.label        = "Architecture";
            s.value        = is_64bit ? "64-bit" : "32-bit";
            s.normal_range = "any";
            s.ok           = true;
            s.note         = "";
            out.stats.push_back(std::move(s));
        }

        // 4. TLS callbacks
        {
            overview_stat_t s;
            s.label        = "TLS callbacks";
            s.value        = std::to_string(tls_callbacks.size());
            s.normal_range = "0";
            s.ok           = tls_callbacks.empty();
            s.note         = tls_callbacks.empty() ? "" : "Pre-entry callbacks detected";
            out.stats.push_back(std::move(s));
        }

        // 5. PE overlay
        {
            overview_stat_t s;
            s.label        = "PE overlay";
            s.value        = has_overlay ? "Yes" : "No";
            s.normal_range = "No";
            s.ok           = !has_overlay;
            s.note         = has_overlay ? "Data appended after last section" : "";
            out.stats.push_back(std::move(s));
        }

        // 6. Anti-debug APIs
        {
            overview_stat_t s;
            s.label        = "Anti-debug APIs";
            s.value        = std::to_string(antidebug_count);
            s.normal_range = "0";
            s.ok           = (antidebug_count == 0);
            s.note         = (antidebug_count > 0) ? "Anti-analysis behaviour detected" : "";
            out.stats.push_back(std::move(s));
        }
    }

    return out;
}
