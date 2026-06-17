#pragma once
#include "../app_dirs.h"
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

// Per-binary rename / comment persistence.
// Stored as "bh_XXXXXXXXXXXXXXXX.meta" in CWD (keyed by FNV-1a of binary path).
namespace meta {

inline std::unordered_map<uint64_t, std::string> names;     // RVA → custom name
inline std::unordered_map<uint64_t, std::string> comments;  // RVA → comment text
inline std::unordered_map<uint64_t, std::string> bookmarks; // RVA → bookmark label

inline uint64_t path_key(const std::string &p) {
    uint64_t h = 14695981039346656037ULL;
    for (char c : p) { h ^= (uint8_t)::tolower((unsigned char)c); h *= 1099511628211ULL; }
    return h;
}

inline std::string meta_filename(const std::string &bin_path) {
    char buf[32]; snprintf(buf, sizeof(buf), "bh_%016llx.meta", (unsigned long long)path_key(bin_path));
    return bh_dir() + buf;
}

inline void load(const std::string &bin_path) {
    names.clear(); comments.clear(); bookmarks.clear();
    std::ifstream f(meta_filename(bin_path));
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string type, rva_s;
        ss >> type >> rva_s;
        if (rva_s.empty()) continue;
        uint64_t rva = (uint64_t)strtoull(rva_s.c_str(), nullptr, 16);
        std::string rest;
        if (std::getline(ss >> std::ws, rest) && !rest.empty()) {
            if      (type == "name")     names[rva]     = rest;
            else if (type == "comment")  comments[rva]  = rest;
            else if (type == "bookmark") bookmarks[rva] = rest;
        }
    }
}

inline void save(const std::string &bin_path) {
    std::ofstream f(meta_filename(bin_path));
    if (!f.is_open()) return;
    for (const auto &[rva, name] : names)
        f << "name 0x" << std::hex << rva << ' ' << name << '\n';
    for (const auto &[rva, cmt] : comments)
        f << "comment 0x" << std::hex << rva << ' ' << cmt << '\n';
    for (const auto &[rva, label] : bookmarks)
        f << "bookmark 0x" << std::hex << rva << ' ' << label << '\n';
}

inline void clear() { names.clear(); comments.clear(); bookmarks.clear(); }

} // namespace meta
