#pragma once

#include <fstream>
#include <string>

#include "../app_dirs.h"

// Locally-stored, optional third-party threat-intel API keys. Settings-UI
// only — nothing in BinaryHammer transmits these anywhere itself.
struct api_settings_t {
    std::string virustotal_key;
    std::string malwarebazaar_key;
};

inline api_settings_t load_api_settings() {
    api_settings_t s;
    std::ifstream f(bh_path("bh_api_keys.dat"));
    if (!f) return s;
    std::getline(f, s.virustotal_key);
    std::getline(f, s.malwarebazaar_key);
    return s;
}

inline void save_api_settings(const api_settings_t &s) {
    std::ofstream f(bh_path("bh_api_keys.dat"), std::ios::trunc);
    f << s.virustotal_key << "\n" << s.malwarebazaar_key << "\n";
}
