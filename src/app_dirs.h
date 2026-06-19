#pragma once
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#endif
#include <cstdlib>
#include <filesystem>
#include <string>

// Returns %APPDATA%\BinaryHammer\ on Windows, ~/.local/share/BinaryHammer/ elsewhere
// (created on first call).
inline const std::string& bh_dir() {
    static std::string s;
    if (!s.empty()) return s;
#ifdef _WIN32
    PWSTR wpath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &wpath))) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, nullptr, 0, nullptr, nullptr);
        std::string tmp(n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, tmp.data(), n, nullptr, nullptr);
        CoTaskMemFree(wpath);
        if (!tmp.empty() && tmp.back() == '\0') tmp.pop_back();
        s = tmp + "\\BinaryHammer\\";
    } else {
        s = ".\\";
    }
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    const char* home = std::getenv("HOME");
    if (xdg && *xdg) {
        s = std::string(xdg) + "/BinaryHammer/";
    } else if (home && *home) {
        s = std::string(home) + "/.local/share/BinaryHammer/";
    } else {
        s = "./";
    }
#endif
    std::filesystem::create_directories(s);
    return s;
}

inline std::string bh_path(const char* filename) { return bh_dir() + filename; }
