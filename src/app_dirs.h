#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <string>

// Returns %APPDATA%\BinaryHammer\ (created on first call).
inline const std::string& bh_dir() {
    static std::string s;
    if (!s.empty()) return s;
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
    std::filesystem::create_directories(s);
    return s;
}

inline std::string bh_path(const char* filename) { return bh_dir() + filename; }
