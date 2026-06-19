#pragma once
#include <string>
#include <map>
#include <vector>

enum class import_cat_t {
    Networking, FileIO, ProcessInjection, AntiAnalysis,
    Persistence, Crypto, ProcessManagement, Memory,
    SystemInfo, UI, Misc
};

struct import_category_info_t {
    import_cat_t cat;
    const char *label;
    const char *description;
    float r, g, b;
};

static const import_category_info_t k_cat_info[] = {
    {import_cat_t::Networking,        "Networking",        "Sends/receives data over network connections",               0.30f, 0.60f, 1.00f},
    {import_cat_t::FileIO,            "File I/O",          "Reads, writes, or modifies files on disk",                   0.40f, 0.85f, 0.40f},
    {import_cat_t::ProcessInjection,  "Process Injection", "Injects code or DLLs into other processes — high risk",     1.00f, 0.25f, 0.25f},
    {import_cat_t::AntiAnalysis,      "Anti-Analysis",     "Detects or evades debuggers and analysis tools",             1.00f, 0.55f, 0.10f},
    {import_cat_t::Persistence,       "Persistence",       "Creates registry keys, services, or startup entries",        1.00f, 0.85f, 0.10f},
    {import_cat_t::Crypto,            "Crypto",            "Encrypts, decrypts, or hashes data",                         0.75f, 0.40f, 1.00f},
    {import_cat_t::ProcessManagement, "Process Mgmt",      "Creates, opens, or terminates processes and threads",        1.00f, 0.60f, 0.70f},
    {import_cat_t::Memory,            "Memory",            "Allocates, maps, or protects memory regions",                0.85f, 0.80f, 0.45f},
    {import_cat_t::SystemInfo,        "System Info",       "Queries computer name, user, hardware, or OS version",       0.40f, 0.85f, 0.85f},
    {import_cat_t::UI,                "UI",                "Creates windows, dialogs, or message boxes",                 0.70f, 0.70f, 0.70f},
    {import_cat_t::Misc,              "Misc",              "General runtime or uncategorised imports",                   0.50f, 0.50f, 0.50f},
};

static const struct { const char *prefix; import_cat_t cat; } k_import_sigs[] = {
    // Networking
    {"WSA",                      import_cat_t::Networking},
    {"socket",                   import_cat_t::Networking},
    {"connect",                  import_cat_t::Networking},
    {"send",                     import_cat_t::Networking},
    {"recv",                     import_cat_t::Networking},
    {"bind",                     import_cat_t::Networking},
    {"listen",                   import_cat_t::Networking},
    {"accept",                   import_cat_t::Networking},
    {"getaddrinfo",              import_cat_t::Networking},
    {"gethostbyname",            import_cat_t::Networking},
    {"InternetOpen",             import_cat_t::Networking},
    {"InternetConnect",          import_cat_t::Networking},
    {"InternetRead",             import_cat_t::Networking},
    {"HttpOpenRequest",          import_cat_t::Networking},
    {"HttpSendRequest",          import_cat_t::Networking},
    {"WinHttpOpen",              import_cat_t::Networking},
    {"WinHttpConnect",           import_cat_t::Networking},
    {"WinHttpSendRequest",       import_cat_t::Networking},
    {"WinHttpReceiveResponse",   import_cat_t::Networking},
    {"URLDownloadToFile",        import_cat_t::Networking},
    {"ObtainUserAgentString",    import_cat_t::Networking},
    // File I/O
    {"CreateFile",               import_cat_t::FileIO},
    {"ReadFile",                 import_cat_t::FileIO},
    {"WriteFile",                import_cat_t::FileIO},
    {"DeleteFile",               import_cat_t::FileIO},
    {"CopyFile",                 import_cat_t::FileIO},
    {"MoveFile",                 import_cat_t::FileIO},
    {"FindFirstFile",            import_cat_t::FileIO},
    {"FindNextFile",             import_cat_t::FileIO},
    {"GetFileAttributes",        import_cat_t::FileIO},
    {"SetFileAttributes",        import_cat_t::FileIO},
    {"GetTempPath",              import_cat_t::FileIO},
    {"GetTempFileName",          import_cat_t::FileIO},
    {"CreateDirectory",          import_cat_t::FileIO},
    {"RemoveDirectory",          import_cat_t::FileIO},
    {"SetCurrentDirectory",      import_cat_t::FileIO},
    {"GetCurrentDirectory",      import_cat_t::FileIO},
    // Process Injection (actual cross-process manipulation APIs only)
    {"VirtualAllocEx",           import_cat_t::ProcessInjection},
    {"WriteProcessMemory",       import_cat_t::ProcessInjection},
    {"ReadProcessMemory",        import_cat_t::ProcessInjection},
    {"CreateRemoteThread",       import_cat_t::ProcessInjection},
    {"NtUnmapViewOfSection",     import_cat_t::ProcessInjection},
    {"ZwUnmapViewOfSection",     import_cat_t::ProcessInjection},
    {"QueueUserAPC",             import_cat_t::ProcessInjection},
    {"NtQueueApcThread",         import_cat_t::ProcessInjection},
    // Anti-Analysis
    {"IsDebuggerPresent",        import_cat_t::AntiAnalysis},
    {"CheckRemoteDebugger",      import_cat_t::AntiAnalysis},
    {"NtQueryInformation",       import_cat_t::AntiAnalysis},
    {"ZwQueryInformation",       import_cat_t::AntiAnalysis},
    {"NtSetInformation",         import_cat_t::AntiAnalysis},
    {"ZwSetInformation",         import_cat_t::AntiAnalysis},
    {"GetThreadContext",         import_cat_t::AntiAnalysis},
    {"FindWindowA",              import_cat_t::AntiAnalysis},
    {"FindWindowW",              import_cat_t::AntiAnalysis},
    {"GetTickCount",             import_cat_t::AntiAnalysis},
    {"QueryPerformanceCounter",  import_cat_t::AntiAnalysis},
    {"OutputDebugString",        import_cat_t::AntiAnalysis},
    {"CreateToolhelp32Snapshot", import_cat_t::AntiAnalysis},
    {"NtQuerySystem",            import_cat_t::AntiAnalysis},
    {"SetUnhandledExceptionFilter", import_cat_t::AntiAnalysis},
    {"RaiseException",           import_cat_t::AntiAnalysis},
    // Persistence
    {"RegSetValue",              import_cat_t::Persistence},
    {"RegCreateKey",             import_cat_t::Persistence},
    {"RegOpenKey",               import_cat_t::Persistence},
    {"RegDeleteKey",             import_cat_t::Persistence},
    {"RegDeleteValue",           import_cat_t::Persistence},
    {"CreateService",            import_cat_t::Persistence},
    {"StartService",             import_cat_t::Persistence},
    {"OpenService",              import_cat_t::Persistence},
    {"SHGetFolderPath",          import_cat_t::Persistence},
    {"SHGetSpecialFolder",       import_cat_t::Persistence},
    // Crypto
    {"Crypt",                    import_cat_t::Crypto},
    {"BCrypt",                   import_cat_t::Crypto},
    {"NCrypt",                   import_cat_t::Crypto},
    // Process Management
    {"CreateProcess",            import_cat_t::ProcessManagement},
    {"OpenProcess",              import_cat_t::ProcessManagement},
    {"TerminateProcess",         import_cat_t::ProcessManagement},
    {"CreateThread",             import_cat_t::ProcessManagement},
    {"OpenThread",               import_cat_t::ProcessManagement},
    {"SuspendThread",            import_cat_t::ProcessManagement},
    {"ResumeThread",             import_cat_t::ProcessManagement},
    {"WaitForSingleObject",      import_cat_t::ProcessManagement},
    {"WaitForMultipleObjects",   import_cat_t::ProcessManagement},
    {"ExitProcess",              import_cat_t::ProcessManagement},
    {"TerminateThread",          import_cat_t::ProcessManagement},
    {"Process32",                import_cat_t::ProcessManagement},
    {"ShellExecute",             import_cat_t::ProcessManagement},
    // Memory
    {"VirtualAlloc",             import_cat_t::Memory},
    {"VirtualFree",              import_cat_t::Memory},
    {"VirtualProtect",           import_cat_t::Memory},
    {"HeapAlloc",                import_cat_t::Memory},
    {"HeapFree",                 import_cat_t::Memory},
    {"GlobalAlloc",              import_cat_t::Memory},
    {"LocalAlloc",               import_cat_t::Memory},
    {"MapViewOfFile",            import_cat_t::Memory},
    {"UnmapViewOfFile",          import_cat_t::Memory},
    {"CreateFileMapping",        import_cat_t::Memory},
    // System Info
    {"GetSystemInfo",            import_cat_t::SystemInfo},
    {"GetComputerName",          import_cat_t::SystemInfo},
    {"GetUserName",              import_cat_t::SystemInfo},
    {"GetWindowsDirectory",      import_cat_t::SystemInfo},
    {"GetSystemDirectory",       import_cat_t::SystemInfo},
    {"GetVersion",               import_cat_t::SystemInfo},
    {"GetVolumeInformation",     import_cat_t::SystemInfo},
    {"RtlGetVersion",            import_cat_t::SystemInfo},
    {"GetDriveType",             import_cat_t::SystemInfo},
    // UI
    {"CreateWindow",             import_cat_t::UI},
    {"MessageBox",               import_cat_t::UI},
    {"DialogBox",                import_cat_t::UI},
    {"ShowWindow",               import_cat_t::UI},
    {"SetWindowText",            import_cat_t::UI},
    {"RegisterClass",            import_cat_t::UI},
    {"DispatchMessage",          import_cat_t::UI},
    {"GetDlgItem",               import_cat_t::UI},
    {"SendMessage",              import_cat_t::UI},
    {"PostMessage",              import_cat_t::UI},
};

inline import_cat_t classify_import(const std::string &func) {
    for (const auto &sig : k_import_sigs)
        if (func.rfind(sig.prefix, 0) == 0)
            return sig.cat;
    return import_cat_t::Misc;
}

inline const import_category_info_t &cat_info(import_cat_t cat) {
    for (const auto &c : k_cat_info)
        if (c.cat == cat) return c;
    return k_cat_info[10];
}
