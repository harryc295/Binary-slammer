#ifndef API_DESCRIPTIONS_H_
#define API_DESCRIPTIONS_H_

#include <string>
#include <unordered_map>

// Short descriptions + malware-relevance notes for common Win32 APIs.
// Used as hover tooltips in the Imports panel.
inline const std::unordered_map<std::string, std::string> &get_api_descriptions() {
  static const std::unordered_map<std::string, std::string> db = {
      // ── Memory ────────────────────────────────────────────────────────────
      {"VirtualAlloc",       "Allocate virtual memory in the calling process. Often used by malware to stage shellcode or unpacked payloads."},
      {"VirtualAllocEx",     "Allocate memory in a REMOTE process. Classic precursor to process injection."},
      {"VirtualFree",        "Release virtual memory previously allocated with VirtualAlloc."},
      {"VirtualProtect",     "Change page protection flags (e.g., RW→RX). Common in shellcode loaders and packers."},
      {"VirtualProtectEx",   "Change page protections in a remote process. Seen in injection chains."},
      {"VirtualQuery",       "Query memory region info. Used in anti-analysis/sandbox detection."},
      {"HeapAlloc",          "Allocate memory on the process heap."},
      {"HeapFree",           "Free a heap allocation."},
      {"HeapCreate",         "Create a private heap. Malware sometimes uses private heaps to hide allocations."},
      {"RtlAllocateHeap",    "Low-level heap allocation (ntdll). Equivalent to HeapAlloc at the NT layer."},

      // ── Process / Thread ──────────────────────────────────────────────────
      {"CreateProcess",      "Spawn a new process. Malware uses this to launch dropped payloads or cmd.exe."},
      {"CreateProcessA",     "ANSI version of CreateProcess."},
      {"CreateProcessW",     "Unicode version of CreateProcess."},
      {"OpenProcess",        "Open a handle to another process. Required for ReadProcessMemory/WriteProcessMemory injection."},
      {"TerminateProcess",   "Kill a process. Used by malware to terminate AV/EDR processes."},
      {"CreateThread",       "Create a thread in the calling process — common way to run shellcode."},
      {"CreateRemoteThread", "Create a thread in a REMOTE process. Canonical injection technique."},
      {"NtCreateThreadEx",   "Undocumented NT API to create a thread in a remote process — often used to bypass hooks."},
      {"ResumeThread",       "Resume a suspended thread. Used in process hollowing after writing payload."},
      {"SuspendThread",      "Suspend a thread. Used in process hollowing."},
      {"GetThreadContext",   "Get register state of a thread. Used in process hollowing to read/patch entry point."},
      {"SetThreadContext",   "Set register state of a thread — redirects execution. Core of thread hijacking."},
      {"WaitForSingleObject","Wait for a handle to be signaled. Used to synchronise with injected threads."},
      {"ExitProcess",        "Terminate the current process."},
      {"GetCurrentProcess",  "Return a pseudo-handle for the current process."},
      {"GetCurrentThread",   "Return a pseudo-handle for the current thread."},
      {"GetCurrentProcessId","Return the current process PID."},
      {"TlsAlloc",           "Allocate a Thread-Local Storage slot. Used by some obfuscators."},

      // ── Memory read/write ─────────────────────────────────────────────────
      {"WriteProcessMemory", "Write bytes into another process's memory. Used in code injection."},
      {"ReadProcessMemory",  "Read bytes from another process's memory."},
      {"NtWriteVirtualMemory","NT-layer equivalent of WriteProcessMemory — often used to bypass usermode hooks."},

      // ── DLL / Module loading ──────────────────────────────────────────────
      {"LoadLibrary",        "Load a DLL by name. Malware loads payloads or dependencies dynamically."},
      {"LoadLibraryA",       "ANSI LoadLibrary."},
      {"LoadLibraryW",       "Unicode LoadLibrary."},
      {"LoadLibraryExA",     "LoadLibrary with flags (e.g. LOAD_LIBRARY_AS_DATAFILE for resource-only loads)."},
      {"FreeLibrary",        "Unload a DLL. Used after dynamic API resolution."},
      {"GetProcAddress",     "Resolve a function by name or ordinal. Malware uses this to hide imports (manual IAT rebuild)."},
      {"GetModuleHandle",    "Get the base address of an already-loaded module."},
      {"GetModuleHandleA",   "ANSI version of GetModuleHandle."},
      {"GetModuleHandleW",   "Unicode version of GetModuleHandle."},
      {"LdrLoadDll",         "Undocumented ntdll function to load a DLL — used to bypass hooks on LoadLibrary."},
      {"LdrGetProcedureAddress","NT-layer equivalent of GetProcAddress."},

      // ── File I/O ──────────────────────────────────────────────────────────
      {"CreateFile",         "Open or create a file / device / pipe."},
      {"CreateFileA",        "ANSI CreateFile."},
      {"CreateFileW",        "Unicode CreateFile."},
      {"ReadFile",           "Read bytes from a file handle."},
      {"WriteFile",          "Write bytes to a file handle. Used to drop payloads to disk."},
      {"DeleteFile",         "Delete a file. Used for self-deletion or cleanup."},
      {"DeleteFileA",        "ANSI DeleteFile."},
      {"DeleteFileW",        "Unicode DeleteFile."},
      {"MoveFile",           "Move or rename a file."},
      {"CopyFile",           "Copy a file to a new path."},
      {"GetFileSize",        "Return the size of an open file."},
      {"SetFilePointer",     "Seek to an offset in a file."},
      {"CloseHandle",        "Close an open handle (file, process, thread, etc.)."},
      {"FindFirstFile",      "Begin a directory enumeration."},
      {"FindNextFile",       "Continue a directory enumeration."},
      {"CreateDirectory",    "Create a directory."},
      {"GetTempPath",        "Get the path to the system temp directory (common drop location)."},
      {"GetTempFileName",    "Generate a temp filename — often used before dropping a payload."},

      // ── Registry ──────────────────────────────────────────────────────────
      {"RegOpenKey",         "Open a registry key."},
      {"RegOpenKeyEx",       "Open a registry key (extended version)."},
      {"RegCreateKey",       "Create or open a registry key."},
      {"RegCreateKeyEx",     "Create/open a key with security attributes."},
      {"RegSetValue",        "Set a registry value."},
      {"RegSetValueEx",      "Set a named registry value. Used to write persistence keys (Run, RunOnce, etc.)."},
      {"RegQueryValue",      "Query a registry value."},
      {"RegQueryValueEx",    "Query a named registry value."},
      {"RegDeleteKey",       "Delete a registry key."},
      {"RegDeleteValue",     "Delete a named registry value."},
      {"RegCloseKey",        "Close an open registry key handle."},

      // ── Networking ────────────────────────────────────────────────────────
      {"socket",             "Create a network socket."},
      {"connect",            "Connect a socket to a remote address — C2 communication."},
      {"bind",               "Bind a socket to a local address."},
      {"listen",             "Mark socket as accepting connections (backdoor/listener)."},
      {"accept",             "Accept an incoming connection."},
      {"send",               "Send data over a socket."},
      {"recv",               "Receive data from a socket."},
      {"closesocket",        "Close a socket."},
      {"WSAStartup",         "Initialize WinSock — present in almost all networking malware."},
      {"WSACleanup",         "Shut down WinSock."},
      {"gethostbyname",      "DNS resolution by hostname. Used for C2 domain lookup."},
      {"getaddrinfo",        "Modern DNS resolution. Replaces gethostbyname."},
      {"InternetOpen",       "Initialize WinInet for HTTP — common in malware downloaders."},
      {"InternetConnect",    "Connect to a remote host via WinInet."},
      {"HttpOpenRequest",    "Create an HTTP request handle."},
      {"HttpSendRequest",    "Send an HTTP request — used to contact C2 or download payload."},
      {"InternetReadFile",   "Read bytes from an internet resource."},
      {"InternetCloseHandle","Close a WinInet handle."},
      {"URLDownloadToFile",  "Download a URL directly to a file — common dropper primitive."},

      // ── Crypto / Encoding ─────────────────────────────────────────────────
      {"CryptAcquireContext","Initialize a crypto provider. Precursor to encryption operations."},
      {"CryptImportKey",     "Import a cryptographic key."},
      {"CryptEncrypt",       "Encrypt data. Used by ransomware to encrypt files."},
      {"CryptDecrypt",       "Decrypt data. Used to unpack encrypted payloads."},
      {"CryptGenRandom",     "Generate cryptographically random bytes. Used for key/IV generation."},
      {"CryptHashData",      "Hash data with a crypto provider."},

      // ── Anti-analysis / System info ───────────────────────────────────────
      {"IsDebuggerPresent",  "Check if a debugger is attached. Extremely common anti-debug check."},
      {"CheckRemoteDebuggerPresent","Check if a remote debugger is attached."},
      {"NtQueryInformationProcess","Query process info. Used to detect debuggers via ProcessDebugPort."},
      {"OutputDebugString",  "Send a string to a debugger. Can be used to check if debugger is present."},
      {"GetTickCount",       "Get milliseconds since boot. Used in timing-based anti-debug checks."},
      {"GetTickCount64",     "64-bit GetTickCount."},
      {"QueryPerformanceCounter","High-resolution timer. Used in timing attacks and anti-sandbox checks."},
      {"Sleep",              "Sleep for N milliseconds. Malware uses long sleeps to evade sandbox time limits."},
      {"NtDelayExecution",   "NT-layer sleep. Used to evade hooks on Sleep."},
      {"GetSystemInfo",      "Query CPU/memory info. Used in sandbox/VM detection."},
      {"GlobalMemoryStatusEx","Query available RAM. Sandboxes often have low memory — used for detection."},
      {"GetComputerName",    "Get the machine hostname. Used for victim fingerprinting."},
      {"GetUserName",        "Get the current username."},
      {"GetSystemTime",      "Get current UTC time."},
      {"GetLocalTime",       "Get current local time."},

      // ── Shell / Execution ─────────────────────────────────────────────────
      {"ShellExecute",       "Run a file or open a URL. Used to launch payloads or browser for phishing."},
      {"ShellExecuteEx",     "Extended ShellExecute with process info output."},
      {"WinExec",            "Execute a command string. Legacy but still seen in older malware."},
      {"system",             "CRT function to execute a shell command."},

      // ── Services ──────────────────────────────────────────────────────────
      {"OpenSCManager",      "Open the Service Control Manager — precursor to service-based persistence."},
      {"CreateService",      "Create a new Windows service. Used for persistence."},
      {"StartService",       "Start a service."},
      {"ChangeServiceConfig","Modify service configuration — can change binary path for hijacking."},

      // ── Misc ──────────────────────────────────────────────────────────────
      {"SetFileAttributes",  "Set file attributes (e.g., hidden). Used to hide dropped files."},
      {"GetFileAttributes",  "Get file attributes."},
      {"SetWindowsHookEx",   "Install a system-wide hook. Used for keylogging, credential theft."},
      {"CallNextHookEx",     "Pass hook message to next hook in chain."},
      {"UnhookWindowsHookEx","Remove a hook."},
      {"GetAsyncKeyState",   "Check key state asynchronously. Used in keyloggers."},
      {"FindWindow",         "Find a window by class/title. Used to detect AV/sandbox windows."},
      {"SendMessage",        "Send a message to a window."},
      {"PostMessage",        "Post a message to a window's message queue."},
      {"AdjustTokenPrivileges","Adjust process token privileges (e.g., enable SeDebugPrivilege for injection)."},
      {"OpenProcessToken",   "Open the access token of a process."},
      {"LookupPrivilegeValue","Look up a privilege LUID by name."},
      {"ImpersonateLoggedOnUser","Impersonate another user's security context."},
  };
  return db;
}

inline const char *get_api_tip(const std::string &name) {
  const auto &db = get_api_descriptions();
  auto it = db.find(name);
  return it != db.end() ? it->second.c_str() : nullptr;
}

#endif // API_DESCRIPTIONS_H_
