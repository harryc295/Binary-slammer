#ifndef BINARY_H_
#define BINARY_H_
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "../logger.h"

#ifdef WIN32
#define NOMINMAX
#include <Windows.h>
#else
#include "../win32_headers.h"
#endif

// ── Data structures ─────────────────────────────────────────────────────────

enum RESOURCE_TYPE : int {
  RESOURCE_TYPE_FORWARDER,
  RESOURCE_TYPE_EXPORT,
};

struct resource_t {
  std::string function;
  std::string value;
  uint32_t rva{};
  uint16_t ordinal{};
  RESOURCE_TYPE type{};
};

struct section_t {
  std::string name;
  uint32_t va{};
  uint32_t raw_offset{};
  uint32_t raw_size{};
  uint32_t virt_size{};
  uint32_t characteristics{};
};

struct import_t {
  std::string dll;
  std::string function;
  uint16_t ordinal{};
  bool by_ordinal{};
};

struct string_t {
  uint64_t offset{};
  std::string value;
  bool is_unicode{};
};

struct function_t {
  uint64_t rva{};
  std::string name;
  bool from_exports{};
};

// ── Helpers ──────────────────────────────────────────────────────────────────

static inline std::string rva_to_hex(uint64_t rva) {
  std::ostringstream ss;
  ss << std::hex << rva;
  return ss.str();
}

// ── Binary class ─────────────────────────────────────────────────────────────

class Binary {
private:
#ifdef _WIN32
  HANDLE m_file = INVALID_HANDLE_VALUE;
  HANDLE m_mapping = nullptr;
  LPVOID m_view    = nullptr;
#endif
  size_t m_file_size{};

  size_t section_table_offset() const {
#ifdef _WIN32
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(m_view);
    const auto *nt  = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        reinterpret_cast<const uint8_t *>(m_view) + dos->e_lfanew);
    return dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
           nt->FileHeader.SizeOfOptionalHeader;
#else
    return 0;
#endif
  }

public:
  Binary() = default;
  ~Binary() { close(); }

  Binary([[maybe_unused]] std::string path) {
#ifdef _WIN32
    std::wstring wpath(path.begin(), path.end());

    m_file = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_file == INVALID_HANDLE_VALUE) {
      Logger::get()->log("Error: Unable to open file.", "BinaryAnalyzer");
      return;
    }

    LARGE_INTEGER fs;
    GetFileSizeEx(m_file, &fs);
    m_file_size = static_cast<size_t>(fs.QuadPart);

    m_mapping = CreateFileMappingW(m_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m_mapping) {
      Logger::get()->log("Error: Unable to create file mapping.", "BinaryAnalyzer");
      close(); return;
    }

    m_view = MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_view) {
      Logger::get()->log("Error: Unable to map view.", "BinaryAnalyzer");
      close(); return;
    }
#endif

    {
      std::string msg = "Read " + std::to_string(m_file_size) + " bytes.";
      Logger::get()->log(msg, "BinaryAnalyzer");
    }

    const auto *dos = get_ptr<IMAGE_DOS_HEADER>(0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
      Logger::get()->log("Error: Not a valid PE binary. (DOS header)", "BinaryAnalyzer");
      close(); return;
    }

    const auto *nt = get_ptr<IMAGE_NT_HEADERS>(dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
      Logger::get()->log("Error: Not a valid PE binary. (PE header)", "BinaryAnalyzer");
      close(); return;
    }

    {
      std::ostringstream ss;
      ss << "Architecture: " << (is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
      Logger::get()->log(ss.str(), "BinaryAnalyzer");
    }
    {
      std::ostringstream ss;
      ss << "Entry Point RVA: 0x" << std::hex << get_entrypoint();
      Logger::get()->log(ss.str(), "BinaryAnalyzer");
    }
  }

  // ── Move support (needed for open_binary = Binary(path)) ──────────────────
  Binary(Binary &&o) noexcept
      :
#ifdef _WIN32
        m_file(o.m_file), m_mapping(o.m_mapping), m_view(o.m_view),
#endif
        m_file_size(o.m_file_size) {
#ifdef _WIN32
    o.m_file = INVALID_HANDLE_VALUE;
    o.m_mapping = nullptr;
    o.m_view = nullptr;
#endif
    o.m_file_size = 0;
  }

  Binary &operator=(Binary &&o) noexcept {
    if (this != &o) {
      close();
#ifdef _WIN32
      m_file    = o.m_file;    o.m_file    = INVALID_HANDLE_VALUE;
      m_mapping = o.m_mapping; o.m_mapping = nullptr;
      m_view    = o.m_view;    o.m_view    = nullptr;
#endif
      m_file_size = o.m_file_size; o.m_file_size = 0;
    }
    return *this;
  }

  Binary(const Binary &) = delete;
  Binary &operator=(const Binary &) = delete;

  // ── Core ──────────────────────────────────────────────────────────────────

  bool is_open() const {
#ifdef _WIN32
    return m_view != nullptr;
#else
    return false;
#endif
  }

  void close() {
#ifdef _WIN32
    if (m_view)    UnmapViewOfFile(m_view);
    if (m_mapping) CloseHandle(m_mapping);
    if (m_file != INVALID_HANDLE_VALUE) CloseHandle(m_file);
    m_view    = nullptr;
    m_mapping = nullptr;
    m_file    = INVALID_HANDLE_VALUE;
    m_file_size = 0;
#endif
  }

  template <typename T>
  const T *get_ptr(size_t file_offset) const {
    if (!is_open()) return nullptr;
    if (file_offset + sizeof(T) > m_file_size) return nullptr;
#ifdef _WIN32
    return reinterpret_cast<const T *>(
        reinterpret_cast<const uint8_t *>(m_view) + file_offset);
#else
    return nullptr;
#endif
  }

  // Reads raw bytes by file offset (safe, clamped)
  std::vector<uint8_t> get_data(size_t file_offset, size_t size) const {
    if (!is_open() || file_offset >= m_file_size || !size) return {};
    size = std::min(size, m_file_size - file_offset);
    std::vector<uint8_t> ret(size);
#ifdef _WIN32
    memcpy(ret.data(), reinterpret_cast<const uint8_t *>(m_view) + file_offset, size);
#endif
    return ret;
  }

  // Reads bytes starting from an RVA
  std::vector<uint8_t> get_data_rva(uint32_t rva, size_t size) const {
    uint32_t off = rva_to_offset(rva);
    return off ? get_data(off, size) : std::vector<uint8_t>{};
  }

  size_t get_binary_size() const { return m_file_size; }

  // ── PE helpers ────────────────────────────────────────────────────────────

  const IMAGE_DOS_HEADER *get_dos() const {
    auto *dos = get_ptr<IMAGE_DOS_HEADER>(0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    return dos;
  }

  const IMAGE_NT_HEADERS *get_nt() const {
    const auto *dos = get_dos();
    if (!dos) return nullptr;
    const auto *nt = get_ptr<IMAGE_NT_HEADERS>(dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
  }

  bool is_64bit() const {
    const auto *nt = get_nt();
    if (!nt) return false;
    return nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  }

  size_t get_entrypoint() const {
    const auto *dos = get_dos();
    if (!dos) return 0;
    const auto *nt = get_ptr<IMAGE_NT_HEADERS>(dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      return reinterpret_cast<const IMAGE_NT_HEADERS64 *>(nt)
                 ->OptionalHeader.AddressOfEntryPoint;
    return reinterpret_cast<const IMAGE_NT_HEADERS32 *>(nt)
               ->OptionalHeader.AddressOfEntryPoint;
  }

  // Convert RVA → raw file offset by walking the section table
  uint32_t rva_to_offset(uint32_t rva) const {
    if (!is_open() || !rva) return 0;
    const auto *dos = get_dos();
    if (!dos) return 0;
    const auto *nt = get_ptr<IMAGE_NT_HEADERS>(dos->e_lfanew);
    if (!nt) return 0;

    WORD num = nt->FileHeader.NumberOfSections;
    size_t base = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                  nt->FileHeader.SizeOfOptionalHeader;

    for (WORD i = 0; i < num; ++i) {
      const auto *s = get_ptr<IMAGE_SECTION_HEADER>(base + i * sizeof(IMAGE_SECTION_HEADER));
      if (!s) break;
      uint32_t virt_end = s->VirtualAddress + std::max(s->Misc.VirtualSize, s->SizeOfRawData);
      if (rva >= s->VirtualAddress && rva < virt_end)
        return s->PointerToRawData + (rva - s->VirtualAddress);
    }
    return rva; // header area — offset == RVA
  }

  // ── Sections ──────────────────────────────────────────────────────────────

  std::vector<section_t> get_sections() const {
    if (!is_open()) return {};
    const auto *dos = get_dos();
    if (!dos) return {};
    const auto *nt = get_ptr<IMAGE_NT_HEADERS>(dos->e_lfanew);
    if (!nt) return {};

    WORD num = nt->FileHeader.NumberOfSections;
    size_t base = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                  nt->FileHeader.SizeOfOptionalHeader;

    std::vector<section_t> out;
    out.reserve(num);
    for (WORD i = 0; i < num; ++i) {
      const auto *sh = get_ptr<IMAGE_SECTION_HEADER>(base + i * sizeof(IMAGE_SECTION_HEADER));
      if (!sh) break;
      section_t s;
      s.name = std::string(reinterpret_cast<const char *>(sh->Name),
                           strnlen(reinterpret_cast<const char *>(sh->Name),
                                   IMAGE_SIZEOF_SHORT_NAME));
      s.va             = sh->VirtualAddress;
      s.raw_offset     = sh->PointerToRawData;
      s.raw_size       = sh->SizeOfRawData;
      s.virt_size      = sh->Misc.VirtualSize;
      s.characteristics = sh->Characteristics;
      out.push_back(std::move(s));
    }
    return out;
  }

  // ── Exports ───────────────────────────────────────────────────────────────

  std::vector<resource_t> get_exports() const {
    if (!is_open()) return {};

    uint32_t exp_rva, exp_size;
    if (is_64bit()) {
      const auto *nt64 = get_ptr<IMAGE_NT_HEADERS64>(get_dos()->e_lfanew);
      if (!nt64) return {};
      exp_rva  = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      exp_size = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
      const auto *nt32 = get_ptr<IMAGE_NT_HEADERS32>(get_dos()->e_lfanew);
      if (!nt32) return {};
      exp_rva  = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      exp_size = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if (!exp_rva) return {};

    const auto *ed = get_ptr<IMAGE_EXPORT_DIRECTORY>(rva_to_offset(exp_rva));
    if (!ed) return {};

    std::vector<resource_t> out;
    out.reserve(ed->NumberOfNames);

    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
      const auto *name_rva = get_ptr<DWORD>(rva_to_offset(ed->AddressOfNames) + i * sizeof(DWORD));
      if (!name_rva) continue;

      const auto *ord_idx = get_ptr<WORD>(rva_to_offset(ed->AddressOfNameOrdinals) + i * sizeof(WORD));
      if (!ord_idx) continue;

      const auto *func_rva = get_ptr<DWORD>(rva_to_offset(ed->AddressOfFunctions) + (*ord_idx) * sizeof(DWORD));
      if (!func_rva) continue;

      const char *name_str = get_ptr<char>(rva_to_offset(*name_rva));

      resource_t r;
      r.function = name_str ? name_str : "";
      r.rva      = *func_rva;
      r.ordinal  = static_cast<uint16_t>(ed->Base + *ord_idx);

      bool is_forwarder = (*func_rva >= exp_rva && *func_rva < exp_rva + exp_size);
      r.type = is_forwarder ? RESOURCE_TYPE_FORWARDER : RESOURCE_TYPE_EXPORT;
      if (is_forwarder) {
        const char *fwd = get_ptr<char>(rva_to_offset(*func_rva));
        r.value = fwd ? fwd : "";
      }
      out.push_back(std::move(r));
    }
    return out;
  }

  // ── Imports ───────────────────────────────────────────────────────────────

  std::vector<import_t> get_imports() const {
    if (!is_open()) return {};

    uint32_t imp_rva;
    if (is_64bit()) {
      const auto *nt64 = get_ptr<IMAGE_NT_HEADERS64>(get_dos()->e_lfanew);
      if (!nt64) return {};
      imp_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
      const auto *nt32 = get_ptr<IMAGE_NT_HEADERS32>(get_dos()->e_lfanew);
      if (!nt32) return {};
      imp_rva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    if (!imp_rva) return {};

    uint32_t imp_off = rva_to_offset(imp_rva);
    std::vector<import_t> out;
    bool is64 = is_64bit();

    for (size_t i = 0; ; ++i) {
      const auto *desc = get_ptr<IMAGE_IMPORT_DESCRIPTOR>(imp_off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
      if (!desc || (!desc->OriginalFirstThunk && !desc->FirstThunk)) break;

      const char *dll_str = desc->Name ? get_ptr<char>(rva_to_offset(desc->Name)) : nullptr;
      std::string dll = dll_str ? dll_str : "unknown.dll";

      uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
      uint32_t thunk_off = rva_to_offset(thunk_rva);

      if (is64) {
        for (size_t j = 0; ; ++j) {
          const auto *thunk = get_ptr<ULONGLONG>(thunk_off + j * sizeof(ULONGLONG));
          if (!thunk || !*thunk) break;
          import_t imp;
          imp.dll = dll;
          if (*thunk & IMAGE_ORDINAL_FLAG64) {
            imp.by_ordinal = true;
            imp.ordinal    = static_cast<uint16_t>(*thunk & 0xFFFF);
            imp.function   = "#" + std::to_string(imp.ordinal);
          } else {
            const auto *ibn = get_ptr<IMAGE_IMPORT_BY_NAME>(
                rva_to_offset(static_cast<uint32_t>(*thunk & 0x7FFFFFFF)));
            if (ibn) { imp.function = ibn->Name; imp.ordinal = ibn->Hint; }
          }
          out.push_back(std::move(imp));
        }
      } else {
        for (size_t j = 0; ; ++j) {
          const auto *thunk = get_ptr<DWORD>(thunk_off + j * sizeof(DWORD));
          if (!thunk || !*thunk) break;
          import_t imp;
          imp.dll = dll;
          if (*thunk & IMAGE_ORDINAL_FLAG32) {
            imp.by_ordinal = true;
            imp.ordinal    = static_cast<uint16_t>(*thunk & 0xFFFF);
            imp.function   = "#" + std::to_string(imp.ordinal);
          } else {
            const auto *ibn = get_ptr<IMAGE_IMPORT_BY_NAME>(
                rva_to_offset(*thunk & 0x7FFFFFFF));
            if (ibn) { imp.function = ibn->Name; imp.ordinal = ibn->Hint; }
          }
          out.push_back(std::move(imp));
        }
      }
    }
    return out;
  }

  // ── Strings ───────────────────────────────────────────────────────────────

  std::vector<string_t> get_strings([[maybe_unused]] size_t min_len = 5) const {
#ifndef _WIN32
    return {};
#else
    if (!is_open()) return {};

    const auto *data = reinterpret_cast<const uint8_t *>(m_view);
    std::vector<string_t> out;

    // ASCII
    size_t run_start = 0;
    bool in_run = false;
    for (size_t i = 0; i <= m_file_size; ++i) {
      bool printable = i < m_file_size && data[i] >= 0x20 && data[i] <= 0x7E;
      if (printable) {
        if (!in_run) { run_start = i; in_run = true; }
      } else {
        if (in_run && (i - run_start) >= min_len)
          out.push_back({run_start, std::string(reinterpret_cast<const char *>(data + run_start), i - run_start), false});
        in_run = false;
      }
    }

    // UTF-16LE
    for (size_t i = 0; i + 1 < m_file_size; ) {
      uint8_t lo = data[i], hi = data[i + 1];
      if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
        size_t j = i;
        std::string tmp;
        while (j + 1 < m_file_size && data[j + 1] == 0 && data[j] >= 0x20 && data[j] <= 0x7E)
          { tmp += data[j]; j += 2; }
        if (tmp.size() >= min_len)
          out.push_back({i, std::move(tmp), true});
        i = (j > i) ? j : i + 2;
      } else {
        ++i;
      }
    }

    return out;
#endif
  }

  // ── Function list ─────────────────────────────────────────────────────────

  std::vector<function_t> get_functions() const {
#ifndef _WIN32
    return {};
#else
    if (!is_open()) return {};

    std::vector<function_t> funcs;
    std::set<uint64_t> seen;

    auto add = [&](uint64_t rva, const std::string &name, bool from_exp) {
      if (seen.insert(rva).second) funcs.push_back({rva, name, from_exp});
    };

    size_t ep = get_entrypoint();
    if (ep) add(ep, "start", false);

    for (const auto &ex : get_exports())
      if (ex.type == RESOURCE_TYPE_EXPORT && ex.rva)
        add(ex.rva, ex.function, true);

    const auto *raw = reinterpret_cast<const uint8_t *>(m_view);
    for (const auto &sec : get_sections()) {
      if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
      if (!sec.raw_offset || !sec.raw_size) continue;

      size_t end = std::min((size_t)(sec.raw_offset + sec.raw_size), m_file_size);
      for (size_t i = sec.raw_offset; i + 4 < end; ++i) {
        bool prologue = false;

        // x64: push rbp + mov rbp,rsp
        if (raw[i]==0x55 && raw[i+1]==0x48 && raw[i+2]==0x89 && raw[i+3]==0xE5)
          prologue = true;
        // x86: push ebp + mov ebp,esp
        else if (raw[i]==0x55 && raw[i+1]==0x8B && raw[i+2]==0xEC)
          prologue = true;
        // x64: sub rsp, imm8
        else if (raw[i]==0x48 && raw[i+1]==0x83 && raw[i+2]==0xEC)
          prologue = true;

        if (prologue) {
          uint64_t rva = sec.va + (i - sec.raw_offset);
          add(rva, "sub_" + rva_to_hex(rva), false);
          i += 3;
        }
      }
    }
    return funcs;
#endif
  }
};

extern Binary open_binary;

#endif // BINARY_H_
