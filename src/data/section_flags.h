#ifndef SECTION_FLAGS_H_
#define SECTION_FLAGS_H_

#include <cstdint>
#include <string>
#include <vector>

#ifdef WIN32
#include <Windows.h>
#endif

struct section_flag_t {
  uint32_t    mask;
  const char *short_name;
  const char *description;
};

// All notable IMAGE_SCN_* bits with plain-English descriptions.
inline const std::vector<section_flag_t> &get_section_flags() {
  static const std::vector<section_flag_t> flags = {
      {IMAGE_SCN_CNT_CODE,               "CNT_CODE",    "Contains executable code"},
      {IMAGE_SCN_CNT_INITIALIZED_DATA,   "INIT_DATA",   "Contains initialized data (e.g. .data, .rdata)"},
      {IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINIT_DATA", "Contains uninitialized data (.bss — zeroed at load time)"},
      {IMAGE_SCN_LNK_INFO,               "LNK_INFO",    "Contains linker metadata, not mapped into memory"},
      {IMAGE_SCN_LNK_REMOVE,             "LNK_REMOVE",  "Section is removed before the image is run"},
      {IMAGE_SCN_LNK_COMDAT,             "COMDAT",      "Section contains COMDAT data (for deduplication by linker)"},
      {IMAGE_SCN_NO_DEFER_SPEC_EXC,      "NO_DEFER_EXC","Reset speculative exceptions handling bits in TLB entries"},
      {IMAGE_SCN_GPREL,                  "GPREL",       "Section contains data referenced through the global pointer"},
      {IMAGE_SCN_MEM_16BIT,              "MEM_16BIT",   "Reserved for ARM: section contains Thumb code"},
      {IMAGE_SCN_MEM_LOCKED,             "MEM_LOCKED",  "Reserved — must not be paged out"},
      {IMAGE_SCN_MEM_PRELOAD,            "MEM_PRELOAD", "Reserved — section should be preloaded"},
      {IMAGE_SCN_ALIGN_1BYTES,           "ALIGN_1",     "Align data on 1-byte boundary"},
      {IMAGE_SCN_ALIGN_2BYTES,           "ALIGN_2",     "Align data on 2-byte boundary"},
      {IMAGE_SCN_ALIGN_4BYTES,           "ALIGN_4",     "Align data on 4-byte boundary"},
      {IMAGE_SCN_ALIGN_8BYTES,           "ALIGN_8",     "Align data on 8-byte boundary"},
      {IMAGE_SCN_ALIGN_16BYTES,          "ALIGN_16",    "Align data on 16-byte boundary (default)"},
      {IMAGE_SCN_ALIGN_32BYTES,          "ALIGN_32",    "Align data on 32-byte boundary"},
      {IMAGE_SCN_ALIGN_64BYTES,          "ALIGN_64",    "Align data on 64-byte boundary"},
      {IMAGE_SCN_LNK_NRELOC_OVFL,        "NRELOC_OVFL", "Section contains extended relocations"},
      {IMAGE_SCN_MEM_DISCARDABLE,        "DISCARDABLE", "Section can be discarded after process init (e.g. .reloc)"},
      {IMAGE_SCN_MEM_NOT_CACHED,         "NOT_CACHED",  "Section cannot be cached"},
      {IMAGE_SCN_MEM_NOT_PAGED,          "NOT_PAGED",   "Section cannot be paged — must stay in physical RAM"},
      {IMAGE_SCN_MEM_SHARED,             "SHARED",      "Section can be shared across processes"},
      {IMAGE_SCN_MEM_EXECUTE,            "EXECUTE",     "Section is executable — suspicious if not .text"},
      {IMAGE_SCN_MEM_READ,               "READ",        "Section is readable"},
      {IMAGE_SCN_MEM_WRITE,              "WRITE",       "Section is writable — RWX (Read+Write+Execute) is highly suspicious"},
  };
  return flags;
}

// Build a comma-separated string of set flag short names
inline std::string describe_section_characteristics(uint32_t chars) {
  std::string result;
  for (const auto &f : get_section_flags()) {
    if (chars & f.mask) {
      if (!result.empty()) result += " | ";
      result += f.short_name;
    }
  }
  return result.empty() ? "none" : result;
}

// Build a multiline tooltip for all set bits
inline std::string section_characteristics_tooltip(uint32_t chars) {
  std::string tip;
  for (const auto &f : get_section_flags()) {
    if (chars & f.mask) {
      if (!tip.empty()) tip += "\n";
      tip += std::string(f.short_name) + ": " + f.description;
    }
  }
  // Highlight RWX
  bool rwx = (chars & IMAGE_SCN_MEM_READ) &&
             (chars & IMAGE_SCN_MEM_WRITE) &&
             (chars & IMAGE_SCN_MEM_EXECUTE);
  if (rwx) tip += "\n\n[!] RWX section — read+write+execute is a strong indicator of self-modifying code or unpacking";
  return tip;
}

#endif // SECTION_FLAGS_H_
