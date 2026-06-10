/*
 * Compatibility header for Linux/macOS — provides the PE/COFF structures
 * normally from <Windows.h> so the binary parser compiles cross-platform.
 * Only PE data structures are defined here; Win32 API calls stay #ifdef _WIN32.
 */

#ifndef _WIN32_HEADERS_H_
#define _WIN32_HEADERS_H_
#ifndef _WIN32

#include <cstdint>
#include <cstring>

typedef long           LONG;
typedef unsigned long  ULONG;
typedef unsigned short USHORT;
typedef unsigned long long ULONGLONG;
typedef unsigned char  UCHAR;
typedef unsigned long  DWORD;
typedef unsigned short WORD;
typedef unsigned char  BYTE;
typedef void *         LPVOID;
typedef int            BOOL;

#ifndef NULL
#define NULL nullptr
#endif

// ── PE signatures ──────────────────────────────────────────────────────────
#define IMAGE_DOS_SIGNATURE            0x5A4D
#define IMAGE_NT_SIGNATURE             0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC  0x010B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC  0x020B

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME          8

// ── Data directory indices ──────────────────────────────────────────────────
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_DIRECTORY_ENTRY_DEBUG       6
#define IMAGE_DIRECTORY_ENTRY_TLS         9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT         12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

// ── Section characteristic flags ───────────────────────────────────────────
#define IMAGE_SCN_CNT_CODE                0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080
#define IMAGE_SCN_LNK_INFO                0x00000200
#define IMAGE_SCN_LNK_REMOVE              0x00000800
#define IMAGE_SCN_LNK_COMDAT              0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC       0x00004000
#define IMAGE_SCN_GPREL                   0x00008000
#define IMAGE_SCN_MEM_16BIT               0x00020000
#define IMAGE_SCN_MEM_LOCKED              0x00040000
#define IMAGE_SCN_MEM_PRELOAD             0x00080000
#define IMAGE_SCN_ALIGN_1BYTES            0x00100000
#define IMAGE_SCN_ALIGN_2BYTES            0x00200000
#define IMAGE_SCN_ALIGN_4BYTES            0x00300000
#define IMAGE_SCN_ALIGN_8BYTES            0x00400000
#define IMAGE_SCN_ALIGN_16BYTES           0x00500000
#define IMAGE_SCN_ALIGN_32BYTES           0x00600000
#define IMAGE_SCN_ALIGN_64BYTES           0x00700000
#define IMAGE_SCN_LNK_NRELOC_OVFL         0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE         0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED          0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED           0x08000000
#define IMAGE_SCN_MEM_SHARED              0x10000000
#define IMAGE_SCN_MEM_EXECUTE             0x20000000
#define IMAGE_SCN_MEM_READ                0x40000000
#define IMAGE_SCN_MEM_WRITE               0x80000000

// ── Import ordinal flags ────────────────────────────────────────────────────
#define IMAGE_ORDINAL_FLAG32  0x80000000UL
#define IMAGE_ORDINAL_FLAG64  0x8000000000000000ULL

// ── DOS Header ─────────────────────────────────────────────────────────────
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER;

// ── File Header (COFF) ──────────────────────────────────────────────────────
typedef struct _IMAGE_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER;

// ── Data Directory ──────────────────────────────────────────────────────────
typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY;

// ── Optional Header (PE32) ─────────────────────────────────────────────────
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

// ── Optional Header (PE32+) ────────────────────────────────────────────────
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

// ── NT Headers ─────────────────────────────────────────────────────────────
typedef struct _IMAGE_NT_HEADERS32 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

// Default IMAGE_NT_HEADERS to 64-bit (matches Windows x64 SDK behaviour)
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;

// ── Section Header ─────────────────────────────────────────────────────────
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;

// ── Export Directory ───────────────────────────────────────────────────────
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

// ── Import Descriptor ──────────────────────────────────────────────────────
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union { DWORD Characteristics; DWORD OriginalFirstThunk; };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

// ── Import By Name ─────────────────────────────────────────────────────────
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME;

#endif // !_WIN32
#endif // !_WIN32_HEADERS_H_
