#ifndef NAV_STATE_H_
#define NAV_STATE_H_
#include <cstdint>

// Shared navigation signals set by any panel or command, consumed by the render loop.
extern int64_t g_nav_hex_offset;  // file offset; -1 = no pending nav
extern int64_t g_nav_disasm_rva;  // RVA; -1 = no pending nav

#endif // NAV_STATE_H_
