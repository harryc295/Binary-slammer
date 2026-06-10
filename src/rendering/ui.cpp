#include "ui.h"

#include <cmath>
#include <cstdio>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#include "../binary/binary.h"
#include "../binary/disassembler.h"
#include "../console_handler.h"
#include "../data/api_descriptions.h"
#include "../data/section_flags.h"
#include "../decompiler/lifter.h"
#include "file_prompt.h"
#include "nav_state.h"

// Navigation state is defined here (declared extern in nav_state.h)
int64_t g_nav_hex_offset = -1;
int64_t g_nav_disasm_rva = -1;
static bool     g_binary_changed   = false;

// Forward declarations
static void disassemble_function(const function_t &fn);

// ── Cached analysis data (rebuilt when g_binary_changed) ─────────────────
static std::vector<section_t>   g_sections;
static std::vector<resource_t>  g_exports;
static std::vector<import_t>    g_imports;
static std::vector<string_t>    g_strings;
static std::vector<function_t>  g_functions;
static std::vector<disasm_t>         g_disasm;
static std::vector<pseudo_line_t>    g_pseudo_code;
static size_t                        g_current_func_rva = 0;
static int                           g_selected_func    = -1;

static void rebuild_cache() {
    g_sections  = open_binary.get_sections();
    g_exports   = open_binary.get_exports();
    g_imports   = open_binary.get_imports();
    g_strings   = open_binary.get_strings(5);
    g_functions = open_binary.get_functions();
    g_disasm.clear();
    g_pseudo_code.clear();
    g_selected_func    = -1;
    g_current_func_rva = 0;

    // Auto-disassemble the entry point on load
    size_t ep = open_binary.get_entrypoint();
    if (ep && !g_functions.empty()) {
        // Select the closest function to the entry point
        for (int i = 0; i < (int)g_functions.size(); ++i) {
            if (g_functions[i].rva == ep) {
                g_selected_func = i;
                disassemble_function(g_functions[i]);
                break;
            }
        }
        if (g_selected_func < 0 && !g_functions.empty()) {
            g_selected_func = 0;
            disassemble_function(g_functions[0]);
        }
    }
}

static void disassemble_function(const function_t &fn) {
    g_current_func_rva = fn.rva;
    uint32_t off = open_binary.rva_to_offset(static_cast<uint32_t>(fn.rva));
    if (!off) return;

    auto bytes = open_binary.get_data(off, 4096);
    if (bytes.empty()) return;

    g_disasm = Disassembler::disassemble(bytes.data(), bytes.size(),
                                         fn.rva, 512,
                                         open_binary.is_64bit());

    // Build call_map: RVA → name from known functions in this binary
    std::unordered_map<uint64_t, std::string> call_map;
    for (const auto &f : g_functions)
        call_map[f.rva] = f.name;

    g_pseudo_code = Lifter::lift(g_disasm, open_binary.is_64bit(), call_map);
}

// ── Shannon entropy ───────────────────────────────────────────────────────
static float calc_entropy(const std::vector<uint8_t> &data) {
    if (data.empty()) return 0.f;
    int freq[256]{};
    for (uint8_t b : data) ++freq[b];
    float e = 0.f;
    float n = static_cast<float>(data.size());
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        float p = freq[i] / n;
        e -= p * std::log2(p);
    }
    return e;
}

// ── Window creation / destruction ─────────────────────────────────────────
bool UI::create_window() {
    srand(static_cast<unsigned>(time(nullptr)));
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return false;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    float scale = ImGui_ImplGlfw_GetContentScaleForMonitor(glfwGetPrimaryMonitor());
    m_window = glfwCreateWindow(static_cast<int>(1280 * scale),
                                static_cast<int>(800  * scale),
                                "BinaryHammer", nullptr, nullptr);
    if (!m_window) return false;

    glfwMakeContextCurrent(m_window);
    glfwSwapInterval(1);

    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;

    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.ScaleAllSizes(scale);
    style.FontScaleDpi = scale;

    ImGui_ImplGlfw_InitForOpenGL(m_window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    return true;
}

void UI::destroy_window() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(m_window);
    glfwTerminate();
}

// ── Panels ────────────────────────────────────────────────────────────────

static void render_function_explorer() {
    ImGui::Begin("Function Explorer");
    if (!open_binary.is_open()) {
        ImGui::TextDisabled("No binary loaded.");
        ImGui::End(); return;
    }

    ImGui::TextDisabled("%zu functions", g_functions.size());
    ImGui::Separator();

    ImGui::SetNextItemWidth(-1.f);
    static char filter[128]{};
    ImGui::InputText("##fnfilter", filter, sizeof(filter));

    ImGui::BeginChild("##fnlist");
    for (int i = 0; i < static_cast<int>(g_functions.size()); ++i) {
        const auto &fn = g_functions[i];
        if (filter[0] && fn.name.find(filter) == std::string::npos) continue;

        char label[256];
        snprintf(label, sizeof(label), "0x%08llX  %s%s",
                 (unsigned long long)fn.rva,
                 fn.name.c_str(),
                 fn.from_exports ? " [exp]" : "");

        if (ImGui::Selectable(label, g_selected_func == i)) {
            g_selected_func   = i;
            g_nav_disasm_rva  = static_cast<int64_t>(fn.rva);
            disassemble_function(fn);
        }
        if (ImGui::IsItemHovered() && fn.from_exports)
            ImGui::SetTooltip("Named export — click to view disassembly");
    }
    ImGui::EndChild();
    ImGui::End();
}

static void render_sections() {
    ImGui::Begin("Sections");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (ImGui::BeginTable("sectable", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Virtual Addr");
        ImGui::TableSetupColumn("Virt Size");
        ImGui::TableSetupColumn("Raw Size");
        ImGui::TableSetupColumn("Flags");
        ImGui::TableSetupColumn("Entropy");
        ImGui::TableHeadersRow();

        for (const auto &s : g_sections) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(s.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%08X", s.va);
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%X", s.virt_size);
            ImGui::TableSetColumnIndex(3); ImGui::Text("0x%X", s.raw_size);

            ImGui::TableSetColumnIndex(4);
            std::string flags = describe_section_characteristics(s.characteristics);
            ImGui::TextUnformatted(flags.c_str());
            if (ImGui::IsItemHovered()) {
                std::string tip = section_characteristics_tooltip(s.characteristics);
                ImGui::SetTooltip("%s", tip.c_str());
            }

            ImGui::TableSetColumnIndex(5);
            auto bytes = open_binary.get_data(s.raw_offset, s.raw_size);
            float ent = calc_entropy(bytes);
            ImVec4 col = ent > 7.0f ? ImVec4(1.f,.2f,.2f,1.f)  // high = suspicious
                       : ent > 6.0f ? ImVec4(1.f,.7f,.1f,1.f)
                       : ImVec4(.6f,.9f,.6f,1.f);
            ImGui::TextColored(col, "%.2f", ent);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Shannon entropy: %.2f/8.0\n%s",
                                  ent, ent > 7.2f
                                    ? "[!] Very high entropy — likely packed, encrypted, or compressed"
                                    : ent > 6.0f
                                    ? "Moderate entropy — may contain compressed data"
                                    : "Normal entropy");
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_exports() {
    ImGui::Begin("Exports");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (g_exports.empty()) { ImGui::TextDisabled("No exports."); ImGui::End(); return; }

    ImGui::TextDisabled("%zu exports", g_exports.size());
    if (ImGui::BeginTable("exptable", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Ordinal");
        ImGui::TableSetupColumn("RVA");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableHeadersRow();

        for (const auto &exp : g_exports) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", exp.ordinal);
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%08X", exp.rva);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(exp.function.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Double-click to navigate disassembly to 0x%08X", exp.rva);
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                g_nav_disasm_rva = exp.rva;
                // find in function list and select it
                for (int i = 0; i < (int)g_functions.size(); ++i)
                    if (g_functions[i].rva == exp.rva) { g_selected_func = i; disassemble_function(g_functions[i]); break; }
            }
            ImGui::TableSetColumnIndex(3);
            if (exp.type == RESOURCE_TYPE_FORWARDER) {
                ImGui::TextColored(ImVec4(.8f,.6f,.2f,1.f), "Forwarder");
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Forwarded to: %s\nThis export redirects callers to another DLL's function.", exp.value.c_str());
            } else {
                ImGui::TextDisabled("Export");
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_imports() {
    ImGui::Begin("Imports");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }
    if (g_imports.empty()) { ImGui::TextDisabled("No imports."); ImGui::End(); return; }

    ImGui::TextDisabled("%zu imported functions", g_imports.size());
    ImGui::Separator();

    // Group by DLL
    std::map<std::string, std::vector<const import_t*>> by_dll;
    for (const auto &imp : g_imports)
        by_dll[imp.dll].push_back(&imp);

    ImGui::BeginChild("##implist");
    for (const auto &[dll, funcs] : by_dll) {
        bool open = ImGui::TreeNodeEx(dll.c_str(),
                                      ImGuiTreeNodeFlags_DefaultOpen |
                                      ImGuiTreeNodeFlags_SpanFullWidth);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%zu imported functions from %s", funcs.size(), dll.c_str());
        if (open) {
            for (const auto *f : funcs) {
                ImGui::Indent(16.f);
                if (f->by_ordinal) {
                    ImGui::TextDisabled("ord#%u", f->ordinal);
                } else {
                    ImGui::TextUnformatted(f->function.c_str());
                    if (ImGui::IsItemHovered()) {
                        const char *tip = get_api_tip(f->function);
                        if (tip)
                            ImGui::SetTooltip("%s", tip);
                        else
                            ImGui::SetTooltip("%s (no description available)", f->function.c_str());
                    }
                }
                ImGui::Unindent(16.f);
            }
            ImGui::TreePop();
        }
    }
    ImGui::EndChild();
    ImGui::End();
}

static void render_disassembly() {
    ImGui::Begin("Disassembly");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (g_disasm.empty()) {
        ImGui::TextDisabled("Select a function from the Function Explorer.");
        ImGui::End(); return;
    }

    // Handle navigation request (e.g. from exports double-click)
    if (g_nav_disasm_rva >= 0) {
        uint64_t target = static_cast<uint64_t>(g_nav_disasm_rva);
        g_nav_disasm_rva = -1;
        // If not already showing this function, find and disassemble it
        if (target != g_current_func_rva) {
            bool found = false;
            for (int i = 0; i < (int)g_functions.size(); ++i) {
                if (g_functions[i].rva == target) {
                    g_selected_func = i;
                    disassemble_function(g_functions[i]);
                    found = true; break;
                }
            }
            if (!found) {
                // Synthesize a temporary function at the target RVA
                function_t tmp{target, "loc_" + rva_to_hex(target), false};
                disassemble_function(tmp);
            }
        }
    }

    // Header
    ImGui::TextColored(ImVec4(.5f,.8f,.5f,1.f), "Function @ 0x%08llX",
                       (unsigned long long)g_current_func_rva);
    ImGui::SameLine();
    ImGui::TextDisabled("  %zu instructions", g_disasm.size());
    ImGui::Separator();

    if (ImGui::BeginTable("disasmtable", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address",   ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("Bytes",     ImGuiTableColumnFlags_WidthFixed, 140.f);
        ImGui::TableSetupColumn("Mnemonic",  ImGuiTableColumnFlags_WidthFixed, 80.f);
        ImGui::TableSetupColumn("Operands",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        size_t ep = open_binary.get_entrypoint();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(g_disasm.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto &d = g_disasm[i];
                bool is_ep = (d.address == ep);

                ImGui::TableNextRow();

                // Address
                ImGui::TableSetColumnIndex(0);
                if (is_ep)
                    ImGui::TextColored(ImVec4(.5f,.2f,1.f,1.f), "%08llX", (unsigned long long)d.address);
                else
                    ImGui::TextDisabled("%08llX", (unsigned long long)d.address);

                // Bytes
                ImGui::TableSetColumnIndex(1);
                std::string byte_str;
                for (uint8_t b : d.bytes) {
                    char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", b);
                    byte_str += tmp;
                }
                ImGui::TextDisabled("%s", byte_str.c_str());

                // Mnemonic
                ImGui::TableSetColumnIndex(2);
                ImVec4 mnem_col = d.is_call  ? ImVec4(.4f,.9f,.4f,1.f)
                                : d.is_jump  ? ImVec4(.9f,.8f,.3f,1.f)
                                : d.is_ret   ? ImVec4(1.f,.4f,.4f,1.f)
                                : ImVec4(1.f,1.f,1.f,1.f);
                ImGui::TextColored(mnem_col, "%s", d.mnemonic.c_str());

                // Operands + tooltip on the whole row
                ImGui::TableSetColumnIndex(3);
                if (d.is_call || d.is_jump) {
                    ImGui::TextColored(ImVec4(.7f,.9f,1.f,1.f), "%s", d.operands.c_str());
                    if (d.branch_target && ImGui::IsItemHovered())
                        ImGui::SetTooltip("Target: 0x%08llX\n%s", (unsigned long long)d.branch_target, d.tooltip.c_str());
                    // Double-click a call/jump to navigate
                    if (d.branch_target && ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        g_nav_disasm_rva = static_cast<int64_t>(d.branch_target);
                        for (int j = 0; j < (int)g_functions.size(); ++j)
                            if (g_functions[j].rva == d.branch_target) {
                                g_selected_func = j;
                                disassemble_function(g_functions[j]);
                                break;
                            }
                    }
                } else {
                    ImGui::TextUnformatted(d.operands.c_str());
                }

                if (ImGui::IsItemHovered() && !d.tooltip.empty())
                    ImGui::SetTooltip("%s", d.tooltip.c_str());
            }
        }
        clipper.End();
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_hex_view() {
    ImGui::Begin("Hex View");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    size_t bin_size = open_binary.get_binary_size();
    size_t ep       = open_binary.get_entrypoint();
    uint32_t ep_off = open_binary.rva_to_offset(static_cast<uint32_t>(ep));

    // Top bar: offset input + go-to
    static char goto_buf[32] = "0x0";
    static int64_t view_offset = 0;
    ImGui::SetNextItemWidth(120.f);
    if (ImGui::InputText("Go to offset", goto_buf, sizeof(goto_buf),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
        char *end; uint64_t v = strtoull(goto_buf, &end, 16);
        if (end != goto_buf) view_offset = static_cast<int64_t>(v);
    }
    ImGui::SameLine();
    if (ImGui::Button("Entry Point"))
        view_offset = static_cast<int64_t>(ep_off);
    ImGui::SameLine();
    ImGui::TextDisabled("File size: %zu bytes", bin_size);

    // Handle external navigation requests
    if (g_nav_hex_offset >= 0) {
        view_offset = g_nav_hex_offset;
        g_nav_hex_offset = -1;
        snprintf(goto_buf, sizeof(goto_buf), "0x%llX", (unsigned long long)view_offset);
    }

    view_offset = std::max((int64_t)0, std::min(view_offset, (int64_t)bin_size - 1));
    size_t total_rows = bin_size / 16 + (bin_size % 16 ? 1 : 0);

    // Header row
    ImGui::Text("Offset     ");
    for (int col = 0; col < 16; ++col) {
        if (col == 8) { ImGui::SameLine(); ImGui::TextDisabled("  "); }
        ImGui::SameLine();
        ImGui::TextDisabled("%02X", col);
    }
    ImGui::SameLine(); ImGui::TextDisabled("   Text");
    ImGui::Separator();

    ImGuiStyle &style = ImGui::GetStyle();

    ImGui::BeginChild("##hexbody", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(total_rows));

    // Scroll to view_offset row on first load / navigation
    static int64_t last_view_offset = -1;
    if (view_offset != last_view_offset) {
        int target_row = static_cast<int>(view_offset / 16);
        ImGui::SetScrollY(static_cast<float>(target_row) *
                          ImGui::GetTextLineHeightWithSpacing());
        last_view_offset = view_offset;
    }

    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            size_t row_off = static_cast<size_t>(row) * 16;
            auto row_data  = open_binary.get_data(row_off, 16);

            ImGui::Text("%08zX   ", row_off);
            std::string text_col;

            for (int col = 0; col < 16; ++col) {
                if (col == 8) { ImGui::SameLine(); ImGui::Text("  "); }
                ImGui::SameLine();

                if (col < static_cast<int>(row_data.size())) {
                    uint8_t byte = row_data[col];
                    size_t abs_off = row_off + col;

                    text_col += (byte >= 0x20 && byte <= 0x7E && byte != '%') ? static_cast<char>(byte) : '.';

                    bool is_ep_byte = (abs_off == ep_off);

                    // Section coloring
                    ImVec4 col_v = style.Colors[ImGuiCol_Text];
                    for (const auto &sec : g_sections) {
                        if (abs_off >= sec.raw_offset && abs_off < sec.raw_offset + sec.raw_size) {
                            if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE)
                                col_v = ImVec4(.7f,.9f,1.f,.8f);
                            else if (sec.characteristics & IMAGE_SCN_MEM_WRITE)
                                col_v = ImVec4(.9f,.8f,.5f,.8f);
                            break;
                        }
                    }

                    if (is_ep_byte)
                        ImGui::TextColored(ImVec4(.5f,.2f,1.f,1.f), "%02X", byte);
                    else
                        ImGui::TextColored(col_v, "%02X", byte);

                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Offset: 0x%08zX  Value: 0x%02X (%u '%c')",
                                          abs_off, byte, byte,
                                          (byte >= 0x20 && byte <= 0x7E) ? byte : '.');
                } else {
                    text_col += ' ';
                    ImGui::TextDisabled("  ");
                }
            }
            ImGui::SameLine(); ImGui::TextDisabled("   ");
            ImGui::SameLine(); ImGui::TextDisabled("%s", text_col.c_str());
        }
    }
    clipper.End();
    ImGui::EndChild();
    ImGui::End();
}

static void render_strings_panel() {
    ImGui::Begin("Strings");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    ImGui::TextDisabled("%zu strings found", g_strings.size());
    ImGui::SameLine();
    static char str_filter[128]{};
    ImGui::SetNextItemWidth(180.f);
    ImGui::InputText("Filter", str_filter, sizeof(str_filter));

    if (ImGui::BeginTable("strtable", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("Type",    ImGuiTableColumnFlags_WidthFixed, 50.f);
        ImGui::TableSetupColumn("Value",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto &s : g_strings) {
            if (str_filter[0] && s.value.find(str_filter) == std::string::npos) continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("0x%08llX", (unsigned long long)s.offset);
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled(s.is_unicode ? "UTF16" : "ASCII");
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(s.value.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Double-click to navigate hex view to this offset");
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
                g_nav_hex_offset = static_cast<int64_t>(s.offset);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_pe_headers() {
    ImGui::Begin("PE Headers");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    const auto *dos = open_binary.get_dos();
    const auto *nt  = open_binary.get_nt();
    if (!dos || !nt) { ImGui::TextDisabled("Invalid PE headers."); ImGui::End(); return; }

    auto tip_row = [](const char *field, const char *value, const char *tip) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(field);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip);
        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(value);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip);
    };

    if (ImGui::CollapsingHeader("DOS Header", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("dostbl", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Field"); ImGui::TableSetupColumn("Value");
            ImGui::TableHeadersRow();
            char buf[64];
            snprintf(buf, sizeof(buf), "0x%04X (MZ)", dos->e_magic);
            tip_row("e_magic",   buf,  "DOS magic number. Must be 0x5A4D ('MZ') — named after Mark Zbikowski.");
            snprintf(buf, sizeof(buf), "0x%X", dos->e_lfanew);
            tip_row("e_lfanew",  buf,  "File offset to the PE signature ('PE\\0\\0'). Should point to the NT headers.");
            snprintf(buf, sizeof(buf), "%u", dos->e_cp);
            tip_row("e_cp",      buf,  "Number of pages in the file (legacy, largely ignored by the loader).");
            snprintf(buf, sizeof(buf), "0x%X", dos->e_ss);
            tip_row("e_ss",      buf,  "Initial SS value for the DOS stub (legacy).");
            snprintf(buf, sizeof(buf), "0x%X", dos->e_sp);
            tip_row("e_sp",      buf,  "Initial SP value for the DOS stub (legacy).");
            ImGui::EndTable();
        }
    }

    if (ImGui::CollapsingHeader("File Header (COFF)", ImGuiTreeNodeFlags_DefaultOpen)) {
        const auto &fh = nt->FileHeader;
        if (ImGui::BeginTable("filetbl", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Field"); ImGui::TableSetupColumn("Value");
            ImGui::TableHeadersRow();
            char buf[64];

            const char *machine = fh.Machine == 0x8664 ? "x64 (AMD64)"
                                : fh.Machine == 0x014C ? "x86 (i386)"
                                : fh.Machine == 0xAA64 ? "ARM64"
                                : fh.Machine == 0x01C4 ? "ARM (Thumb-2)"
                                : "Unknown";
            snprintf(buf, sizeof(buf), "0x%04X (%s)", fh.Machine, machine);
            tip_row("Machine",          buf, "Target CPU architecture. 0x8664 = x64, 0x014C = x86.");
            snprintf(buf, sizeof(buf), "%u", fh.NumberOfSections);
            tip_row("NumberOfSections", buf, "Number of section headers that follow the NT headers.");
            snprintf(buf, sizeof(buf), "0x%08X", fh.TimeDateStamp);
            tip_row("TimeDateStamp",    buf, "Build timestamp (seconds since Unix epoch). Can be zeroed/forged by malware.");
            snprintf(buf, sizeof(buf), "0x%X", fh.Characteristics);
            tip_row("Characteristics",  buf, "Flags describing the file (EXE, DLL, large address aware, etc.).");
            ImGui::EndTable();
        }
    }

    if (ImGui::CollapsingHeader("Optional Header", ImGuiTreeNodeFlags_DefaultOpen)) {
        bool b64 = open_binary.is_64bit();
        if (ImGui::BeginTable("opttbl", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Field"); ImGui::TableSetupColumn("Value");
            ImGui::TableHeadersRow();
            char buf[64];

            snprintf(buf, sizeof(buf), "0x%04X (%s)", nt->OptionalHeader.Magic,
                     b64 ? "PE32+" : "PE32");
            tip_row("Magic",                buf, "0x10B = PE32 (32-bit), 0x20B = PE32+ (64-bit). Determines pointer sizes.");
            snprintf(buf, sizeof(buf), "0x%X", (unsigned)nt->OptionalHeader.MajorLinkerVersion * 256 + nt->OptionalHeader.MinorLinkerVersion);
            tip_row("LinkerVersion",        buf, "Version of the linker that produced this binary.");
            snprintf(buf, sizeof(buf), "0x%08llX", (unsigned long long)open_binary.get_entrypoint());
            tip_row("AddressOfEntryPoint",  buf, "RVA of the first instruction to execute. In DLLs this is DllMain.");

            if (b64) {
                const auto *nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(nt);
                snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)nt64->OptionalHeader.ImageBase);
                tip_row("ImageBase", buf, "Preferred virtual base address. Loaders use ASLR to vary this at runtime.");
                snprintf(buf, sizeof(buf), "0x%X",  nt64->OptionalHeader.SectionAlignment);
                tip_row("SectionAlignment", buf, "Alignment of sections in virtual memory (must be >= FileAlignment).");
                snprintf(buf, sizeof(buf), "0x%X",  nt64->OptionalHeader.FileAlignment);
                tip_row("FileAlignment",    buf, "Alignment of raw section data in the file (commonly 0x200 or 0x1000).");
                snprintf(buf, sizeof(buf), "0x%X",  nt64->OptionalHeader.SizeOfImage);
                tip_row("SizeOfImage",      buf, "Total size of the image in memory — must be a multiple of SectionAlignment.");
                snprintf(buf, sizeof(buf), "0x%X",  nt64->OptionalHeader.Subsystem);
                tip_row("Subsystem",        buf,
                    nt64->OptionalHeader.Subsystem == 2 ? "2 = Windows GUI (no console window)"
                  : nt64->OptionalHeader.Subsystem == 3 ? "3 = Windows CUI (console application)"
                  : "Other subsystem");
                snprintf(buf, sizeof(buf), "0x%04X", nt64->OptionalHeader.DllCharacteristics);
                tip_row("DllCharacteristics", buf, "Security flags: ASLR (0x40), DEP/NX (0x100), CFG (0x4000), etc.");
            } else {
                const auto *nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(nt);
                snprintf(buf, sizeof(buf), "0x%08X", nt32->OptionalHeader.ImageBase);
                tip_row("ImageBase", buf, "Preferred virtual base address (32-bit).");
                snprintf(buf, sizeof(buf), "0x%X", nt32->OptionalHeader.SectionAlignment);
                tip_row("SectionAlignment", buf, "Alignment of sections in virtual memory.");
                snprintf(buf, sizeof(buf), "0x%X", nt32->OptionalHeader.FileAlignment);
                tip_row("FileAlignment",    buf, "Alignment of raw section data in the file.");
                snprintf(buf, sizeof(buf), "0x%X", nt32->OptionalHeader.SizeOfImage);
                tip_row("SizeOfImage",      buf, "Total in-memory size of the image.");
                snprintf(buf, sizeof(buf), "0x%X", nt32->OptionalHeader.Subsystem);
                tip_row("Subsystem",        buf,
                    nt32->OptionalHeader.Subsystem == 2 ? "2 = Windows GUI"
                  : nt32->OptionalHeader.Subsystem == 3 ? "3 = Console"
                  : "Other");
                snprintf(buf, sizeof(buf), "0x%04X", nt32->OptionalHeader.DllCharacteristics);
                tip_row("DllCharacteristics", buf, "Security flags: ASLR, DEP/NX, CFG, etc.");
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

static void render_pseudo_code() {
    ImGui::Begin("Pseudo Code");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (g_pseudo_code.empty()) {
        ImGui::TextDisabled("Select a function in the Function Explorer to decompile it.");
        ImGui::End(); return;
    }

    ImGui::TextColored(ImVec4(.5f,.8f,.5f,1.f), "Function @ 0x%08llX",
                       (unsigned long long)g_current_func_rva);
    ImGui::SameLine();
    ImGui::TextDisabled("  %zu lines  (in-process lifter)", g_pseudo_code.size());
    ImGui::Separator();

    // Colours
    const ImVec4 col_keyword  = ImVec4(.56f,.74f,1.0f,1.f);  // blue — if/while/return/goto
    const ImVec4 col_comment  = ImVec4(.50f,.80f,.50f,1.f);  // green
    const ImVec4 col_brace    = ImVec4(.80f,.80f,.80f,1.f);  // light gray
    const ImVec4 col_label    = ImVec4(.90f,.70f,.30f,1.f);  // yellow — loc_XXXXX:
    const ImVec4 col_sig      = ImVec4(.80f,.60f,1.0f,1.f);  // purple — function signature
    const ImVec4 col_normal   = ImGui::GetStyleColorVec4(ImGuiCol_Text);

    static int selected_line = -1;

    ImGui::BeginChild("##pseudobody", ImVec2(0,0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(g_pseudo_code.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto &pl = g_pseudo_code[i];

            // Build indented text
            std::string indent_str(static_cast<size_t>(pl.indent) * 4, ' ');
            std::string full_text = indent_str + pl.text;

            // Determine colour
            ImVec4 col;
            if (pl.is_comment) {
                col = col_comment;
            } else if (pl.text == "{" || pl.text == "}") {
                col = col_brace;
            } else if (pl.indent == 0) {
                col = col_sig;  // function signature / closing brace at root
            } else {
                // keyword check
                const char *t = pl.text.c_str();
                if (strncmp(t, "if ",     3) == 0 ||
                    strncmp(t, "while ",  6) == 0 ||
                    strncmp(t, "return ", 7) == 0 ||
                    strncmp(t, "goto ",   5) == 0 ||
                    strncmp(t, "swap(",   5) == 0) {
                    col = col_keyword;
                } else if (pl.text.size() > 5 && pl.text.substr(pl.text.size()-1) == ":") {
                    col = col_label;  // loc_XXXX:
                } else {
                    col = col_normal;
                }
            }

            bool sel = (selected_line == i);
            if (ImGui::Selectable(("##ps" + std::to_string(i)).c_str(), sel,
                                  ImGuiSelectableFlags_SpanAllColumns,
                                  ImVec2(0, ImGui::GetTextLineHeight()))) {
                selected_line = i;
                // Navigate hex/disasm to the RVA if the line has one
                if (pl.rva) {
                    g_nav_hex_offset = static_cast<int64_t>(
                        open_binary.rva_to_offset(static_cast<uint32_t>(pl.rva)));
                }
            }
            ImGui::SameLine(0, 0);
            ImGui::TextColored(col, "%s", full_text.c_str());
        }
    }
    clipper.End();
    ImGui::EndChild();
    ImGui::End();
}

static void render_console() {
    ImGui::Begin("Console");

    static char buffer[1024]{};
    if (ImGui::InputText("Input (prefix: \".\")", buffer, sizeof(buffer),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
        CommandHandler::get()->handle_command(buffer);
        buffer[0] = '\0';
    }
    ImGui::Separator();
    ImGui::BeginChild("##consolelog", ImVec2(0,0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto &msg : Logger::get()->get_logs())
        ImGui::Text("[%s]: %s", msg.owner.c_str(), msg.message.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
    ImGui::End();
}

// ── Frame ─────────────────────────────────────────────────────────────────

bool UI::render_frame() {
    if (glfwWindowShouldClose(m_window)) return false;

    glfwPollEvents();
    if (glfwGetWindowAttrib(m_window, GLFW_ICONIFIED)) {
        ImGui_ImplGlfw_Sleep(10);
        return true;
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    // ── Menu bar ─────────────────────────────────────────────────────────
    static bool open_file_dialog = false;
    float menubar_h = 0.f;
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open", "Ctrl+O"))  open_file_dialog = true;
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4"))  glfwSetWindowShouldClose(m_window, true);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Function Explorer"); ImGui::MenuItem("Sections");
            ImGui::MenuItem("Disassembly");       ImGui::MenuItem("Exports");
            ImGui::MenuItem("Imports");           ImGui::MenuItem("Hex View");
            ImGui::MenuItem("Strings");           ImGui::MenuItem("PE Headers");
            ImGui::MenuItem("Pseudo Code");       ImGui::MenuItem("Console");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) {}
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
        menubar_h = ImGui::GetFrameHeight();
    }

    // ── Welcome popup ────────────────────────────────────────────────────
    static bool first_run = true;
    if (first_run) { ImGui::OpenPopup("Welcome"); first_run = false; }

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(.5f,.5f));
    if (ImGui::BeginPopupModal("Welcome", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("BinaryHammer");
        ImGui::TextDisabled("Open a PE binary to begin analysis.");
        ImGui::Separator();
        if (ImGui::Button("Load File", ImVec2(120,0))) { ImGui::CloseCurrentPopup(); open_file_dialog = true; }
        ImGui::SameLine();
        if (ImGui::Button("Exit", ImVec2(120,0))) glfwSetWindowShouldClose(m_window, true);
        ImGui::EndPopup();
    }

    // ── Open file ────────────────────────────────────────────────────────
    if (open_file_dialog) {
        open_file_dialog = false;
        std::string path = GetFileDialog();
        if (!path.empty()) {
            open_binary = Binary(path);
            if (open_binary.is_open()) {
                rebuild_cache();
                Logger::get()->log("Loaded: " + path, "BinaryAnalyzer");
            }
        }
    }

    // ── Dockspace ────────────────────────────────────────────────────────
    ImGuiViewport *vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos({vp->Pos.x, vp->Pos.y + menubar_h});
    ImGui::SetNextWindowSize({vp->Size.x, vp->Size.y - menubar_h});
    ImGui::SetNextWindowViewport(vp->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    {0,0});
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);

    ImGui::Begin("##DockHost", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                 ImGuiWindowFlags_NoResize   | ImGuiWindowFlags_NoMove     |
                 ImGuiWindowFlags_NoBringToFrontOnFocus |
                 ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoBackground |
                 ImGuiWindowFlags_NoDocking);
    ImGui::PopStyleVar(2);

    ImGuiID ds = ImGui::GetID("MainDS");
    if (!ImGui::DockBuilderGetNode(ds)) {
        ImGui::DockBuilderRemoveNode(ds);
        ImGui::DockBuilderAddNode(ds, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(ds, {vp->Size.x, vp->Size.y - menubar_h});

        ImGuiID left, right;
        ImGui::DockBuilderSplitNode(ds, ImGuiDir_Left, 0.22f, &left, &right);

        ImGuiID lt, lb;
        ImGui::DockBuilderSplitNode(left, ImGuiDir_Up, 0.55f, &lt, &lb);

        ImGuiID rt, rb;
        ImGui::DockBuilderSplitNode(right, ImGuiDir_Up, 0.70f, &rt, &rb);

        ImGuiID rtl, rtr;
        ImGui::DockBuilderSplitNode(rt, ImGuiDir_Left, 0.55f, &rtl, &rtr);

        ImGui::DockBuilderDockWindow("Function Explorer", lt);
        ImGui::DockBuilderDockWindow("Sections",          lb);
        ImGui::DockBuilderDockWindow("Exports",           lb);
        ImGui::DockBuilderDockWindow("Imports",           lb);
        ImGui::DockBuilderDockWindow("Disassembly",       rtl);
        ImGui::DockBuilderDockWindow("Pseudo Code",       rtl);
        ImGui::DockBuilderDockWindow("Hex View",          rtr);
        ImGui::DockBuilderDockWindow("PE Headers",        rtr);
        ImGui::DockBuilderDockWindow("Strings",           rtr);
        ImGui::DockBuilderDockWindow("Console",           rb);
        ImGui::DockBuilderFinish(ds);
    }
    ImGui::DockSpace(ds);
    ImGui::End();

    // ── Render all panels ────────────────────────────────────────────────
    render_function_explorer();
    render_sections();
    render_exports();
    render_imports();
    render_disassembly();
    render_hex_view();
    render_strings_panel();
    render_pe_headers();
    render_pseudo_code();
    render_console();

    // ── Flush ─────────────────────────────────────────────────────────────
    ImGui::Render();
    int w, h;
    glfwGetFramebufferSize(m_window, &w, &h);
    glViewport(0, 0, w, h);
    glClearColor(.08f, .08f, .09f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(m_window);
    return true;
}
