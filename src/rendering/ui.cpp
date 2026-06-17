#include "ui.h"
#include "app_icon.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../binary/binary.h"
#include "../binary/disassembler.h"
#include "../console_handler.h"
#include "../data/api_descriptions.h"
#include "../data/metadata.h"
#include "../data/section_flags.h"
#include "../decompiler/lifter.h"
#include "../analysis/cfg.h"
#include "../analysis/md5.h"
#include "../analysis/rich_header.h"
#include "../analysis/security_analyzer.h"
#include "../analysis/import_categories.h"
#include "../analysis/overview.h"
#include "../analysis/asm_annotate.h"
#ifdef HAVE_LLVM
#include "../ir/ir_lifter.h"
#endif
#include "file_prompt.h"
#include "nav_state.h"

#ifdef HAVE_YARA
#include <yara.h>
#endif

// Navigation state is defined here (declared extern in nav_state.h)
int64_t g_nav_hex_offset = -1;
int64_t g_nav_disasm_rva = -1;
bool    g_load_pending   = false;
char    g_demo_path[512] = {};
static bool     g_binary_changed   = false;

// Forward declarations
static void disassemble_function(const function_t &fn);
static float calc_entropy(const std::vector<uint8_t> &data);

// ── Cached analysis data (rebuilt when g_binary_changed) ─────────────────
static std::vector<section_t>   g_sections;
static std::vector<resource_t>  g_exports;
static std::vector<import_t>    g_imports;
static std::vector<string_t>    g_strings;
static std::vector<function_t>  g_functions;
static std::vector<disasm_t>         g_disasm;
static std::vector<pseudo_line_t>    g_pseudo_code;
#ifdef HAVE_LLVM
static IRResult                      g_ir_result;
#endif
static CFG                           g_cfg;
static size_t                        g_current_func_rva = 0;
static int                           g_selected_func    = -1;

static std::unordered_map<uint64_t, std::vector<uint64_t>> g_xrefs;
static std::string                   g_imphash;
static std::vector<std::string>      g_section_hashes;
static std::vector<float>            g_section_entropies; // cached, not recomputed per-frame

// Imports grouped by DLL — cached so we don't rebuild the map every frame
static std::map<std::string, std::vector<const import_t*>> g_imports_by_dll;

// Pre-filtered string list — rebuilt only when filter changes
static std::vector<size_t> g_str_filtered_idx;
static char g_str_filter_cache[128]{};
static bool g_str_filter_dirty = true;

static std::vector<int> g_fn_filtered_idx;
static char g_fn_filter_cache[128]{};
static bool g_fn_filter_dirty = true;

static overview_t g_overview{};
static std::map<import_cat_t, std::vector<const import_t*>> g_imports_by_cat;
static bool g_asm_annotate = false;
static int  g_sel_section  = -1;

static bool g_dark_theme    = true;
static bool g_theme_changed = false;

// Security analysis
static std::vector<security_finding_t> g_security_findings;

// TLS callbacks (RVAs)
static std::vector<uint64_t> g_tls_callbacks;

// PE overlay
static overlay_info_t g_overlay{};

// Resource types
static std::vector<pe_resource_type_t> g_resource_types;

// Navigation history (back/forward)
struct nav_entry_t { uint64_t rva; std::string name; };
static std::vector<nav_entry_t> g_nav_history;
static int  g_nav_pos     = -1;
static bool g_nav_back_fwd = false;

// Byte pattern search
static char g_search_pattern[256]{};
struct search_result_t { uint32_t offset; std::vector<uint8_t> context; };
static std::vector<search_result_t> g_search_results;
static bool g_search_done = false;

#ifdef HAVE_YARA
struct YaraMatch { std::string rule; std::vector<std::pair<std::string,uint64_t>> hits; };
static std::vector<YaraMatch> g_yara_matches;
static std::string            g_yara_error;
static char                   g_yara_rules_path[512]{};
static bool                   g_yara_ready = false;

static int yara_scan_cb(YR_SCAN_CONTEXT *ctx, int msg, void *data, void *user) {
    if (msg == CALLBACK_MSG_RULE_MATCHING) {
        auto *rule    = static_cast<YR_RULE*>(data);
        auto *matches = static_cast<std::vector<YaraMatch>*>(user);
        YaraMatch m; m.rule = rule->identifier;
        YR_STRING *str; YR_MATCH *match;
        yr_rule_strings_foreach(rule, str) {
            yr_string_matches_foreach(ctx, str, match)
                m.hits.emplace_back(str->identifier, (uint64_t)match->offset);
        }
        matches->push_back(std::move(m));
    }
    return CALLBACK_CONTINUE;
}

static void do_yara_scan() {
    g_yara_matches.clear(); g_yara_error.clear();
    if (!g_yara_rules_path[0]) { g_yara_error = "No rules file specified."; return; }
    YR_COMPILER *comp = nullptr;
    if (yr_compiler_create(&comp) != ERROR_SUCCESS) { g_yara_error = "yr_compiler_create failed"; return; }
    FILE *f = fopen(g_yara_rules_path, "r");
    if (!f) { yr_compiler_destroy(comp); g_yara_error = "Cannot open rules file"; return; }
    if (yr_compiler_add_file(comp, f, nullptr, g_yara_rules_path) > 0) {
        fclose(f); yr_compiler_destroy(comp); g_yara_error = "Rules compilation failed"; return;
    }
    fclose(f);
    YR_RULES *rules = nullptr;
    yr_compiler_get_rules(comp, &rules);
    yr_compiler_destroy(comp);
    auto data = open_binary.get_data(0, open_binary.get_binary_size());
    yr_rules_scan_mem(rules, data.data(), data.size(), 0, yara_scan_cb, &g_yara_matches, 0);
    yr_rules_destroy(rules);
}
#endif

static void build_xrefs() {
    g_xrefs.clear();
    std::unordered_set<uint64_t> func_rvas;
    for (const auto &f : g_functions) func_rvas.insert(f.rva);

    for (const auto &sec : g_sections) {
        if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        auto bytes = open_binary.get_data(sec.raw_offset, sec.raw_size);
        for (size_t i = 0; i + 4 < bytes.size(); ++i) {
            if (bytes[i] == 0xE8) {
                int32_t rel; memcpy(&rel, &bytes[i+1], 4);
                uint64_t caller = sec.va + (uint64_t)i;
                uint64_t target = caller + 5 + (uint64_t)(int64_t)rel;
                if (func_rvas.count(target))
                    g_xrefs[target].push_back(caller);
            }
        }
    }
}

static void rebuild_cache() {
    g_sections  = open_binary.get_sections();
    g_exports   = open_binary.get_exports();
    g_imports   = open_binary.get_imports();
    g_strings   = open_binary.get_strings(5);
    g_functions = open_binary.get_functions();
    g_disasm.clear();
    g_pseudo_code.clear();
#ifdef HAVE_LLVM
    g_ir_result = {};
#endif
    g_cfg       = {};
    g_selected_func    = -1;
    g_current_func_rva = 0;

    // Per-binary hashes and entropies (computed once, not per-frame)
    g_imphash = open_binary.get_imphash();
    g_section_hashes.resize(g_sections.size());
    g_section_entropies.resize(g_sections.size(), 0.f);
    for (size_t i = 0; i < g_sections.size(); ++i) {
        auto d = open_binary.get_data(g_sections[i].raw_offset, g_sections[i].raw_size);
        g_section_hashes[i]   = d.empty() ? "" : md5::hash(d.data(), d.size());
        g_section_entropies[i] = calc_entropy(d);
    }

    // Group imports by DLL once
    g_imports_by_dll.clear();
    for (const auto &imp : g_imports)
        g_imports_by_dll[imp.dll].push_back(&imp);

    // Mark string filter as needing a rebuild
    g_str_filter_dirty = true;
    g_fn_filter_dirty  = true;

    build_xrefs();
    meta::load(open_binary.get_path());

    // Security analysis (import scan + packer sigs)
    g_security_findings = analyze_security(g_imports, g_sections);
    // Augment with entropy-based findings (use already-computed g_section_entropies)
    for (size_t i = 0; i < g_sections.size(); ++i) {
        float ent = (i < g_section_entropies.size()) ? g_section_entropies[i] : 0.f;
        if (ent > 7.2f) {
            bool already = false;
            for (const auto &f : g_security_findings)
                if (f.title.find(g_sections[i].name) != std::string::npos) { already = true; break; }
            if (!already) {
                security_finding_t sf;
                sf.category    = "High Entropy";
                sf.title       = "Section '" + g_sections[i].name + "' entropy " + std::to_string(ent).substr(0,4) + "/8.0";
                sf.description = "Shannon entropy > 7.2 strongly suggests encrypted, compressed, or packed content.";
                sf.bypass      = "Run an entropy analysis tool; if packed, OEP-hunt via VirtualProtect bp and dump with Scylla.";
                sf.severity    = 2;
                g_security_findings.push_back(std::move(sf));
            }
        }
    }

    g_tls_callbacks  = open_binary.get_tls_callbacks();
    g_overlay        = open_binary.get_overlay();
    g_resource_types = open_binary.get_resource_types();

    g_imports_by_cat.clear();
    for (const auto &imp : g_imports)
        if (!imp.by_ordinal)
            g_imports_by_cat[classify_import(imp.function)].push_back(&imp);

    g_overview = compute_overview(g_sections, g_imports, g_section_entropies,
                                  g_security_findings, open_binary.is_64bit(),
                                  g_overlay.size > 0, g_tls_callbacks,
                                  g_strings, g_resource_types);
    g_sel_section = -1;

    g_search_results.clear();
    g_search_done   = false;
    g_nav_history.clear();
    g_nav_pos       = -1;

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

static void nav_history_push(uint64_t rva, const std::string &name) {
    if (g_nav_back_fwd) return;
    if (g_nav_pos >= 0 && (int)g_nav_history.size() > g_nav_pos + 1)
        g_nav_history.erase(g_nav_history.begin() + g_nav_pos + 1, g_nav_history.end());
    if (!g_nav_history.empty() && g_nav_history.back().rva == rva) return;
    g_nav_history.push_back({rva, name});
    if ((int)g_nav_history.size() > 50) g_nav_history.erase(g_nav_history.begin());
    g_nav_pos = (int)g_nav_history.size() - 1;
}

static void disassemble_function(const function_t &fn) {
    nav_history_push(fn.rva, fn.name);
    g_current_func_rva = fn.rva;
    uint32_t off = open_binary.rva_to_offset(static_cast<uint32_t>(fn.rva));
    if (!off) return;

    auto bytes = open_binary.get_data(off, 4096);
    if (bytes.empty()) return;

    g_disasm = Disassembler::disassemble(bytes.data(), bytes.size(),
                                         fn.rva, 512,
                                         open_binary.is_64bit());

    // Build call_map: RVA → name (custom name takes priority)
    std::unordered_map<uint64_t, std::string> call_map;
    for (const auto &f : g_functions) {
        auto it = meta::names.find(f.rva);
        call_map[f.rva] = (it != meta::names.end()) ? it->second : f.name;
    }

    g_pseudo_code = Lifter::lift(g_disasm, open_binary.is_64bit(), call_map);

    g_cfg = CFG::build(g_disasm);
#ifdef HAVE_LLVM
    g_ir_result = IRLifter::lift(g_cfg, open_binary.is_64bit(), fn.name, call_map);
#endif
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

    glfwMaximizeWindow(m_window);
    glfwMakeContextCurrent(m_window);
    glfwSwapInterval(1);

    // Set window icon
    GLFWimage icon_img{32, 32, const_cast<unsigned char*>(app_icon_32x32)};
    glfwSetWindowIcon(m_window, 1, &icon_img);

    // If the layout version file is missing or stale, wipe imgui.ini so the
    // dock builder runs fresh (prevents new panels from floating after updates).
    {
        static const int k_layout_ver = 4;
        int stored = 0;
        if (FILE *vf = fopen("bh_layout.ver", "r")) { fscanf(vf, "%d", &stored); fclose(vf); }
        if (stored != k_layout_ver) {
            remove("imgui.ini");
            if (FILE *vf = fopen("bh_layout.ver", "w")) { fprintf(vf, "%d", k_layout_ver); fclose(vf); }
        }
    }

    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;

    // Load persisted theme (1 = dark, 0 = light; default dark)
    {
        int stored = 1;
        FILE *tf = fopen("bh_settings.dat", "r");
        if (tf) { fscanf(tf, "%d", &stored); fclose(tf); }
        g_dark_theme = (stored != 0);
    }
    if (g_dark_theme) ImGui::StyleColorsDark();
    else              ImGui::StyleColorsLight();
    ImGuiStyle &style = ImGui::GetStyle();
    style.ScaleAllSizes(scale);
    style.FontScaleDpi = scale;

    ImGui_ImplGlfw_InitForOpenGL(m_window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

#ifdef HAVE_YARA
    yr_initialize();
#endif
    return true;
}

void UI::destroy_window() {
#ifdef HAVE_YARA
    yr_finalize();
#endif
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

    ImGui::SetNextItemWidth(-1.f);
    static char filter[128]{};
    ImGui::InputText("##fnfilter", filter, sizeof(filter));

    // Rebuild filtered index only when filter or names change
    if (g_fn_filter_dirty || memcmp(filter, g_fn_filter_cache, sizeof(filter)) != 0) {
        g_fn_filtered_idx.clear();
        g_fn_filtered_idx.reserve(g_functions.size());
        for (int i = 0; i < (int)g_functions.size(); ++i) {
            const auto &fn = g_functions[i];
            auto nit = meta::names.find(fn.rva);
            const std::string &dn = (nit != meta::names.end()) ? nit->second : fn.name;
            if (!filter[0] || dn.find(filter) != std::string::npos
                           || fn.name.find(filter) != std::string::npos)
                g_fn_filtered_idx.push_back(i);
        }
        memcpy(g_fn_filter_cache, filter, sizeof(filter));
        g_fn_filter_dirty = false;
    }

    ImGui::TextDisabled("%zu / %zu", g_fn_filtered_idx.size(), g_functions.size());
    ImGui::Separator();

    static uint64_t rename_rva   = 0;
    static char     rename_buf[256]{};
    static bool     open_rename  = false;
    static uint64_t xrefs_rva   = 0;
    static bool     open_xrefs  = false;

    ImGui::BeginChild("##fnlist");
    ImGuiListClipper clipper;
    clipper.Begin((int)g_fn_filtered_idx.size());
    while (clipper.Step()) {
        for (int ci = clipper.DisplayStart; ci < clipper.DisplayEnd; ++ci) {
            int i = g_fn_filtered_idx[ci];
            const auto &fn = g_functions[i];
            auto nit = meta::names.find(fn.rva);
            const std::string &display_name = (nit != meta::names.end()) ? nit->second : fn.name;

            auto xr   = g_xrefs.find(fn.rva);
            size_t nc = (xr != g_xrefs.end()) ? xr->second.size() : 0;

            char label[288];
            if (nc > 0)
                snprintf(label, sizeof(label), "0x%08llX  %s%s [%zu↑]",
                         (unsigned long long)fn.rva, display_name.c_str(),
                         fn.from_exports ? " [exp]" : "", nc);
            else
                snprintf(label, sizeof(label), "0x%08llX  %s%s",
                         (unsigned long long)fn.rva, display_name.c_str(),
                         fn.from_exports ? " [exp]" : "");

            if (ImGui::Selectable(label, g_selected_func == i)) {
                g_selected_func  = i;
                g_nav_disasm_rva = static_cast<int64_t>(fn.rva);
                disassemble_function(fn);
            }
            if (ImGui::IsItemHovered() && fn.from_exports)
                ImGui::SetTooltip("Named export — right-click for options");

            if (ImGui::BeginPopupContextItem()) {
                ImGui::TextDisabled("0x%08llX  %s", (unsigned long long)fn.rva, display_name.c_str());
                ImGui::Separator();
                if (ImGui::MenuItem("Rename...")) {
                    rename_rva = fn.rva;
                    strncpy(rename_buf, display_name.c_str(), sizeof(rename_buf) - 1);
                    rename_buf[sizeof(rename_buf) - 1] = '\0';
                    open_rename = true;
                }
                char xref_label[64];
                snprintf(xref_label, sizeof(xref_label), "Show Callers (%zu)", nc);
                if (ImGui::MenuItem(xref_label, nullptr, false, nc > 0)) {
                    xrefs_rva  = fn.rva;
                    open_xrefs = true;
                }
                bool has_bm = meta::bookmarks.count(fn.rva) > 0;
                if (ImGui::MenuItem(has_bm ? "Remove Bookmark" : "Add Bookmark")) {
                    if (has_bm) meta::bookmarks.erase(fn.rva);
                    else        meta::bookmarks[fn.rva] = display_name;
                    meta::save(open_binary.get_path());
                }
                ImGui::EndPopup();
            }
        }
    }
    clipper.End();
    ImGui::EndChild();

    // ── Rename modal ─────────────────────────────────────────────────────────
    if (open_rename) { ImGui::OpenPopup("##rename_fn"); open_rename = false; }
    if (ImGui::BeginPopupModal("##rename_fn", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Rename  0x%08llX", (unsigned long long)rename_rva);
        ImGui::SetNextItemWidth(320.f);
        bool enter = ImGui::InputText("##renval", rename_buf, sizeof(rename_buf),
                                      ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::Separator();
        if (ImGui::Button("OK") || enter) {
            if (rename_buf[0]) meta::names[rename_rva] = rename_buf;
            else               meta::names.erase(rename_rva);
            meta::save(open_binary.get_path());
            g_fn_filter_dirty = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // ── Xrefs / callers modal ─────────────────────────────────────────────────
    if (open_xrefs) { ImGui::OpenPopup("##xrefs_fn"); open_xrefs = false; }
    if (ImGui::BeginPopupModal("##xrefs_fn", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        auto nit2 = meta::names.find(xrefs_rva);
        const char *xname = (nit2 != meta::names.end()) ? nit2->second.c_str() : "";
        ImGui::Text("Callers of  0x%08llX  %s", (unsigned long long)xrefs_rva, xname);
        ImGui::Separator();
        auto xr = g_xrefs.find(xrefs_rva);
        if (xr != g_xrefs.end() && !xr->second.empty()) {
            ImGui::BeginChild("##xreflist", ImVec2(480.f, 280.f));
            for (uint64_t caller : xr->second) {
                uint64_t best = 0;
                const function_t *bf = nullptr;
                for (const auto &f : g_functions)
                    if (f.rva <= caller && f.rva > best) { best = f.rva; bf = &f; }
                auto cit2 = bf ? meta::names.find(bf->rva) : meta::names.end();
                const char *fn_label = bf ? (cit2 != meta::names.end() ? cit2->second.c_str() : bf->name.c_str()) : "?";
                char row[160];
                snprintf(row, sizeof(row), "0x%08llX  (in %s)###xr%llx",
                         (unsigned long long)caller, fn_label, (unsigned long long)caller);
                if (ImGui::Selectable(row)) {
                    g_nav_disasm_rva = (int64_t)caller;
                    if (bf) {
                        for (int j = 0; j < (int)g_functions.size(); ++j)
                            if (g_functions[j].rva == bf->rva) { g_selected_func = j; disassemble_function(g_functions[j]); break; }
                    }
                    ImGui::CloseCurrentPopup();
                }
            }
            ImGui::EndChild();
        } else {
            ImGui::TextDisabled("No callers found.");
        }
        ImGui::Separator();
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

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

        for (size_t si = 0; si < g_sections.size(); ++si) {
            const auto &s = g_sections[si];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            bool row_sel = (g_sel_section == (int)si);
            char sel_id[32]; snprintf(sel_id, sizeof(sel_id), "##sr%zu", si);
            if (ImGui::Selectable(sel_id, row_sel,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                    ImVec2(0, 0)))
                g_sel_section = row_sel ? -1 : (int)si;
            ImGui::SameLine();
            ImGui::TextUnformatted(s.name.c_str());
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
            float ent = (si < g_section_entropies.size()) ? g_section_entropies[si] : 0.f;
            ImVec4 ecol = ent > 7.0f ? ImVec4(1.f,.2f,.2f,1.f)
                        : ent > 6.0f ? ImVec4(1.f,.7f,.1f,1.f)
                        : ImVec4(.6f,.9f,.6f,1.f);
            ImGui::TextColored(ecol, "%.2f", ent);
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

    // Description card for the selected section
    if (g_sel_section >= 0 && g_sel_section < (int)g_sections.size()) {
        const auto &s   = g_sections[g_sel_section];
        float        ent = (g_sel_section < (int)g_section_entropies.size())
                           ? g_section_entropies[g_sel_section] : 0.f;
        ImGui::Separator();
        ImGui::TextColored(ImVec4(.8f,.9f,1.f,1.f), "%s", s.name.c_str());
        ImGui::Spacing();

        // Purpose description
        static const struct { const char *name; const char *desc; } k_sec_descs[] = {
            {".text",    "Executable code — the CPU instructions that make up the program. Normal entropy is ~5.0–6.5."},
            {".data",    "Initialized global/static variables that the program can read and write at runtime."},
            {".rdata",   "Read-only data: string constants, import/export tables, vtables. Cannot be written at runtime."},
            {".bss",     "Uninitialized global variables. Zero-filled by the OS at load time; takes no space on disk."},
            {".rsrc",    "Resources embedded in the binary: icons, bitmaps, dialogs, version info, manifests."},
            {".reloc",   "Relocation table — lets the loader fix absolute addresses when the binary loads at a different base."},
            {".pdata",   "Exception handler data (x64 only). Used by the OS for stack unwinding when exceptions occur."},
            {".idata",   "Import directory and Import Address Table (IAT) — lists every DLL and function this binary uses."},
            {".edata",   "Export directory — lists functions this binary exposes so other DLLs or EXEs can call them."},
            {".tls",     "Thread Local Storage — per-thread data and TLS callbacks that run before the entry point."},
            {".cfg",     "Control Flow Guard data. A compiler security feature listing valid indirect-call targets."},
            {".vmp0",    "VMProtect section. Code has been virtualized and is very hard to reverse directly. Use ScyllaHide + OEP finding."},
            {".vmp1",    "VMProtect section (stage 2). Same approach as .vmp0."},
            {".vmp2",    "VMProtect section (stage 3)."},
            {"UPX0",     "UPX packer section. Run 'upx -d <file.exe>' to decompress and recover the original binary."},
            {"UPX1",     "UPX packer section (decompressed code will land here after unpacking)."},
            {".themida", "Themida/WinLicense protection section. Use OEP hunting + Scylla dump to bypass."},
        };
        const char *purpose = nullptr;
        for (const auto &d : k_sec_descs)
            if (s.name == d.name) { purpose = d.desc; break; }

        ImGui::PushTextWrapPos(0.f);
        if (purpose)
            ImGui::TextUnformatted(purpose);
        else
            ImGui::TextDisabled("No description available for this section name.");
        ImGui::PopTextWrapPos();

        ImGui::Spacing();
        // Entropy interpretation
        const char *ent_label = ent > 7.2f ? "Very high — likely packed or encrypted"
                              : ent > 6.4f ? "Elevated — may contain compressed data"
                              : ent > 5.0f ? "Normal for executable code"
                              : "Low — likely data or padding";
        ImVec4 ecol = ent > 7.0f ? ImVec4(1.f,.3f,.3f,1.f)
                    : ent > 6.4f ? ImVec4(1.f,.75f,.2f,1.f)
                    : ImVec4(.5f,.9f,.5f,1.f);
        ImGui::TextColored(ecol, "Entropy: %.2f/8.0 — %s", ent, ent_label);
        ImGui::TextDisabled("Hash: %s", g_sel_section < (int)g_section_hashes.size()
                            ? g_section_hashes[g_sel_section].c_str() : "");
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

    static int imp_tab = 0;
    ImGui::RadioButton("By DLL", &imp_tab, 0); ImGui::SameLine();
    ImGui::RadioButton("By Category", &imp_tab, 1);
    ImGui::Separator();

    ImGui::BeginChild("##implist");
    if (imp_tab == 0) {
        // ── Original DLL tree ────────────────────────────────────────────
        for (const auto &[dll, funcs] : g_imports_by_dll) {
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
                            if (tip) ImGui::SetTooltip("%s", tip);
                            else ImGui::SetTooltip("%s (no description available)", f->function.c_str());
                        }
                    }
                    ImGui::Unindent(16.f);
                }
                ImGui::TreePop();
            }
        }
    } else {
        // ── Category view ─────────────────────────────────────────────────
        for (const auto &ci : k_cat_info) {
            auto it = g_imports_by_cat.find(ci.cat);
            if (it == g_imports_by_cat.end() || it->second.empty()) continue;
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(ci.r, ci.g, ci.b, 1.f));
            bool open = ImGui::TreeNodeEx(ci.label,
                                          ImGuiTreeNodeFlags_DefaultOpen |
                                          ImGuiTreeNodeFlags_SpanFullWidth);
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%zu function(s)", ci.description, it->second.size());
            if (open) {
                ImGui::SameLine();
                ImGui::TextDisabled("  %zu", it->second.size());
                for (const auto *f : it->second) {
                    ImGui::Indent(16.f);
                    ImGui::TextUnformatted(f->function.c_str());
                    if (ImGui::IsItemHovered()) {
                        const char *tip = get_api_tip(f->function);
                        if (tip) ImGui::SetTooltip("%s\n[from %s]", tip, f->dll.c_str());
                        else     ImGui::SetTooltip("from %s", f->dll.c_str());
                    }
                    ImGui::Unindent(16.f);
                }
                ImGui::TreePop();
            }
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

    // Navigation history buttons
    bool can_back = (g_nav_pos > 0);
    bool can_fwd  = (g_nav_pos < (int)g_nav_history.size() - 1);
    if (!can_back) ImGui::BeginDisabled();
    if (ImGui::Button("< Back")) {
        --g_nav_pos;
        g_nav_back_fwd = true;
        uint64_t rva = g_nav_history[g_nav_pos].rva;
        bool found = false;
        for (int i = 0; i < (int)g_functions.size(); ++i)
            if (g_functions[i].rva == rva) { g_selected_func = i; disassemble_function(g_functions[i]); found = true; break; }
        if (!found) { function_t tmp{rva, "loc_" + rva_to_hex(rva), false}; disassemble_function(tmp); }
        g_nav_back_fwd = false;
    }
    if (!can_back) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!can_fwd) ImGui::BeginDisabled();
    if (ImGui::Button("Fwd >")) {
        ++g_nav_pos;
        g_nav_back_fwd = true;
        uint64_t rva = g_nav_history[g_nav_pos].rva;
        bool found = false;
        for (int i = 0; i < (int)g_functions.size(); ++i)
            if (g_functions[i].rva == rva) { g_selected_func = i; disassemble_function(g_functions[i]); found = true; break; }
        if (!found) { function_t tmp{rva, "loc_" + rva_to_hex(rva), false}; disassemble_function(tmp); }
        g_nav_back_fwd = false;
    }
    if (!can_fwd) ImGui::EndDisabled();
    ImGui::SameLine();

    // Header
    ImGui::TextColored(ImVec4(.5f,.8f,.5f,1.f), "Function @ 0x%08llX",
                       (unsigned long long)g_current_func_rva);
    ImGui::SameLine();
    ImGui::TextDisabled("  %zu instructions", g_disasm.size());
    ImGui::SameLine(0, 20.f);
    ImGui::Checkbox("Explain", &g_asm_annotate);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Show plain-English explanations for each instruction");
    ImGui::Separator();

    static uint64_t pending_comment_rva = 0;
    static char     comment_buf[256]{};
    static bool     open_comment_popup  = false;

    if (ImGui::BeginTable("disasmtable", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address",   ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("Bytes",     ImGuiTableColumnFlags_WidthFixed, 140.f);
        ImGui::TableSetupColumn("Mnemonic",  ImGuiTableColumnFlags_WidthFixed, 80.f);
        ImGui::TableSetupColumn("Operands",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Comment",   ImGuiTableColumnFlags_WidthFixed, 200.f);
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

                // Comment column (user comment or auto-annotation)
                ImGui::TableSetColumnIndex(4);
                {
                    auto cit = meta::comments.find(d.address);
                    if (cit != meta::comments.end()) {
                        ImGui::TextColored(ImVec4(.8f,.8f,.4f,1.f), "; %s", cit->second.c_str());
                    } else if (g_asm_annotate) {
                        std::string ann = annotate_insn(d);
                        if (!ann.empty())
                            ImGui::TextColored(ImVec4(.55f,.75f,.55f,1.f), "// %s", ann.c_str());
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Click to edit, right-click to clear");
                    } else {
                        ImGui::TextDisabled("+");
                    }
                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                        pending_comment_rva = d.address;
                        auto cit2 = meta::comments.find(d.address);
                        strncpy(comment_buf, cit2 != meta::comments.end() ? cit2->second.c_str() : "", sizeof(comment_buf)-1);
                        comment_buf[sizeof(comment_buf)-1] = '\0';
                        open_comment_popup = true;
                    }
                    if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                        meta::comments.erase(d.address);
                        meta::save(open_binary.get_path());
                    }
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    // Comment edit modal
    if (open_comment_popup) { ImGui::OpenPopup("##setcmt"); open_comment_popup = false; }
    if (ImGui::BeginPopupModal("##setcmt", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Comment  0x%08llX", (unsigned long long)pending_comment_rva);
        ImGui::SetNextItemWidth(380.f);
        bool enter = ImGui::InputText("##cmtval", comment_buf, sizeof(comment_buf),
                                      ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::Separator();
        if (ImGui::Button("Save") || enter) {
            if (comment_buf[0]) meta::comments[pending_comment_rva] = comment_buf;
            else               meta::comments.erase(pending_comment_rva);
            meta::save(open_binary.get_path());
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            meta::comments.erase(pending_comment_rva);
            meta::save(open_binary.get_path());
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
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

    static char str_filter[128]{};
    ImGui::SetNextItemWidth(180.f);
    bool filter_changed = ImGui::InputText("Filter", str_filter, sizeof(str_filter));

    // Rebuild filtered index only when filter or data changes
    if (filter_changed || g_str_filter_dirty ||
        memcmp(str_filter, g_str_filter_cache, sizeof(str_filter)) != 0) {
        g_str_filtered_idx.clear();
        g_str_filtered_idx.reserve(g_strings.size());
        for (size_t i = 0; i < g_strings.size(); ++i) {
            if (!str_filter[0] || g_strings[i].value.find(str_filter) != std::string::npos)
                g_str_filtered_idx.push_back(i);
        }
        memcpy(g_str_filter_cache, str_filter, sizeof(str_filter));
        g_str_filter_dirty = false;
    }

    ImGui::SameLine();
    ImGui::TextDisabled("%zu / %zu", g_str_filtered_idx.size(), g_strings.size());

    if (ImGui::BeginTable("strtable", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 90.f);
        ImGui::TableSetupColumn("Type",   ImGuiTableColumnFlags_WidthFixed, 50.f);
        ImGui::TableSetupColumn("Value",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(g_str_filtered_idx.size()));
        while (clipper.Step()) {
            for (int ci = clipper.DisplayStart; ci < clipper.DisplayEnd; ++ci) {
                const auto &s = g_strings[g_str_filtered_idx[ci]];
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
        }
        clipper.End();
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

    if (ImGui::CollapsingHeader("Rich Header")) {
        auto stub = open_binary.get_data(0, (size_t)dos->e_lfanew);
        auto rich = parse_rich_header(stub.data(), stub.size());
        if (rich.empty()) {
            ImGui::TextDisabled("No Rich header found (binary may not be MSVC-compiled).");
        } else {
            ImGui::TextDisabled("%zu tool/linker entr%s", rich.size(), rich.size()==1?"y":"ies");
            if (ImGui::BeginTable("richtbl", 4,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
                ImGui::TableSetupColumn("Product ID", ImGuiTableColumnFlags_WidthFixed, 80.f);
                ImGui::TableSetupColumn("Build ID",   ImGuiTableColumnFlags_WidthFixed, 70.f);
                ImGui::TableSetupColumn("Count",      ImGuiTableColumnFlags_WidthFixed, 55.f);
                ImGui::TableSetupColumn("Tool",       ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (const auto &e : rich) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("0x%04X", e.product_id);
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%u",      e.build_id);
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%u",      e.count);
                    ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(rich_product_name(e.product_id));
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Product 0x%04X  Build %u  Used %u time(s)\n"
                                          "Look up exact tool at richprint.com",
                                          e.product_id, e.build_id, e.count);
                }
                ImGui::EndTable();
            }
        }
    }

    if (ImGui::CollapsingHeader("TLS Callbacks")) {
        if (g_tls_callbacks.empty()) {
            ImGui::TextDisabled("No TLS directory / no callbacks.");
        } else {
            ImGui::TextColored(ImVec4(1.f,.7f,.2f,1.f),
                               "[!] %zu TLS callback(s) — execute BEFORE the entry point",
                               g_tls_callbacks.size());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("TLS callbacks run before AddressOfEntryPoint.\n"
                                  "Malware uses them for early anti-debug or decryption.");
            for (uint64_t rva : g_tls_callbacks) {
                char label[64]; snprintf(label, sizeof(label), "0x%08llX###tls%llX",
                                         (unsigned long long)rva, (unsigned long long)rva);
                if (ImGui::Selectable(label)) {
                    g_nav_disasm_rva = (int64_t)rva;
                    for (int i = 0; i < (int)g_functions.size(); ++i)
                        if (g_functions[i].rva == rva) { g_selected_func = i; disassemble_function(g_functions[i]); break; }
                }
            }
        }
    }

    if (ImGui::CollapsingHeader("PE Overlay")) {
        if (!g_overlay.size) {
            ImGui::TextDisabled("No overlay detected.");
        } else {
            ImGui::TextColored(ImVec4(1.f,.7f,.2f,1.f),
                               "[!] Overlay detected: %u bytes at file offset 0x%X",
                               g_overlay.size, g_overlay.offset);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Data exists after the last section's raw data.\n"
                                  "May contain encrypted payloads, configuration, "
                                  "certificates, or installer resources.");
            if (ImGui::Button("Jump to overlay in Hex View"))
                g_nav_hex_offset = (int64_t)g_overlay.offset;
        }
    }

    if (ImGui::CollapsingHeader("Hashes")) {
        if (ImGui::BeginTable("hashtbl", 2,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupColumn("Label",  ImGuiTableColumnFlags_WidthFixed, 130.f);
            ImGui::TableSetupColumn("MD5",    ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // ImpHash
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted("ImpHash");
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("MD5 of lowercased dll_stem.func pairs (VirusTotal compatible)");
            ImGui::TableSetColumnIndex(1);
            if (g_imphash.empty()) ImGui::TextDisabled("N/A");
            else {
                ImGui::TextUnformatted(g_imphash.c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click to copy");
                if (ImGui::IsItemClicked()) ImGui::SetClipboardText(g_imphash.c_str());
            }

            // Section MD5s
            for (size_t i = 0; i < g_sections.size() && i < g_section_hashes.size(); ++i) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char slabel[40]; snprintf(slabel, sizeof(slabel), "%s (MD5)", g_sections[i].name.c_str());
                ImGui::TextUnformatted(slabel);
                ImGui::TableSetColumnIndex(1);
                if (g_section_hashes[i].empty()) ImGui::TextDisabled("empty");
                else {
                    ImGui::TextUnformatted(g_section_hashes[i].c_str());
                    if (ImGui::IsItemClicked()) ImGui::SetClipboardText(g_section_hashes[i].c_str());
                }
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

static void render_ir_panel() {
    ImGui::Begin("LLVM IR");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

#ifndef HAVE_LLVM
    ImGui::TextDisabled("LLVM IR not enabled.");
    ImGui::Separator();
    ImGui::TextWrapped("To enable: add \"llvm\" to vcpkg.json dependencies, then rebuild. "
                       "CMakeLists.txt already has optional detection — "
                       "HAVE_LLVM will be defined automatically when the package is found. "
                       "Note: LLVM compiles from source and may take 1-2 hours.");
    ImGui::End();
    return;
#else
    if (!g_ir_result.valid) {
        if (!g_ir_result.error.empty())
            ImGui::TextColored(ImVec4(1.f,.4f,.4f,1.f), "Lift error: %s", g_ir_result.error.c_str());
        else
            ImGui::TextDisabled("Select a function to lift to LLVM IR.");
        ImGui::End(); return;
    }

    static bool show_optimized = true;
    static bool show_raw       = false;
    ImGui::Checkbox("Optimized", &show_optimized);
    ImGui::SameLine();
    ImGui::Checkbox("Raw", &show_raw);
    ImGui::SameLine();
    ImGui::TextDisabled("  %zu blocks", g_cfg.blocks.size());
    ImGui::Separator();

    const std::string &ir = show_optimized ? g_ir_result.opt_ir : g_ir_result.raw_ir;

    const ImVec4 col_def    = ImVec4(0.85f, 0.85f, 0.85f, 1.f);
    const ImVec4 col_kw     = ImVec4(0.56f, 0.74f, 1.0f,  1.f);
    const ImVec4 col_label  = ImVec4(0.90f, 0.70f, 0.30f, 1.f);
    const ImVec4 col_meta   = ImVec4(0.50f, 0.80f, 0.50f, 1.f);

    ImGui::BeginChild("##ir_body", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);

    static std::string cached_ir;
    static std::vector<std::string> cached_lines;
    if (cached_ir != ir) {
        cached_ir = ir;
        cached_lines.clear();
        size_t pos = 0;
        while (pos < ir.size()) {
            size_t nl = ir.find('\n', pos);
            if (nl == std::string::npos) nl = ir.size();
            cached_lines.push_back(ir.substr(pos, nl - pos));
            pos = nl + 1;
        }
    }

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(cached_lines.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const std::string &line = cached_lines[i];
            if (line.empty()) { ImGui::Spacing(); continue; }

            ImVec4 col = col_def;
            const char *t = line.c_str();
            while (*t == ' ') ++t;

            if (*t == ';')
                col = col_meta;
            else if (strncmp(t, "define", 6) == 0 || strncmp(t, "declare", 7) == 0 ||
                     strncmp(t, "attributes", 10) == 0)
                col = col_kw;
            else if (strncmp(t, "br ", 3) == 0 || strncmp(t, "ret ", 4) == 0 ||
                     strncmp(t, "call ", 5) == 0 || strncmp(t, "unreachable", 11) == 0)
                col = col_kw;
            else if (line.back() == ':' && line.find(' ') == std::string::npos)
                col = col_label;

            ImGui::TextColored(col, "%s", line.c_str());
        }
    }
    clipper.End();
    ImGui::EndChild();
    ImGui::End();
#endif // HAVE_LLVM
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
    const auto &logs = Logger::get()->get_logs();
    ImGuiListClipper clilog;
    clilog.Begin((int)logs.size());
    while (clilog.Step()) {
        for (int i = clilog.DisplayStart; i < clilog.DisplayEnd; ++i)
            ImGui::Text("[%s]: %s", logs[i].owner.c_str(), logs[i].message.c_str());
    }
    clilog.End();
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
    ImGui::End();
}

static void render_yara_panel() {
    ImGui::Begin("YARA");
#ifndef HAVE_YARA
    ImGui::TextDisabled("YARA not enabled.");
    ImGui::Separator();
    ImGui::TextWrapped("To enable: add \"yara\" to vcpkg.json, then rebuild. "
                       "CMakeLists.txt already has optional detection — "
                       "HAVE_YARA will be defined automatically when the package is found.");
#else
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    ImGui::SetNextItemWidth(-80.f);
    ImGui::InputText("##yarpath", g_yara_rules_path, sizeof(g_yara_rules_path));
    ImGui::SameLine();
    if (ImGui::Button("Scan")) {
        do_yara_scan();
        g_yara_ready = true;
    }

    if (!g_yara_error.empty())
        ImGui::TextColored(ImVec4(1.f,.3f,.3f,1.f), "Error: %s", g_yara_error.c_str());

    if (g_yara_ready) {
        ImGui::Separator();
        if (g_yara_matches.empty()) {
            ImGui::TextDisabled("No matches.");
        } else {
            ImGui::TextDisabled("%zu rule(s) matched", g_yara_matches.size());
            ImGui::BeginChild("##yara_results");
            for (const auto &m : g_yara_matches) {
                bool open = ImGui::TreeNodeEx(m.rule.c_str(), ImGuiTreeNodeFlags_DefaultOpen);
                if (open) {
                    for (const auto &[sid, off] : m.hits) {
                        char row[128];
                        snprintf(row, sizeof(row), "%s  @ 0x%08llX", sid.c_str(), (unsigned long long)off);
                        if (ImGui::Selectable(row)) g_nav_hex_offset = (int64_t)off;
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::EndChild();
        }
    }
#endif
    ImGui::End();
}

static void render_security_panel() {
    ImGui::Begin("Security Analysis");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (g_security_findings.empty()) {
        ImGui::TextColored(ImVec4(.4f,.9f,.4f,1.f), "No known protections or anti-debug APIs detected.");
        ImGui::End(); return;
    }

    ImGui::TextDisabled("%zu finding(s)", g_security_findings.size());
    ImGui::Separator();
    ImGui::BeginChild("##seclist");
    for (const auto &f : g_security_findings) {
        ImVec4 col = f.severity >= 3 ? ImVec4(1.f,.3f,.3f,1.f)
                   : f.severity == 2 ? ImVec4(1.f,.7f,.2f,1.f)
                   : ImVec4(.7f,.85f,1.f,1.f);
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        bool open = ImGui::TreeNodeEx(f.title.c_str(), ImGuiTreeNodeFlags_SpanAvailWidth);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled(" [%s]", f.category.c_str());
        if (open) {
            ImGui::TextWrapped("%s", f.description.c_str());
            if (!f.bypass.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(.4f,.9f,.9f,1.f), "Bypass:");
                ImGui::SameLine();
                ImGui::TextWrapped("%s", f.bypass.c_str());
            }
            ImGui::TreePop();
        }
    }
    ImGui::EndChild();
    ImGui::End();
}

static void do_byte_search() {
    g_search_results.clear();
    g_search_done = false;
    if (!open_binary.is_open()) return;

    // Parse hex pattern with optional ?? wildcards
    std::vector<int16_t> pattern;
    for (const char *p = g_search_pattern; *p; ) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') {
            pattern.push_back(-1);
            p += 2;
        } else if (isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) {
            char hex[3] = {p[0], p[1], 0};
            pattern.push_back((int16_t)strtoul(hex, nullptr, 16));
            p += 2;
        } else {
            ++p;
        }
    }

    if (pattern.empty()) { g_search_done = true; return; }
    size_t plen      = pattern.size();
    size_t file_size = open_binary.get_binary_size();
    if (file_size < plen) { g_search_done = true; return; }

    const size_t CHUNK = 65536;
    size_t off = 0;
    while (off + plen <= file_size && g_search_results.size() < 1000) {
        size_t chunk = std::min(CHUNK + plen - 1, file_size - off);
        auto buf = open_binary.get_data(off, chunk);
        if (buf.empty()) break;
        for (size_t i = 0; i + plen <= buf.size() && g_search_results.size() < 1000; ++i) {
            bool match = true;
            for (size_t j = 0; j < plen; ++j) {
                if (pattern[j] >= 0 && buf[i + j] != (uint8_t)pattern[j]) { match = false; break; }
            }
            if (match) {
                search_result_t r;
                r.offset  = (uint32_t)(off + i);
                size_t cs = (off + i > 4) ? off + i - 4 : 0;
                r.context = open_binary.get_data(cs, 16);
                g_search_results.push_back(std::move(r));
            }
        }
        off += CHUNK;
    }
    g_search_done = true;
}

static void render_search_panel() {
    ImGui::Begin("Search");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    ImGui::SetNextItemWidth(-80.f);
    ImGui::InputText("##spat", g_search_pattern, sizeof(g_search_pattern));
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Hex bytes with wildcard bytes, e.g.:\n  FF 25 ?? ?? ?? ??\n  48 83 EC ??");
    ImGui::SameLine();
    if (ImGui::Button("Search")) do_byte_search();

    if (!g_search_done) {
        ImGui::TextDisabled("Enter a hex byte pattern and click Search.");
    } else if (g_search_results.empty()) {
        ImGui::TextDisabled("No matches found.");
    } else {
        ImGui::TextDisabled("%zu match(es)%s", g_search_results.size(),
                            g_search_results.size() >= 1000 ? " (capped at 1000)" : "");
        if (ImGui::BeginTable("searchtbl", 2,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("File Offset", ImGuiTableColumnFlags_WidthFixed, 100.f);
            ImGui::TableSetupColumn("Context",     ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const auto &r : g_search_results) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char row[32]; snprintf(row, sizeof(row), "0x%08X###sr%u", r.offset, r.offset);
                if (ImGui::Selectable(row, false, ImGuiSelectableFlags_SpanAllColumns))
                    g_nav_hex_offset = (int64_t)r.offset;
                ImGui::TableSetColumnIndex(1);
                std::string hex;
                for (uint8_t b : r.context) { char tmp[4]; snprintf(tmp,sizeof(tmp),"%02X ",b); hex+=tmp; }
                ImGui::TextDisabled("%s", hex.c_str());
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

static void render_bookmarks_panel() {
    ImGui::Begin("Bookmarks");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (meta::bookmarks.empty()) {
        ImGui::TextDisabled("No bookmarks yet.");
        ImGui::TextDisabled("Right-click a function in the Function Explorer to add one.");
    } else {
        ImGui::TextDisabled("%zu bookmark(s)", meta::bookmarks.size());
        ImGui::Separator();
        std::vector<uint64_t> to_del;
        ImGui::BeginChild("##bklist");
        for (const auto &[rva, label] : meta::bookmarks) {
            char row[256];
            snprintf(row, sizeof(row), "0x%08llX  %s###bm%llX",
                     (unsigned long long)rva, label.c_str(), (unsigned long long)rva);
            if (ImGui::Selectable(row)) {
                g_nav_disasm_rva = (int64_t)rva;
                for (int i = 0; i < (int)g_functions.size(); ++i)
                    if (g_functions[i].rva == rva) { g_selected_func = i; disassemble_function(g_functions[i]); break; }
            }
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Remove")) to_del.push_back(rva);
                ImGui::EndPopup();
            }
        }
        ImGui::EndChild();
        for (uint64_t rva : to_del) {
            meta::bookmarks.erase(rva);
            meta::save(open_binary.get_path());
        }
    }
    ImGui::End();
}

static void render_callgraph_panel() {
    ImGui::Begin("Call Graph");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }
    if (g_selected_func < 0 || g_selected_func >= (int)g_functions.size()) {
        ImGui::TextDisabled("Select a function in the Function Explorer.");
        ImGui::End(); return;
    }

    const function_t &fn = g_functions[g_selected_func];

    auto name_of = [](uint64_t rva) -> std::string {
        auto it = meta::names.find(rva);
        if (it != meta::names.end()) return it->second;
        for (const auto &f : g_functions) if (f.rva == rva) return f.name;
        char tmp[32]; snprintf(tmp, sizeof(tmp), "sub_%llX", (unsigned long long)rva);
        return tmp;
    };

    auto nav_to = [](uint64_t rva) {
        for (int i = 0; i < (int)g_functions.size(); ++i)
            if (g_functions[i].rva == rva) { g_selected_func = i; disassemble_function(g_functions[i]); return; }
        function_t tmp{rva, "loc_" + rva_to_hex(rva), false};
        disassemble_function(tmp);
    };

    // Callers
    if (ImGui::CollapsingHeader("Callers", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto it = g_xrefs.find(fn.rva);
        if (it == g_xrefs.end() || it->second.empty()) {
            ImGui::TextDisabled("No callers found.");
        } else {
            ImGui::BeginChild("##cgcallers", ImVec2(0, 120.f));
            for (uint64_t ca : it->second) {
                uint64_t best = 0;
                for (const auto &f : g_functions) if (f.rva <= ca && f.rva > best) best = f.rva;
                char row[192];
                if (best)
                    snprintf(row, sizeof(row), "0x%08llX  (in %s)###cgcr%llX",
                             (unsigned long long)ca, name_of(best).c_str(), (unsigned long long)ca);
                else
                    snprintf(row, sizeof(row), "0x%08llX###cgcr%llX", (unsigned long long)ca, (unsigned long long)ca);
                if (ImGui::Selectable(row) && best) nav_to(best);
            }
            ImGui::EndChild();
        }
    }

    // Current function label
    ImGui::TextColored(ImVec4(.5f,.8f,1.f,1.f), "► 0x%08llX  %s",
                       (unsigned long long)fn.rva, name_of(fn.rva).c_str());

    // Callees (from current disassembly)
    if (ImGui::CollapsingHeader("Callees", ImGuiTreeNodeFlags_DefaultOpen)) {
        std::unordered_set<uint64_t> seen;
        std::vector<std::pair<uint64_t,uint64_t>> callees;
        for (const auto &d : g_disasm)
            if (d.is_call && d.branch_target && seen.insert(d.branch_target).second)
                callees.emplace_back(d.address, d.branch_target);

        if (callees.empty()) {
            ImGui::TextDisabled("No outgoing calls in current disassembly.");
        } else {
            ImGui::BeginChild("##cgcallees", ImVec2(0, 120.f));
            for (const auto &[ca, tgt] : callees) {
                char row[192];
                snprintf(row, sizeof(row), "0x%08llX  → %s###cgce%llX",
                         (unsigned long long)ca, name_of(tgt).c_str(), (unsigned long long)tgt);
                if (ImGui::Selectable(row)) nav_to(tgt);
            }
            ImGui::EndChild();
        }
    }
    ImGui::End();
}

static void render_resources_panel() {
    ImGui::Begin("Resources");
    if (!open_binary.is_open()) { ImGui::TextDisabled("No binary loaded."); ImGui::End(); return; }

    if (g_resource_types.empty()) {
        ImGui::TextDisabled("No resource directory found.");
        ImGui::End(); return;
    }

    ImGui::TextDisabled("%zu resource type(s)", g_resource_types.size());
    if (ImGui::BeginTable("restbl", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Type ID", ImGuiTableColumnFlags_WidthFixed, 70.f);
        ImGui::TableSetupColumn("Name",    ImGuiTableColumnFlags_WidthFixed, 160.f);
        ImGui::TableSetupColumn("Count",   ImGuiTableColumnFlags_WidthFixed, 60.f);
        ImGui::TableHeadersRow();
        for (const auto &rt : g_resource_types) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (rt.id == 0xFFFFu) ImGui::TextDisabled("Named");
            else ImGui::Text("%u", rt.id);
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(rt.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("%u", rt.count);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void export_json() {
    if (!open_binary.is_open()) return;
    const std::string &path = open_binary.get_path();
    std::string out_path    = path + ".bh_report.json";

    FILE *f = fopen(out_path.c_str(), "w");
    if (!f) { Logger::get()->log("JSON export failed: cannot write " + out_path, "Export"); return; }

    auto esc = [](const std::string &s) -> std::string {
        std::string o;
        for (char c : s) {
            if      (c == '"')  o += "\\\"";
            else if (c == '\\') o += "\\\\";
            else if (c == '\n') o += "\\n";
            else if (c == '\r') o += "\\r";
            else if (c == '\t') o += "\\t";
            else if ((unsigned char)c < 0x20) { char t[8]; snprintf(t,sizeof(t),"\\u%04X",(unsigned char)c); o+=t; }
            else o += c;
        }
        return o;
    };

    fprintf(f, "{\n");
    fprintf(f, "  \"file\": \"%s\",\n", esc(path).c_str());
    fprintf(f, "  \"arch\": \"%s\",\n", open_binary.is_64bit() ? "x64" : "x86");
    fprintf(f, "  \"imphash\": \"%s\",\n", g_imphash.c_str());
    fprintf(f, "  \"entrypoint\": \"0x%llX\",\n", (unsigned long long)open_binary.get_entrypoint());
    fprintf(f, "  \"file_size\": %zu,\n", open_binary.get_binary_size());
    fprintf(f, "  \"has_overlay\": %s,\n", g_overlay.size ? "true" : "false");
    fprintf(f, "  \"overlay_offset\": \"0x%X\",\n", g_overlay.offset);
    fprintf(f, "  \"tls_callback_count\": %zu,\n", g_tls_callbacks.size());

    // Sections
    fprintf(f, "  \"sections\": [\n");
    for (size_t i = 0; i < g_sections.size(); ++i) {
        const auto &s = g_sections[i];
        fprintf(f, "    {\"name\":\"%s\",\"va\":\"0x%X\",\"raw_offset\":\"0x%X\",\"raw_size\":\"0x%X\",\"virt_size\":\"0x%X\"%s}%s\n",
                esc(s.name).c_str(), s.va, s.raw_offset, s.raw_size, s.virt_size,
                (i < g_section_hashes.size() && !g_section_hashes[i].empty())
                    ? (",\"md5\":\"" + g_section_hashes[i] + "\"").c_str() : "",
                i + 1 < g_sections.size() ? "," : "");
    }
    fprintf(f, "  ],\n");

    // Imports
    fprintf(f, "  \"imports\": [\n");
    for (size_t i = 0; i < g_imports.size(); ++i) {
        const auto &imp = g_imports[i];
        fprintf(f, "    {\"dll\":\"%s\",\"function\":\"%s\",\"by_ordinal\":%s}%s\n",
                esc(imp.dll).c_str(), esc(imp.function).c_str(),
                imp.by_ordinal ? "true" : "false",
                i + 1 < g_imports.size() ? "," : "");
    }
    fprintf(f, "  ],\n");

    // Exports
    fprintf(f, "  \"exports\": [\n");
    for (size_t i = 0; i < g_exports.size(); ++i) {
        const auto &e = g_exports[i];
        fprintf(f, "    {\"ordinal\":%u,\"rva\":\"0x%X\",\"name\":\"%s\"}%s\n",
                e.ordinal, e.rva, esc(e.function).c_str(),
                i + 1 < g_exports.size() ? "," : "");
    }
    fprintf(f, "  ],\n");

    // Functions
    fprintf(f, "  \"functions\": [\n");
    for (size_t i = 0; i < g_functions.size(); ++i) {
        const auto &fn = g_functions[i];
        auto nit = meta::names.find(fn.rva);
        const std::string &nm = (nit != meta::names.end()) ? nit->second : fn.name;
        auto xr = g_xrefs.find(fn.rva);
        fprintf(f, "    {\"rva\":\"0x%llX\",\"name\":\"%s\",\"xref_count\":%zu}%s\n",
                (unsigned long long)fn.rva, esc(nm).c_str(),
                xr != g_xrefs.end() ? xr->second.size() : 0,
                i + 1 < g_functions.size() ? "," : "");
    }
    fprintf(f, "  ],\n");

    // Security findings
    fprintf(f, "  \"security_findings\": [\n");
    for (size_t i = 0; i < g_security_findings.size(); ++i) {
        const auto &sf = g_security_findings[i];
        fprintf(f, "    {\"category\":\"%s\",\"title\":\"%s\",\"severity\":%d}%s\n",
                esc(sf.category).c_str(), esc(sf.title).c_str(), sf.severity,
                i + 1 < g_security_findings.size() ? "," : "");
    }
    fprintf(f, "  ],\n");

    // Comments
    fprintf(f, "  \"comments\": [\n");
    {
        size_t idx = 0, total = meta::comments.size();
        for (const auto &[rva, cmt] : meta::comments)
            fprintf(f, "    {\"rva\":\"0x%llX\",\"text\":\"%s\"}%s\n",
                    (unsigned long long)rva, esc(cmt).c_str(), ++idx < total ? "," : "");
    }
    fprintf(f, "  ]\n}\n");

    fclose(f);
    Logger::get()->log("JSON report: " + out_path, "Export");
}

// ── Overview panel ────────────────────────────────────────────────────────

static void render_overview_panel() {
    ImGui::Begin("Overview");
    if (!open_binary.is_open()) {
        ImGui::TextDisabled("No binary loaded.");
        ImGui::End();
        return;
    }

    const auto &ov = g_overview;

    // ── Threat score bar ─────────────────────────────────────────────────
    ImVec4 score_col;
    if      (ov.score < 20) score_col = ImVec4(.25f, .85f, .30f, 1.f);
    else if (ov.score < 45) score_col = ImVec4(.95f, .80f, .10f, 1.f);
    else if (ov.score < 70) score_col = ImVec4(1.f,  .45f, .10f, 1.f);
    else                    score_col = ImVec4(1.f,  .15f, .15f, 1.f);

    ImGui::TextUnformatted("Threat Score");
    ImGui::SameLine();
    ImGui::TextColored(score_col, "%d / 100  (%s)", ov.score, ov.verdict.c_str());

    float frac = std::clamp(ov.score / 100.f, 0.f, 1.f);
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, score_col);
    ImGui::ProgressBar(frac, ImVec2(-1.f, 10.f), "");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(.55f, .55f, .55f, 1.f));
    ImGui::TextWrapped("This score is a rough static analysis estimate based on import patterns, "
                       "entropy, and known signatures. It is not a definitive verdict -- legitimate "
                       "software can score high (e.g. installers, packers) and some malware may "
                       "score low if well-obfuscated. Always verify with dynamic analysis or an AV "
                       "scanner before drawing conclusions.");
    ImGui::PopStyleColor();

    ImGui::Spacing();

    // ── Narrative ────────────────────────────────────────────────────────
    ImGui::SeparatorText("Summary");
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(ov.narrative.c_str());
    ImGui::PopTextWrapPos();

    ImGui::Spacing();

    // ── Findings ─────────────────────────────────────────────────────────
    if (!ov.findings.empty()) {
        ImGui::SeparatorText("Key Findings");
        for (const auto &f : ov.findings) {
            ImGui::Bullet();
            ImGui::SameLine();
            ImGui::PushTextWrapPos(0.f);
            ImGui::TextUnformatted(f.c_str());
            ImGui::PopTextWrapPos();
        }
        ImGui::Spacing();
    }

    // ── "Is this normal?" stats table ────────────────────────────────────
    ImGui::SeparatorText("Is This Normal?");
    if (ImGui::BeginTable("##ovstats", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Property",     ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Value",        ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Normal Range", ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Note",         ImGuiTableColumnFlags_WidthStretch, 1.8f);
        ImGui::TableHeadersRow();

        for (const auto &s : ov.stats) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(s.label.c_str());
            ImGui::TableSetColumnIndex(1);
            if (s.ok) ImGui::TextColored(ImVec4(.3f,.9f,.3f,1.f), "%s", s.value.c_str());
            else      ImGui::TextColored(ImVec4(1.f,.4f,.4f,1.f), "%s", s.value.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextDisabled("%s", s.normal_range.c_str());
            ImGui::TableSetColumnIndex(3);
            if (!s.note.empty())
                ImGui::TextColored(ImVec4(1.f,.75f,.3f,1.f), "%s", s.note.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();

    // ── Behaviour category badges ─────────────────────────────────────────
    ImGui::SeparatorText("Import Behaviour Categories");
    bool any = false;
    for (const auto &ci : k_cat_info) {
        auto it = ov.cat_counts.find(ci.cat);
        if (it == ov.cat_counts.end() || it->second == 0) continue;
        any = true;
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(ci.r*.5f, ci.g*.5f, ci.b*.5f, 1.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(ci.r*.7f, ci.g*.7f, ci.b*.7f, 1.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(ci.r,     ci.g,     ci.b,     1.f));
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "%s  %d##ovbadge%d", ci.label, it->second, (int)ci.cat);
        ImGui::SmallButton(lbl);
        ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", ci.description);
        ImGui::SameLine(0, 6.f);
    }
    if (any) ImGui::NewLine();
    else     ImGui::TextDisabled("No categorised imports.");

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

    // ── Onboarding state ─────────────────────────────────────────────────
    static bool s_onboard_checked = false;
    static bool s_show_onboard    = false;
    static int  s_onboard_page    = 0;
    static bool s_onboard_skip    = false;
    static bool s_open_onboard    = false;

    // ── Menu bar ─────────────────────────────────────────────────────────
    static bool open_file_dialog = false;
    float menubar_h = 0.f;
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open", "Ctrl+O"))  open_file_dialog = true;
            ImGui::Separator();
            if (ImGui::MenuItem("Export JSON Report", nullptr, false, open_binary.is_open()))
                export_json();
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4"))  glfwSetWindowShouldClose(m_window, true);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Function Explorer"); ImGui::MenuItem("Sections");
            ImGui::MenuItem("Disassembly");       ImGui::MenuItem("Exports");
            ImGui::MenuItem("Imports");           ImGui::MenuItem("Hex View");
            ImGui::MenuItem("Strings");           ImGui::MenuItem("PE Headers");
            ImGui::MenuItem("Pseudo Code");       ImGui::MenuItem("LLVM IR");
            ImGui::MenuItem("YARA");              ImGui::MenuItem("Console");
            ImGui::MenuItem("Security Analysis"); ImGui::MenuItem("Search");
            ImGui::MenuItem("Bookmarks");         ImGui::MenuItem("Call Graph");
            ImGui::MenuItem("Resources");
            ImGui::Separator();
            if (ImGui::MenuItem(g_dark_theme ? "Switch to Light Theme" : "Switch to Dark Theme")) {
                g_dark_theme    = !g_dark_theme;
                g_theme_changed = true;
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About / Help")) s_open_onboard = true;
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
        menubar_h = ImGui::GetFrameHeight();
    }

    // Apply theme when toggled — persist choice to disk
    if (g_theme_changed) {
        g_theme_changed = false;
        if (g_dark_theme) ImGui::StyleColorsDark();
        else              ImGui::StyleColorsLight();
        if (FILE *tf = fopen("bh_settings.dat", "w")) {
            fprintf(tf, "%d", g_dark_theme ? 1 : 0); fclose(tf);
        }
    }

    // ── Onboarding modal ─────────────────────────────────────────────────
    if (!s_onboard_checked) {
        s_onboard_checked = true;
        FILE *vf = fopen("bh_onboarded.ver", "r");
        if (vf) { fclose(vf); }
        else    { s_show_onboard = true; }
    }
    if (s_open_onboard) {
        s_open_onboard = false;
        s_show_onboard = true;
        s_onboard_page = 0;
        s_onboard_skip = false;
    }
    if (s_show_onboard && !ImGui::IsPopupOpen("##Onboarding"))
        ImGui::OpenPopup("##Onboarding");

    {
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Always, {0.5f, 0.5f});
        ImGui::SetNextWindowSize({580, 0}, ImGuiCond_Always);
        if (ImGui::BeginPopupModal("##Onboarding", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
            ImGuiStyle &sty = ImGui::GetStyle();
            const ImVec4 kOrange{0.86f, 0.35f, 0.16f, 1.f};
            const ImVec4 kBlue  {0.50f, 0.72f, 1.00f, 1.f};
            const ImVec4 kGold  {0.86f, 0.72f, 0.30f, 1.f};
            const ImVec4 kMuted {0.55f, 0.55f, 0.55f, 1.f};

            // ── Progress dots ────────────────────────────────────────────
            float dot_total = 3 * 12.f + 2 * 8.f;
            ImGui::SetCursorPosX((580 - dot_total) * 0.5f);
            for (int i = 0; i < 3; ++i) {
                ImGui::TextColored(i == s_onboard_page ? kOrange : ImVec4{0.35f,0.35f,0.35f,1.f},
                                   i == s_onboard_page ? "●" : "○");
                if (i < 2) ImGui::SameLine(0, 8.f);
            }
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // ── Page content ─────────────────────────────────────────────
            if (s_onboard_page == 0) {
                float title_w = ImGui::CalcTextSize("BinaryHammer").x;
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - title_w) * 0.5f);
                ImGui::TextColored(kOrange, "BinaryHammer");
                ImGui::Spacing();
                ImGui::TextWrapped(
                    "An open-source PE binary analysis tool for malware analysts and reverse "
                    "engineers who need fast, structured inspection without the overhead of "
                    "commercial tools.");
                ImGui::Spacing();
                ImGui::TextWrapped(
                    "Load any Windows PE executable and BinaryHammer will automatically detect "
                    "functions, disassemble them, extract imports/exports, compute section entropy, "
                    "and flag suspicious patterns.");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextColored(kBlue, "What's included:");
                ImGui::BulletText("x86 / x64 PE support (EXE, DLL, SYS)");
                ImGui::BulletText("Zydis-powered disassembly with annotated call targets");
                ImGui::BulletText("Pseudo-C code lifting from assembly");
                ImGui::BulletText("Shannon entropy analysis per section");
                ImGui::BulletText("YARA rule scanning");
                ImGui::BulletText("JSON report export");

            } else if (s_onboard_page == 1) {
                ImGui::TextColored(kOrange, "Panel Overview");
                ImGui::Spacing();

                auto row = [&](const char *name, const char *desc) {
                    ImGui::TextColored(kGold, "  %-20s", name);
                    ImGui::SameLine();
                    ImGui::TextWrapped("%s", desc);
                };

                ImGui::TextColored(kBlue, "Left");
                row("Function Explorer", "All detected functions; click to disassemble. Rename/bookmark/xref via right-click.");
                ImGui::Spacing();

                ImGui::TextColored(kBlue, "Center");
                row("Disassembly",  "Full x86/x64 disassembly. Hover instructions for details; click RVAs to navigate.");
                row("Pseudo Code",  "Lifted pseudo-C view of the selected function.");
                row("Hex View",     "Raw byte view with offset jumping and byte-pattern search.");
                row("Call Graph",   "Visual call graph centred on the current function.");
                ImGui::Spacing();

                ImGui::TextColored(kBlue, "Right");
                row("Overview",    "At-a-glance threat score and binary summary.");
                row("Strings",     "Extracted ASCII / UTF-16 strings with filter.");
                row("Imports",     "DLL dependencies grouped by category (net, crypto, …).");
                row("Exports",     "Exported symbols with RVAs.");
                row("PE Headers",  "Full COFF / Optional header dump.");
                row("Sections",    "Section table with entropy and flags.");
                ImGui::Spacing();

                ImGui::TextColored(kBlue, "Bottom");
                row("Security",    "Packer detection, W+X sections, suspicious IOC strings, threat score.");
                row("YARA",        "Run custom YARA rule files against the loaded binary.");
                row("Search",      "Hex byte-pattern search across the full file.");
                row("Console",     "CLI interface — type  .help  for the full command list.");

            } else {
                ImGui::TextColored(kOrange, "Getting Started");
                ImGui::Spacing();

                auto step = [&](const char *num, const char *text) {
                    ImGui::TextColored(kGold, "%s", num);
                    ImGui::SameLine();
                    ImGui::TextWrapped("%s", text);
                    ImGui::Spacing();
                };

                step("1.", "Open a binary via  File > Open  (Ctrl+O). Any PE file will work — EXE, DLL, SYS.");
                step("2.", "Functions are detected automatically. Click one in the Function Explorer to disassemble it.");
                step("3.", "Right-click any function to  Rename  it, add a  Bookmark, or view  Show Callers.");
                step("4.", "Check the  Security Analysis  and  Overview  panels for an automated threat summary and risk score.");
                step("5.", "Export findings via  File > Export JSON Report. Reopen this guide any time from  Help > About / Help.");

                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextColored(kMuted, "Tip: resize and rearrange panels freely — the layout is saved between sessions.");
                ImGui::Spacing();
                ImGui::Checkbox("Don't show this again on startup", &s_onboard_skip);
            }

            // ── Navigation row ───────────────────────────────────────────
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (s_onboard_page > 0) {
                if (ImGui::Button("< Back", {80, 0})) --s_onboard_page;
                ImGui::SameLine();
            }

            float win_w  = ImGui::GetWindowWidth();
            float pad    = sty.WindowPadding.x;

            if (s_onboard_page < 2) {
                float bw = 80.f;
                ImGui::SetCursorPosX(win_w - bw - pad);
                if (ImGui::Button("Next >", {bw, 0})) ++s_onboard_page;
            } else {
                float bw_load = 110.f, bw_skip = 70.f, gap = 8.f;
                ImGui::SetCursorPosX(win_w - bw_load - gap - bw_skip - pad);
                if (ImGui::Button("Skip", {bw_skip, 0})) {
                    if (s_onboard_skip) {
                        if (FILE *f = fopen("bh_onboarded.ver", "w")) { fputs("1", f); fclose(f); }
                    }
                    s_show_onboard = false;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine(0, gap);
                if (ImGui::Button("Load File", {bw_load, 0})) {
                    if (s_onboard_skip) {
                        if (FILE *f = fopen("bh_onboarded.ver", "w")) { fputs("1", f); fclose(f); }
                    }
                    s_show_onboard = false;
                    ImGui::CloseCurrentPopup();
                    open_file_dialog = true;
                }
            }

            ImGui::EndPopup();
        }
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

    // ── Programmatic load (e.g. .demo command) ───────────────────────────
    if (g_load_pending) {
        g_load_pending = false;
        if (g_demo_path[0]) {
            std::string path(g_demo_path);
            g_demo_path[0] = '\0';
            open_binary = Binary(path);
            if (open_binary.is_open()) {
                rebuild_cache();
                Logger::get()->log("Demo loaded: " + path, "Demo");
            } else {
                Logger::get()->log("Failed to load demo binary.", "Demo");
            }
        }
    }

    // ── Toolbar ──────────────────────────────────────────────────────────
    ImGuiViewport *vp = ImGui::GetMainViewport();
    float toolbar_h = ImGui::GetFrameHeightWithSpacing() + 4.f;
    ImGui::SetNextWindowPos({vp->Pos.x, vp->Pos.y + menubar_h});
    ImGui::SetNextWindowSize({vp->Size.x, toolbar_h});
    ImGui::SetNextWindowViewport(vp->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    {6.f, 3.f});
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::Begin("##Toolbar", nullptr,
                 ImGuiWindowFlags_NoTitleBar   | ImGuiWindowFlags_NoCollapse |
                 ImGuiWindowFlags_NoResize     | ImGuiWindowFlags_NoMove     |
                 ImGuiWindowFlags_NoScrollbar  | ImGuiWindowFlags_NoDocking  |
                 ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus);
    ImGui::PopStyleVar(2);

    // Each button focuses (raises to front) the named panel
    auto panel_btn = [](const char *name) {
        if (ImGui::SmallButton(name)) ImGui::SetWindowFocus(name);
        ImGui::SameLine(0, 4.f);
    };

    panel_btn("Function Explorer");
    panel_btn("Disassembly");
    panel_btn("Pseudo Code");
    panel_btn("LLVM IR");
    panel_btn("Call Graph");
    ImGui::SameLine(0, 12.f);
    panel_btn("Hex View");
    panel_btn("Strings");
    panel_btn("Sections");
    panel_btn("Imports");
    panel_btn("Exports");
    panel_btn("PE Headers");
    panel_btn("Resources");
    ImGui::SameLine(0, 12.f);
    panel_btn("Security Analysis");
    panel_btn("Search");
    panel_btn("Bookmarks");
    panel_btn("YARA");
    panel_btn("Console");
    panel_btn("Overview");

    ImGui::End(); // ##Toolbar

    // ── Dockspace ────────────────────────────────────────────────────────
    ImGui::SetNextWindowPos({vp->Pos.x, vp->Pos.y + menubar_h + toolbar_h});
    ImGui::SetNextWindowSize({vp->Size.x, vp->Size.y - menubar_h - toolbar_h});
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
        ImGui::DockBuilderSetNodeSize(ds, {vp->Size.x, vp->Size.y - menubar_h - toolbar_h});

        // ── 4-region layout ───────────────────────────────────────────────
        //  left (20%)  |  center (56%)  |  side (24%)
        //              |                               |
        //              └────────── bottom (25% height) ┘

        ImGuiID ds_left, ds_right;
        ImGui::DockBuilderSplitNode(ds, ImGuiDir_Left, 0.20f, &ds_left, &ds_right);

        ImGuiID ds_top, ds_bot;
        ImGui::DockBuilderSplitNode(ds_right, ImGuiDir_Down, 0.25f, &ds_bot, &ds_top);

        ImGuiID ds_center, ds_side;
        ImGui::DockBuilderSplitNode(ds_top, ImGuiDir_Right, 0.30f, &ds_side, &ds_center);

        // Left — navigator
        ImGui::DockBuilderDockWindow("Function Explorer", ds_left);

        // Center — primary analysis (Disassembly shown first)
        ImGui::DockBuilderDockWindow("Hex View",          ds_center);
        ImGui::DockBuilderDockWindow("Call Graph",        ds_center);
        ImGui::DockBuilderDockWindow("LLVM IR",           ds_center);
        ImGui::DockBuilderDockWindow("Pseudo Code",       ds_center);
        ImGui::DockBuilderDockWindow("Disassembly",       ds_center);

        // Right side — reference data (Strings shown first)
        ImGui::DockBuilderDockWindow("Bookmarks",         ds_side);
        ImGui::DockBuilderDockWindow("Resources",         ds_side);
        ImGui::DockBuilderDockWindow("Sections",          ds_side);
        ImGui::DockBuilderDockWindow("Exports",           ds_side);
        ImGui::DockBuilderDockWindow("PE Headers",        ds_side);
        ImGui::DockBuilderDockWindow("Imports",           ds_side);
        ImGui::DockBuilderDockWindow("Strings",           ds_side);
        ImGui::DockBuilderDockWindow("Overview",          ds_side);

        // Bottom — tools and output (Console shown first)
        ImGui::DockBuilderDockWindow("YARA",              ds_bot);
        ImGui::DockBuilderDockWindow("Search",            ds_bot);
        ImGui::DockBuilderDockWindow("Security Analysis", ds_bot);
        ImGui::DockBuilderDockWindow("Console",           ds_bot);

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
    render_ir_panel();
    render_yara_panel();
    render_console();
    render_security_panel();
    render_search_panel();
    render_bookmarks_panel();
    render_callgraph_panel();
    render_resources_panel();
    render_overview_panel();

    // ── Flush ─────────────────────────────────────────────────────────────
    ImGui::Render();
    int w, h;
    glfwGetFramebufferSize(m_window, &w, &h);
    glViewport(0, 0, w, h);
    if (g_dark_theme) glClearColor(.08f, .08f, .09f, 1.f);
    else              glClearColor(.87f, .87f, .87f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(m_window);
    return true;
}
