#include "console_handler.h"
#include "logger.h"
#include "binary/binary.h"
#include "rendering/nav_state.h"

#include <map>
#include <sstream>
#include <vector>

static void cmd_demo()  { Logger::get()->log("Demo command called!", "Demo"); }
static void cmd_exit()  { exit(0); }
static void cmd_clear() { Logger::get()->clear_logs(); Logger::get()->log("Console cleared.", "Console"); }

static void cmd_info() {
    if (!open_binary.is_open()) {
        Logger::get()->log("No binary loaded.", "Console"); return;
    }
    std::ostringstream ss;
    ss << "Architecture : " << (open_binary.is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    Logger::get()->log(ss.str(), "Info");
    ss.str("");
    ss << "Entry Point  : 0x" << std::hex << open_binary.get_entrypoint();
    Logger::get()->log(ss.str(), "Info");
    ss.str("");
    ss << "Sections     : " << std::dec << open_binary.get_sections().size();
    Logger::get()->log(ss.str(), "Info");
    ss.str("");
    ss << "Imports      : " << open_binary.get_imports().size() << " functions";
    Logger::get()->log(ss.str(), "Info");
    ss.str("");
    ss << "Exports      : " << open_binary.get_exports().size();
    Logger::get()->log(ss.str(), "Info");
    ss.str("");
    ss << "File size    : " << std::dec << open_binary.get_binary_size() << " bytes";
    Logger::get()->log(ss.str(), "Info");
}

typedef void (*func)();
struct command_t {
    std::string short_description;
    func callback;
    std::vector<std::string> documentation{};
};

static std::map<std::string, command_t> commands = {
    {"exit",  {"Exit BinaryHammer",                        cmd_exit,  {}}},
    {"clear", {"Clear the console",                        cmd_clear, {}}},
    {"demo",  {"Demo command (testing)",                   cmd_demo,  {"Takes no arguments."}}},
    {"info",  {"Print a summary of the loaded binary",     cmd_info,  {"Usage: .info"}}},
};

void CommandHandler::handle_command(std::string input) {
    if (input.empty()) return;

    if (input[0] == '.') {
        input = input.substr(1);
        size_t sp = input.find(' ');
        std::string command = input.substr(0, sp);
        std::vector<std::string> args;

        while (sp != std::string::npos) {
            size_t next = input.find(' ', sp + 1);
            if (next == std::string::npos)
                args.push_back(input.substr(sp + 1));
            else
                args.push_back(input.substr(sp + 1, (next - 1) - sp));
            sp = next;
        }

        if (command == "help") {
            if (args.empty()) {
                Logger::get()->log("Available commands:", "Console");
                for (const auto &[name, cmd] : commands)
                    Logger::get()->log("  ." + name + " — " + cmd.short_description);
                Logger::get()->log("  .goto <hex_rva> — navigate to an RVA in hex view");
                Logger::get()->log("  .strings [min_len] — list extracted strings");
                return;
            }
            Logger::get()->log("Documentation for: ." + args[0], "Console");
            auto it = commands.find(args[0]);
            if (it == commands.end() || it->second.documentation.empty())
                Logger::get()->log("  No documentation available.", "Console");
            else
                for (const auto &doc : it->second.documentation)
                    Logger::get()->log("  " + doc, "Console");
            return;
        }

        if (command == "strings") {
            if (!open_binary.is_open()) { Logger::get()->log("No binary loaded.", "Console"); return; }
            size_t min_len = 5;
            if (!args.empty()) {
                try { min_len = std::stoul(args[0]); } catch (...) {}
            }
            auto strs = open_binary.get_strings(min_len);
            Logger::get()->log(std::to_string(strs.size()) + " strings (min " +
                               std::to_string(min_len) + " chars):", "Strings");
            size_t shown = 0;
            for (const auto &s : strs) {
                std::ostringstream ss;
                ss << "  0x" << std::hex << s.offset << "  " << (s.is_unicode ? "[utf16] " : "[ascii] ") << s.value;
                Logger::get()->log(ss.str());
                if (++shown >= 50) { Logger::get()->log("  ... (first 50 shown)", "Strings"); break; }
            }
            return;
        }

        if (command == "goto") {
            if (args.empty()) { Logger::get()->log("Usage: .goto <hex_rva>", "Console"); return; }
            if (!open_binary.is_open()) { Logger::get()->log("No binary loaded.", "Console"); return; }
            char *end;
            uint64_t rva = strtoull(args[0].c_str(), &end, 16);
            std::ostringstream ss;
            ss << "Navigating to RVA 0x" << std::hex << rva;
            Logger::get()->log(ss.str(), "Console");
            g_nav_hex_offset = static_cast<int64_t>(open_binary.rva_to_offset(static_cast<uint32_t>(rva)));
            return;
        }

        auto it = commands.find(command);
        if (it != commands.end() && it->second.callback) {
            it->second.callback(); return;
        }
        Logger::get()->log("Unknown command. Type \".help\" for a list.", "Console");
    } else {
        Logger::get()->log(input, "Console");
    }
}
