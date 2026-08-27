// trocto - the contract compiler command line.
//
//   trocto <source.tc|source.rg> -o <output.bin>
//   trocto <source.tc> --emit-regol          print the lowered Regol text
//
// Input language is selected by extension; .tc compiles the high-level tier,
// .rg assembles the low-level one.

#include "trocto/compiler.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

bool read_file(const std::string& path, std::string& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

bool has_suffix(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) ==
               0;
}

int print_diagnostics(const trocto::Diagnostics& diagnostics) {
    for (const trocto::Diagnostic& entry : diagnostics.entries()) {
        if (entry.line != 0) {
            std::cerr << "trocto: error at line " << entry.line << ": "
                      << entry.message << "\n";
        } else {
            std::cerr << "trocto: error: " << entry.message << "\n";
        }
    }
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    std::string input;
    std::string output;
    bool emit_regol = false;

    for (int i = 1; i < argc; ++i) {
        std::string argument = argv[i];
        if (argument == "-o" && i + 1 < argc) {
            output = argv[++i];
        } else if (argument == "--emit-regol") {
            emit_regol = true;
        } else if (argument == "--help" || argument == "-h") {
            std::cout << "usage: trocto <file.tc|.rg> [-o out.bin] "
                         "[--emit-regol]\n";
            return 0;
        } else if (!argument.empty() && argument[0] == '-') {
            std::cerr << "trocto: unknown option '" << argument << "'\n";
            return 2;
        } else {
            input = argument;
        }
    }

    if (input.empty()) {
        std::cerr << "usage: trocto <file.tc|.rg> [-o out.bin] "
                     "[--emit-regol]\n";
        return 2;
    }

    std::string source;
    if (!read_file(input, source)) {
        std::cerr << "trocto: cannot read '" << input << "'\n";
        return 1;
    }

    trocto::Diagnostics diagnostics;
    trocto::CompileResult partial;
    bool have_partial = false;
    {
        auto module = trocto::lower_source_for_debug(source, diagnostics);
        if (module) {
            partial.regol_text = trocto::regol_text(*module);
            have_partial = true;
        }
    }
    diagnostics.clear();  // fresh run below

    trocto::CompileOptions options;
    options.keep_ir = true;
    options.skip_validation = emit_regol; /* IR dump without the gate */
    std::optional<trocto::CompileResult> result;
    if (has_suffix(input, ".rg")) {
        result = trocto::assemble_regol(source, diagnostics);
    } else {
        result = trocto::compile_trocto(source, options, diagnostics, input);
    }
    if (!result) {
        if (emit_regol && have_partial)
            std::cout << "/* lowered IR (unvalidated) */\n"
                      << partial.regol_text;
        return print_diagnostics(diagnostics);
    }

    if (emit_regol) std::cout << result->regol_text;
    if (emit_regol && output.empty()) return 0;

    if (output.empty()) {
        // No -o: validation-only run.
        std::cout << input << ": ok (" << result->container.size()
                  << " bytes)\n";
        return 0;
    }
    std::ofstream out(output, std::ios::binary);
    if (!out) {
        std::cerr << "trocto: cannot write '" << output << "'\n";
        return 1;
    }
    out.write(reinterpret_cast<const char*>(result->container.data()),
              static_cast<std::streamsize>(result->container.size()));
    if (!out) {
        std::cerr << "trocto: write failed for '" << output << "'\n";
        return 1;
    }
    std::cout << input << ": " << result->container.size() << " bytes -> "
              << output << "\n";
    return 0;
}
