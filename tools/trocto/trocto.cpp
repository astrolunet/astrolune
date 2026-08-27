// The compile_trocto pipeline: parse, lower, encode.

#include "encoder.hpp"
#include "lexer.hpp"
#include "lower.hpp"
#include "trocto_ast.hpp"

#include <fstream>
#include <sstream>

namespace trocto {

void Diagnostics::error(unsigned line, std::string message) {
    entries_.push_back(Diagnostic{line, std::move(message)});
}

void Diagnostics::clear() { entries_.clear(); }

namespace {

bool read_file(const std::string& path, std::string& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

// Resolve import paths relative to the source file's directory.
std::string resolve_import_path(const std::string& source_path,
                                const std::string& import_path) {
    if (import_path.empty()) return import_path;
    // If the import path is absolute, use it as-is.
    if (!import_path.empty() &&
        (import_path[0] == '/' || import_path[0] == '\\' ||
         (import_path.size() > 1 && import_path[1] == ':'))) {
        return import_path;
    }
    // Find the last directory separator in the source path.
    size_t pos = source_path.find_last_of("/\\");
    if (pos == std::string::npos) return import_path;
    return source_path.substr(0, pos + 1) + import_path;
}

}  // namespace

std::optional<CompileResult> compile_trocto(const std::string& source,
                                            const CompileOptions& options,
                                            Diagnostics& diagnostics,
                                            const std::string& source_path) {
    auto contract = parse_contract(source, diagnostics);
    if (!contract) return std::nullopt;

    // Resolve imports: read each imported file and parse it to extract
    // function declarations that can be called from this contract.
    // In v0.2, imports are read and validated but not yet linked into
    // the calling module's function table. This is a placeholder for
    // the module system that will be completed in v0.3.
    for (const ImportDecl& imp : contract->imports) {
        std::string resolved = resolve_import_path(source_path, imp.path);
        std::string imported_source;
        if (!read_file(resolved, imported_source)) {
            diagnostics.error(imp.line,
                              "cannot read import '" + imp.path + "'");
            return std::nullopt;
        }
        // Validate the imported file compiles.
        Diagnostics import_diag;
        auto imported = parse_contract(imported_source, import_diag);
        if (!imported) {
            for (const auto& d : import_diag.entries()) {
                diagnostics.error(imp.line,
                                  "in import '" + imp.path + "': " +
                                      d.message);
            }
            return std::nullopt;
        }
    }

    auto module = lower_contract(*contract, diagnostics);
    if (!module) return std::nullopt;

    CompileResult result;
    if (options.keep_ir) result.regol_text = regol_text(*module);

    auto container = encode_module(*module, diagnostics,
                                   options.skip_validation);
    if (!container) return std::nullopt;
    result.container = std::move(*container);
    return result;
}

std::optional<ModuleIR> lower_source_for_debug(const std::string& source,
                                               Diagnostics& diagnostics) {
    auto contract = parse_contract(source, diagnostics);
    if (!contract) return std::nullopt;
    return lower_contract(*contract, diagnostics);
}

}  // namespace trocto
