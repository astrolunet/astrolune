/* Dependency-free source-level guard for the public C ABI manifest. */

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#ifndef AL_SOURCE_DIR
#  error "AL_SOURCE_DIR must name the source tree"
#endif

namespace {

std::string read_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

void record_function(const std::string &declaration,
                     std::map<std::string, unsigned> &names) {
    std::size_t position = 0;
    while ((position = declaration.find("al_", position)) != std::string::npos) {
        std::size_t end = position + 3u;
        while (end < declaration.size()) {
            const unsigned char ch = static_cast<unsigned char>(declaration[end]);
            if (std::isalnum(ch) == 0 && ch != static_cast<unsigned char>('_')) break;
            ++end;
        }
        std::size_t next = end;
        while (next < declaration.size() &&
               std::isspace(static_cast<unsigned char>(declaration[next])) != 0)
            ++next;
        if (next < declaration.size() && declaration[next] == '(') {
            ++names[declaration.substr(position, end - position)];
            return;
        }
        position = end;
    }
}

std::map<std::string, unsigned> public_declarations(
    const std::filesystem::path &directory) {
    std::map<std::string, unsigned> names;
    for (const auto &entry : std::filesystem::directory_iterator(directory)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".h") continue;
        const std::string source = read_file(entry.path());
        std::size_t position = 0;
        while ((position = source.find("AL_PUBLIC", position)) != std::string::npos) {
            const std::size_t end = source.find(';', position);
            if (end == std::string::npos) break;
            record_function(source.substr(position, end - position + 1u), names);
            position = end + 1u;
        }
    }
    return names;
}

std::map<std::string, unsigned> manifest_symbols(
    const std::filesystem::path &path) {
    std::map<std::string, unsigned> names;
    const std::string source = read_file(path);
    constexpr const char marker[] = "AL_ABI_SYM(";
    std::size_t position = 0;
    while ((position = source.find(marker, position)) != std::string::npos) {
        position += sizeof(marker) - 1u;
        while (position < source.size() &&
               std::isspace(static_cast<unsigned char>(source[position])) != 0)
            ++position;
        const std::size_t end = source.find(')', position);
        if (end == std::string::npos) break;
        const std::string name = source.substr(position, end - position);
        if (name.starts_with("al_")) ++names[name];
        position = end + 1u;
    }
    return names;
}

bool report_duplicates(const char *label,
                       const std::map<std::string, unsigned> &names) {
    bool failed = false;
    for (const auto &[name, count] : names) {
        if (count > 1u) {
            std::cerr << label << " contains " << count << " copies of "
                      << name << '\n';
            failed = true;
        }
    }
    return failed;
}

} // namespace

int main() {
    const std::filesystem::path root(AL_SOURCE_DIR);
    const auto declarations = public_declarations(root / "include" / "astrolune");
    const auto manifest = manifest_symbols(root / "abi" /
                                           "boundary_symbols.cpp");
    bool failed = report_duplicates("public headers", declarations) |
                  report_duplicates("ABI manifest", manifest);
    for (const auto &[name, count] : declarations) {
        (void)count;
        if (!manifest.contains(name)) {
            std::cerr << "public declaration missing from ABI manifest: "
                      << name << '\n';
            failed = true;
        }
    }
    for (const auto &[name, count] : manifest) {
        (void)count;
        if (!declarations.contains(name)) {
            std::cerr << "ABI manifest symbol lacks AL_PUBLIC declaration: "
                      << name << '\n';
            failed = true;
        }
    }
    if (declarations.size() != manifest.size()) {
        std::cerr << "ABI symbol count differs: headers=" << declarations.size()
                  << ", manifest=" << manifest.size() << '\n';
        failed = true;
    }
    return failed ? 1 : 0;
}
