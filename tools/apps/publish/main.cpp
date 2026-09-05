// astrolune-publish — deploy static websites to the Astrolune network.
//
//   astrolune-publish <directory> [--output manifest.json] [--dry-run]
//   astrolune-publish --help
//   astrolune-publish --version

#include "ecosystem/hosting/site_manifest.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string to_hex_string(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(kHex[data[i] >> 4]);
        result.push_back(kHex[data[i] & 0x0F]);
    }
    return result;
}

bool store_content(const std::filesystem::path& store_root,
                   const al_hash256& hash,
                   const std::string& data) {
    auto hex = to_hex_string(hash.bytes, AL_HASH_SIZE);
    auto dir1 = store_root / hex.substr(0, 2);
    auto dir2 = dir1 / hex.substr(2, 2);
    auto file = dir2 / hex.substr(4);

    if (std::filesystem::exists(file)) return true;

    std::error_code ec;
    std::filesystem::create_directories(dir2, ec);
    if (ec) {
        std::fprintf(stderr, "error: cannot create store dirs: %s\n",
                     ec.message().c_str());
        return false;
    }

    std::ofstream ofs(file, std::ios::binary);
    if (!ofs) {
        std::fprintf(stderr, "error: cannot write to store: %s\n",
                     file.string().c_str());
        return false;
    }
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    return ofs.good();
}

std::string read_file_str(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

void print_help() {
    std::printf(
        "usage: astrolune-publish <directory> [options]\n"
        "\n"
        "Deploy a static website directory to the Astrolune content store.\n"
        "Scans all files, computes SHA-256 hashes, builds a site manifest,\n"
        "and stores each file in a content-addressed store.\n"
        "\n"
        "Options:\n"
        "  --output <path>    Write manifest JSON to <path>\n"
        "  --store <path>     Content store root (default: ./astrolune-store)\n"
        "  --dry-run          Scan and hash but do not store files\n"
        "  --no-spa           Disable SPA fallback (serve 404 for missing paths)\n"
        "  --help             Show this help message\n"
        "  --version          Show version\n"
        "\n"
        "Output:\n"
        "  Prints progress to stdout. On success, prints the root CID\n"
        "  and file count. With --output, writes the manifest JSON to the\n"
        "  given path.\n"
        "\n"
        "Examples:\n"
        "  astrolune-publish ./dist --output manifest.json\n"
        "  astrolune-publish ./dist --dry-run\n"
        "  astrolune-publish ./dist --store /data/astrolune/store\n"
    );
}

void print_version() {
    std::printf("astrolune-publish %d.%d.%d\n",
                AL_VERSION_MAJOR, AL_VERSION_MINOR, AL_VERSION_PATCH);
}

}  // namespace

int main(int argc, char** argv) {
    using namespace astrolune::hosting;

    std::string directory;
    std::string output_path;
    std::string store_root_str = "./astrolune-store";
    bool dry_run = false;
    bool spa_fallback = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            print_version();
            return 0;
        } else if (arg == "--output" || arg == "-o") {
            if (i + 1 < argc) {
                output_path = argv[++i];
            } else {
                std::fprintf(stderr, "error: --output requires a path argument\n");
                return 2;
            }
        } else if (arg == "--store") {
            if (i + 1 < argc) {
                store_root_str = argv[++i];
            } else {
                std::fprintf(stderr, "error: --store requires a path argument\n");
                return 2;
            }
        } else if (arg == "--dry-run") {
            dry_run = true;
        } else if (arg == "--no-spa") {
            spa_fallback = false;
        } else if (arg[0] == '-') {
            std::fprintf(stderr, "error: unknown option '%s'\n", arg.c_str());
            return 2;
        } else if (directory.empty()) {
            directory = arg;
        } else {
            std::fprintf(stderr, "error: unexpected argument '%s'\n", arg.c_str());
            return 2;
        }
    }

    if (directory.empty()) {
        std::fprintf(stderr, "error: no directory specified\n");
        print_help();
        return 2;
    }

    std::filesystem::path dir_path(directory);
    std::error_code ec;
    if (!std::filesystem::is_directory(dir_path, ec) || ec) {
        std::fprintf(stderr, "error: '%s' is not a directory\n", directory.c_str());
        return 1;
    }

    // --- Build manifest ---
    std::printf("scanning %s ...\n", directory.c_str());

    auto manifest = build_manifest(dir_path, spa_fallback);
    if (!manifest) {
        std::fprintf(stderr, "error: %s\n", manifest.error().message.c_str());
        return 1;
    }

    std::printf("found %zu files\n", manifest->files.size());

    // --- Print file list ---
    for (size_t i = 0; i < manifest->files.size(); ++i) {
        const auto& f = manifest->files[i];
        std::printf("  [%zu/%zu] %s %s (%zu bytes)\n",
                    i + 1, manifest->files.size(),
                    f.hash.c_str(),
                    f.path.c_str(),
                    f.size);
    }

    // --- Store files ---
    if (!dry_run) {
        std::filesystem::path store_root(store_root_str);
        std::printf("storing %zu files in %s ...\n",
                    manifest->files.size(), store_root_str.c_str());

        for (size_t i = 0; i < manifest->files.size(); ++i) {
            const auto& f = manifest->files[i];

            // Parse the sha256: prefix to get raw hash bytes
            auto hex_str = f.hash;
            if (hex_str.starts_with("sha256:")) {
                hex_str = hex_str.substr(7);
            }

            al_hash256 h{};
            for (size_t j = 0; j < AL_HASH_SIZE && j * 2 + 1 < hex_str.size(); ++j) {
                uint8_t hi = 0, lo = 0;
                auto hc = hex_str[j * 2];
                auto lc = hex_str[j * 2 + 1];
                if (hc >= '0' && hc <= '9') hi = hc - '0';
                else if (hc >= 'a' && hc <= 'f') hi = 10 + hc - 'a';
                if (lc >= '0' && lc <= '9') lo = lc - '0';
                else if (lc >= 'a' && lc <= 'f') lo = 10 + lc - 'a';
                h.bytes[j] = (hi << 4) | lo;
            }

            // Read file and store
            auto full_path = dir_path / f.path.substr(1);  // strip leading /
            auto content = read_file_str(full_path);
            if (content.empty()) {
                std::fprintf(stderr, "error: cannot read '%s'\n",
                             full_path.string().c_str());
                return 1;
            }

            if (!store_content(store_root, h, content)) {
                std::fprintf(stderr, "error: failed to store '%s'\n",
                             f.path.c_str());
                return 1;
            }

            std::printf("  stored %s (%s)\n", f.path.c_str(), f.hash.c_str());
        }
    } else {
        std::printf("dry-run: skipping store\n");
    }

    // --- Write manifest ---
    if (!output_path.empty()) {
        auto json = manifest->to_json_signed();
        std::ofstream ofs(output_path);
        if (!ofs) {
            std::fprintf(stderr, "error: cannot write '%s'\n",
                         output_path.c_str());
            return 1;
        }
        ofs << json;
        if (!ofs) {
            std::fprintf(stderr, "error: write failed for '%s'\n",
                         output_path.c_str());
            return 1;
        }
        std::printf("manifest written to %s\n", output_path.c_str());
    }

    // --- Summary ---
    std::printf("\n");
    std::printf("root CID: %s\n", manifest->root_cid.c_str());
    std::printf("files:    %zu\n", manifest->files.size());
    if (dry_run) {
        std::printf("mode:     dry-run (no files stored)\n");
    }

    return 0;
}
