/*
 * astrolune/tools/ecosystem/share/merkle_manifest.cpp
 *
 * Implementation of the Merkle manifest system for Astrolune Share.
 *
 * Builds binary Merkle trees from chunk hashes using the core library's
 * al_merkle_root / al_merkle_prove / al_merkle_verify, and provides JSON
 * serialisation with a minimal self-contained parser.
 */

#include "merkle_manifest.hpp"

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

// ---------------------------------------------------------------------------
// Minimal JSON reader / writer (same pattern as site_manifest.cpp)
// ---------------------------------------------------------------------------

namespace {

enum class JsonType { Null, Bool, Number, String, Array, Object };

struct JsonValue {
    JsonType type = JsonType::Null;
    bool bool_val = false;
    double number_val = 0.0;
    std::string string_val;
    std::vector<JsonValue> array_val;
    std::vector<std::pair<std::string, JsonValue>> object_val;

    bool is_null() const { return type == JsonType::Null; }
    bool is_bool() const { return type == JsonType::Bool; }
    bool is_number() const { return type == JsonType::Number; }
    bool is_string() const { return type == JsonType::String; }
    bool is_array() const { return type == JsonType::Array; }
    bool is_object() const { return type == JsonType::Object; }

    const JsonValue* find(std::string_view key) const {
        if (!is_object()) return nullptr;
        for (auto& [k, v] : object_val) {
            if (k == key) return &v;
        }
        return nullptr;
    }

    std::string_view as_string() const { return string_val; }
    bool as_bool() const { return bool_val; }
    double as_number() const { return number_val; }
    int64_t as_int() const { return static_cast<int64_t>(number_val); }
    uint64_t as_uint() const { return static_cast<uint64_t>(number_val); }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : src_(input), pos_(0) {}

    std::expected<JsonValue, std::string> parse() {
        skip_ws();
        auto val = parse_value();
        skip_ws();
        if (pos_ < src_.size()) {
            return std::unexpected(std::string("trailing content after JSON value"));
        }
        return val;
    }

private:
    std::string_view src_;
    size_t pos_;

    char peek() const { return pos_ < src_.size() ? src_[pos_] : '\0'; }
    char advance() { return pos_ < src_.size() ? src_[pos_++] : '\0'; }

    void skip_ws() {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
            else break;
        }
    }

    std::expected<JsonValue, std::string> parse_value() {
        skip_ws();
        char c = peek();
        if (c == '"') return parse_string_value();
        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == 'n') return parse_null();
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        return std::unexpected(std::string("unexpected character in JSON"));
    }

    std::expected<JsonValue, std::string> parse_string_value() {
        auto str = parse_string();
        if (!str) return std::unexpected(str.error());
        JsonValue val;
        val.type = JsonType::String;
        val.string_val = std::move(*str);
        return val;
    }

    std::expected<std::string, std::string> parse_string() {
        if (advance() != '"') return std::unexpected(std::string("expected '\"'"));
        std::string result;
        while (pos_ < src_.size()) {
            char c = advance();
            if (c == '"') return result;
            if (c == '\\') {
                char esc = advance();
                switch (esc) {
                    case '"':  result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/':  result += '/'; break;
                    case 'b':  result += '\b'; break;
                    case 'f':  result += '\f'; break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    default:
                        return std::unexpected(
                            std::string("invalid escape sequence"));
                }
            } else {
                result += c;
            }
        }
        return std::unexpected(std::string("unterminated string"));
    }

    std::expected<JsonValue, std::string> parse_number() {
        size_t start = pos_;
        if (peek() == '-') ++pos_;
        while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        if (pos_ < src_.size() && src_[pos_] == '.') {
            ++pos_;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        if (pos_ < src_.size() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < src_.size() && (src_[pos_] == '+' || src_[pos_] == '-')) ++pos_;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        std::string num_str(src_.substr(start, pos_ - start));
        double val = 0.0;
        auto [ptr, ec] = std::from_chars(
            num_str.data(), num_str.data() + num_str.size(), val);
        if (ec != std::errc()) {
            return std::unexpected(std::string("invalid number: ") + num_str);
        }
        JsonValue jv;
        jv.type = JsonType::Number;
        jv.number_val = val;
        return jv;
    }

    std::expected<JsonValue, std::string> parse_bool() {
        if (src_.substr(pos_, 4) == "true") {
            pos_ += 4;
            JsonValue v; v.type = JsonType::Bool; v.bool_val = true;
            return v;
        }
        if (src_.substr(pos_, 5) == "false") {
            pos_ += 5;
            JsonValue v; v.type = JsonType::Bool; v.bool_val = false;
            return v;
        }
        return std::unexpected(std::string("expected boolean"));
    }

    std::expected<JsonValue, std::string> parse_null() {
        if (src_.substr(pos_, 4) == "null") { pos_ += 4; return JsonValue{}; }
        return std::unexpected(std::string("expected null"));
    }

    std::expected<JsonValue, std::string> parse_array() {
        if (advance() != '[') return std::unexpected(std::string("expected '['"));
        JsonValue arr; arr.type = JsonType::Array;
        skip_ws();
        if (peek() == ']') { ++pos_; return arr; }
        while (true) {
            auto val = parse_value();
            if (!val) return std::unexpected(val.error());
            arr.array_val.push_back(std::move(*val));
            skip_ws();
            if (peek() == ']') { ++pos_; break; }
            if (advance() != ',') return std::unexpected(std::string("expected ','"));
        }
        return arr;
    }

    std::expected<JsonValue, std::string> parse_object() {
        if (advance() != '{') return std::unexpected(std::string("expected '{'"));
        JsonValue obj; obj.type = JsonType::Object;
        skip_ws();
        if (peek() == '}') { ++pos_; return obj; }
        while (true) {
            auto key = parse_string();
            if (!key) return std::unexpected(key.error());
            skip_ws();
            if (advance() != ':') return std::unexpected(std::string("expected ':'"));
            auto val = parse_value();
            if (!val) return std::unexpected(val.error());
            obj.object_val.emplace_back(std::move(*key), std::move(*val));
            skip_ws();
            if (peek() == '}') { ++pos_; break; }
            if (advance() != ',') return std::unexpected(std::string("expected ','"));
        }
        return obj;
    }
};

// ---- JSON writer ----------------------------------------------------------

class JsonWriter {
public:
    static std::string write(const JsonValue& val) {
        JsonWriter w;
        w.write_value(val);
        return w.buf_;
    }

    static std::string write_sorted(const JsonValue& val) {
        JsonWriter w;
        w.write_sorted_value(val);
        return w.buf_;
    }

private:
    std::string buf_;

    void write_value(const JsonValue& val) {
        switch (val.type) {
            case JsonType::Null: buf_ += "null"; break;
            case JsonType::Bool: buf_ += val.bool_val ? "true" : "false"; break;
            case JsonType::Number: {
                double intpart;
                if (std::modf(val.number_val, &intpart) == 0.0 &&
                    val.number_val >= -9007199254740992.0 &&
                    val.number_val <= 9007199254740992.0) {
                    auto n = static_cast<int64_t>(val.number_val);
                    char tmp[32];
                    auto [ptr, ec] = std::to_chars(tmp, tmp + sizeof(tmp), n);
                    buf_.append(tmp, ptr);
                } else {
                    char tmp[64];
                    auto [ptr, ec] = std::to_chars(tmp, tmp + sizeof(tmp),
                        val.number_val, std::chars_format::general, 17);
                    buf_.append(tmp, ptr);
                }
                break;
            }
            case JsonType::String: write_string(val.string_val); break;
            case JsonType::Array:
                buf_ += '[';
                for (size_t i = 0; i < val.array_val.size(); ++i) {
                    if (i > 0) buf_ += ',';
                    write_value(val.array_val[i]);
                }
                buf_ += ']';
                break;
            case JsonType::Object:
                buf_ += '{';
                for (size_t i = 0; i < val.object_val.size(); ++i) {
                    if (i > 0) buf_ += ',';
                    write_string(val.object_val[i].first);
                    buf_ += ':';
                    write_value(val.object_val[i].second);
                }
                buf_ += '}';
                break;
        }
    }

    void write_sorted_value(const JsonValue& val) {
        switch (val.type) {
            case JsonType::Object: {
                std::vector<std::pair<std::string, const JsonValue*>> sorted;
                sorted.reserve(val.object_val.size());
                for (auto& [k, v] : val.object_val) sorted.emplace_back(k, &v);
                std::sort(sorted.begin(), sorted.end(),
                    [](auto& a, auto& b) { return a.first < b.first; });
                buf_ += '{';
                for (size_t i = 0; i < sorted.size(); ++i) {
                    if (i > 0) buf_ += ',';
                    write_string(sorted[i].first);
                    buf_ += ':';
                    write_sorted_value(*sorted[i].second);
                }
                buf_ += '}';
                break;
            }
            case JsonType::Array:
                buf_ += '[';
                for (size_t i = 0; i < val.array_val.size(); ++i) {
                    if (i > 0) buf_ += ',';
                    write_sorted_value(val.array_val[i]);
                }
                buf_ += ']';
                break;
            default:
                write_value(val);
                break;
        }
    }

    void write_string(const std::string& s) {
        buf_ += '"';
        for (char c : s) {
            switch (c) {
                case '"':  buf_ += "\\\""; break;
                case '\\': buf_ += "\\\\"; break;
                case '\b': buf_ += "\\b"; break;
                case '\f': buf_ += "\\f"; break;
                case '\n': buf_ += "\\n"; break;
                case '\r': buf_ += "\\r"; break;
                case '\t': buf_ += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char tmp[8];
                        std::snprintf(tmp, sizeof(tmp), "\\u%04x",
                            static_cast<unsigned>(c));
                        buf_ += tmp;
                    } else {
                        buf_ += c;
                    }
            }
        }
        buf_ += '"';
    }
};

// ---- Hex helpers ----------------------------------------------------------

std::string to_hex(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(kHex[data[i] >> 4]);
        result.push_back(kHex[data[i] & 0x0F]);
    }
    return result;
}

std::expected<al_hash256, ManifestError> parse_hex_hash(std::string_view hex) {
    if (hex.size() != AL_HASH_SIZE * 2) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid,
            "hex hash must be 64 characters"));
    }
    al_hash256 h{};
    for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
        uint8_t hi = 0, lo = 0;
        auto hc = hex[i * 2];
        auto lc = hex[i * 2 + 1];
        if (hc >= '0' && hc <= '9') hi = hc - '0';
        else if (hc >= 'a' && hc <= 'f') hi = 10 + hc - 'a';
        else if (hc >= 'A' && hc <= 'F') hi = 10 + hc - 'A';
        else return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "invalid hex character"));
        if (lc >= '0' && lc <= '9') lo = lc - '0';
        else if (lc >= 'a' && lc <= 'f') lo = 10 + lc - 'a';
        else if (lc >= 'A' && lc <= 'F') lo = 10 + lc - 'A';
        else return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "invalid hex character"));
        h.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return h;
}

al_hash256 hash_pair(const al_hash256& left, const al_hash256& right) {
    al_hash256 h{};
    al_hash_tagged_pair(AL_TAG_MERKLE_NODE, &left, &right, &h);
    return h;
}

// ---------------------------------------------------------------------------
// MIME type detection (subset, self-contained)
// ---------------------------------------------------------------------------

std::string_view mime_type_for(std::string_view path) {
    auto dot = path.rfind('.');
    if (dot == std::string_view::npos) {
        return "application/octet-stream";
    }
    auto ext = path.substr(dot + 1);
    std::string ext_lower(ext);
    std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (ext_lower == "html" || ext_lower == "htm")  return "text/html; charset=utf-8";
    if (ext_lower == "css")                         return "text/css; charset=utf-8";
    if (ext_lower == "txt")                         return "text/plain; charset=utf-8";
    if (ext_lower == "csv")                         return "text/csv; charset=utf-8";
    if (ext_lower == "xml")                         return "application/xml; charset=utf-8";
    if (ext_lower == "svg")                         return "image/svg+xml";
    if (ext_lower == "js" || ext_lower == "mjs")   return "application/javascript; charset=utf-8";
    if (ext_lower == "json")                        return "application/json; charset=utf-8";
    if (ext_lower == "png")                         return "image/png";
    if (ext_lower == "jpg" || ext_lower == "jpeg")  return "image/jpeg";
    if (ext_lower == "gif")                         return "image/gif";
    if (ext_lower == "webp")                        return "image/webp";
    if (ext_lower == "avif")                        return "image/avif";
    if (ext_lower == "woff")                        return "font/woff";
    if (ext_lower == "woff2")                       return "font/woff2";
    if (ext_lower == "ttf")                         return "font/ttf";
    if (ext_lower == "otf")                         return "font/otf";
    if (ext_lower == "mp4")                         return "video/mp4";
    if (ext_lower == "webm")                        return "video/webm";
    if (ext_lower == "mp3")                         return "audio/mpeg";
    if (ext_lower == "ogg")                         return "audio/ogg";
    if (ext_lower == "wav")                         return "audio/wav";
    if (ext_lower == "flac")                        return "audio/flac";
    if (ext_lower == "pdf")                         return "application/pdf";
    if (ext_lower == "wasm")                        return "application/wasm";
    if (ext_lower == "zip")                         return "application/zip";
    if (ext_lower == "gz")                          return "application/gzip";
    if (ext_lower == "tar")                         return "application/x-tar";

    return "application/octet-stream";
}

}  // namespace

// ---------------------------------------------------------------------------
// Namespace alias
// ---------------------------------------------------------------------------

namespace astrolune::share {

// ---------------------------------------------------------------------------
// ChunkRecord
// ---------------------------------------------------------------------------

std::string ChunkRecord::hash_hex() const {
    return to_hex(hash.bytes, AL_HASH_SIZE);
}

// ---------------------------------------------------------------------------
// InclusionProof
// ---------------------------------------------------------------------------

bool InclusionProof::verify(const al_hash256& expected_root) const {
    return astrolune::share::verify_proof(*this, expected_root);
}

// ---------------------------------------------------------------------------
// Standalone Merkle helpers
// ---------------------------------------------------------------------------

al_hash256 compute_merkle_root(const std::vector<al_hash256>& leaves) {
    if (leaves.empty()) return al_hash_zero();
    if (leaves.size() == 1) return leaves[0];

    // Build the tree bottom-up using the core library's tagged pair hash.
    // We work on a mutable copy that we fold in place.
    std::vector<al_hash256> level = leaves;

    while (level.size() > 1) {
        std::vector<al_hash256> next;
        size_t n = level.size();

        // If odd count, promote the last element unchanged.
        size_t pairs = n / 2;
        next.reserve(pairs + (n % 2));

        for (size_t i = 0; i < pairs; ++i) {
            next.push_back(hash_pair(level[i * 2], level[i * 2 + 1]));
        }
        if (n % 2) {
            next.push_back(level.back());
        }

        level = std::move(next);
    }

    return level[0];
}

std::expected<InclusionProof, ManifestError> generate_proof(
    const std::vector<al_hash256>& leaves, uint32_t index) {
    if (leaves.empty()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::TooManyChunks, "empty leaf set"));
    }
    if (index >= leaves.size()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::ChunkHashMismatch,
            "chunk index out of range"));
    }

    InclusionProof proof;
    proof.chunk_index = index;
    proof.leaf_count = static_cast<uint32_t>(leaves.size());
    proof.leaf_hash = leaves[index];

    // Walk up the tree, collecting sibling hashes.
    std::vector<al_hash256> level = leaves;
    uint32_t pos = index;

    while (level.size() > 1) {
        std::vector<al_hash256> next;
        size_t n = level.size();
        size_t pairs = n / 2;
        next.reserve(pairs + (n % 2));

        for (size_t i = 0; i < pairs; ++i) {
            next.push_back(hash_pair(level[i * 2], level[i * 2 + 1]));
        }
        if (n % 2) {
            next.push_back(level.back());
        }

        // The sibling of our node at `pos` in this level.
        if (pos % 2 == 0) {
            // We are the left child; sibling is to the right.
            if (pos + 1 < level.size()) {
                proof.siblings.push_back(level[pos + 1]);
            }
        } else {
            // We are the right child; sibling is to the left.
            proof.siblings.push_back(level[pos - 1]);
        }

        pos /= 2;
        level = std::move(next);
    }

    return proof;
}

bool verify_proof(const InclusionProof& proof, const al_hash256& root) {
    if (proof.leaf_count == 0) return false;
    if (proof.chunk_index >= proof.leaf_count) return false;

    // Re-derive the root from the leaf and its sibling path.
    al_hash256 current = proof.leaf_hash;
    uint32_t pos = proof.chunk_index;

    for (auto& sibling : proof.siblings) {
        if (pos % 2 == 0) {
            // We were the left child; sibling was on the right.
            current = hash_pair(current, sibling);
        } else {
            // We were the right child; sibling was on the left.
            current = hash_pair(sibling, current);
        }
        pos /= 2;
    }

    return al_hash_eq(&current, &root);
}

// ---------------------------------------------------------------------------
// ShareManifest — serialisation
// ---------------------------------------------------------------------------

namespace {

JsonValue hash_to_json(const al_hash256& h) {
    return JsonValue{JsonType::String, false, 0.0,
        "sha256:" + to_hex(h.bytes, AL_HASH_SIZE), {}, {}};
}

JsonValue chunk_to_json(const ChunkRecord& c) {
    JsonValue obj;
    obj.type = JsonType::Object;
    obj.object_val.emplace_back("index",
        JsonValue{JsonType::Number, false, static_cast<double>(c.index), "", {}, {}});
    obj.object_val.emplace_back("offset",
        JsonValue{JsonType::Number, false, static_cast<double>(c.offset), "", {}, {}});
    obj.object_val.emplace_back("size",
        JsonValue{JsonType::Number, false, static_cast<double>(c.size), "", {}, {}});
    obj.object_val.emplace_back("hash", hash_to_json(c.hash));
    return obj;
}

JsonValue file_to_json(const FileRecord& f) {
    JsonValue obj;
    obj.type = JsonType::Object;
    obj.object_val.emplace_back("path",
        JsonValue{JsonType::String, false, 0.0, f.path, {}, {}});
    obj.object_val.emplace_back("mime",
        JsonValue{JsonType::String, false, 0.0, f.mime, {}, {}});
    obj.object_val.emplace_back("size",
        JsonValue{JsonType::Number, false, static_cast<double>(f.size), "", {}, {}});
    obj.object_val.emplace_back("file_hash", hash_to_json(f.file_hash));
    obj.object_val.emplace_back("merkle_root", hash_to_json(f.merkle_root));
    obj.object_val.emplace_back("chunk_count",
        JsonValue{JsonType::Number, false, static_cast<double>(f.chunk_count), "", {}, {}});

    JsonValue chunks_arr;
    chunks_arr.type = JsonType::Array;
    for (auto& c : f.chunks) {
        chunks_arr.array_val.push_back(chunk_to_json(c));
    }
    obj.object_val.emplace_back("chunks", std::move(chunks_arr));
    return obj;
}

std::expected<ChunkRecord, ManifestError> chunk_from_json(const JsonValue& val) {
    if (!val.is_object()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "chunk is not an object"));
    }
    ChunkRecord c;
    auto* idx = val.find("index");
    if (!idx || !idx->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing chunk 'index'"));
    }
    c.index = static_cast<uint32_t>(idx->as_uint());

    auto* off = val.find("offset");
    if (!off || !off->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing chunk 'offset'"));
    }
    c.offset = off->as_uint();

    auto* sz = val.find("size");
    if (!sz || !sz->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing chunk 'size'"));
    }
    c.size = static_cast<uint32_t>(sz->as_uint());

    auto* hash = val.find("hash");
    if (!hash || !hash->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing chunk 'hash'"));
    }
    auto h = parse_hex_hash(
        std::string_view(hash->as_string()).starts_with("sha256:")
        ? std::string_view(hash->as_string()).substr(7)
        : std::string_view(hash->as_string()));
    if (!h) return std::unexpected(h.error());
    c.hash = *h;

    return c;
}

std::expected<FileRecord, ManifestError> file_from_json(const JsonValue& val) {
    if (!val.is_object()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "file is not an object"));
    }
    FileRecord f;

    auto* path = val.find("path");
    if (!path || !path->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing file 'path'"));
    }
    f.path = std::string(path->as_string());

    auto* mime = val.find("mime");
    if (!mime || !mime->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing file 'mime'"));
    }
    f.mime = std::string(mime->as_string());

    auto* size = val.find("size");
    if (!size || !size->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing file 'size'"));
    }
    f.size = size->as_uint();

    auto* fh = val.find("file_hash");
    if (!fh || !fh->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing file 'file_hash'"));
    }
    auto fhash = parse_hex_hash(
        std::string_view(fh->as_string()).starts_with("sha256:")
        ? std::string_view(fh->as_string()).substr(7)
        : std::string_view(fh->as_string()));
    if (!fhash) return std::unexpected(fhash.error());
    f.file_hash = *fhash;

    auto* mr = val.find("merkle_root");
    if (!mr || !mr->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing file 'merkle_root'"));
    }
    auto mroot = parse_hex_hash(
        std::string_view(mr->as_string()).starts_with("sha256:")
        ? std::string_view(mr->as_string()).substr(7)
        : std::string_view(mr->as_string()));
    if (!mroot) return std::unexpected(mroot.error());
    f.merkle_root = *mroot;

    auto* cc = val.find("chunk_count");
    if (cc && cc->is_number()) {
        f.chunk_count = static_cast<uint32_t>(cc->as_uint());
    }

    auto* chunks = val.find("chunks");
    if (chunks && chunks->is_array()) {
        for (auto& cv : chunks->array_val) {
            auto cr = chunk_from_json(cv);
            if (!cr) return std::unexpected(cr.error());
            f.chunks.push_back(std::move(*cr));
        }
        f.chunk_count = static_cast<uint32_t>(f.chunks.size());
    }

    return f;
}

JsonValue manifest_to_json_value(const ShareManifest& m) {
    JsonValue root;
    root.type = JsonType::Object;

    root.object_val.emplace_back("version",
        JsonValue{JsonType::Number, false, static_cast<double>(m.version), "", {}, {}});
    root.object_val.emplace_back("root_cid", hash_to_json(m.root_cid));

    JsonValue files_arr;
    files_arr.type = JsonType::Array;
    for (auto& f : m.files) {
        files_arr.array_val.push_back(file_to_json(f));
    }
    root.object_val.emplace_back("files", std::move(files_arr));

    return root;
}

}  // namespace

std::string ShareManifest::to_json() const {
    return JsonWriter::write_sorted(manifest_to_json_value(*this));
}

std::expected<ShareManifest, ManifestError> ShareManifest::from_json(
    std::string_view json) {
    if (json.size() > kMaxManifestSize) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "manifest too large"));
    }

    JsonParser parser(json);
    auto val = parser.parse();
    if (!val) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonParseError, val.error()));
    }
    if (!val->is_object()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "manifest root is not an object"));
    }

    ShareManifest m;

    auto* ver = val->find("version");
    if (!ver || !ver->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'version'"));
    }
    m.version = ver->as_uint();
    if (m.version != kManifestVersion) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::VersionUnsupported,
            "unsupported version: " + std::to_string(m.version)));
    }

    auto* rcid = val->find("root_cid");
    if (!rcid || !rcid->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'root_cid'"));
    }
    auto cid = parse_hex_hash(
        std::string_view(rcid->as_string()).starts_with("sha256:")
        ? std::string_view(rcid->as_string()).substr(7)
        : std::string_view(rcid->as_string()));
    if (!cid) return std::unexpected(cid.error());
    m.root_cid = *cid;

    auto* files = val->find("files");
    if (!files || !files->is_array()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'files' array"));
    }
    for (auto& fv : files->array_val) {
        auto fr = file_from_json(fv);
        if (!fr) return std::unexpected(fr.error());
        m.files.push_back(std::move(*fr));
    }

    return m;
}

// ---------------------------------------------------------------------------
// ShareManifest — CID computation
// ---------------------------------------------------------------------------

std::expected<al_hash256, ManifestError> ShareManifest::compute_root_cid() const {
    if (files.empty()) {
        return al_hash_zero();
    }

    // Sort files by path for deterministic ordering.
    std::vector<const FileRecord*> sorted;
    sorted.reserve(files.size());
    for (auto& f : files) sorted.push_back(&f);
    std::sort(sorted.begin(), sorted.end(),
        [](auto* a, auto* b) { return a->path < b->path; });

    // Concatenate the Merkle roots of all files.
    std::vector<al_hash256> roots;
    roots.reserve(sorted.size());
    for (auto* f : sorted) {
        roots.push_back(f->merkle_root);
    }

    // The overall root is the Merkle root of the per-file roots.
    return compute_merkle_root(roots);
}

std::expected<void, ManifestError> ShareManifest::verify_root_cid() const {
    auto computed = compute_root_cid();
    if (!computed) return std::unexpected(computed.error());

    if (!al_hash_eq(&*computed, &root_cid)) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::RootCidMismatch, "root CID mismatch"));
    }
    return {};
}

// ---------------------------------------------------------------------------
// ShareManifest — proofs
// ---------------------------------------------------------------------------

std::expected<InclusionProof, ManifestError> ShareManifest::prove_chunk(
    std::string_view file_path, uint32_t chunk_index) const {
    // Find the file.
    const FileRecord* file = nullptr;
    for (auto& f : files) {
        if (f.path == file_path) { file = &f; break; }
    }
    if (!file) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileNotFound,
            "file not found: " + std::string(file_path)));
    }

    // Collect chunk hashes.
    std::vector<al_hash256> leaves;
    leaves.reserve(file->chunks.size());
    for (auto& c : file->chunks) {
        leaves.push_back(c.hash);
    }

    return generate_proof(leaves, chunk_index);
}

std::expected<void, ManifestError> ShareManifest::verify_proof(
    std::string_view file_path, const InclusionProof& proof) const {
    // Find the file.
    const FileRecord* file = nullptr;
    for (auto& f : files) {
        if (f.path == file_path) { file = &f; break; }
    }
    if (!file) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileNotFound,
            "file not found: " + std::string(file_path)));
    }

    // Verify the proof against the file's Merkle root.
    if (!proof.verify(file->merkle_root)) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::ProofInvalid, "inclusion proof verification failed"));
    }

    return {};
}

// ---------------------------------------------------------------------------
// ShareManifest — validation
// ---------------------------------------------------------------------------

std::expected<void, ManifestError> ShareManifest::validate() const {
    if (version != kManifestVersion) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::VersionUnsupported,
            "unsupported version: " + std::to_string(version)));
    }

    if (files.empty()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileEmpty, "manifest contains no files"));
    }

    // Check for duplicate paths.
    std::vector<std::string> paths;
    paths.reserve(files.size());
    for (auto& f : files) paths.push_back(f.path);
    std::sort(paths.begin(), paths.end());
    auto dup = std::adjacent_find(paths.begin(), paths.end());
    if (dup != paths.end()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileDuplicatePath,
            "duplicate file path: " + *dup));
    }

    // Verify each file's Merkle root matches its chunk hashes.
    for (auto& f : files) {
        std::vector<al_hash256> leaves;
        leaves.reserve(f.chunks.size());
        for (auto& c : f.chunks) {
            leaves.push_back(c.hash);
        }
        auto computed_root = compute_merkle_root(leaves);
        if (!al_hash_eq(&computed_root, &f.merkle_root)) {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::ChunkHashMismatch,
                "Merkle root mismatch for file: " + f.path));
        }
    }

    // Verify root CID.
    auto cid_res = verify_root_cid();
    if (!cid_res) return cid_res;

    return {};
}

// ---------------------------------------------------------------------------
// MerkleManifestBuilder — internals
// ---------------------------------------------------------------------------

struct MerkleManifestBuilder::Impl {
    FileChunkerConfig chunker_config;
    std::vector<FileRecord> files;

    explicit Impl(FileChunkerConfig cfg) : chunker_config(std::move(cfg)) {}

    std::expected<void, ManifestError> add_chunked_file(
        const std::filesystem::path& path,
        std::string_view logical_path,
        std::string_view mime_type,
        std::span<const uint8_t> data) {

        // Chunk the data.
        FileChunker chunker(chunker_config);
        auto chunked = chunker.chunk_buffer(data, logical_path);
        if (!chunked) {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::InternalError,
                "chunking failed: " + std::string(chunked.error().message)));
        }

        if (chunked->chunks.empty()) {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::FileEmpty,
                "file produced no chunks: " + std::string(logical_path)));
        }

        // Build the per-file Merkle tree from chunk hashes.
        std::vector<al_hash256> leaves;
        leaves.reserve(chunked->chunks.size());
        for (auto& c : chunked->chunks) {
            leaves.push_back(c.hash);
        }

        al_hash256 file_root = compute_merkle_root(leaves);

        // Build the FileRecord.
        FileRecord rec;
        rec.path = std::string(logical_path);
        rec.mime = std::string(mime_type);
        rec.size = data.size();
        rec.file_hash = chunked->file_hash;
        rec.merkle_root = file_root;
        rec.chunk_count = static_cast<uint32_t>(chunked->chunks.size());
        rec.chunks.reserve(chunked->chunks.size());
        for (auto& c : chunked->chunks) {
            ChunkRecord cr;
            cr.index = c.index;
            cr.offset = c.offset;
            cr.size = c.size;
            cr.hash = c.hash;
            rec.chunks.push_back(cr);
        }

        files.push_back(std::move(rec));
        return {};
    }
};

// ---------------------------------------------------------------------------
// MerkleManifestBuilder — public API
// ---------------------------------------------------------------------------

MerkleManifestBuilder::MerkleManifestBuilder()
    : impl_(std::make_unique<Impl>(FileChunkerConfig{})) {}

MerkleManifestBuilder::MerkleManifestBuilder(FileChunkerConfig chunker_config)
    : impl_(std::make_unique<Impl>(std::move(chunker_config))) {}

MerkleManifestBuilder::~MerkleManifestBuilder() = default;

MerkleManifestBuilder::MerkleManifestBuilder(MerkleManifestBuilder&&) noexcept = default;
MerkleManifestBuilder& MerkleManifestBuilder::operator=(MerkleManifestBuilder&&) noexcept = default;

std::expected<void, ManifestError> MerkleManifestBuilder::add_file(
    const std::filesystem::path& path) {
    auto mime = mime_type_for(path.generic_string());
    return add_file(path, path.generic_string(), mime);
}

std::expected<void, ManifestError> MerkleManifestBuilder::add_file(
    const std::filesystem::path& path,
    std::string_view logical_path,
    std::string_view mime_type) {
    // Read the file.
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileNotFound,
            "cannot stat: " + path.string()));
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "failed to open: " + path.string()));
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "read failed: " + path.string()));
    }

    return impl_->add_chunked_file(path, logical_path, mime_type,
        std::span<const uint8_t>(buffer.data(), buffer.size()));
}

std::expected<void, ManifestError> MerkleManifestBuilder::add_buffer(
    std::span<const uint8_t> data,
    std::string_view logical_path,
    std::string_view mime_type) {
    return impl_->add_chunked_file(
        {}, logical_path, mime_type, data);
}

std::expected<ShareManifest, ManifestError> MerkleManifestBuilder::build() const {
    if (impl_->files.empty()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileEmpty, "no files added to manifest"));
    }

    ShareManifest manifest;
    manifest.version = kManifestVersion;
    manifest.files = impl_->files;

    // Sort files by path.
    std::sort(manifest.files.begin(), manifest.files.end(),
        [](auto& a, auto& b) { return a.path < b.path; });

    auto cid = manifest.compute_root_cid();
    if (!cid) return std::unexpected(cid.error());
    manifest.root_cid = *cid;

    return manifest;
}

std::expected<std::string, ManifestError> MerkleManifestBuilder::build_json() const {
    auto manifest = build();
    if (!manifest) return std::unexpected(manifest.error());
    return manifest->to_json();
}

size_t MerkleManifestBuilder::file_count() const {
    return impl_->files.size();
}

uint64_t MerkleManifestBuilder::total_bytes() const {
    uint64_t total = 0;
    for (auto& f : impl_->files) total += f.size;
    return total;
}

// ---------------------------------------------------------------------------
// MerkleManifestBuilder — static helpers
// ---------------------------------------------------------------------------

std::expected<ShareManifest, ManifestError> MerkleManifestBuilder::from_directory(
    const std::filesystem::path& root_dir,
    FileChunkerConfig config) {
    if (!std::filesystem::is_directory(root_dir)) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileNotFound,
            "not a directory: " + root_dir.string()));
    }

    MerkleManifestBuilder builder(std::move(config));

    for (auto& entry : std::filesystem::recursive_directory_iterator(root_dir)) {
        if (!entry.is_regular_file()) continue;

        auto rel = std::filesystem::relative(entry.path(), root_dir);
        auto rel_str = "/" + rel.generic_string();
        auto mime = mime_type_for(rel_str);

        auto result = builder.add_file(entry.path(), rel_str, mime);
        if (!result) return std::unexpected(result.error());
    }

    return builder.build();
}

std::expected<ShareManifest, ManifestError> MerkleManifestBuilder::load(
    const std::filesystem::path& path) {
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileNotFound,
            "cannot stat: " + path.string()));
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "failed to open: " + path.string()));
    }

    std::string data(static_cast<size_t>(size), '\0');
    ifs.read(data.data(), static_cast<std::streamsize>(size));
    if (!ifs) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "read failed: " + path.string()));
    }

    return ShareManifest::from_json(data);
}

std::expected<void, ManifestError> MerkleManifestBuilder::save(
    const ShareManifest& manifest,
    const std::filesystem::path& path) {
    auto json = manifest.to_json();

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "failed to open for writing: " + path.string()));
    }

    ofs.write(json.data(), static_cast<std::streamsize>(json.size()));
    if (!ofs) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "write failed: " + path.string()));
    }

    return {};
}

}  // namespace astrolune::share
