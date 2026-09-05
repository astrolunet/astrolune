/*
 * astrolune/tools/ecosystem/hosting/site_manifest.cpp
 *
 * Implementation of the content-addressed manifest for static .lune hosting.
 *
 * JSON handling is done with a minimal hand-rolled parser that avoids an
 * external dependency.  The parser supports only the exact subset of JSON
 * required by the manifest format (objects, arrays, strings, numbers,
 * booleans, null).  For a production deployment this could be swapped for
 * nlohmann/json or simdjson.
 */

#include "site_manifest.hpp"

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

// ---------------------------------------------------------------------------
// Minimal JSON reader / writer
//
// This is intentionally self-contained to keep the tooling dependency-free.
// Only the JSON features needed by the manifest format are supported.
// ---------------------------------------------------------------------------

namespace {

// ---- JSON value -----------------------------------------------------------

enum class JsonType { Null, Bool, Number, String, Array, Object };

struct JsonValue {
    JsonType type = JsonType::Null;

    bool bool_val = false;
    double number_val = 0.0;
    std::string string_val;
    std::vector<JsonValue> array_val;
    std::vector<std::pair<std::string, JsonValue>> object_val;

    // Convenience accessors
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

    const JsonValue& at(std::string_view key) const {
        auto* p = find(key);
        assert(p != nullptr);
        return *p;
    }

    std::string_view as_string() const { return string_val; }
    bool as_bool() const { return bool_val; }
    double as_number() const { return number_val; }
    int64_t as_int() const { return static_cast<int64_t>(number_val); }
    uint64_t as_uint() const { return static_cast<uint64_t>(number_val); }
};

// ---- JSON parser ----------------------------------------------------------

class JsonParser {
public:
    explicit JsonParser(std::string_view input)
        : src_(input), pos_(0) {}

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

    char peek() const {
        return pos_ < src_.size() ? src_[pos_] : '\0';
    }

    char advance() {
        return pos_ < src_.size() ? src_[pos_++] : '\0';
    }

    void skip_ws() {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            } else {
                break;
            }
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
        return std::unexpected(std::string("unexpected character: ") + c);
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
        if (advance() != '"') {
            return std::unexpected(std::string("expected '\"'"));
        }
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
                    case 'u': {
                        auto hex = src_.substr(pos_, 4);
                        if (hex.size() < 4) {
                            return std::unexpected(std::string("incomplete unicode escape"));
                        }
                        uint32_t cp = 0;
                        for (char h : hex) {
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp += h - '0';
                            else if (h >= 'a' && h <= 'f') cp += 10 + h - 'a';
                            else if (h >= 'A' && h <= 'F') cp += 10 + h - 'A';
                            else return std::unexpected(std::string("invalid hex in unicode escape"));
                        }
                        pos_ += 4;
                        // Simple UTF-8 encode
                        if (cp < 0x80) {
                            result += static_cast<char>(cp);
                        } else if (cp < 0x800) {
                            result += static_cast<char>(0xC0 | (cp >> 6));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            result += static_cast<char>(0xE0 | (cp >> 12));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        break;
                    }
                    default:
                        return std::unexpected(std::string("invalid escape: \\") + esc);
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
        auto [ptr, ec] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), val);
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
            JsonValue v;
            v.type = JsonType::Bool;
            v.bool_val = true;
            return v;
        }
        if (src_.substr(pos_, 5) == "false") {
            pos_ += 5;
            JsonValue v;
            v.type = JsonType::Bool;
            v.bool_val = false;
            return v;
        }
        return std::unexpected(std::string("expected boolean"));
    }

    std::expected<JsonValue, std::string> parse_null() {
        if (src_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return JsonValue{};
        }
        return std::unexpected(std::string("expected null"));
    }

    std::expected<JsonValue, std::string> parse_array() {
        if (advance() != '[') return std::unexpected(std::string("expected '['"));
        JsonValue arr;
        arr.type = JsonType::Array;
        skip_ws();
        if (peek() == ']') { ++pos_; return arr; }
        while (true) {
            auto val = parse_value();
            if (!val) return std::unexpected(val.error());
            arr.array_val.push_back(std::move(*val));
            skip_ws();
            if (peek() == ']') { ++pos_; break; }
            if (advance() != ',') return std::unexpected(std::string("expected ',' or ']'"));
        }
        return arr;
    }

    std::expected<JsonValue, std::string> parse_object() {
        if (advance() != '{') return std::unexpected(std::string("expected '{'"));
        JsonValue obj;
        obj.type = JsonType::Object;
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
            if (advance() != ',') return std::unexpected(std::string("expected ',' or '}'"));
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

    // Write an object with sorted keys (canonical form).
    static std::string write_sorted(const JsonValue& val) {
        JsonWriter w;
        w.write_sorted_value(val);
        return w.buf_;
    }

private:
    std::string buf_;

    void write_value(const JsonValue& val) {
        switch (val.type) {
            case JsonType::Null:
                buf_ += "null";
                break;
            case JsonType::Bool:
                buf_ += val.bool_val ? "true" : "false";
                break;
            case JsonType::Number: {
                // Use integer representation when possible
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
                    auto [ptr, ec] = std::to_chars(tmp, tmp + sizeof(tmp), val.number_val,
                                                    std::chars_format::general, 17);
                    buf_.append(tmp, ptr);
                }
                break;
            }
            case JsonType::String:
                write_string(val.string_val);
                break;
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

    // Write with sorted keys (for canonical signing).
    void write_sorted_value(const JsonValue& val) {
        switch (val.type) {
            case JsonType::Object: {
                // Sort keys
                std::vector<std::pair<std::string, const JsonValue*>> sorted;
                sorted.reserve(val.object_val.size());
                for (auto& [k, v] : val.object_val) {
                    sorted.emplace_back(k, &v);
                }
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
            case JsonType::Array: {
                buf_ += '[';
                for (size_t i = 0; i < val.array_val.size(); ++i) {
                    if (i > 0) buf_ += ',';
                    write_sorted_value(val.array_val[i]);
                }
                buf_ += ']';
                break;
            }
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

// ---- Helper: hex encode ---------------------------------------------------

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

// ---- Helper: hex decode ---------------------------------------------------

std::expected<std::vector<uint8_t>, std::string> from_hex_string(
    std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::unexpected(std::string("odd-length hex string"));
    }
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        auto h = hex[i];
        auto l = hex[i + 1];
        if (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'a' && h <= 'f') hi = 10 + h - 'a';
        else if (h >= 'A' && h <= 'F') hi = 10 + h - 'A';
        else return std::unexpected(std::string("invalid hex char"));
        if (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'a' && l <= 'f') lo = 10 + l - 'a';
        else if (l >= 'A' && l <= 'F') lo = 10 + l - 'A';
        else return std::unexpected(std::string("invalid hex char"));
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
}

// ---- Helper: read file to string ------------------------------------------

std::expected<std::string, std::string> read_file_str(
    const std::filesystem::path& path) {
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec) return std::unexpected(ec.message());

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected("failed to open: " + path.string());
    }

    std::string data(static_cast<size_t>(size), '\0');
    ifs.read(data.data(), static_cast<std::streamsize>(size));
    if (!ifs) return std::unexpected("read failed: " + path.string());
    return data;
}

}  // namespace

// ---------------------------------------------------------------------------
// Namespace alias for brevity
// ---------------------------------------------------------------------------

namespace astrolune::hosting {

// ---------------------------------------------------------------------------
// ManifestFile
// ---------------------------------------------------------------------------

std::string ManifestFile::to_json() const {
    JsonValue obj;
    obj.type = JsonType::Object;
    obj.object_val.emplace_back("path", JsonValue{JsonType::String, false, 0.0, path, {}, {}});
    obj.object_val.emplace_back("mime", JsonValue{JsonType::String, false, 0.0, mime, {}, {}});
    obj.object_val.emplace_back("size", JsonValue{JsonType::Number, false, static_cast<double>(size), "", {}, {}});
    obj.object_val.emplace_back("hash", JsonValue{JsonType::String, false, 0.0, hash, {}, {}});

    if (!headers.empty()) {
        JsonValue hdr;
        hdr.type = JsonType::Object;
        for (auto& [k, v] : headers) {
            hdr.object_val.emplace_back(k, JsonValue{JsonType::String, false, 0.0, v, {}, {}});
        }
        obj.object_val.emplace_back("headers", std::move(hdr));
    }

    return JsonWriter::write_sorted(obj);
}

std::expected<ManifestFile, ManifestError> ManifestFile::from_json(
    std::string_view json) {
    JsonParser parser(json);
    auto val = parser.parse();
    if (!val) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonParseError, val.error()));
    }
    if (!val->is_object()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid, "manifest file is not an object"));
    }

    ManifestFile f;

    auto* path_val = val->find("path");
    if (!path_val || !path_val->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'path' field"));
    }
    f.path = std::string(path_val->as_string());

    auto* mime_val = val->find("mime");
    if (!mime_val || !mime_val->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'mime' field"));
    }
    f.mime = std::string(mime_val->as_string());

    auto* size_val = val->find("size");
    if (!size_val || !size_val->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'size' field"));
    }
    f.size = size_val->as_uint();

    auto* hash_val = val->find("hash");
    if (!hash_val || !hash_val->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'hash' field"));
    }
    f.hash = std::string(hash_val->as_string());

    auto* hdr_val = val->find("headers");
    if (hdr_val && hdr_val->is_object()) {
        for (auto& [k, v] : hdr_val->object_val) {
            if (v.is_string()) {
                f.headers[k] = std::string(v.as_string());
            }
        }
    }

    return f;
}

// ---------------------------------------------------------------------------
// SiteManifest — serialisation
// ---------------------------------------------------------------------------

namespace {

JsonValue manifest_to_json_value(const SiteManifest& m, bool include_signature) {
    JsonValue root;
    root.type = JsonType::Object;

    root.object_val.emplace_back("version",
        JsonValue{JsonType::Number, false, static_cast<double>(m.version), "", {}, {}});
    root.object_val.emplace_back("mode",
        JsonValue{JsonType::String, false, 0.0, m.mode, {}, {}});
    root.object_val.emplace_back("root_cid",
        JsonValue{JsonType::String, false, 0.0, m.root_cid, {}, {}});

    // Files array
    JsonValue files_arr;
    files_arr.type = JsonType::Array;
    for (auto& f : m.files) {
        JsonValue fobj;
        fobj.type = JsonType::Object;
        fobj.object_val.emplace_back("path",
            JsonValue{JsonType::String, false, 0.0, f.path, {}, {}});
        fobj.object_val.emplace_back("mime",
            JsonValue{JsonType::String, false, 0.0, f.mime, {}, {}});
        fobj.object_val.emplace_back("size",
            JsonValue{JsonType::Number, false, static_cast<double>(f.size), "", {}, {}});
        fobj.object_val.emplace_back("hash",
            JsonValue{JsonType::String, false, 0.0, f.hash, {}, {}});

        if (!f.headers.empty()) {
            JsonValue hdr;
            hdr.type = JsonType::Object;
            for (auto& [k, v] : f.headers) {
                hdr.object_val.emplace_back(k,
                    JsonValue{JsonType::String, false, 0.0, v, {}, {}});
            }
            fobj.object_val.emplace_back("headers", std::move(hdr));
        }
        files_arr.array_val.push_back(std::move(fobj));
    }
    root.object_val.emplace_back("files", std::move(files_arr));

    root.object_val.emplace_back("spa_fallback",
        JsonValue{JsonType::Bool, m.spa_fallback, 0.0, "", {}, {}});

    // Cache headers
    JsonValue ch;
    ch.type = JsonType::Object;
    for (auto& [k, v] : m.cache_headers) {
        ch.object_val.emplace_back(k,
            JsonValue{JsonType::String, false, 0.0, v, {}, {}});
    }
    root.object_val.emplace_back("cache_headers", std::move(ch));

    root.object_val.emplace_back("owner",
        JsonValue{JsonType::String, false, 0.0, m.owner, {}, {}});

    if (include_signature) {
        root.object_val.emplace_back("signature",
            JsonValue{JsonType::String, false, 0.0, m.signature, {}, {}});
    } else {
        root.object_val.emplace_back("signature",
            JsonValue{JsonType::Null, false, 0.0, "", {}, {}});
    }

    if (m.previous_version.has_value()) {
        root.object_val.emplace_back("previous_version",
            JsonValue{JsonType::String, false, 0.0, *m.previous_version, {}, {}});
    } else {
        root.object_val.emplace_back("previous_version",
            JsonValue{JsonType::Null, false, 0.0, "", {}, {}});
    }

    // Mirrors
    JsonValue mirrors_arr;
    mirrors_arr.type = JsonType::Array;
    for (auto& m : m.mirrors) {
        mirrors_arr.array_val.push_back(
            JsonValue{JsonType::String, false, 0.0, m, {}, {}});
    }
    root.object_val.emplace_back("mirrors", std::move(mirrors_arr));

    return root;
}

}  // namespace

std::string SiteManifest::to_json() const {
    return JsonWriter::write_sorted(manifest_to_json_value(*this, false));
}

std::string SiteManifest::to_json_signed() const {
    return JsonWriter::write_sorted(manifest_to_json_value(*this, true));
}

std::expected<SiteManifest, ManifestError> SiteManifest::from_json(
    std::string_view json) {
    if (json.size() > kMaxManifestSize) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::ManifestTooLarge,
            "manifest exceeds maximum size"));
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

    SiteManifest m;

    // version
    auto* ver = val->find("version");
    if (!ver || !ver->is_number()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'version'"));
    }
    m.version = ver->as_uint();
    if (m.version != kManifestVersion) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::VersionUnsupported,
            "unsupported manifest version: " + std::to_string(m.version)));
    }

    // mode
    auto* mode = val->find("mode");
    if (!mode || !mode->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'mode'"));
    }
    m.mode = std::string(mode->as_string());

    // root_cid
    auto* rcid = val->find("root_cid");
    if (!rcid || !rcid->is_string()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'root_cid'"));
    }
    m.root_cid = std::string(rcid->as_string());

    // files
    auto* files = val->find("files");
    if (!files || !files->is_array()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldMissing, "missing 'files' array"));
    }
    for (auto& fval : files->array_val) {
        // Serialise the sub-value back to JSON for parsing
        auto fjson = JsonWriter::write(fval);
        auto file = ManifestFile::from_json(fjson);
        if (!file) return std::unexpected(file.error());
        m.files.push_back(std::move(*file));
    }

    // spa_fallback
    auto* spa = val->find("spa_fallback");
    if (spa && spa->is_bool()) {
        m.spa_fallback = spa->as_bool();
    }

    // cache_headers
    auto* ch = val->find("cache_headers");
    if (ch && ch->is_object()) {
        for (auto& [k, v] : ch->object_val) {
            if (v.is_string()) {
                m.cache_headers[k] = std::string(v.as_string());
            }
        }
    }

    // owner
    auto* owner = val->find("owner");
    if (owner && owner->is_string()) {
        m.owner = std::string(owner->as_string());
    }

    // signature
    auto* sig = val->find("signature");
    if (sig && sig->is_string()) {
        m.signature = std::string(sig->as_string());
    }

    // previous_version
    auto* pv = val->find("previous_version");
    if (pv && pv->is_string()) {
        m.previous_version = std::string(pv->as_string());
    } else {
        m.previous_version = std::nullopt;
    }

    // mirrors
    auto* mirrors = val->find("mirrors");
    if (mirrors && mirrors->is_array()) {
        for (auto& mv : mirrors->array_val) {
            if (mv.is_string()) {
                m.mirrors.push_back(std::string(mv.as_string()));
            }
        }
    }

    return m;
}

// ---------------------------------------------------------------------------
// SiteManifest — CID computation
// ---------------------------------------------------------------------------

std::expected<std::string, ManifestError> SiteManifest::compute_root_cid() const {
    // Sort files by path for deterministic ordering
    std::vector<const ManifestFile*> sorted;
    sorted.reserve(files.size());
    for (auto& f : files) sorted.push_back(&f);
    std::sort(sorted.begin(), sorted.end(),
              [](auto* a, auto* b) { return a->path < b->path; });

    // Concatenate: path + "\0" + hash for each file
    std::string concatenated;
    for (auto* f : sorted) {
        concatenated += f->path;
        concatenated += '\0';
        concatenated += f->hash;
    }

    // SHA-256 of the concatenation
    al_hash256 digest{};
    al_sha256(concatenated.data(), concatenated.size(), &digest);

    return "sha256:" + to_hex_string(digest.bytes, AL_HASH_SIZE);
}

std::expected<void, ManifestError> SiteManifest::verify_root_cid() const {
    auto computed = compute_root_cid();
    if (!computed) return std::unexpected(computed.error());

    if (*computed != root_cid) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::RootCidMismatch,
            "root CID mismatch: expected " + root_cid +
            ", computed " + *computed));
    }
    return {};
}

// ---------------------------------------------------------------------------
// SiteManifest — signature verification
// ---------------------------------------------------------------------------

std::expected<void, ManifestError> SiteManifest::verify_signature(
    std::string_view public_key) const {
    if (signature.empty()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::SignatureInvalid, "no signature present"));
    }

    // Remove "0x" prefix if present
    auto pk = public_key;
    if (pk.starts_with("0x") || pk.starts_with("0X")) {
        pk = pk.substr(2);
    }

    auto pk_bytes = from_hex_string(pk);
    if (!pk_bytes) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::SignatureInvalid,
            "invalid public key hex: " + pk_bytes.error()));
    }

    // Remove "0x" prefix from signature
    auto sig = signature;
    if (sig.starts_with("0x") || sig.starts_with("0X")) {
        sig = sig.substr(2);
    }

    auto sig_bytes = from_hex_string(sig);
    if (!sig_bytes) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::SignatureInvalid,
            "invalid signature hex: " + sig_bytes.error()));
    }

    // The signed payload is the canonical JSON without the signature field
    auto canonical = to_json();

    // Verify secp256k1 signature
    // Reinterpret the packed data for the C ABI call
    struct alignas(1) {
        const uint8_t* msg;
        size_t msg_len;
        const uint8_t* sig;
        size_t sig_len;
        const uint8_t* pk;
        size_t pk_len;
    } verify_input{
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size(),
        sig_bytes->data(), sig_bytes->size(),
        pk_bytes->data(), pk_bytes->size()
    };

    auto result = al_secp256k1_verify(
        verify_input.msg, verify_input.msg_len,
        verify_input.sig, verify_input.sig_len,
        verify_input.pk, verify_input.pk_len);

    if (result != 0) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::SignatureVerifyFailed,
            "secp256k1 signature verification failed"));
    }

    return {};
}

// ---------------------------------------------------------------------------
// SiteManifest — validation
// ---------------------------------------------------------------------------

std::expected<void, ManifestError> SiteManifest::validate() const {
    // Version check
    if (version != kManifestVersion) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::VersionUnsupported,
            "unsupported version: " + std::to_string(version)));
    }

    // Mode check
    if (mode != "static") {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid,
            "unsupported mode: " + mode));
    }

    // Root CID format
    if (!root_cid.starts_with("sha256:")) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::JsonFieldInvalid,
            "root_cid must start with 'sha256:'"));
    }

    // Verify root CID
    auto cid_res = verify_root_cid();
    if (!cid_res) return cid_res;

    // Check for duplicate paths
    std::vector<std::string> paths;
    paths.reserve(files.size());
    for (auto& f : files) {
        paths.push_back(f.path);
    }
    std::sort(paths.begin(), paths.end());
    auto dup = std::adjacent_find(paths.begin(), paths.end());
    if (dup != paths.end()) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileDuplicatePath,
            "duplicate file path: " + *dup));
    }

    // Validate each file
    for (auto& f : files) {
        if (f.path.empty() || f.path[0] != '/') {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::FileHashInvalid,
                "file path must start with '/': " + f.path));
        }
        if (!f.hash.starts_with("sha256:")) {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::FileHashInvalid,
                "file hash must start with 'sha256:': " + f.hash));
        }
    }

    return {};
}

// ---------------------------------------------------------------------------
// MIME type detection
// ---------------------------------------------------------------------------

std::string_view mime_type_for(std::string_view path) {
    auto dot = path.rfind('.');
    if (dot == std::string_view::npos) {
        return "application/octet-stream";
    }

    auto ext = path.substr(dot + 1);
    // Lowercase the extension
    std::string ext_lower(ext);
    std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Text
    if (ext_lower == "html" || ext_lower == "htm")  return "text/html; charset=utf-8";
    if (ext_lower == "css")                         return "text/css; charset=utf-8";
    if (ext_lower == "txt")                         return "text/plain; charset=utf-8";
    if (ext_lower == "csv")                         return "text/csv; charset=utf-8";
    if (ext_lower == "xml")                         return "application/xml; charset=utf-8";
    if (ext_lower == "svg")                         return "image/svg+xml";

    // JavaScript / JSON
    if (ext_lower == "js" || ext_lower == "mjs")   return "application/javascript; charset=utf-8";
    if (ext_lower == "json")                        return "application/json; charset=utf-8";
    if (ext_lower == "map")                         return "application/json; charset=utf-8";
    if (ext_lower == "ts" || ext_lower == "tsx")    return "application/javascript; charset=utf-8";
    if (ext_lower == "jsx")                         return "application/javascript; charset=utf-8";

    // Images
    if (ext_lower == "png")                         return "image/png";
    if (ext_lower == "jpg" || ext_lower == "jpeg")  return "image/jpeg";
    if (ext_lower == "gif")                         return "image/gif";
    if (ext_lower == "ico")                         return "image/x-icon";
    if (ext_lower == "webp")                        return "image/webp";
    if (ext_lower == "avif")                        return "image/avif";
    if (ext_lower == "bmp")                         return "image/bmp";
    if (ext_lower == "tiff" || ext_lower == "tif")  return "image/tiff";

    // Fonts
    if (ext_lower == "woff")                        return "font/woff";
    if (ext_lower == "woff2")                       return "font/woff2";
    if (ext_lower == "ttf")                         return "font/ttf";
    if (ext_lower == "otf")                         return "font/otf";
    if (ext_lower == "eot")                         return "application/vnd.ms-fontobject";

    // Media
    if (ext_lower == "mp4")                         return "video/mp4";
    if (ext_lower == "webm")                        return "video/webm";
    if (ext_lower == "mp3")                         return "audio/mpeg";
    if (ext_lower == "ogg")                         return "audio/ogg";
    if (ext_lower == "wav")                         return "audio/wav";
    if (ext_lower == "flac")                        return "audio/flac";

    // Archives / binary
    if (ext_lower == "pdf")                         return "application/pdf";
    if (ext_lower == "wasm")                        return "application/wasm";
    if (ext_lower == "zip")                         return "application/zip";
    if (ext_lower == "gz")                          return "application/gzip";
    if (ext_lower == "tar")                         return "application/x-tar";
    if (ext_lower == "exe" || ext_lower == "dll")   return "application/octet-stream";

    // Data
    if (ext_lower == "woff2.map")                   return "application/json; charset=utf-8";

    return "application/octet-stream";
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

std::expected<SiteManifest, ManifestError> load_manifest(
    const std::filesystem::path& path) {
    auto data = read_file_str(path);
    if (!data) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError, data.error()));
    }
    return SiteManifest::from_json(*data);
}

std::expected<void, ManifestError> save_manifest(
    const SiteManifest& manifest,
    const std::filesystem::path& path) {
    auto json = manifest.to_json_signed();

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

std::expected<SiteManifest, ManifestError> build_manifest(
    const std::filesystem::path& root_dir,
    bool spa_fallback) {
    if (!std::filesystem::is_directory(root_dir)) {
        return std::unexpected(ManifestError::make(
            ManifestErrorCode::FileReadError,
            "not a directory: " + root_dir.string()));
    }

    SiteManifest manifest;
    manifest.version = kManifestVersion;
    manifest.mode = "static";
    manifest.spa_fallback = spa_fallback;

    // Walk the directory tree
    for (auto& entry : std::filesystem::recursive_directory_iterator(root_dir)) {
        if (!entry.is_regular_file()) continue;

        auto rel = std::filesystem::relative(entry.path(), root_dir);
        auto rel_str = rel.generic_string();

        ManifestFile f;
        f.path = "/" + rel_str;
        f.mime = std::string(mime_type_for(f.path));
        f.size = static_cast<uint64_t>(entry.file_size());

        // Compute SHA-256 of the file contents
        auto file_data = read_file_str(entry.path());
        if (!file_data) {
            return std::unexpected(ManifestError::make(
                ManifestErrorCode::FileReadError,
                "failed to read: " + entry.path().string()));
        }

        al_hash256 digest{};
        al_sha256(file_data->data(), file_data->size(), &digest);
        f.hash = "sha256:" + to_hex_string(digest.bytes, AL_HASH_SIZE);

        manifest.files.push_back(std::move(f));
    }

    // Sort files by path
    std::sort(manifest.files.begin(), manifest.files.end(),
              [](auto& a, auto& b) { return a.path < b.path; });

    // Compute root CID
    auto cid = manifest.compute_root_cid();
    if (!cid) return std::unexpected(cid.error());
    manifest.root_cid = *cid;

    return manifest;
}

}  // namespace astrolune::hosting
