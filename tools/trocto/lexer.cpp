// Tokenizer shared by the Trocto parser and the Regol assembler.

#include "lexer.hpp"

#include <cctype>

namespace trocto {

namespace {

bool ident_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
}
bool ident_continue(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

// Longest-match first: two-character operators before their prefixes.
const char* const kTwoChar[] = {
    "->", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=",
    "%=", "<<", ">>",
};

const char* const kKeywords[] = {
    // Trocto
    "contract", "state", "pub", "fn", "let", "if", "else", "while",
    "return", "require", "emit", "self", "true", "false", "u64",
    "init", "import", "assert", "string", "address",
    // Regol
    "fn", "entry",
};

}  // namespace

bool is_keyword(const std::string& text) {
    for (const char* keyword : kKeywords) {
        if (text == keyword) return true;
    }
    return false;
}

std::vector<Token> Lexer::tokenize(Diagnostics& diagnostics) {
    std::vector<Token> tokens;
    size_t i = 0;
    unsigned line = 1;

    auto push = [&](TokenKind kind, std::string text, uint64_t number) {
        tokens.push_back(Token{kind, std::move(text), number, line});
    };

    while (i < source_.size()) {
        char c = source_[i];
        if (c == '\n') { ++line; ++i; continue; }
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }

        // Comments: // to end of line, and # too (assembly convention).
        if ((c == '/' && i + 1 < source_.size() && source_[i + 1] == '/') ||
            c == '#') {
            while (i < source_.size() && source_[i] != '\n') ++i;
            continue;
        }

        if (c == '"') {
            size_t begin = ++i;
            while (i < source_.size() && source_[i] != '"') {
                if (source_[i] == '\n') {
                    diagnostics.error(line, "unterminated string literal");
                    return tokens;
                }
                ++i;
            }
            if (i >= source_.size()) {
                diagnostics.error(line, "unterminated string literal");
                return tokens;
            }
            push(TokenKind::String, source_.substr(begin, i - begin), 0);
            ++i;
            continue;
        }

        if (std::isdigit(static_cast<unsigned char>(c))) {
            uint64_t value = 0;
            bool overflow = false;
            if (c == '0' && i + 1 < source_.size() &&
                (source_[i + 1] == 'x' || source_[i + 1] == 'X')) {
                i += 2;
                size_t digits = 0;
                while (i < source_.size() &&
                       std::isxdigit(static_cast<unsigned char>(source_[i]))) {
                    char d = source_[i++];
                    uint64_t digit = d <= '9' ? uint64_t(d - '0')
                                              : uint64_t((d | 32) - 'a' + 10);
                    if (value > (UINT64_MAX >> 4)) overflow = true;
                    value = (value << 4) | digit;
                    ++digits;
                }
                if (digits == 0) {
                    diagnostics.error(line, "hex literal needs digits");
                    return tokens;
                }
            } else {
                while (i < source_.size() &&
                       std::isdigit(static_cast<unsigned char>(source_[i]))) {
                    uint64_t digit = uint64_t(source_[i++] - '0');
                    if (value > (UINT64_MAX - digit) / 10) overflow = true;
                    value = value * 10 + digit;
                }
            }
            if (overflow) {
                diagnostics.error(line, "integer literal overflows u64");
                return tokens;
            }
            push(TokenKind::Number, "", value);
            continue;
        }

        if (ident_start(c)) {
            size_t begin = i;
            while (i < source_.size() && ident_continue(source_[i])) ++i;
            std::string text = source_.substr(begin, i - begin);
            push(is_keyword(text) ? TokenKind::Keyword : TokenKind::Ident,
                 std::move(text), 0);
            continue;
        }

        bool matched_two = false;
        for (const char* op : kTwoChar) {
            if (source_.compare(i, 2, op) == 0) {
                push(TokenKind::Punct, op, 0);
                i += 2;
                matched_two = true;
                break;
            }
        }
        if (matched_two) continue;

        switch (c) {
        case '{': case '}': case '(': case ')': case ':': case ';':
        case ',': case '=': case '+': case '-': case '*': case '/':
        case '%': case '<': case '>': case '!': case '&': case '|':
        case '^': case '.': case '[': case ']':
            push(TokenKind::Punct, std::string(1, c), 0);
            ++i;
            break;
        default:
            diagnostics.error(line,
                              "unexpected character '" + std::string(1, c) + "'");
            return tokens;
        }
    }

    tokens.push_back(Token{TokenKind::End, "", 0, line});
    return tokens;
}

}  // namespace trocto
