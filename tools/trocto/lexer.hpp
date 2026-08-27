// Shared lexer for Trocto and Regol. One token vocabulary keeps both
// front ends honest about what the surface syntax can contain.

#ifndef TROCTO_LEXER_HPP
#define TROCTO_LEXER_HPP

#include "trocto/compiler.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace trocto {

enum class TokenKind {
    End,
    Ident,       // [A-Za-z_][A-Za-z0-9_]*
    Number,      // decimal or 0x hex, fits u64
    String,      // double-quoted, no escapes in v0.1
    Punct,       // one of {} ( ) : ; , -> = + - * / % < > ! & | ^ . == != <= >= && || += -= *= /= %= << >>
    Keyword,     // see keywords()
};

struct Token {
    TokenKind kind = TokenKind::End;
    std::string text;      // identifier/keyword text or decoded string
    uint64_t number = 0;
    unsigned line = 0;
};

bool is_keyword(const std::string& text);

class Lexer {
public:
    explicit Lexer(const std::string& source) : source_(source) {}

    // Tokenizes everything up front; both grammars are small enough that a
    // token vector is simpler and reproducible than streaming.
    std::vector<Token> tokenize(Diagnostics& diagnostics);

private:
    const std::string& source_;
};

}  // namespace trocto

#endif  // TROCTO_LEXER_HPP
