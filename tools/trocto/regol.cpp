// Regol: the low-level tier. Text maps one-to-one onto ALVM containers with
// two conveniences over raw bytes - named functions and jump labels.
//
//   fn no_args() -> u0 {
//       push64 42
//       push64 8          ; scratch offset chosen by the author
//       store64           ; memory[8..16) = 42
//       push64 8
//       load64
//       push64 8
//       return            ; return(memory[8..16))
//   }
//
// The first function in the file is the default transaction entrypoint and
// must take no parameters, mirroring the container contract.

#include "encoder.hpp"
#include "lexer.hpp"

namespace trocto {
namespace {

struct Mnemonic {
    const char* name;
    Opcode opcode;
};

const Mnemonic kMnemonics[] = {
    {"stop", Opcode::Stop}, {"push64", Opcode::Push64},
    {"add", Opcode::Add}, {"sub", Opcode::Sub}, {"mul", Opcode::Mul},
    {"div", Opcode::Div}, {"eq", Opcode::Eq}, {"lt", Opcode::Lt},
    {"dup", Opcode::Dup}, {"drop", Opcode::Drop},
    {"jump", Opcode::Jump}, {"jumpi", Opcode::JumpIf},
    {"load8", Opcode::Load8}, {"store8", Opcode::Store8},
    {"return", Opcode::Return}, {"revert", Opcode::Revert},
    {"mod", Opcode::Mod}, {"and", Opcode::And}, {"or", Opcode::Or},
    {"xor", Opcode::Xor}, {"not", Opcode::Not}, {"shl", Opcode::Shl},
    {"shr", Opcode::Shr}, {"gt", Opcode::Gt}, {"le", Opcode::Le},
    {"ge", Opcode::Ge}, {"swap", Opcode::Swap},
    {"load64", Opcode::Load64}, {"store64", Opcode::Store64},
    {"calldata_size", Opcode::CalldataSize},
    {"calldata_copy", Opcode::CalldataCopy},
    {"call", Opcode::Call}, {"ret", Opcode::Ret},
    {"host", Opcode::Host},
};

bool opcode_from_mnemonic(const std::string& word, Opcode& out) {
    for (const Mnemonic& m : kMnemonics) {
        if (word == m.name) {
            out = m.opcode;
            return true;
        }
    }
    return false;
}

bool host_from_name(const std::string& word, uint16_t& id) {
    struct Entry { const char* name; Host host; };
    static const Entry kTable[] = {
        {"sender", Host::Sender},
        {"current_address", Host::CurrentAddress},
        {"block_height", Host::BlockHeight},
        {"protocol_day", Host::ProtocolDay},
        {"balance", Host::Balance},
        {"transfer", Host::Transfer},
        {"storage_get", Host::StorageGet},
        {"storage_set", Host::StorageSet},
        {"storage_delete", Host::StorageDelete},
        {"emit_event", Host::EmitEvent},
        {"hash_tagged", Host::HashTagged},
        {"verify_signature", Host::VerifySignature},
        {"call_contract", Host::CallContract},
    };
    for (const Entry& e : kTable) {
        if (word == e.name) {
            id = static_cast<uint16_t>(e.host);
            return true;
        }
    }
    return false;
}

class RegolParser {
public:
    RegolParser(std::vector<Token> tokens, Diagnostics& diagnostics)
        : tokens_(std::move(tokens)), diagnostics_(diagnostics) {}

    std::optional<ModuleIR> parse() {
        ModuleIR module;
        while (!failed_ && peek().kind != TokenKind::End) {
            const Token& head = peek();
            if ((head.kind == TokenKind::Keyword || head.kind == TokenKind::Ident) &&
                head.text == "fn") {
                advance();
                auto fn = parse_function();
                if (!fn) return std::nullopt;
                module.functions.push_back(std::move(*fn));
                continue;
            }
            diagnostics_.error(head.line,
                               "expected 'fn', found '" + head.text + "'");
            failed_ = true;
        }
        if (failed_) return std::nullopt;
        if (module.functions.empty()) {
            diagnostics_.error(1, "regol module needs at least one function");
            return std::nullopt;
        }
        if (module.functions.front().parameters != 0) {
            diagnostics_.error(
                1, "the first function is the default entrypoint and must "
                   "take no parameters");
            return std::nullopt;
        }
        return module;
    }

private:
    const Token& peek(size_t ahead = 0) const {
        size_t index = position_ + ahead;
        if (index >= tokens_.size()) index = tokens_.size() - 1;
        return tokens_[index];
    }
    const Token& advance() {
        const Token& t = peek();
        if (position_ + 1 < tokens_.size()) ++position_;
        return t;
    }
    bool accept_punct(const char* text) {
        if (peek().kind == TokenKind::Punct && peek().text == text) {
            advance();
            return true;
        }
        return false;
    }

    std::optional<FunctionIR> parse_function() {
        FunctionIR fn;
        fn.name = advance().text;

        if (!accept_punct("(")) {
            diagnostics_.error(peek().line, "expected '(' after fn name");
            return std::nullopt;
        }
        uint16_t params = 0;
        while (!accept_punct(")")) {
            if (!consume_type_name()) return std::nullopt;  // parameter name
            if (!accept_punct(":")) {
                diagnostics_.error(peek().line, "expected ':' in parameters");
                return std::nullopt;
            }
            if (!consume_type_name()) return std::nullopt;  // type
            ++params;
            if (!accept_punct(",")) {
                if (!accept_punct(")")) {
                    diagnostics_.error(peek().line,
                                       "expected ',' or ')' in parameters");
                    return std::nullopt;
                }
                break;
            }
        }
        fn.parameters = params;

        uint16_t results = 0;
        if (accept_punct("->")) {
            // Either a count ("-> 2") or a comma list of uN types.
            if (peek().kind == TokenKind::Number) {
                results = static_cast<uint16_t>(advance().number);
            } else {
                for (;;) {
                    if (peek().kind != TokenKind::Ident ||
                        peek().text.empty() || peek().text[0] != 'u') {
                        diagnostics_.error(peek().line, "expected result type");
                        return std::nullopt;
                    }
                    advance();
                    ++results;
                    if (!accept_punct(",")) break;
                }
            }
        }
        fn.results = results;

        if (!accept_punct("{")) {
            diagnostics_.error(peek().line, "expected '{' to open function");
            return std::nullopt;
        }
        while (!accept_punct("}")) {
            if (peek().kind == TokenKind::End) {
                diagnostics_.error(peek().line,
                                   "unexpected end of file inside '" +
                                       fn.name + "'");
                return std::nullopt;
            }
            if (!parse_instruction(fn)) return std::nullopt;
        }
        if (pending_label_line_ != 0) {
            diagnostics_.error(pending_label_line_,
                               "label '" + pending_label_ +
                                   "' has no instruction to attach to");
            return std::nullopt;
        }
        return fn;
    }

    bool consume_type_name() {
        if (peek().kind != TokenKind::Ident && peek().kind != TokenKind::Keyword) {
            diagnostics_.error(peek().line, "expected an identifier");
            return false;
        }
        advance();
        return true;
    }

    bool parse_instruction(FunctionIR& fn) {
        const Token& head = peek();

        // Label forms: ".name" or "name:".
        if (head.kind == TokenKind::Punct && head.text == ".") {
            advance();
            return take_pending_label(head.line);
        }
        if ((head.kind == TokenKind::Ident || head.kind == TokenKind::Keyword) &&
            peek(1).kind == TokenKind::Punct && peek(1).text == ":") {
            advance();
            advance();
            return take_pending_label(head.line);
        }

        if (head.kind != TokenKind::Ident) {
            diagnostics_.error(head.line,
                               "unexpected token '" + head.text + "'");
            return false;
        }

        Opcode opcode;
        std::string word = advance().text;
        unsigned line = head.line;
        if (!opcode_from_mnemonic(word, opcode)) {
            diagnostics_.error(line, "unknown mnemonic '" + word + "'");
            return false;
        }

        Instruction insn;
        insn.opcode = opcode;
        insn.line = line;
        apply_pending_label(insn);

        switch (opcode) {
        case Opcode::Push64: {
            if (peek().kind != TokenKind::Number) {
                diagnostics_.error(line, "push64 needs a number");
                return false;
            }
            insn.immediate = advance().number;
            break;
        }
        case Opcode::Jump:
        case Opcode::JumpIf: {
            if (!accept_punct(".")) {
                diagnostics_.error(line, "jumps need '.label'");
                return false;
            }
            insn.label_ref = advance().text;
            break;
        }
        case Opcode::Call: {
            if (peek().kind != TokenKind::Number) {
                diagnostics_.error(line, "call needs a function index");
                return false;
            }
            insn.immediate = advance().number;
            break;
        }
        case Opcode::Host: {
            const Token& target = advance();
            uint16_t host_id = 0;
            if (target.kind == TokenKind::Number &&
                target.number <= UINT16_MAX) {
                host_id = static_cast<uint16_t>(target.number);
            } else if (!host_from_name(target.text, host_id)) {
                diagnostics_.error(line,
                                   "unknown host '" + target.text + "'");
                return false;
            }
            insn.immediate = host_id;
            break;
        }
        default:
            break;
        }

        fn.body.push_back(std::move(insn));
        return true;
    }

    bool take_pending_label(unsigned line) {
        if (pending_label_line_ != 0) {
            diagnostics_.error(line, "label '" + pending_label_ +
                                         "' has no instruction to attach to");
            return false;
        }
        pending_label_ = advance().text;
        pending_label_line_ = line;
        return true;
    }

    void apply_pending_label(Instruction& insn) {
        if (pending_label_line_ != 0) {
            insn.label = pending_label_;
            pending_label_.clear();
            pending_label_line_ = 0;
        }
    }

    std::vector<Token> tokens_;
    Diagnostics& diagnostics_;
    size_t position_ = 0;
    bool failed_ = false;
    std::string pending_label_;
    unsigned pending_label_line_ = 0;
};

}  // namespace

std::optional<CompileResult> assemble_regol(const std::string& source,
                                            Diagnostics& diagnostics) {
    Lexer lexer(source);
    auto tokens = lexer.tokenize(diagnostics);
    RegolParser parser(std::move(tokens), diagnostics);
    auto module = parser.parse();
    if (!module) return std::nullopt;

    auto bytes = encode_module(*module, diagnostics);
    if (!bytes) return std::nullopt;

    CompileResult result;
    result.container = std::move(*bytes);
    result.regol_text = regol_text(*module);
    return result;
}

}  // namespace trocto
