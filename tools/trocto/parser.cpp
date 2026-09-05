// Recursive-descent parser for the Trocto v0.3 subset.
//
// v0.3 additions over v0.2:
//   - enum EnumName { Variant: value, ... }
//   - struct StructName { field: type, ... }
//   - event EventName { field: type, ... }
//   - only_owner modifier on pub fn
//   - Struct literal: MyStruct { field: expr, ... }
//   - Member access: expr.field (for struct instances)
//   - AssignMember: instance.field = expr; or instance[key].field = expr;

#include "lexer.hpp"
#include "trocto_ast.hpp"

namespace trocto {
namespace {

class Parser {
public:
    Parser(std::vector<Token> tokens, Diagnostics& diagnostics)
        : tokens_(std::move(tokens)), diagnostics_(diagnostics) {}

    std::optional<ContractDecl> parse_contract() {
        ContractDecl contract;

        // File-level imports: allow `import "path";` before the contract.
        while (!failed_ && peek_is("import")) {
            advance();  // import
            parse_import(contract);
        }

        expect_keyword("contract");
        contract.name = consume_ident("contract name");
        if (failed_) return std::nullopt;
        expect_punct("{");

        while (!failed_ && !accept_punct("}")) {
            if (at_end()) return fail("unexpected end of file in contract");
            if (accept_keyword("import")) {
                parse_import(contract);
                continue;
            }
            if (accept_keyword("state")) {
                parse_state(contract);
                continue;
            }
            // v0.3: enum declarations
            if (accept_keyword("enum")) {
                parse_enum(contract);
                continue;
            }
            // v0.3: struct declarations
            if (accept_keyword("struct")) {
                parse_struct(contract);
                continue;
            }
            // v0.3: event declarations
            if (accept_keyword("event")) {
                parse_event(contract);
                continue;
            }
            if (accept_keyword("init")) {
                if (contract.constructor.has_value()) {
                    return fail("contract already has a constructor");
                }
                FunctionDecl fn;
                fn.is_constructor = true;
                fn.line = peek().line;
                parse_function_body(fn);
                if (!failed_) contract.constructor = std::move(fn);
                continue;
            }
            if (peek_is("pub") || peek_is("fn") ||
                peek_is("only_owner")) {
                FunctionDecl fn;
                parse_function(fn);
                if (!failed_) contract.functions.push_back(std::move(fn));
                continue;
            }
            return fail(
                "expected 'import', 'state', 'enum', 'struct', 'event', "
                "'init', 'pub fn', 'fn', or 'only_owner' "
                "inside contract");
        }
        if (failed_) return std::nullopt;
        return contract;
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
    bool at_end() const { return peek().kind == TokenKind::End; }
    bool failed() const { return failed_; }

    bool accept_punct(const char* text) {
        if (peek().kind == TokenKind::Punct && peek().text == text) {
            advance();
            return true;
        }
        return false;
    }
    void expect_punct(const char* text) {
        if (!accept_punct(text)) {
            fail(std::string("expected '") + text + "', found '" +
                 peek().text + "'");
        }
    }
    bool peek_is(const char* word) {
        return (peek().kind == TokenKind::Keyword ||
                peek().kind == TokenKind::Ident) &&
               peek().text == word;
    }
    bool accept_keyword(const char* word) {
        if (peek_is(word)) {
            advance();
            return true;
        }
        return false;
    }
    void expect_keyword(const char* word) {
        if (!accept_keyword(word)) {
            fail(std::string("expected '") + word + "'");
        }
    }

    std::string consume_ident(const char* what) {
        if (peek().kind != TokenKind::Ident &&
            !(peek().kind == TokenKind::Keyword && !peek().text.empty())) {
            fail(std::string("expected ") + what);
            return "";
        }
        // Keywords are usable as identifiers only where unambiguous; v0.2
        // simply forbids it to keep diagnostics sharp.
        if (peek().kind == TokenKind::Keyword) {
            fail(std::string(what) + " cannot be a keyword ('" +
                 peek().text + "')");
            return "";
        }
        return advance().text;
    }

    std::optional<ContractDecl> fail(std::string message) {
        diagnostics_.error(peek().line, std::move(message));
        failed_ = true;
        return std::nullopt;
    }

    // --- declarations ------------------------------------------------------

    void parse_import(ContractDecl& contract) {
        ImportDecl imp;
        imp.line = peek().line;
        if (peek().kind != TokenKind::String) {
            fail("import path must be a string literal");
            return;
        }
        imp.path = advance().text;
        expect_punct(";");
        if (!failed_) contract.imports.push_back(std::move(imp));
    }

    void parse_state(ContractDecl& contract) {
        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            StateFieldDecl field;
            field.line = peek().line;
            field.name = consume_ident("state field name");
            if (failed_) return;
            expect_punct(":");
            if (accept_keyword("u64")) {
                contract.state.push_back(std::move(field));
            } else if (peek_is("map")) {
                advance();  // map
                expect_punct("<");
                // Parse map key type
                if (accept_keyword("address")) {
                    field.map_key_type = ValueType::Address;
                } else if (accept_keyword("u64")) {
                    field.map_key_type = ValueType::U64;
                } else {
                    fail("map key types are 'address' or 'u64'");
                    return;
                }
                expect_punct(",");
                // Parse map value type
                if (accept_keyword("u64")) {
                    field.map_value_type = ValueType::U64;
                } else if (accept_keyword("address")) {
                    field.map_value_type = ValueType::Address;
                } else {
                    fail("map value types are 'u64' or 'address'");
                    return;
                }
                expect_punct(">");
                field.is_map = true;
                contract.state.push_back(std::move(field));
            } else {
                fail("state fields are u64 or map<K,V>");
                return;
            }
            expect_punct(",");
            if (accept_punct(";")) continue;  // tolerate both separators
        }
    }

    // v0.3: Parse enum declaration
    // enum RecordType { LUNE_ADDRESS: 1, CONTENT: 2, SERVICE: 3 }
    void parse_enum(ContractDecl& contract) {
        EnumDecl en;
        en.line = peek().line - 1;  // 'enum' keyword was consumed
        en.name = consume_ident("enum name");
        if (failed_) return;
        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            EnumDecl::Variant var;
            var.line = peek().line;
            var.name = consume_ident("enum variant name");
            if (failed_) return;
            expect_punct(":");
            if (peek().kind != TokenKind::Number) {
                fail("enum variant value must be a u64 literal");
                return;
            }
            var.value = advance().number;
            variants_.push_back(var.name);  // track for name resolution
            en.variants.push_back(std::move(var));
            if (!accept_punct(",")) {
                expect_punct("}");
                break;
            }
        }
        if (!failed_) contract.enums.push_back(std::move(en));
    }

    // v0.3: Parse struct declaration
    // struct DomainRecord { owner: address, expiry: u64, flags: u64 }
    void parse_struct(ContractDecl& contract) {
        StructDecl st;
        st.line = peek().line - 1;  // 'struct' keyword was consumed
        st.name = consume_ident("struct name");
        if (failed_) return;
        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            StructDecl::Field field;
            field.line = peek().line;
            field.name = consume_ident("struct field name");
            if (failed_) return;
            expect_punct(":");
            if (!parse_type(field.type)) return;
            st.fields.push_back(std::move(field));
            if (!accept_punct(",")) {
                expect_punct("}");
                break;
            }
        }
        if (!failed_) {
            struct_size_[st.name] = st.fields.size();  // track for lowering
            contract.structs.push_back(std::move(st));
        }
    }

    // v0.3: Parse event declaration
    // event DomainRegistered { name: string, owner: address, expiry: u64 }
    void parse_event(ContractDecl& contract) {
        EventDecl ev;
        ev.line = peek().line - 1;  // 'event' keyword was consumed
        ev.name = consume_ident("event name");
        if (failed_) return;
        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            EventDecl::Field field;
            field.line = peek().line;
            field.name = consume_ident("event field name");
            if (failed_) return;
            expect_punct(":");
            if (!parse_type(field.type)) return;
            ev.fields.push_back(std::move(field));
            if (!accept_punct(",")) {
                expect_punct("}");
                break;
            }
        }
        if (!failed_) contract.events.push_back(std::move(ev));
    }

    bool parse_type(ValueType& out) {
        if (accept_keyword("u64")) {
            out = ValueType::U64;
            return true;
        }
        if (accept_keyword("address")) {
            out = ValueType::Address;
            return true;
        }
        if (accept_keyword("string")) {
            out = ValueType::String;
            return true;
        }
        if (accept_keyword("bytes")) {
            out = ValueType::U64;  // bytes stored as u64 offset/length
            return true;
        }
        fail("types are u64, address, string, or bytes");
        return false;
    }

    void parse_function(FunctionDecl& fn) {
        fn.line = peek().line;
        // v0.3: only_owner modifier
        if (accept_keyword("only_owner")) {
            fn.is_only_owner = true;
        }
        fn.public_abi = accept_keyword("pub");
        expect_keyword("fn");
        fn.name = consume_ident("function name");
        if (failed_) return;
        parse_function_body(fn);
    }

    void parse_function_body(FunctionDecl& fn) {
        expect_punct("(");
        while (!failed_ && !accept_punct(")")) {
            ParamDecl param;
            param.line = peek().line;
            param.name = consume_ident("parameter name");
            if (failed_) return;
            expect_punct(":");
            if (!parse_type(param.type)) return;
            fn.params.push_back(std::move(param));
            if (!accept_punct(",")) {
                expect_punct(")");
                break;
            }
        }

        if (accept_punct("->")) {
            if (!accept_keyword("u64")) {
                fail("result types are u64 or none");
                return;
            }
            fn.has_result = true;
        }

        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            if (at_end()) {
                fail("unexpected end of file in function body");
                return;
            }
            auto stmt = parse_statement();
            if (!stmt) return;
            fn.body.push_back(std::move(stmt));
        }
    }

    // --- statements ---------------------------------------------------------

    StmtPtr parse_statement() {
        unsigned line = peek().line;
        if (accept_keyword("let")) {
            auto stmt = make(StmtKind::Let, line);
            stmt->name = consume_ident("variable name");
            expect_punct("=");
            stmt->expr = parse_expr();
            expect_punct(";");
            return finish(std::move(stmt));
        }
        if (accept_keyword("return")) {
            auto stmt = make(StmtKind::Return, line);
            bool has_value =
                !(peek().kind == TokenKind::Punct && peek().text == ";");
            if (has_value) stmt->expr = parse_expr();
            expect_punct(";");
            return finish(std::move(stmt));
        }
        if (accept_keyword("if")) {
            auto stmt = make(StmtKind::If, line);
            expect_punct("(");
            stmt->expr = parse_expr();
            expect_punct(")");
            parse_block(stmt->body);
            if (accept_keyword("else")) parse_block(stmt->else_body);
            return finish(std::move(stmt));
        }
        if (accept_keyword("while")) {
            auto stmt = make(StmtKind::While, line);
            expect_punct("(");
            stmt->expr = parse_expr();
            expect_punct(")");
            parse_block(stmt->body);
            return finish(std::move(stmt));
        }
        if (accept_keyword("require")) {
            auto stmt = make(StmtKind::Require, line);
            expect_punct("(");
            stmt->expr = parse_expr();
            expect_punct(",");
            if (peek().kind != TokenKind::Number) {
                fail("require's second argument is a u64 error code");
                return nullptr;
            }
            stmt->code = advance().number;
            expect_punct(")");
            expect_punct(";");
            return finish(std::move(stmt));
        }
        if (accept_keyword("assert")) {
            auto stmt = make(StmtKind::Assert, line);
            expect_punct("(");
            stmt->expr = parse_expr();
            expect_punct(")");
            expect_punct(";");
            return finish(std::move(stmt));
        }
        if (accept_keyword("emit")) {
            auto stmt = make(StmtKind::Emit, line);
            stmt->name = consume_ident("event name");
            expect_punct("(");
            while (!accept_punct(")")) {
                stmt->emit_args.push_back(parse_expr());
                if (failed_) return nullptr;
                if (!accept_punct(",")) {
                    expect_punct(")");
                    break;
                }
            }
            expect_punct(";");
            return finish(std::move(stmt));
        }

        if (accept_keyword("pay")) {
            auto stmt = make(StmtKind::Pay, line);
            expect_punct("(");
            stmt->to = parse_expr();    // recipient (address expression)
            expect_punct(",");
            stmt->expr = parse_expr();  // amount
            expect_punct(")");
            expect_punct(";");
            return finish(std::move(stmt));
        }

        // Assignment targets: `name = …`, `self.name = …`, `name[key] = …`,
        // and v0.3: `name.field = …`, `name[key].field = …`.
        // Distinguished by fixed token offsets so expression statements stay
        // unambiguous.
        if (peek_is("self") && peek(1).kind == TokenKind::Punct &&
            peek(1).text == "." && peek(2).kind == TokenKind::Ident &&
            is_assign_start(peek(3))) {
            auto stmt = make(StmtKind::AssignField, line);
            advance();  // self
            advance();  // .
            stmt->name = advance().text;
            parse_assign_rest(*stmt);
            return finish(std::move(stmt));
        }
        // v0.3: name[key].field = expr;
        if (peek().kind == TokenKind::Ident && peek(1).kind == TokenKind::Punct &&
            peek(1).text == "[" && peek(3).kind == TokenKind::Punct &&
            peek(3).text == "]" && peek(4).kind == TokenKind::Punct &&
            peek(4).text == "." && peek(5).kind == TokenKind::Ident &&
            is_assign_start(peek(6))) {
            auto stmt = make(StmtKind::AssignMember, line);
            stmt->name = advance().text;       // map name
            advance();  // [
            stmt->map_key = parse_expr();
            expect_punct("]");
            advance();  // .
            stmt->member_name = advance().text;
            parse_assign_rest(*stmt);
            return finish(std::move(stmt));
        }
        // v0.3: name.field = expr;
        if (peek().kind == TokenKind::Ident && peek(1).kind == TokenKind::Punct &&
            peek(1).text == "." && peek(2).kind == TokenKind::Ident &&
            is_assign_start(peek(3))) {
            auto stmt = make(StmtKind::AssignMember, line);
            stmt->name = advance().text;       // variable name
            advance();  // .
            stmt->member_name = advance().text;
            parse_assign_rest(*stmt);
            return finish(std::move(stmt));
        }
        if (peek().kind == TokenKind::Ident && is_assign_start(peek(1))) {
            auto stmt = make(StmtKind::AssignLocal, line);
            stmt->name = advance().text;
            parse_assign_rest(*stmt);
            return finish(std::move(stmt));
        }
        // Map index assignment: `name[key] (=|+=|…) expr;`
        if (peek().kind == TokenKind::Ident && peek(1).kind == TokenKind::Punct &&
            peek(1).text == "[") {
            auto stmt = make(StmtKind::AssignMap, line);
            stmt->name = advance().text;
            advance();  // [
            stmt->map_key = parse_expr();
            expect_punct("]");
            if (failed_) return nullptr;
            if (!is_assign_start(peek())) {
                fail("expected assignment after map index");
                return nullptr;
            }
            parse_assign_rest(*stmt);
            return finish(std::move(stmt));
        }

        // Expression statement (internal calls).
        if (peek().kind == TokenKind::Ident) {
            auto stmt = make(StmtKind::ExprState, line);
            stmt->expr = parse_expr();
            expect_punct(";");
            return finish(std::move(stmt));
        }
        diagnostics_.error(peek().line, "unsupported statement");
        failed_ = true;
        return nullptr;
    }

    bool is_assign_start(const Token& t) {
        if (t.kind != TokenKind::Punct) return false;
        static const char* kOps[] = {"=", "+=", "-=", "*=", "/=", "%="};
        for (const char* op : kOps) {
            if (t.text == op) return true;
        }
        return false;
    }

    void parse_assign_rest(Stmt& stmt) {
        stmt.op = advance().text;  // one of = += -= *= /= %=
        stmt.expr = parse_expr();
        expect_punct(";");
    }

    void parse_block(std::vector<StmtPtr>& out) {
        expect_punct("{");
        while (!failed_ && !accept_punct("}")) {
            if (at_end()) {
                fail("unexpected end of file in block");
                return;
            }
            auto stmt = parse_statement();
            if (!stmt) return;
            out.push_back(std::move(stmt));
        }
    }

    // --- expressions ---------------------------------------------------------

    ExprPtr parse_expr() { return parse_or(); }

    ExprPtr parse_or() {
        ExprPtr lhs = parse_and();
        while (!failed_ && peek().kind == TokenKind::Punct &&
               peek().text == "||") {
            unsigned line = advance().line;
            ExprPtr rhs = parse_and();
            lhs = binary("||", std::move(lhs), std::move(rhs), line);
        }
        return lhs;
    }

    ExprPtr parse_and() {
        ExprPtr lhs = parse_bit_or();
        while (!failed_ && peek().kind == TokenKind::Punct &&
               peek().text == "&&") {
            unsigned line = advance().line;
            ExprPtr rhs = parse_bit_or();
            lhs = binary("&&", std::move(lhs), std::move(rhs), line);
        }
        return lhs;
    }

    ExprPtr parse_bit_or() { return parse_chain({"|"}, [this] { return parse_bit_xor(); }); }
    ExprPtr parse_bit_xor() { return parse_chain({"^"}, [this] { return parse_bit_and(); }); }
    ExprPtr parse_bit_and() { return parse_chain({"&"}, [this] { return parse_equality(); }); }
    ExprPtr parse_equality() {
        return parse_chain({"==", "!="}, [this] { return parse_comparison(); });
    }
    ExprPtr parse_comparison() {
        return parse_chain({"<", "<=", ">", ">="}, [this] { return parse_shift(); });
    }
    ExprPtr parse_shift() {
        return parse_chain({"<<", ">>"}, [this] { return parse_additive(); });
    }
    ExprPtr parse_additive() {
        return parse_chain({"+", "-"}, [this] { return parse_multiplicative(); });
    }
    ExprPtr parse_multiplicative() {
        return parse_chain({"*", "/", "%"},
                           [this] { return parse_unary(); });
    }

    template <typename Next>
    ExprPtr parse_chain(std::initializer_list<const char*> ops, Next next) {
        ExprPtr lhs = next();
        for (;;) {
            bool matched = false;
            for (const char* op : ops) {
                if (peek().kind == TokenKind::Punct && peek().text == op) {
                    unsigned line = advance().line;
                    ExprPtr rhs = next();
                    lhs = binary(op, std::move(lhs), std::move(rhs), line);
                    matched = true;
                    break;
                }
            }
            if (!matched || failed_) return lhs;
        }
    }

    ExprPtr parse_unary() {
        unsigned line = peek().line;
        if (peek().kind == TokenKind::Punct && peek().text == "!") {
            advance();
            auto expr = make_expr(ExprKind::Unary, line);
            expr->op = "!";
            expr->lhs = parse_unary();
            return expr;
        }
        if (peek().kind == TokenKind::Punct && peek().text == "-") {
            // Only literal negation fits u64 semantics; -x on a variable is
            // rejected because unsigned wrap-around is never implicit here.
            advance();
            if (peek().kind == TokenKind::Number) {
                uint64_t value = advance().number;
                if (value == 0) {
                    return fail_expr(line, "cannot negate zero");
                }
                auto expr = make_expr(ExprKind::U64Literal, line);
                expr->literal = ~value + 1;  // two's complement magnitude
                return expr;
            }
            return fail_expr(line,
                             "'-' needs a literal operand in v0.2");
        }
        if (peek().kind == TokenKind::Number) {
            auto expr = make_expr(ExprKind::U64Literal, line);
            expr->literal = advance().number;
            return expr;
        }
        if (peek().kind == TokenKind::String) {
            auto expr = make_expr(ExprKind::StringLiteral, line);
            expr->string_value = advance().text;
            return expr;
        }
        if (accept_punct("(")) {
            ExprPtr inner = parse_expr();
            expect_punct(")");
            return inner;
        }
        if (peek_is("self")) {
            advance();
            expect_punct(".");
            auto expr = make_expr(ExprKind::StateField, line);
            expr->name = consume_ident("field name");
            return expr;
        }

        // Calls: internal fns and builtins.
        if ((peek().kind == TokenKind::Ident || peek().kind == TokenKind::Keyword)) {
            std::string name = peek().text;
            // Map read: `balances[key]`.
            if (peek(1).kind == TokenKind::Punct && peek(1).text == "[") {
                advance();  // name
                advance();  // [
                auto expr = make_expr(ExprKind::MapRead, line);
                expr->name = name;
                expr->args.push_back(parse_expr());
                if (failed_) return nullptr;
                expect_punct("]");
                // v0.3: member access on map read: map[key].field
                if (peek().kind == TokenKind::Punct && peek().text == ".") {
                    advance();  // .
                    auto member = make_expr(ExprKind::MemberAccess, line);
                    member->lhs = std::move(expr);
                    member->field_name = consume_ident("struct field");
                    return member;
                }
                return expr;
            }
            if (peek(1).kind == TokenKind::Punct && peek(1).text == "(") {
                advance();  // name
                advance();  // (
                auto call = builtin_kind(name);
                if (call) {
                    if (!accept_punct(")")) {
                        fail("builtin '" + name + "' takes no arguments");
                        return nullptr;
                    }
                    return call;
                }
                auto expr = make_expr(ExprKind::CallInternal, line);
                expr->name = name;
                while (!accept_punct(")")) {
                    ExprPtr arg = parse_expr();
                    if (!arg) return nullptr;
                    expr->args.push_back(std::move(arg));
                    if (!accept_punct(",")) {
                        expect_punct(")");
                        break;
                    }
                }
                return expr;
            }
            // v0.3: Enum variant access: EnumName.VariantName
            if (peek(1).kind == TokenKind::Punct && peek(1).text == ".") {
                std::string enum_name = name;
                advance();  // enum name
                advance();  // .
                if (peek().kind == TokenKind::Ident) {
                    std::string variant = advance().text;
                    auto expr = make_expr(ExprKind::EnumVariant, line);
                    expr->name = enum_name;
                    expr->field_name = variant;
                    return expr;
                }
                fail("expected variant name after '.'");
                return nullptr;
            }
            // v0.3: Struct literal construction: MyStruct { field: value, ... }
            if (peek(1).kind == TokenKind::Punct && peek(1).text == "{") {
                std::string struct_name = name;
                advance();  // struct name
                advance();  // {
                auto expr = make_expr(ExprKind::StructNew, line);
                expr->name = struct_name;
                while (!accept_punct("}")) {
                    std::string field = consume_ident("struct field name");
                    if (failed_) return nullptr;
                    expect_punct(":");
                    ExprPtr value = parse_expr();
                    if (!value) return nullptr;
                    expr->field_names.push_back(std::move(field));
                    expr->args.push_back(std::move(value));
                    if (!accept_punct(",")) {
                        expect_punct("}");
                        break;
                    }
                }
                return expr;
            }
        }

        // v0.3: member access on local variable: instance.field
        if (peek().kind == TokenKind::Ident && peek(1).kind == TokenKind::Punct &&
            peek(1).text == ".") {
            std::string var_name = advance().text;
            advance();  // .
            auto base = make_expr(ExprKind::Local, line);
            base->name = var_name;
            auto expr = make_expr(ExprKind::MemberAccess, line);
            expr->lhs = std::move(base);
            expr->field_name = consume_ident("struct field");
            return expr;
        }

        if (peek().kind == TokenKind::Ident) {
            auto expr = make_expr(ExprKind::Local, line);
            expr->name = advance().text;
            return expr;
        }
        return fail_expr(line, "expected expression, found '" + peek().text + "'");
    }

    static ExprPtr builtin_kind(const std::string& name) {
        unsigned line = 0;
        ExprKind kind;
        if (name == "height") kind = ExprKind::CallHeight;
        else if (name == "day") kind = ExprKind::CallDay;
        else if (name == "self_balance") kind = ExprKind::CallSelfBalance;
        else if (name == "caller_balance") kind = ExprKind::CallCallerBalance;
        else if (name == "sender") kind = ExprKind::CallSender;
        else if (name == "self") kind = ExprKind::CallSelf;
        else return nullptr;
        return make_expr(kind, line);
    }

    // --- helpers -------------------------------------------------------------

    static StmtPtr make(StmtKind kind, unsigned line) {
        auto stmt = std::make_unique<Stmt>();
        stmt->kind = kind;
        stmt->line = line;
        return stmt;
    }
    StmtPtr finish(StmtPtr stmt) { return failed_ ? nullptr : std::move(stmt); }

    static ExprPtr make_expr(ExprKind kind, unsigned line) {
        auto expr = std::make_unique<Expr>();
        expr->kind = kind;
        expr->line = line;
        return expr;
    }
    static ExprPtr binary(const char* op, ExprPtr lhs, ExprPtr rhs,
                          unsigned line) {
        auto expr = make_expr(ExprKind::Binary, line);
        expr->op = op;
        expr->lhs = std::move(lhs);
        expr->args.push_back(std::move(rhs));
        return expr;
    }
    ExprPtr fail_expr(unsigned line, std::string message) {
        diagnostics_.error(line, std::move(message));
        failed_ = true;
        return nullptr;
    }

    std::vector<Token> tokens_;
    Diagnostics& diagnostics_;
    size_t position_ = 0;
    bool failed_ = false;
    // v0.3 tracking
    std::vector<std::string> variants_;       // all enum variant names
    std::map<std::string, size_t> struct_size_;  // struct name -> field count
};

}  // namespace

std::optional<ContractDecl> parse_contract(const std::string& source,
                                           Diagnostics& diagnostics) {
    Lexer lexer(source);
    auto tokens = lexer.tokenize(diagnostics);
    Parser parser(std::move(tokens), diagnostics);
    auto contract = parser.parse_contract();
    if (!contract) return std::nullopt;
    return contract;
}

}  // namespace trocto
