// Trocto v0.2 abstract syntax.
//
// v0.2 adds: constructors (init), string literals, address comparisons,
// expanded map types (map<u64,u64>, map<address,address>), assert() builtin,
// and a module/import system.

#ifndef TROCTO_AST_HPP
#define TROCTO_AST_HPP

#include "trocto/compiler.hpp"

#include <memory>
#include <string>
#include <vector>

namespace trocto {

struct Expr;
using ExprPtr = std::unique_ptr<Expr>;

struct Stmt;
using StmtPtr = std::unique_ptr<Stmt>;

enum class ExprKind {
    U64Literal,
    StringLiteral,  // "hello" -> 32-byte pointer in linear memory
    Local,          // variable or parameter by name
    StateField,     // self.<name>            (u64 scalar field)
    MapRead,        // <map>[key_expr]        (value read, type depends on map)
    Unary,          // op: '!' or '-'
    Binary,         // + - * / % == != < <= > >= && || & | ^ << >>
    CallInternal,   // plain fn call
    CallHeight,
    CallDay,
    CallSelfBalance,
    CallCallerBalance,
    CallSender,     // address builtin
    CallSelf,       // address builtin
};

// Value types. Addresses are 32-byte values materialized in linear memory;
// strings are 32-byte pointers (offset + length packed into 8 bytes each).
enum class ValueType : uint8_t { U64, Address, String };

struct Expr {
    ExprKind kind;
    unsigned line = 0;
    uint64_t literal = 0;             // U64Literal
    std::string string_value;         // StringLiteral raw bytes
    std::string name;                 // Local / StateField / MapRead / calls
    std::string op;                   // Unary / Binary operator text
    ExprPtr lhs;                      // unary operand / binary left
    std::vector<ExprPtr> args;        // binary right (args[0]) / call args;
                                      // MapRead uses args[0] as the key
};

enum class StmtKind {
    Let,           // let name = expr;
    AssignLocal,   // name (=|+=|...) expr;
    AssignField,   // self.name (=|+=|...) expr;
    AssignMap,     // name[key] (=|+=|...) expr;
    If,            // if cond { } else { }
    While,         // while cond { }
    Return,        // return [expr];
    Require,       // require(cond, code);
    Emit,          // emit Name(expr, ...);
    Pay,           // pay(to_addr, amount);
    Assert,        // assert(cond);
    ExprState,     // expr;  (call statements)
};

struct Stmt {
    StmtKind kind;
    unsigned line = 0;
    std::string name;              // Let/Assign/Emit target
    std::string op;                // assignment compound operator
    ExprPtr expr;                  // rhs / condition / amount / emitted expr
    ExprPtr to;                    // Pay recipient
    ExprPtr map_key;               // AssignMap key expression
    uint64_t code = 0;             // Require revert code
    std::vector<ExprPtr> emit_args;
    std::vector<StmtPtr> body;     // If/While then-branch
    std::vector<StmtPtr> else_body;
};

struct StateFieldDecl {
    std::string name;
    // Map key/value type combinations:
    //   map<address,u64>   (default, v0.1 compatible)
    //   map<u64,u64>       (index-based)
    //   map<address,address> (address->address mapping)
    ValueType map_key_type = ValueType::Address;
    ValueType map_value_type = ValueType::U64;
    bool is_map = false;
    unsigned line = 0;
};

struct ParamDecl {
    std::string name;
    ValueType type = ValueType::U64;
    unsigned line = 0;
};

struct FunctionDecl {
    bool public_abi = false;       // pub fn
    bool is_constructor = false;   // init
    std::string name;
    std::vector<ParamDecl> params;
    bool has_result = false;       // -> u64
    std::vector<StmtPtr> body;
    unsigned line = 0;
};

struct ImportDecl {
    std::string path;              // relative path to imported file
    unsigned line = 0;
};

struct ContractDecl {
    std::string name;
    std::vector<ImportDecl> imports;
    std::vector<StateFieldDecl> state;   // scalars and maps
    std::vector<FunctionDecl> functions;
    // The constructor, if present. Compiled as the default entrypoint
    // (function 0). A contract may have at most one init block.
    std::optional<FunctionDecl> constructor;
};

// Parses one contract block.
std::optional<ContractDecl> parse_contract(const std::string& source,
                                           Diagnostics& diagnostics);

}  // namespace trocto

#endif  // TROCTO_AST_HPP
