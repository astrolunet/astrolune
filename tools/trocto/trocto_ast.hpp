// Trocto v0.3 abstract syntax.
//
// v0.3 additions over v0.2:
//   - enum declarations with named variants
//   - struct declarations with typed fields and member access
//   - event declarations with typed fields
//   - only_owner access control modifier
//   - struct literal construction: MyStruct { field: value, ... }
//   - struct member access: instance.field
//   - bytes type for raw binary data (stored as u64 offset/length pair)

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
    // v0.3 additions
    EnumVariant,    // EnumName.VariantName -> u64 constant
    StructNew,      // MyStruct { field: expr, ... } -> offset in linear memory
    MemberAccess,   // expr.field_name -> u64 from struct at offset
};

// Value types. Addresses are 32-byte values materialized in linear memory;
// strings are 32-byte pointers (offset + length packed into 8 bytes each).
// structs are u64 offsets into linear memory where fields are packed.
enum class ValueType : uint8_t { U64, Address, String };

struct Expr {
    ExprKind kind;
    unsigned line = 0;
    uint64_t literal = 0;             // U64Literal, EnumVariant index
    std::string string_value;         // StringLiteral raw bytes
    std::string name;                 // Local / StateField / MapRead / calls / EnumVariant enum name
    std::string op;                   // Unary / Binary operator text
    ExprPtr lhs;                      // unary operand / binary left / MemberAccess base
    std::vector<ExprPtr> args;        // binary right (args[0]) / call args;
                                      // MapRead uses args[0] as the key
                                      // StructNew uses args as field values
    std::string field_name;           // MemberAccess field / EnumVariant variant name
    std::vector<std::string> field_names; // StructNew field names (parallel to args)
};

enum class StmtKind {
    Let,           // let name = expr;
    AssignLocal,   // name (=|+=|...) expr;
    AssignField,   // self.name (=|+=|...) expr;
    AssignMap,     // name[key] (=|+=|...) expr;
    AssignMember,  // name.field (=|+=|...) expr;  or  name[key].field (=|+=|...) expr;
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
    ExprPtr map_key;               // AssignMap / AssignMember key expression
    uint64_t code = 0;             // Require revert code
    std::vector<ExprPtr> emit_args;
    std::vector<StmtPtr> body;     // If/While then-branch
    std::vector<StmtPtr> else_body;
    std::string member_name;       // AssignMember field name
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
    bool is_only_owner = false;    // only_owner modifier
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

// v0.3: Enum declaration with named variants.
// enum RecordType { LUNE_ADDRESS: 1, CONTENT: 2, SERVICE: 3, ... }
struct EnumDecl {
    std::string name;
    struct Variant {
        std::string name;
        uint64_t value = 0;
        unsigned line = 0;
    };
    std::vector<Variant> variants;
    unsigned line = 0;
};

// v0.3: Struct declaration with typed fields.
// struct DomainRecord { owner: address, expiry: u64, ... }
// Struct fields are stored in linear memory as packed u64 slots.
// Each struct instance occupies sizeof(fields) bytes starting at a base offset.
struct StructDecl {
    std::string name;
    struct Field {
        std::string name;
        ValueType type = ValueType::U64;
        unsigned line = 0;
    };
    std::vector<Field> fields;
    unsigned line = 0;
};

// v0.3: Event declaration with typed fields.
// event DomainRegistered { name: string, owner: address, expiry: u64 }
struct EventDecl {
    std::string name;
    struct Field {
        std::string name;
        ValueType type = ValueType::U64;
        unsigned line = 0;
    };
    std::vector<Field> fields;
    unsigned line = 0;
};

struct ContractDecl {
    std::string name;
    std::vector<ImportDecl> imports;
    std::vector<StateFieldDecl> state;   // scalars and maps
    std::vector<FunctionDecl> functions;
    // v0.3 additions
    std::vector<EnumDecl> enums;
    std::vector<StructDecl> structs;
    std::vector<EventDecl> events;
    // The constructor, if present. Compiled as the default entrypoint
    // (function 0). A contract may have at most one init block.
    std::optional<FunctionDecl> constructor;
};

// Parses one contract block.
std::optional<ContractDecl> parse_contract(const std::string& source,
                                           Diagnostics& diagnostics);

}  // namespace trocto

#endif  // TROCTO_AST_HPP
