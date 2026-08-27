// Trocto lowering. See lower.hpp for the ABI and memory layout contract.
//
// All emission funnels through emit_instruction() so that branch targets are
// attached exactly once: set_label(name) arms a slot, the next emitted
// instruction receives it. A dangling arm at function end is a compiler bug
// and is reported, never silently dropped.

#include "lower.hpp"

#include "astrolune/hash.h"

#include <algorithm>
#include <map>
#include <set>

namespace trocto {
namespace {

constexpr uint32_t kScratchA = 0;       // state key / event topic / preimage
constexpr uint32_t kScratchB = 32;      // event data / second key / revert code
constexpr uint32_t kResultSlot = 64;    // public-function return value
constexpr uint32_t kSenderSlot = 72;    // 32B: sender() materialization
constexpr uint32_t kSelfSlot = 104;     // 32B: self() materialization
constexpr uint32_t kKeySlot = 136;      // 32B: derived map storage key
constexpr uint32_t kFrameBase = 168;    // locals and parameters

class Lowerer {
public:
    Lowerer(const ContractDecl& contract, Diagnostics& diagnostics)
        : contract_(contract), diagnostics_(diagnostics) {
        for (const StateFieldDecl& field : contract.state) {
            if (field.is_map) {
                map_prefix_[field.name] =
                    "map." + contract.name + "." + field.name + ".";
                map_key_types_[field.name] = field.map_key_type;
                map_value_types_[field.name] = field.map_value_type;
            } else {
                scalar_fields_.insert(field.name);
            }
        }
        // Public functions: declared after init (if any).
        // init becomes the default entrypoint (function 0).
        size_t public_count = 0;
        for (const FunctionDecl& fn : contract.functions) {
            if (fn.public_abi) {
                ++public_count;
                public_names_.insert(fn.name);
            } else if (!internal_names_.insert(fn.name).second) {
                duplicate(fn.name);
            }
        }
        // Internal call indices come after the default entrypoint, the
        // constructor (if present) and every public function.
        bool has_init = contract.constructor.has_value();
        uint16_t next = static_cast<uint16_t>(
            1 + (has_init ? 1 : 0) + public_count);
        for (const FunctionDecl& fn : contract.functions) {
            if (fn.public_abi) continue;
            internal_index_[fn.name] = next++;
        }
    }

    std::optional<ModuleIR> run() {
        ModuleIR module;

        // Function 0: the default entrypoint. If the contract has a
        // constructor, it becomes function 0; otherwise it's a bare STOP.
        if (contract_.constructor) {
            auto compiled = compile_function(*contract_.constructor,
                                             /*is_init=*/true);
            if (!compiled) return std::nullopt;
            module.functions.push_back(std::move(*compiled));
        } else {
            FunctionIR entry;
            entry.name = "__default";
            entry.max_stack = 1;
            emit_instruction(entry, plain(Opcode::Stop, 0));
            module.functions.push_back(std::move(entry));
        }

        for (const FunctionDecl& decl : contract_.functions) {
            auto compiled = compile_function(decl, /*is_init=*/false);
            if (!compiled) return std::nullopt;
            module.functions.push_back(std::move(*compiled));
        }
        return module;
    }

private:
    struct Scope {
        struct Var {
            uint32_t offset;
            ValueType type = ValueType::U64;
        };
        std::map<std::string, Var> variables;  // name -> slot
    };

    // --- emission ---------------------------------------------------------------

    static Instruction plain(Opcode opcode, unsigned line) {
        Instruction i;
        i.opcode = opcode;
        i.line = line;
        return i;
    }

    void emit_instruction(FunctionIR& fn, Instruction i) {
        if (!pending_label_.empty()) {
            i.label = pending_label_;
            pending_label_.clear();
            armed_line_ = 0;
        }
        fn.body.push_back(std::move(i));
    }

    void emit(FunctionIR& fn, Opcode opcode, unsigned line) {
        emit_instruction(fn, plain(opcode, line));
    }

    void push(FunctionIR& fn, uint64_t value, unsigned line) {
        Instruction i = plain(Opcode::Push64, line);
        i.immediate = value;
        emit_instruction(fn, std::move(i));
    }

    void push_host(FunctionIR& fn, Host host, unsigned line) {
        Instruction i = plain(Opcode::Host, line);
        i.immediate = static_cast<uint16_t>(host);
        emit_instruction(fn, std::move(i));
    }

    void jump(FunctionIR& fn, const char* target, unsigned line) {
        Instruction j = plain(Opcode::Jump, line);
        j.label_ref = target;
        emit_instruction(fn, std::move(j));
    }

    void jump_if(FunctionIR& fn, const char* target, unsigned line) {
        Instruction j = plain(Opcode::JumpIf, line);
        j.label_ref = target;
        emit_instruction(fn, std::move(j));
    }

    void set_label(const std::string& name, unsigned line) {
        pending_label_ = name;
        armed_line_ = line;
    }

    std::string fresh_label(const char* tag) {
        return std::string(tag) + std::to_string(label_counter_++);
    }

    // Canonicalize any u64 into 0/1 (comparison results are already boolean).
    void normalize_bool(FunctionIR& fn, unsigned line) {
        push(fn, 0, line);
        emit(fn, Opcode::Eq, line);
        push(fn, 0, line);
        emit(fn, Opcode::Eq, line);
    }

    // --- state access ---------------------------------------------------------------

    // key = tagged_hash(contract_data domain, "field.<contract>.<name>"),
    // embedded as four little-endian words.
    void load_state_key(FunctionIR& fn, const std::string& field,
                        unsigned line, uint32_t scratch) {
        for (unsigned word = 0; word < 4; ++word) {
            push(fn, field_key_word(contract_.name, field, word), line);
            push(fn, scratch + word * 8, line);
            emit(fn, Opcode::Store64, line);
        }
    }

    static uint64_t field_key_word(const std::string& contract,
                                   const std::string& field, unsigned word) {
        std::string preimage = "field." + contract + "." + field;
        al_hash256 hash;
        al_hash_tagged(AL_TAG_CONTRACT_DATA, preimage.data(), preimage.size(),
                       &hash);
        uint64_t value = 0;
        for (unsigned b = 0; b < 8; ++b) {
            value |= uint64_t(hash.bytes[word * 8 + b]) << (b * 8);
        }
        return value;
    }

    // Reads a field onto the stack; an absent storage slot reads as zero.
    void read_state_field(FunctionIR& fn, const std::string& field,
                          unsigned line) {
        load_state_key(fn, field, line, kScratchA);
        push(fn, 0, line);                    // zero the buffer first
        push(fn, kScratchB, line);
        emit(fn, Opcode::Store64, line);
        push(fn, kScratchA, line);
        push(fn, 32, line);
        push(fn, kScratchB, line);
        push(fn, 32, line);
        push_host(fn, Host::StorageGet, line);
        emit(fn, Opcode::Drop, line);         // stored length
        push(fn, kScratchB, line);
        emit(fn, Opcode::Load64, line);
    }

    // Stores stack-top value into a field.
    void write_state_field(FunctionIR& fn, const std::string& field,
                           unsigned line) {
        push(fn, kScratchB, line);
        emit(fn, Opcode::Store64, line);
        load_state_key(fn, field, line, kScratchA);
        push(fn, kScratchA, line);
        push(fn, 32, line);
        push(fn, kScratchB, line);
        push(fn, 8, line);
        push_host(fn, Host::StorageSet, line);
    }

    // --- maps -----------------------------------------------------------------------
    //
    // A map entry's storage key is derived on chain:
    //   key = tagged_hash(contract_data, prefix || key_bytes)
    // where prefix is the compile-time constant "map.<Contract>.<map>.".
    // For address keys, key_bytes is 32 bytes. For u64 keys, key_bytes is 8 LE.
    // Preimage lives in scratchA; the derived key lands in the function's
    // dedicated kKeySlot so later value staging cannot clobber it.

    void build_map_key(FunctionIR& fn, const std::string& map,
                       uint32_t address_slot, unsigned line) {
        auto pit = map_prefix_.find(map);
        if (pit == map_prefix_.end()) {
            error(line, "unknown map '" + map + "'");
            return;
        }
        const std::string& prefix = pit->second;
        const uint32_t prefix_len = (uint32_t)prefix.size();
        const uint32_t padded = (prefix_len + 7u) / 8u * 8u;

        /* Prefix words (zero-padded tail word included). */
        for (uint32_t i = 0u; i < padded; i += 8u) {
            uint64_t word = 0u;
            for (uint32_t b = 0u; b < 8u && i + b < prefix.size(); ++b)
                word |= uint64_t(unsigned char(prefix[i + b])) << (b * 8u);
            push(fn, word, line);
            push(fn, kScratchA + i, line);
            emit(fn, Opcode::Store64, line);
        }
        /* Address bytes start exactly at prefix_len so the hashed preimage
         * is prefix || addr32 with no padding gap. */
        for (uint32_t w = 0u; w < 4u; ++w) {
            push(fn, address_slot + w * 8u, line);
            emit(fn, Opcode::Load64, line);
            push(fn, kScratchA + prefix_len + w * 8u, line);
            emit(fn, Opcode::Store64, line);
        }

        push(fn, kScratchA, line);                          /* data     */
        push(fn, (uint64_t)prefix_len + 32u, line);         /* length   */
        push(fn, kKeySlot, line);                           /* out      */
        push(fn, 0u, line);                                 /* tag      */
        push_host(fn, Host::HashTagged, line);
    }

    // Build a map key from a u64 value stored in kScratchB.
    void build_map_key_u64(FunctionIR& fn, const std::string& map,
                           unsigned line) {
        auto pit = map_prefix_.find(map);
        if (pit == map_prefix_.end()) {
            error(line, "unknown map '" + map + "'");
            return;
        }
        const std::string& prefix = pit->second;
        const uint32_t prefix_len = (uint32_t)prefix.size();
        const uint32_t padded = (prefix_len + 7u) / 8u * 8u;

        for (uint32_t i = 0u; i < padded; i += 8u) {
            uint64_t word = 0u;
            for (uint32_t b = 0u; b < 8u && i + b < prefix.size(); ++b)
                word |= uint64_t(unsigned char(prefix[i + b])) << (b * 8u);
            push(fn, word, line);
            push(fn, kScratchA + i, line);
            emit(fn, Opcode::Store64, line);
        }
        // u64 key: 8 bytes appended after prefix
        push(fn, kScratchB, line);
        emit(fn, Opcode::Load64, line);
        push(fn, kScratchA + prefix_len, line);
        emit(fn, Opcode::Store64, line);

        push(fn, kScratchA, line);                          /* data     */
        push(fn, (uint64_t)prefix_len + 8u, line);          /* length   */
        push(fn, kKeySlot, line);                           /* out      */
        push(fn, 0u, line);                                 /* tag      */
        push_host(fn, Host::HashTagged, line);
    }

    void compile_map_read(FunctionIR& fn, const Expr& expr,
                          const Scope& scope) {
        if (!map_prefix_.count(expr.name)) {
            error(expr.line, "unknown map '" + expr.name + "'");
            return;
        }
        auto key_it = map_key_types_.find(expr.name);
        auto val_it = map_value_types_.find(expr.name);
        ValueType key_type = key_it != map_key_types_.end()
                                 ? key_it->second : ValueType::Address;
        ValueType val_type = val_it != map_value_types_.end()
                                 ? val_it->second : ValueType::U64;

        if (key_type == ValueType::Address) {
            if (!is_address_expr(*expr.args[0], scope)) {
                error(expr.line, "map keys must be address-typed");
                return;
            }
            uint32_t addr = compile_address(fn, *expr.args[0], scope);
            if (failed_) return;
            build_map_key(fn, expr.name, addr, expr.line);
        } else {
            // u64 key: materialize as 8 bytes in scratch, then hash
            compile_u64(fn, *expr.args[0], scope);
            if (failed_) return;
            push(fn, kScratchB, expr.line);
            emit(fn, Opcode::Store64, expr.line);
            build_map_key_u64(fn, expr.name, expr.line);
        }

        /* Absent entries read as zero. */
        push(fn, 0u, expr.line);
        push(fn, kScratchB, expr.line);
        emit(fn, Opcode::Store64, expr.line);
        push(fn, kKeySlot, expr.line);
        push(fn, 32u, expr.line);
        push(fn, kScratchB, expr.line);
        push(fn, 32u, expr.line);
        push_host(fn, Host::StorageGet, expr.line);
        emit(fn, Opcode::Drop, expr.line);

        if (val_type == ValueType::Address) {
            // Return the slot offset for address values (32 bytes at kScratchB)
            // Address map reads return the materialized 32-byte slot
            error(expr.line, "address-valued map reads not yet supported");
            return;
        }
        push(fn, kScratchB, expr.line);
        emit(fn, Opcode::Load64, expr.line);
    }

    /* Stack-top u64 value goes into the map whose key is ALREADY derived
     * in kKeySlot. The value is staged into kScratchB here, so callers must
     * run build_map_key BEFORE staging — key derivation clobbers the
     * scratch region where the staged value would otherwise sit. */
    void write_map_entry_at_key(FunctionIR& fn, unsigned line) {
        push(fn, kScratchB, line);
        emit(fn, Opcode::Store64, line);
        push(fn, kKeySlot, line);
        push(fn, 32u, line);
        push(fn, kScratchB, line);
        push(fn, 8u, line);
        push_host(fn, Host::StorageSet, line);
    }

    // --- expressions -----------------------------------------------------------------
    //
    // Two value domains:
    //   u64     - pushed on the operand stack (compile_u64).
    //   address - materialized as 32 bytes at a static slot; the slot offset
    //             is the "value" (compile_address). Copying a 32-byte address
    //             between slots is four LOAD64/STORE64 pairs, which needs no
    //             consensus-side memcpy opcode.

    bool is_address_expr(const Expr& expr, const Scope& scope) const {
        switch (expr.kind) {
        case ExprKind::Local: {
            auto it = scope.variables.find(expr.name);
            return it != scope.variables.end() &&
                   it->second.type == ValueType::Address;
        }
        case ExprKind::CallSender:
        case ExprKind::CallSelf:
            return true;
        default:
            return false;
        }
    }

    bool is_string_expr(const Expr& expr, const Scope& scope) const {
        switch (expr.kind) {
        case ExprKind::StringLiteral:
            return true;
        case ExprKind::Local: {
            auto it = scope.variables.find(expr.name);
            return it != scope.variables.end() &&
                   it->second.type == ValueType::String;
        }
        default:
            return false;
        }
    }

    void compile_expr(FunctionIR& fn, const Expr& expr, const Scope& scope) {
        if (is_address_expr(expr, scope)) {
            /* Address-typed expression in u64 context: only comparisons
             * against another address make sense, and v0.2 does not provide
             * them. Reject instead of silently truncating to an offset. */
            error(expr.line,
                  "address value used where u64 is required");
            return;
        }
        if (is_string_expr(expr, scope)) {
            /* String-typed expression in u64 context: not valid. */
            error(expr.line,
                  "string value used where u64 is required");
            return;
        }
        compile_u64(fn, expr, scope);
    }

    uint32_t compile_address(FunctionIR& fn, const Expr& expr,
                             const Scope& scope) {
        switch (expr.kind) {
        case ExprKind::Local: {
            auto it = scope.variables.find(expr.name);
            if (it == scope.variables.end() ||
                it->second.type != ValueType::Address) {
                error(expr.line,
                      "'" + expr.name + "' is not an address variable");
                return 0u;
            }
            return it->second.offset;
        }
        case ExprKind::CallSender:
            push(fn, kSenderSlot, expr.line);
            push_host(fn, Host::Sender, expr.line);
            return kSenderSlot;
        case ExprKind::CallSelf:
            push(fn, kSelfSlot, expr.line);
            push_host(fn, Host::CurrentAddress, expr.line);
            return kSelfSlot;
        default:
            error(expr.line,
                  "expression does not produce an address");
            return 0u;
        }
    }

    void compile_u64(FunctionIR& fn, const Expr& expr, const Scope& scope) {
        switch (expr.kind) {
        case ExprKind::U64Literal:
            push(fn, expr.literal, expr.line);
            return;

        case ExprKind::StringLiteral: {
            // String literals are placed in linear memory at compile time.
            // The expression evaluates to the memory offset (a u64 pointer).
            uint32_t offset = string_literal_slot_;
            string_literal_slot_ += static_cast<uint32_t>(expr.string_value.size() + 1);
            // Store the string bytes into scratchA area for later staging.
            // In v0.2, string literals are materialized at function entry
            // and referenced by offset. For now, we push the offset as a
            // constant and rely on the host to resolve it.
            push(fn, offset, expr.line);
            return;
        }

        case ExprKind::Local: {
            auto it = scope.variables.find(expr.name);
            if (it == scope.variables.end()) {
                error(expr.line, "unknown variable '" + expr.name + "'");
                return;
            }
            if (it->second.type == ValueType::Address) {
                error(expr.line,
                      "address variable used as u64 (compare or hash it "
                      "through a map key instead)");
                return;
            }
            if (it->second.type == ValueType::String) {
                error(expr.line,
                      "string variable used as u64 (use it as a map key "
                      "or pass to a host function)");
                return;
            }
            push(fn, it->second.offset, expr.line);
            emit(fn, Opcode::Load64, expr.line);
            return;
        }

        case ExprKind::StateField:
            if (!scalar_fields_.count(expr.name)) {
                error(expr.line,
                      "unknown scalar state field '" + expr.name + "'");
                return;
            }
            read_state_field(fn, expr.name, expr.line);
            return;

        case ExprKind::MapRead:
            compile_map_read(fn, expr, scope);
            return;

        case ExprKind::Unary:
            compile_expr(fn, *expr.lhs, scope);
            if (expr.op == "!") {
                push(fn, 0, expr.line);
                emit(fn, Opcode::Eq, expr.line);
                return;
            }
            error(expr.line, "unsupported unary operator '" + expr.op + "'");
            return;
        case ExprKind::Binary:
            compile_binary(fn, expr, scope);
            return;

        case ExprKind::CallInternal: {
            auto it = internal_index_.find(expr.name);
            if (it == internal_index_.end()) {
                if (public_names_.count(expr.name)) {
                    error(expr.line,
                          "'" + expr.name +
                              "' is public; calls to public functions only "
                              "from outside");
                } else {
                    error(expr.line,
                          "unknown function '" + expr.name + "'");
                }
                return;
            }
            for (const ExprPtr& arg : expr.args) {
                compile_expr(fn, *arg, scope);
                if (failed_) return;
            }
            Instruction call = plain(Opcode::Call, expr.line);
            call.immediate = it->second;
            emit_instruction(fn, std::move(call));
            return;
        }

        case ExprKind::CallHeight:
            push_host(fn, Host::BlockHeight, expr.line);
            return;
        case ExprKind::CallDay:
            push_host(fn, Host::ProtocolDay, expr.line);
            return;
        case ExprKind::CallSelfBalance:
            push(fn, kScratchA, expr.line);
            push_host(fn, Host::CurrentAddress, expr.line);
            push(fn, kScratchA, expr.line);
            push_host(fn, Host::Balance, expr.line);
            return;
        case ExprKind::CallCallerBalance:
            push(fn, kScratchA, expr.line);
            push_host(fn, Host::Sender, expr.line);
            push(fn, kScratchA, expr.line);
            push_host(fn, Host::Balance, expr.line);
            return;
        case ExprKind::CallSender:
        case ExprKind::CallSelf:
            error(expr.line,
                  "address value used where u64 is required");
            return;
        }
        error(expr.line, "cannot lower this expression");
    }

    void compile_binary(FunctionIR& fn, const Expr& expr, const Scope& scope) {
        if (expr.op == "&&" || expr.op == "||") {
            compile_short_circuit(fn, expr, scope);
            return;
        }

        Opcode op;
        bool negate = expr.op == "!=";
        if (!binary_opcode(negate ? "==" : expr.op, op)) {
            error(expr.line, "unsupported operator '" + expr.op + "'");
            return;
        }
        compile_expr(fn, *expr.lhs, scope);
        if (failed_) return;
        compile_expr(fn, *expr.args[0], scope);
        if (failed_) return;
        emit(fn, op, expr.line);
        if (negate) {
            push(fn, 0, expr.line);
            emit(fn, Opcode::Eq, expr.line);
        }
    }

    //   && : eval lhs; DUP; NOT; JUMPI false; DROP; eval rhs; JUMP end
    //        false: DROP; PUSH 0
    //   || : eval lhs; DUP; JUMPI true; DROP; eval rhs; JUMP end
    //        true:  DROP; PUSH 1
    void compile_short_circuit(FunctionIR& fn, const Expr& expr,
                               const Scope& scope) {
        std::string side = fresh_label(expr.op == "&&" ? "andf" : "ortr");
        std::string end = fresh_label("sc");

        compile_expr(fn, *expr.lhs, scope);
        if (failed_) return;
        normalize_bool(fn, expr.line);
        emit(fn, Opcode::Dup, expr.line);

        if (expr.op == "&&") {
            push(fn, 0, expr.line);
            emit(fn, Opcode::Eq, expr.line);
        }
        jump_if(fn, side.c_str(), expr.line);

        emit(fn, Opcode::Drop, expr.line);
        compile_expr(fn, *expr.args[0], scope);
        if (failed_) return;
        normalize_bool(fn, expr.line);
        jump(fn, end.c_str(), expr.line);

        set_label(side, expr.line);
        emit(fn, Opcode::Drop, expr.line);
        push(fn, expr.op == "&&" ? 0 : 1, expr.line);

        set_label(end, expr.line);
    }

    static bool binary_opcode(const std::string& op, Opcode& out) {
        if (op == "+") out = Opcode::Add;
        else if (op == "-") out = Opcode::Sub;
        else if (op == "*") out = Opcode::Mul;
        else if (op == "/") out = Opcode::Div;
        else if (op == "%") out = Opcode::Mod;
        else if (op == "==") out = Opcode::Eq;
        else if (op == "<") out = Opcode::Lt;
        else if (op == ">") out = Opcode::Gt;
        else if (op == "<=") out = Opcode::Le;
        else if (op == ">=") out = Opcode::Ge;
        else if (op == "&") out = Opcode::And;
        else if (op == "|") out = Opcode::Or;
        else if (op == "^") out = Opcode::Xor;
        else if (op == "<<") out = Opcode::Shl;
        else if (op == ">>") out = Opcode::Shr;
        else return false;
        return true;
    }

    // --- statements --------------------------------------------------------------------

    void compile_block(FunctionIR& fn, const std::vector<StmtPtr>& body,
                       Scope& scope) {
        for (const StmtPtr& stmt : body) {
            compile_stmt(fn, *stmt, scope);
            if (failed_) return;
        }
    }

    void compile_stmt(FunctionIR& fn, const Stmt& stmt, Scope& scope) {
        switch (stmt.kind) {
        case StmtKind::Let: {
            if (scope.variables.count(stmt.name)) {
                error(stmt.line,
                      "variable '" + stmt.name + "' declared twice");
                return;
            }
            bool addr = is_address_expr(*stmt.expr, scope);
            Scope::Var slot{
                kFrameBase + static_cast<uint32_t>(scope.variables.size()) *
                                 8u,
                addr ? ValueType::Address : ValueType::U64};
            scope.variables[stmt.name] = slot;
            if (addr) {
                /* Address rhs materializes in its own slot; copy 32 bytes
                 * into the new variable's slot (4 word moves). */
                uint32_t src = compile_address(fn, *stmt.expr, scope);
                if (failed_) return;
                for (uint32_t w = 0u; w < 4u; ++w) {
                    push(fn, src + w * 8u, stmt.line);
                    emit(fn, Opcode::Load64, stmt.line);
                    push(fn, slot.offset + w * 8u, stmt.line);
                    emit(fn, Opcode::Store64, stmt.line);
                }
            } else {
                compile_u64(fn, *stmt.expr, scope);
                if (failed_) return;
                push(fn, slot.offset, stmt.line);
                emit(fn, Opcode::Store64, stmt.line);
            }
            return;
        }

        case StmtKind::AssignLocal: {
            auto it = scope.variables.find(stmt.name);
            if (it == scope.variables.end()) {
                error(stmt.line,
                      "assignment to unknown variable '" + stmt.name + "'");
                return;
            }
            uint32_t slot = it->second.offset;
            if (it->second.type == ValueType::Address) {
                /* Address copy: 4 word moves from the rhs slot. */
                uint32_t src = compile_address(fn, *stmt.expr, scope);
                if (failed_) return;
                for (uint32_t w = 0u; w < 4u; ++w) {
                    push(fn, src + w * 8u, stmt.line);
                    emit(fn, Opcode::Load64, stmt.line);
                    push(fn, slot + w * 8u, stmt.line);
                    emit(fn, Opcode::Store64, stmt.line);
                }
                return;
            }
            compile_assign_value(
                fn, stmt, scope,
                [&] { push(fn, slot, stmt.line); emit(fn, Opcode::Store64, stmt.line); },
                [&] {
                    push(fn, slot, stmt.line);
                    emit(fn, Opcode::Load64, stmt.line);
                });
            return;
        }

        case StmtKind::AssignField: {
            if (!scalar_fields_.count(stmt.name)) {
                error(stmt.line,
                      "unknown scalar state field '" + stmt.name + "'");
                return;
            }
            compile_assign_value(
                fn, stmt, scope,
                [&] { write_state_field(fn, stmt.name, stmt.line); },
                [&] { read_state_field(fn, stmt.name, stmt.line); });
            return;
        }

        case StmtKind::AssignMap: {
            if (!map_prefix_.count(stmt.name)) {
                error(stmt.line, "unknown map '" + stmt.name + "'");
                return;
            }
            auto key_it = map_key_types_.find(stmt.name);
            ValueType key_type = key_it != map_key_types_.end()
                                     ? key_it->second : ValueType::Address;

            if (key_type == ValueType::Address) {
                if (!is_address_expr(*stmt.map_key, scope)) {
                    error(stmt.line, "map keys must be address-typed");
                    return;
                }
                uint32_t key_addr = compile_address(fn, *stmt.map_key, scope);
                if (failed_) return;
                build_map_key(fn, stmt.name, key_addr, stmt.line);
            } else {
                // u64 key
                compile_u64(fn, *stmt.map_key, scope);
                if (failed_) return;
                push(fn, kScratchB, stmt.line);
                emit(fn, Opcode::Store64, stmt.line);
                build_map_key_u64(fn, stmt.name, stmt.line);
            }
            if (failed_) return;

            if (stmt.op == "=") {
                compile_u64(fn, *stmt.expr, scope);
                if (failed_) return;
                write_map_entry_at_key(fn, stmt.line);
                return;
            }

            /* Compound: current value (absent reads as zero) combined with
             * the rhs, stored back under the same pre-derived key. */
            push(fn, 0u, stmt.line);
            push(fn, kScratchB, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
            push(fn, kKeySlot, stmt.line);
            push(fn, 32u, stmt.line);
            push(fn, kScratchB, stmt.line);
            push(fn, 32u, stmt.line);
            push_host(fn, Host::StorageGet, stmt.line);
            emit(fn, Opcode::Drop, stmt.line);
            push(fn, kScratchB, stmt.line);
            emit(fn, Opcode::Load64, stmt.line);

            std::string arithmetic = stmt.op.substr(0, stmt.op.size() - 1);
            Opcode op;
            if (!binary_opcode(arithmetic, op)) {
                error(stmt.line,
                      "unsupported compound assignment '" + stmt.op + "'");
                return;
            }
            compile_u64(fn, *stmt.expr, scope);
            if (failed_) return;
            emit(fn, op, stmt.line);
            write_map_entry_at_key(fn, stmt.line);
            return;
        }

        case StmtKind::Pay: {
            uint32_t to = compile_address(fn, *stmt.to, scope);
            if (failed_) return;
            compile_u64(fn, *stmt.expr, scope);
            if (failed_) return;
            push(fn, to, stmt.line);
            push_host(fn, Host::Transfer, stmt.line);
            return;
        }

        case StmtKind::Return:
            compile_return(fn, stmt, scope);
            return;

        case StmtKind::Require: {
            std::string ok = fresh_label("req");
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            jump_if(fn, ok.c_str(), stmt.line);
            push(fn, stmt.code, stmt.line);
            push(fn, kScratchB, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
            push(fn, kScratchB, stmt.line);
            push(fn, 8, stmt.line);
            emit(fn, Opcode::Revert, stmt.line);
            set_label(ok, stmt.line);   // anchored on whatever follows
            return;
        }

        case StmtKind::If: {
            std::string otherwise = fresh_label("else");
            std::string end = fresh_label("ifi");
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            normalize_bool(fn, stmt.line);
            push(fn, 0, stmt.line);
            emit(fn, Opcode::Eq, stmt.line);
            jump_if(fn, otherwise.c_str(), stmt.line);
            compile_block(fn, stmt.body, scope);
            if (failed_) return;
            jump(fn, end.c_str(), stmt.line);
            set_label(otherwise, stmt.line);
            compile_block(fn, stmt.else_body, scope);
            if (failed_) return;
            set_label(end, stmt.line);
            return;
        }

        case StmtKind::While: {
            std::string top = fresh_label("whl");
            std::string exit = fresh_label("wend");
            set_label(top, stmt.line);
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            normalize_bool(fn, stmt.line);
            push(fn, 0, stmt.line);
            emit(fn, Opcode::Eq, stmt.line);
            jump_if(fn, exit.c_str(), stmt.line);
            compile_block(fn, stmt.body, scope);
            if (failed_) return;
            jump(fn, top.c_str(), stmt.line);
            set_label(exit, stmt.line);
            return;
        }

        case StmtKind::Emit:
            compile_emit(fn, stmt, scope);
            return;

        case StmtKind::Assert: {
            std::string ok = fresh_label("asrt");
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            jump_if(fn, ok.c_str(), stmt.line);
            // assert failure: revert with code 0 (unrecoverable)
            push(fn, 0, stmt.line);
            push(fn, kScratchB, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
            push(fn, kScratchB, stmt.line);
            push(fn, 8, stmt.line);
            emit(fn, Opcode::Revert, stmt.line);
            set_label(ok, stmt.line);
            return;
        }

        case StmtKind::ExprState:
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            emit(fn, Opcode::Drop, stmt.line);
            return;
        }
        error(stmt.line, "unsupported statement");
    }

    void compile_return(FunctionIR& fn, const Stmt& stmt, Scope& scope) {
        if (!current_public_) {
            if (stmt.expr != nullptr) {
                compile_expr(fn, *stmt.expr, scope);
            } else if (current_has_result_) {
                // A bare `return` in a u64 function yields zero.
                push(fn, 0, stmt.line);
            }
            emit(fn, Opcode::Ret, stmt.line);
            return;
        }
        // Public functions hand data back through RETURN from the reserved
        // slot; a missing value means zero.
        if (stmt.expr != nullptr) {
            compile_expr(fn, *stmt.expr, scope);
            if (failed_) return;
            push(fn, kResultSlot, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
        } else {
            push(fn, 0, stmt.line);
            push(fn, kResultSlot, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
        }
        push(fn, kResultSlot, stmt.line);
        push(fn, current_has_result_ ? 8 : 0, stmt.line);
        emit(fn, Opcode::Return, stmt.line);
    }

    template <typename Store, typename Load>
    void compile_assign_value(FunctionIR& fn, const Stmt& stmt,
                              const Scope& scope, Store store,
                              Load load_current) {
        if (stmt.op == "=") {
            compile_u64(fn, *stmt.expr, scope);
            if (failed_) return;
            store();
            return;
        }
        std::string arithmetic = stmt.op.substr(0, stmt.op.size() - 1);
        Opcode op;
        if (!binary_opcode(arithmetic, op)) {
            error(stmt.line,
                  "unsupported compound assignment '" + stmt.op + "'");
            return;
        }
        load_current();
        compile_u64(fn, *stmt.expr, scope);
        if (failed_) return;
        emit(fn, op, stmt.line);
        store();
    }

    void compile_emit(FunctionIR& fn, const Stmt& stmt, Scope& scope) {
        al_hash256 topic;
        al_hash_tagged(AL_TAG_EVENT, stmt.name.data(), stmt.name.size(),
                       &topic);
        for (unsigned word = 0; word < 4; ++word) {
            uint64_t piece = 0;
            for (unsigned b = 0; b < 8; ++b) {
                piece |= uint64_t(topic.bytes[word * 8 + b]) << (b * 8);
            }
            push(fn, piece, stmt.line);
            push(fn, kScratchA + word * 8, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
        }
        for (size_t i = 0; i < stmt.emit_args.size(); ++i) {
            compile_expr(fn, *stmt.emit_args[i], scope);
            if (failed_) return;
            push(fn, kScratchB + static_cast<uint32_t>(i) * 8, stmt.line);
            emit(fn, Opcode::Store64, stmt.line);
        }
        push(fn, kScratchA, stmt.line);
        push(fn, 32, stmt.line);
        push(fn, kScratchB, stmt.line);
        push(fn, stmt.emit_args.size() * 8, stmt.line);
        push_host(fn, Host::EmitEvent, stmt.line);
    }

    // --- functions ------------------------------------------------------------------------

    std::optional<FunctionIR> compile_function(const FunctionDecl& decl,
                                               bool is_init = false) {
        FunctionIR fn;
        fn.name = is_init
                      ? "__init"
                      : (decl.public_abi ? "pub_" + decl.name
                                         : "int_" + decl.name);
        // Constructors and public functions have 0 VM parameters;
        // their arguments come from calldata via the prologue.
        fn.parameters =
            (decl.public_abi || is_init)
                ? 0
                : static_cast<uint16_t>(decl.params.size());
        fn.results = decl.has_result ? 1u : 0u;
        current_public_ = decl.public_abi || is_init;
        current_has_result_ = decl.has_result;
        current_param_count_ = decl.params.size();
        string_literal_slot_ = 0;

        Scope scope;
        if (is_init || decl.public_abi)
            compile_pub_prologue(fn, decl, scope);
        else
            compile_internal_prologue(fn, decl, scope);
        if (failed_) return std::nullopt;

        compile_block(fn, decl.body, scope);
        if (failed_) return std::nullopt;

        // Implicit epilogue when control falls off the end of the body.
        if (current_public_) {
            if (current_has_result_) {
                // Falling off the end of a u64 function yields zero.
                push(fn, 0, decl.line);
                push(fn, kResultSlot, decl.line);
                emit(fn, Opcode::Store64, decl.line);
            }
            push(fn, kResultSlot, decl.line);
            push(fn, decl.has_result ? 8 : 0, decl.line);
            emit(fn, Opcode::Return, decl.line);
        } else {
            if (decl.has_result) push(fn, 0, decl.line);
            emit(fn, Opcode::Ret, decl.line);
        }

        if (!pending_label_.empty()) {
            diagnostics_.error(armed_line_,
                               "internal: label '" + pending_label_ +
                                   "' never attached in '" + fn.name + "'");
            failed_ = true;
            return std::nullopt;
        }
        fn.max_stack = static_cast<uint16_t>(std::max<size_t>(
            {4u, static_cast<size_t>(fn.parameters) + 2u,
             decl.params.size() + 4u}));
        return fn;
    }

    void compile_pub_prologue(FunctionIR& fn, const FunctionDecl& decl,
                               Scope& scope) {
        // Calldata ABI: n*8 bytes for u64, n*32 bytes for address, variable
        // for string. A shorter payload reverts with code 1.
        uint64_t required = 0u;
        for (const ParamDecl& p : decl.params) {
            switch (p.type) {
            case ValueType::Address: required += 32u; break;
            case ValueType::String:  required += 8u; break;  // offset+length
            case ValueType::U64:     required += 8u; break;
            }
        }
        emit(fn, Opcode::CalldataSize, decl.line);   // pushes actual length
        push(fn, required, decl.line);               // required minimum
        emit(fn, Opcode::Ge, decl.line);             // length >= required?
        std::string ok = fresh_label("abi");
        jump_if(fn, ok.c_str(), decl.line);
        push(fn, 1, decl.line);
        push(fn, kScratchB, decl.line);
        emit(fn, Opcode::Store64, decl.line);
        push(fn, kScratchB, decl.line);
        push(fn, 8, decl.line);
        emit(fn, Opcode::Revert, decl.line);
        set_label(ok, decl.line);

        uint64_t source = 0u;
        uint32_t slot = kFrameBase;
        for (const ParamDecl& param : decl.params) {
            uint32_t size = 0u;
            switch (param.type) {
            case ValueType::Address: size = 32u; break;
            case ValueType::String:  size = 8u; break;
            case ValueType::U64:     size = 8u; break;
            }
            scope.variables[param.name] = Scope::Var{slot, param.type};
            push(fn, source, decl.line);         // calldata source offset
            push(fn, slot, decl.line);           // destination
            push(fn, size, decl.line);           // length
            emit(fn, Opcode::CalldataCopy, decl.line);
            source += size;
            slot += size;
        }
    }

    void compile_internal_prologue(FunctionIR& fn, const FunctionDecl& decl,
                                   Scope& scope) {
        // Frame protocol: parameters arrive deepest-first on the operand
        // stack, so they spill into slots in reverse pop order. Address
        // parameters occupy 32 bytes, u64 and string ones 8.
        uint32_t slot = kFrameBase;
        for (size_t i = decl.params.size(); i-- > 0;) {
            scope.variables[decl.params[i].name] =
                Scope::Var{slot, decl.params[i].type};
            push(fn, slot, decl.line);
            emit(fn, Opcode::Store64, decl.line);
            slot += decl.params[i].type == ValueType::Address ? 32u : 8u;
        }
    }

    // --- misc -------------------------------------------------------------------------------

    void duplicate(const std::string& name) {
        diagnostics_.error(0, "duplicate function '" + name + "'");
        failed_ = true;
    }
    void error(unsigned line, std::string message) {
        diagnostics_.error(line, std::move(message));
        failed_ = true;
    }

    const ContractDecl& contract_;
    Diagnostics& diagnostics_;
    std::map<std::string, uint16_t> internal_index_;
    std::map<std::string, std::string> map_prefix_;
    std::map<std::string, ValueType> map_key_types_;
    std::map<std::string, ValueType> map_value_types_;
    std::set<std::string> scalar_fields_;
    std::set<std::string> public_names_;
    std::set<std::string> internal_names_;
    uint16_t label_counter_ = 0;
    uint32_t string_literal_slot_ = 0;
    std::string pending_label_;
    unsigned armed_line_ = 0;
    bool current_public_ = false;
    bool current_has_result_ = false;
    size_t current_param_count_ = 0;
    bool failed_ = false;
};

}  // namespace

std::optional<ModuleIR> lower_contract(const ContractDecl& contract,
                                       Diagnostics& diagnostics) {
    Lowerer lowerer(contract, diagnostics);
    return lowerer.run();
}

}  // namespace trocto
