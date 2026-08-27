/*
 * trocto/compiler.hpp - the contract-language toolchain front door.
 *
 * Two tiers, one pipeline:
 *
 *     Trocto (.tc)  -> lower -> Regol (.rg) IR -> encode -> ALVM container
 *     Regol (.rg)   -> assemble ------------^
 *
 * Regol is both the hand-written low-level language and the intermediate
 * representation: the Trocto compiler emits the same ModuleIR that the Regol
 * assembler consumes, so text output (--emit-regol) is always a faithful,
 * round-trippable view of what was compiled.
 *
 * Diagnostics are collected, never thrown; compilation failures leave the
 * sink populated with line-anchored messages and return std::nullopt.
 */

#ifndef TROCTO_COMPILER_HPP
#define TROCTO_COMPILER_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace trocto {

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

struct Diagnostic {
    unsigned line = 0;      // 1-based; 0 means "not source-anchored"
    std::string message;
};

class Diagnostics {
public:
    void error(unsigned line, std::string message);
    bool ok() const { return entries_.empty(); }
    const std::vector<Diagnostic>& entries() const { return entries_; }
    void clear();

private:
    std::vector<Diagnostic> entries_;
};

// ---------------------------------------------------------------------------
// Intermediate representation (shared by the assembler and the compiler)
// ---------------------------------------------------------------------------

enum class Opcode : uint8_t {
    Stop = 0x00, Push64 = 0x01, Add = 0x02, Sub = 0x03, Mul = 0x04,
    Div = 0x05, Eq = 0x06, Lt = 0x07, Dup = 0x08, Drop = 0x09,
    Jump = 0x0a, JumpIf = 0x0b, Load8 = 0x0c, Store8 = 0x0d,
    Return = 0x0e, Revert = 0x0f, Mod = 0x10, And = 0x11, Or = 0x12,
    Xor = 0x13, Not = 0x14, Shl = 0x15, Shr = 0x16, Gt = 0x17,
    Le = 0x18, Ge = 0x19, Swap = 0x1a, Load64 = 0x1b, Store64 = 0x1c,
    CalldataSize = 0x1d, CalldataCopy = 0x1e, Call = 0x1f, Ret = 0x20,
    Host = 0x21,
};

// Host function numbers, matching al_vm_host_id.
enum class Host : uint16_t {
    Sender = 0, CurrentAddress = 1, BlockHeight = 2, ProtocolDay = 3,
    Balance = 4, Transfer = 5, StorageGet = 6, StorageSet = 7,
    StorageDelete = 8, EmitEvent = 9, HashTagged = 10,
    VerifySignature = 11, CallContract = 12,
};

struct Instruction {
    Opcode opcode;
    // Immediates: Push64 uses u64; Call/Host use u16.
    uint64_t immediate = 0;
    // Label DEFINITION attached to this instruction (jump target site).
    std::string label;
    // Label REFERENCE used by Jump/JumpIf immediates.
    std::string label_ref;
    unsigned line = 0;
};

struct FunctionIR {
    std::string name;
    uint16_t parameters = 0;
    uint16_t results = 0;
    // Peak operand height tracked or declared; encoded into the descriptor.
    uint16_t max_stack = 0;
    std::vector<Instruction> body;
};

struct ModuleIR {
    // Index 0 is the default transaction entrypoint (zero parameters).
    std::vector<FunctionIR> functions;
};

// ---------------------------------------------------------------------------
// Compilation entry points
// ---------------------------------------------------------------------------

struct CompileOptions {
    // Emit the lowered Regol text next to compilation (used by --emit-regol
    // and by tests that assert on the IR).
    bool keep_ir = false;
    // Debugging aid for the toolchain itself: assemble the container but do
    // not run the consensus validator over it.
    bool skip_validation = false;
};

struct CompileResult {
    std::vector<uint8_t> container;
    std::string regol_text;     // filled when options.keep_ir is set
};

// Compiles Trocto source into a validated ALVM container.
// source_path is used for resolving imports; pass "" for inline sources.
std::optional<CompileResult> compile_trocto(const std::string& source,
                                            const CompileOptions& options,
                                            Diagnostics& diagnostics,
                                            const std::string& source_path = "");

// Assembles Regol source into a validated ALVM container.
std::optional<CompileResult> assemble_regol(const std::string& source,
                                            Diagnostics& diagnostics);

/* Debugging aid for the CLI: parse + lower without encoding/validation so
 * --emit-regol can show the IR of a program that does not yet assemble.
 * Also exposes the IR text generator for the same purpose. */
std::optional<ModuleIR> lower_source_for_debug(const std::string& source,
                                               Diagnostics& diagnostics);
std::string regol_text(const ModuleIR& module);
}  // namespace trocto

#endif  // TROCTO_COMPILER_HPP
