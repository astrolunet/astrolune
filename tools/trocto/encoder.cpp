// Encoding and text generation for the shared IR.
//
// Labels resolve to absolute code-section offsets (ALVM jumps are absolute
// and function-bounded). The encoded container is re-validated through
// al_vm_validate so the toolchain can never emit bytes the consensus VM
// would reject on chain.

#include "encoder.hpp"

#include "astrolune/vm.h"

#include <cstdlib>
#include <map>
#include <algorithm>
#include <unordered_map>

namespace trocto {
namespace {

constexpr size_t kInsnSizePush64 = 9;
constexpr size_t kInsnSizeJump = 5;
constexpr size_t kInsnSizeIndex = 3;

size_t insn_size(const Instruction& insn) {
    switch (insn.opcode) {
    case Opcode::Push64: return kInsnSizePush64;
    case Opcode::Jump:
    case Opcode::JumpIf: return kInsnSizeJump;
    case Opcode::Call:
    case Opcode::Host: return kInsnSizeIndex;
    default: return 1;
    }
}

void push_le(std::vector<uint8_t>& out, uint64_t value, unsigned bytes) {
    for (unsigned i = 0; i < bytes; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xff));
    }
}

const char* opcode_name(Opcode op) {
    switch (op) {
    case Opcode::Stop: return "stop";
    case Opcode::Push64: return "push64";
    case Opcode::Add: return "add";
    case Opcode::Sub: return "sub";
    case Opcode::Mul: return "mul";
    case Opcode::Div: return "div";
    case Opcode::Eq: return "eq";
    case Opcode::Lt: return "lt";
    case Opcode::Dup: return "dup";
    case Opcode::Drop: return "drop";
    case Opcode::Jump: return "jump";
    case Opcode::JumpIf: return "jumpi";
    case Opcode::Load8: return "load8";
    case Opcode::Store8: return "store8";
    case Opcode::Return: return "return";
    case Opcode::Revert: return "revert";
    case Opcode::Mod: return "mod";
    case Opcode::And: return "and";
    case Opcode::Or: return "or";
    case Opcode::Xor: return "xor";
    case Opcode::Not: return "not";
    case Opcode::Shl: return "shl";
    case Opcode::Shr: return "shr";
    case Opcode::Gt: return "gt";
    case Opcode::Le: return "le";
    case Opcode::Ge: return "ge";
    case Opcode::Swap: return "swap";
    case Opcode::Load64: return "load64";
    case Opcode::Store64: return "store64";
    case Opcode::CalldataSize: return "calldata_size";
    case Opcode::CalldataCopy: return "calldata_copy";
    case Opcode::Call: return "call";
    case Opcode::Ret: return "ret";
    case Opcode::Host: return "host";
    }
    return "?";
}

std::string host_name(uint16_t id) {
    switch (static_cast<Host>(id)) {
    case Host::Sender: return "sender";
    case Host::CurrentAddress: return "current_address";
    case Host::BlockHeight: return "block_height";
    case Host::ProtocolDay: return "protocol_day";
    case Host::Balance: return "balance";
    case Host::Transfer: return "transfer";
    case Host::StorageGet: return "storage_get";
    case Host::StorageSet: return "storage_set";
    case Host::StorageDelete: return "storage_delete";
    case Host::EmitEvent: return "emit_event";
    case Host::HashTagged: return "hash_tagged";
    case Host::VerifySignature: return "verify_signature";
    case Host::CallContract: return "call_contract";
    }
    return std::to_string(id);
}

}  // namespace

static std::optional<std::vector<uint8_t>> encode_module_impl(
    const ModuleIR& module, Diagnostics& diagnostics, bool skip_validation) {
    if (module.functions.empty()) {
        diagnostics.error(0, "module has no functions");
        return std::nullopt;
    }
    if (module.functions.size() > AL_VM_MAX_FUNCTIONS) {
        diagnostics.error(0, "too many functions");
        return std::nullopt;
    }

    // Pass 1: per-function layout. Label definitions ride on the instruction
    // they precede; their value is that instruction's absolute offset.
    std::vector<al_vm_function> descriptors;
    descriptors.reserve(module.functions.size());
    // name -> absolute offset, keyed per function then merged with a prefix.
    std::unordered_map<std::string, uint32_t> labels;

    size_t cursor = 0;
    for (const FunctionIR& fn : module.functions) {
        if (fn.body.empty()) {
            diagnostics.error(0, "function '" + fn.name + "' is empty");
            return std::nullopt;
        }
        for (const Instruction& insn : fn.body) {
            if (!insn.label.empty()) {
                std::string key = fn.name + "\x01" + insn.label;
                if (!labels.emplace(key, static_cast<uint32_t>(cursor)).second) {
                    diagnostics.error(insn.line, "duplicate label '" +
                                                     insn.label + "' in '" +
                                                     fn.name + "'");
                    return std::nullopt;
                }
            }
            cursor += insn_size(insn);
        }
        if (cursor > AL_VM_MAX_CODE_SIZE) {
            diagnostics.error(0, "code section exceeds 1 MiB");
            return std::nullopt;
        }
    }

    // Pass 2: emit bytes and patch jump immediates.
    std::vector<uint8_t> code;
    code.reserve(cursor);
    for (const FunctionIR& fn : module.functions) {
        al_vm_function descriptor{};
        descriptor.offset = static_cast<al_u32>(code.size());
        descriptor.parameter_count = fn.parameters;
        descriptor.result_count = fn.results;
        descriptor.max_stack = fn.max_stack != 0
                                   ? fn.max_stack
                                   : static_cast<al_u16>(
                                         std::max<size_t>({2u,
                                                           fn.parameters + 2u,
                                                           fn.results + 2u}));
        descriptors.push_back(descriptor);

        for (const Instruction& insn : fn.body) {
            code.push_back(static_cast<uint8_t>(static_cast<uint8_t>(insn.opcode)));
            switch (insn.opcode) {
            case Opcode::Push64:
                push_le(code, insn.immediate, 8);
                break;
            case Opcode::Jump:
            case Opcode::JumpIf: {
                auto it = labels.find(fn.name + "\x01" + insn.label_ref);
                if (it == labels.end()) {
                    diagnostics.error(insn.line,
                                      "undefined label '" + insn.label_ref +
                                          "' in function '" + fn.name + "'");
                    return std::nullopt;
                }
                push_le(code, it->second, 4);
                break;
            }
            case Opcode::Call:
            case Opcode::Host:
                push_le(code, insn.immediate, 2);
                break;
            default:
                break;
            }
        }
    }

    // Pass 3: canonical container through the core encoder, then the same
    // validation deployment performs - a build failure beats a rejected
    // deploy transaction.
    std::vector<uint8_t> container(AL_VM_MAX_CODE_SIZE + 4096, 0);
    al_size written = 0;
    al_status status = al_vm_container_encode(
        descriptors.data(), descriptors.size(),
        al_bytes_make(code.data(), code.size()),
        al_bytes_mut{container.data(), container.size()}, &written);
    if (status != AL_OK) {
        diagnostics.error(0,
                          std::string("container encoding failed: ") +
                              al_status_str(status));
        return std::nullopt;
    }

    al_arena arena;
    if (al_arena_init(&arena, 1u << 20) != AL_OK) {
        diagnostics.error(0, "validation arena allocation failed");
        return std::nullopt;
    }
    status = al_vm_validate(al_bytes_make(container.data(), written),
                            nullptr, &arena);
    al_arena_destroy(&arena);
    if (status != AL_OK && !skip_validation) {
        /* Point at the functions whose terminator/protocol tripped the
         * validator so the message is actionable. */
        std::string note;
        for (const FunctionIR& fn : module.functions) {
            const Instruction* last =
                fn.body.empty() ? nullptr : &fn.body.back();
            std::string ends = "?";
            if (last) {
                switch (last->opcode) {
                case Opcode::Ret: ends = "ret"; break;
                case Opcode::Return: ends = "return"; break;
                case Opcode::Revert: ends = "revert"; break;
                case Opcode::Stop: ends = "stop"; break;
                default: ends = "NOT-TERMINATOR"; break;
                }
            }
            note += " [" + fn.name + ":params=" +
                    std::to_string(fn.parameters) + ",ends " + ends + "]";
        }
        diagnostics.error(0,
                          std::string("generated container is invalid: ") +
                              al_status_str(status) +
                              " (function protocol summary above)");
        return std::nullopt;
    }

    container.resize(written);
    return container;
}

std::optional<std::vector<uint8_t>> encode_module(const ModuleIR& module,
                                                  Diagnostics& diagnostics,
                                                  bool skip_validation) {
    return encode_module_impl(module, diagnostics, skip_validation);
}

std::string regol_text(const ModuleIR& module) {
    std::string out;
    bool first_function = true;
    for (const FunctionIR& fn : module.functions) {
        if (!first_function) out += "\n";
        first_function = false;
        out += "fn " + fn.name + "(";
        for (uint16_t i = 0; i < fn.parameters; ++i) {
            if (i != 0) out += ", ";
            out += "arg" + std::to_string(i) + ": u64";
        }
        out += ")";
        out += " -> u" + std::to_string(fn.results) + " {\n";
        for (const Instruction& insn : fn.body) {
            if (!insn.label.empty()) {
                out += "." + insn.label + "\n";
            }
            out += "    ";
            out += opcode_name(insn.opcode);
            switch (insn.opcode) {
            case Opcode::Push64:
                out += " " + std::to_string(insn.immediate);
                break;
            case Opcode::Jump:
            case Opcode::JumpIf:
                out += " ." + insn.label_ref;
                break;
            case Opcode::Host:
                out += " " + host_name(static_cast<uint16_t>(insn.immediate));
                break;
            case Opcode::Call:
                out += " " + std::to_string(insn.immediate);
                break;
            default:
                break;
            }
            out += "\n";
        }
        out += "}\n";
    }
    return out;
}

}  // namespace trocto
