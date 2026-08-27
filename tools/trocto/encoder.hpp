// ModuleIR -> canonical ALVM container, with authoritative validation.
// Also the inverse-facing text generator used by --emit-regol.

#ifndef TROCTO_ENCODER_HPP
#define TROCTO_ENCODER_HPP

#include "trocto/compiler.hpp"

#include <string>

namespace trocto {

// Resolves labels to absolute code offsets (jump targets are absolute and
// function-bounded in ALVM), builds descriptors and encodes the container.
// The result is then re-validated through al_vm_validate so the toolchain can
// never emit a container the consensus VM would reject.
std::optional<std::vector<uint8_t>> encode_module(const ModuleIR& module,
                                                  Diagnostics& diagnostics,
                                                  bool skip_validation = false);

// Renders the module as Regol source. The output assembles back to an
// equivalent container: the text form is the IR, not a listing.
std::string regol_text(const ModuleIR& module);

}  // namespace trocto

#endif  // TROCTO_ENCODER_HPP
