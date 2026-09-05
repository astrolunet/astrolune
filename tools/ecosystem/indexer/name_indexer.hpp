/*
 * astrolune/tools/ecosystem/indexer/name_indexer.hpp
 *
 * In-memory index of .lune domain name registrations. Subscribes to
 * DomainRegistered, DomainRenewed and DomainTransferred events emitted by the
 * LuneRegistry contract and maintains a thread-safe lookup table keyed by
 * domain hash.
 *
 * Design constraints:
 *   - No exceptions across ABI boundaries; errors return std::expected.
 *   - Thread-safe for concurrent reads; writes are serialised internally.
 *   - Lifetime is managed through shared_ptr so consumers can hold the index
 *     across asynchronous operations.
 */

#ifndef ASTROLUNE_INDEXER_NAME_INDEXER_HPP
#define ASTROLUNE_INDEXER_NAME_INDEXER_HPP

#include "astrolune/base.h"
#include "astrolune/hash.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace astrolune::indexer {

// ---------------------------------------------------------------------------
// Domain flags
// ---------------------------------------------------------------------------

enum class DomainFlags : al_u8 {
    None        = 0,
    Locked      = 1 << 0,   // transfer-restricted
    Resolver    = 1 << 1,   // custom resolver configured
    Delegated   = 1 << 2,   // management delegated to another address
};

DomainFlags operator|(DomainFlags a, DomainFlags b) noexcept;
DomainFlags operator&(DomainFlags a, DomainFlags b) noexcept;
DomainFlags& operator|=(DomainFlags& a, DomainFlags b) noexcept;

// ---------------------------------------------------------------------------
// Domain info stored in the index
// ---------------------------------------------------------------------------

struct DomainInfo {
    al_hash256 domain_hash{};       // deterministic hash of the normalised name
    al_address owner{};             // current owner address
    al_address resolver{};          // resolver address (zero = default)
    al_u64     expiry = 0;          // block height at which the domain expires
    al_u64     registered_at = 0;   // block height at registration
    DomainFlags flags = DomainFlags::None;
};

// ---------------------------------------------------------------------------
// Blockchain event types that the indexer processes
// ---------------------------------------------------------------------------

struct DomainRegistered {
    al_hash256 domain_hash;
    al_address owner;
    al_u64     expiry;
    al_address resolver;
};

struct DomainRenewed {
    al_hash256 domain_hash;
    al_address caller;          // must be owner or approved
    al_u64     new_expiry;
};

struct DomainTransferred {
    al_hash256 domain_hash;
    al_address from;
    al_address to;
};

// Error codes returned by the indexer.
enum class IndexError : al_u8 {
    Ok = 0,
    DomainNotFound,
    AlreadyIndexed,
};

// ---------------------------------------------------------------------------
// NameIndexer
// ---------------------------------------------------------------------------

class NameIndexer {
public:
    NameIndexer();
    ~NameIndexer();

    NameIndexer(const NameIndexer&) = delete;
    NameIndexer& operator=(const NameIndexer&) = delete;
    NameIndexer(NameIndexer&&) noexcept;
    NameIndexer& operator=(NameIndexer&&) noexcept;

    // -- Event processing ---------------------------------------------------

    // Process a DomainRegistered event.  Returns an error if the domain is
    // already present (idempotent at the contract level).
    std::expected<void, IndexError> process_event(const DomainRegistered& ev);

    // Process a DomainRenewed event.  Updates the expiry height.
    std::expected<void, IndexError> process_event(const DomainRenewed& ev);

    // Process a DomainTransferred event.  Changes the owner.
    std::expected<void, IndexError> process_event(const DomainTransferred& ev);

    // -- Query API (thread-safe for concurrent readers) ---------------------

    // Look up a domain by its hash.  Returns an error when the domain is not
    // present in the index.
    std::expected<DomainInfo, IndexError> lookup(const al_hash256& domain_hash) const;

    // Check whether a domain exists and has not expired at `current_height`.
    std::expected<bool, IndexError> is_valid(const al_hash256& domain_hash,
                                              al_u64 current_height) const;

    // Retrieve the owner of a domain.
    std::expected<al_address, IndexError> get_owner(const al_hash256& domain_hash) const;

    // Retrieve the expiry block height of a domain.
    std::expected<al_u64, IndexError> get_expiry(const al_hash256& domain_hash) const;

    // Return a snapshot of every indexed domain.
    std::vector<DomainInfo> get_all_domains() const;

    // Number of domains currently in the index.
    std::size_t size() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::indexer

#endif  // ASTROLUNE_INDEXER_NAME_INDEXER_HPP
