/*
 * astrolune/tools/ecosystem/indexer/name_indexer.cpp
 *
 * Implementation of the in-memory .lune domain name index.  The index is
 * organised as a flat hash-map keyed by al_hash256.  All reads go through a
 * shared_lock (reader-writer) so concurrent queries do not block each other,
 * while event processing takes a unique_lock.
 */

#include "name_indexer.hpp"

#include <algorithm>
#include <shared_mutex>

namespace astrolune::indexer {

// ---------------------------------------------------------------------------
// DomainFlags operators
// ---------------------------------------------------------------------------

DomainFlags operator|(DomainFlags a, DomainFlags b) noexcept {
    return static_cast<DomainFlags>(
        static_cast<al_u8>(a) | static_cast<al_u8>(b));
}

DomainFlags operator&(DomainFlags a, DomainFlags b) noexcept {
    return static_cast<DomainFlags>(
        static_cast<al_u8>(a) & static_cast<al_u8>(b));
}

DomainFlags& operator|=(DomainFlags& a, DomainFlags b) noexcept {
    a = a | b;
    return a;
}

// ---------------------------------------------------------------------------
// Helper: compare al_hash256 for use as hash-map key
// ---------------------------------------------------------------------------

namespace {

struct Hash256Equal {
    bool operator()(const al_hash256& a, const al_hash256& b) const noexcept {
        return al_hash_eq(&a, &b);
    }
};

// FNV-1a style hash for al_hash256.  The 32 raw bytes are mixed into a
// size_t in a way that is fast and distributes well.
struct Hash256Hash {
    std::size_t operator()(const al_hash256& h) const noexcept {
        std::size_t result = 14695981039346656037ULL;
        for (std::size_t i = 0; i < AL_HASH_SIZE; ++i) {
            result ^= static_cast<std::size_t>(h.bytes[i]);
            result *= 1099511628211ULL;
        }
        return result;
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Impl - the internal state behind the pimpl
// ---------------------------------------------------------------------------

struct NameIndexer::Impl {
    mutable std::shared_mutex mutex;
    std::unordered_map<al_hash256, DomainInfo, Hash256Hash, Hash256Equal> domains;
};

// ---------------------------------------------------------------------------
// Construction / destruction / movement
// ---------------------------------------------------------------------------

NameIndexer::NameIndexer()
    : impl_(std::make_unique<Impl>()) {}

NameIndexer::~NameIndexer() = default;

NameIndexer::NameIndexer(NameIndexer&&) noexcept = default;
NameIndexer& NameIndexer::operator=(NameIndexer&&) noexcept = default;

// ---------------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------------

std::expected<void, IndexError>
NameIndexer::process_event(const DomainRegistered& ev) {
    std::unique_lock lock(impl_->mutex);

    DomainInfo info{};
    info.domain_hash    = ev.domain_hash;
    info.owner          = ev.owner;
    info.expiry         = ev.expiry;
    info.registered_at  = ev.expiry;  // approximate; caller may refine
    info.resolver       = ev.resolver;
    info.flags          = DomainFlags::None;

    auto [it, inserted] = impl_->domains.try_emplace(ev.domain_hash, info);
    if (!inserted) {
        return std::unexpected(IndexError::AlreadyIndexed);
    }
    return {};
}

std::expected<void, IndexError>
NameIndexer::process_event(const DomainRenewed& ev) {
    std::unique_lock lock(impl_->mutex);

    auto it = impl_->domains.find(ev.domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }

    it->second.expiry = ev.new_expiry;
    return {};
}

std::expected<void, IndexError>
NameIndexer::process_event(const DomainTransferred& ev) {
    std::unique_lock lock(impl_->mutex);

    auto it = impl_->domains.find(ev.domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }

    it->second.owner = ev.to;
    return {};
}

// ---------------------------------------------------------------------------
// Query API
// ---------------------------------------------------------------------------

std::expected<DomainInfo, IndexError>
NameIndexer::lookup(const al_hash256& domain_hash) const {
    std::shared_lock lock(impl_->mutex);

    auto it = impl_->domains.find(domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }
    return it->second;
}

std::expected<bool, IndexError>
NameIndexer::is_valid(const al_hash256& domain_hash,
                       al_u64 current_height) const {
    std::shared_lock lock(impl_->mutex);

    auto it = impl_->domains.find(domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }
    return current_height < it->second.expiry;
}

std::expected<al_address, IndexError>
NameIndexer::get_owner(const al_hash256& domain_hash) const {
    std::shared_lock lock(impl_->mutex);

    auto it = impl_->domains.find(domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }
    return it->second.owner;
}

std::expected<al_u64, IndexError>
NameIndexer::get_expiry(const al_hash256& domain_hash) const {
    std::shared_lock lock(impl_->mutex);

    auto it = impl_->domains.find(domain_hash);
    if (it == impl_->domains.end()) {
        return std::unexpected(IndexError::DomainNotFound);
    }
    return it->second.expiry;
}

std::vector<DomainInfo> NameIndexer::get_all_domains() const {
    std::shared_lock lock(impl_->mutex);

    std::vector<DomainInfo> result;
    result.reserve(impl_->domains.size());
    for (const auto& [hash, info] : impl_->domains) {
        result.push_back(info);
    }
    return result;
}

std::size_t NameIndexer::size() const {
    std::shared_lock lock(impl_->mutex);
    return impl_->domains.size();
}

}  // namespace astrolune::indexer
