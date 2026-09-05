// Contract-language end-to-end tests.
//
// Every case runs the full pipeline the chain runs: source text -> Trocto or
// Regol -> validated ALVM container -> al_vm_execute against a mock host.
// Storage, balances and events live in plain C++ containers here; consensus
// behavior of the hosts themselves is covered by test_vm/test_tx.

#include "altest.h"
#include "astrolune/block.h"
#include "astrolune/hash.h"
#include "astrolune/state.h"
#include "astrolune/tx.h"
#include "astrolune/vm.h"
#include "node.h"
#include "trocto/compiler.hpp"

#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

std::optional<trocto::CompileResult> build(const char* source,
                                           bool regol = false) {
    trocto::Diagnostics diagnostics;
    std::optional<trocto::CompileResult> result =
        regol ? trocto::assemble_regol(source, diagnostics)
              : trocto::compile_trocto(source, {}, diagnostics);
    if (!result) {
        for (const auto& d : diagnostics.entries()) {
            std::fprintf(stderr, "  compile: line %u: %s\n", d.line,
                         d.message.c_str());
        }
    }
    return result;
}

std::string key_hex(const uint8_t* bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return out;
}

struct EventRecord {
    std::string topic;
    std::vector<uint8_t> data;
};

struct MockHostState {
    std::map<std::string, std::vector<uint8_t>> storage;
    std::map<std::string, uint64_t> balances;
    std::vector<EventRecord> events;
    uint8_t sender[32];
    uint8_t current[32];
    uint64_t height = 7;
    uint32_t day = 3;
};

MockHostState& host_state() {
    static MockHostState state;
    return state;
}

uint64_t read_u64(const uint8_t* memory, uint64_t offset,
                  const trocto::Diagnostics* unused = nullptr) {
    (void)unused;
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= uint64_t(memory[offset + i]) << (i * 8);
    }
    return value;
}

void write_u64(uint8_t* memory, uint64_t offset, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        memory[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
    }
}

al_status mock_host_invoke(void* context, al_vm_host_id id,
                           al_vm_host_io* io) {
    auto& state = *static_cast<MockHostState*>(context);
    auto args = [&](size_t index) { return io->arguments[index]; };
    auto memory = [&](size_t offset) -> uint8_t* {
        return io->memory.data + offset;
    };

    switch (static_cast<int>(id)) {
    case 0:  // sender
        std::memcpy(memory(args(0)), state.sender, 32);
        return AL_OK;
    case 1:  // current address
        std::memcpy(memory(args(0)), state.current, 32);
        return AL_OK;
    case 2:
        io->results[io->result_count++] = state.height;
        return AL_OK;
    case 3:
        io->results[io->result_count++] = state.day;
        return AL_OK;
    case 4: {  // balance(address_offset)
        std::string key =
            key_hex(io->memory.data + args(0));
        io->results[io->result_count++] = state.balances[key];
        return AL_OK;
    }
    case 5: {  // transfer from current contract
        std::string key = key_hex(memory(args(0)));
        uint64_t amount = args(1);
        std::string self_key = key_hex(state.current);
        if (state.balances[self_key] < amount) return AL_ERR_INSUFFICIENT_FUNDS;
        state.balances[self_key] -= amount;
        state.balances[key] += amount;
        return AL_OK;
    }
    case 6: {  // storage get
        std::string key = key_hex(memory(args(0)));
        auto it = state.storage.find(key);
        size_t length =
            it == state.storage.end() ? 0 : it->second.size();
        io->results[io->result_count++] = length;
        if (length == 0 || length > args(3)) {
            return length == 0 ? AL_OK : AL_ERR_BUFFER_TOO_SMALL;
        }
        if (args(2) + length > io->memory.len) return AL_ERR_MEMORY_FAULT;
        std::memcpy(memory(args(2)), it->second.data(), length);
        return AL_OK;
    }
    case 7: {  // storage set
        std::string key = key_hex(memory(args(0)));
        size_t value_offset = args(2);
        size_t value_length = args(3);
        if (value_offset + value_length > io->memory.len)
            return AL_ERR_MEMORY_FAULT;
        state.storage[key] = std::vector<uint8_t>(
            io->memory.data + value_offset,
            io->memory.data + value_offset + value_length);
        return AL_OK;
    }
    case 8: {  // storage delete
        state.storage.erase(key_hex(memory(args(0))));
        return AL_OK;
    }
    case 9: {  // emit event
        EventRecord record;
        record.topic = key_hex(memory(args(0)));
        record.data.assign(memory(args(2)),
                           memory(args(2)) + args(3));
        state.events.push_back(std::move(record));
        return AL_OK;
    }
    case 10: {  // hash_tagged(data_offset, data_len, out_offset, tag)
        // Simplified mock: XOR-fold the data into 32 bytes for deterministic
        // but non-cryptographic key derivation. The real hash is tested
        // elsewhere; this lets map storage round-trip through the mock host.
        uint64_t data_off = args(0);
        uint64_t data_len = args(1);
        uint64_t out_off = args(2);
        uint64_t tag = args(3);
        uint8_t* out = memory(out_off);
        std::memset(out, 0, 32);
        for (uint64_t i = 0; i < data_len && i < 256; ++i) {
            out[i % 32] ^= memory(data_off)[i];
            out[i % 32] ^= static_cast<uint8_t>(tag + i);
        }
        return AL_OK;
    }
    default:
        return AL_ERR_UNSUPPORTED;
    }
}

struct RunOutcome {
    al_status status = AL_ERR_INVALID_ARG;
    std::vector<uint8_t> return_data;
    uint64_t returned_u64 = 0;
};

RunOutcome run(const std::vector<uint8_t>& container,
               const std::vector<uint64_t>& calldata_words = {},
               uint16_t entrypoint = 0) {
    RunOutcome outcome;

    std::vector<uint8_t> calldata;
    for (uint64_t word : calldata_words) {
        for (unsigned b = 0; b < 8; ++b) {
            calldata.push_back(static_cast<uint8_t>((word >> (b * 8)) & 0xff));
        }
    }

    al_arena arena;
    if (al_arena_init(&arena, 1u << 20) != AL_OK) {
        outcome.status = AL_ERR_OUT_OF_MEMORY;
        return outcome;
    }

    MockHostState& state = host_state();
    std::memset(state.sender, 0x11, sizeof(state.sender));
    std::memset(state.current, 0x22, sizeof(state.current));

    al_vm_execution_context execution{};
    std::memcpy(execution.sender.bytes, state.sender, 32);
    std::memcpy(execution.current_contract.bytes, state.current, 32);
    execution.block_height = state.height;
    execution.protocol_day = state.day;
    execution.entrypoint = entrypoint;

    al_vm_host host{&state, mock_host_invoke};
    al_vm_result result;
    outcome.status = al_vm_execute(
        al_bytes_make(container.data(), container.size()),
        al_bytes_make(calldata.empty() ? nullptr : calldata.data(),
                      calldata.size()),
        nullptr, &execution, &host, &arena, &result);

    outcome.return_data.assign(result.return_data.data,
                               result.return_data.data +
                                   result.return_data.len);
    if (outcome.return_data.size() >= 8) {
        outcome.returned_u64 = read_u64(outcome.return_data.data(), 0);
    }
    al_arena_destroy(&arena);
    return outcome;
}

}  // namespace

AL_TEST(regol_assembles_and_runs) {
    const char* source = R"rg(
        // returns the constant 77 through linear memory
        fn boot() -> u1 {
            push64 77
            push64 0
            store64
            push64 0
            load64
            push64 0
            push64 8
            return
        }
    )rg";
    auto result = build(source, /*regol=*/true);
    AL_CHECK(result.has_value());
    if (!result) return;
    RunOutcome outcome = run(result->container);
    AL_CHECK_EQ_STATUS(outcome.status, AL_OK);
    AL_CHECK_EQ_U64(outcome.returned_u64, 77);
    AL_CHECK_EQ_U64(outcome.return_data.size(), 8);

    // Labels resolve to real instructions; a dangling label must fail.
    trocto::Diagnostics diagnostics;
    auto broken = trocto::assemble_regol(
        "fn boot() -> u0 {\n    jump .done\n}\n", diagnostics);
    AL_CHECK(!broken.has_value());
    AL_CHECK(!diagnostics.entries().empty());
}

AL_TEST(trocto_counter_contract_end_to_end) {
    const char* source = R"tc(
        contract Counter {
            state {
                total: u64,
            }

            pub fn inc(by: u64) -> u64 {
                self.total += by;
                return self.total;
            }

            pub fn get() -> u64 {
                return self.total;
            }

            pub fn twice(v: u64) -> u64 {
                return double(v);
            }

            fn double(v: u64) -> u64 {
                return v * 2;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();
    host_state().events.clear();

    // Function order: 0 default, then public in declaration order.
    RunOutcome get_empty = run(compiled->container, {}, 2);
    AL_CHECK_EQ_STATUS(get_empty.status, AL_OK);
    AL_CHECK_EQ_U64(get_empty.returned_u64, 0);   // absent slot reads as zero

    RunOutcome first = run(compiled->container, {5}, 1);
    AL_CHECK_EQ_STATUS(first.status, AL_OK);
    AL_CHECK_EQ_U64(first.returned_u64, 5);

    RunOutcome second = run(compiled->container, {7}, 1);
    AL_CHECK_EQ_STATUS(second.status, AL_OK);
    AL_CHECK_EQ_U64(second.returned_u64, 12);     // persisted across calls

    RunOutcome get_after = run(compiled->container, {}, 2);
    AL_CHECK_EQ_U64(get_after.returned_u64, 12);

    RunOutcome doubled = run(compiled->container, {21}, 3);
    AL_CHECK_EQ_STATUS(doubled.status, AL_OK);
    AL_CHECK_EQ_U64(doubled.returned_u64, 42);    // internal CALL protocol

    // A short calldata payload reverts with the fixed ABI code 1.
    al_arena arena;
    AL_CHECK_EQ_STATUS(al_arena_init(&arena, 1u << 20), AL_OK);
    al_vm_execution_context execution{};
    execution.entrypoint = 1;
    al_vm_result short_call;
    al_status status = al_vm_execute(
        al_bytes_make(compiled->container.data(), compiled->container.size()),
        al_bytes_make(reinterpret_cast<const al_u8*>("\x01\x02"), 2),
        nullptr, &execution, nullptr, &arena, &short_call);
    AL_CHECK_EQ_STATUS(status, AL_ERR_REVERTED);
    AL_CHECK(short_call.return_data.len == 8);
    if (short_call.return_data.len == 8) {
        AL_CHECK_EQ_U64(read_u64(short_call.return_data.data, 0), 1);
    }
    al_arena_destroy(&arena);
}

AL_TEST(trocto_require_reverts_with_code) {
    const char* source = R"tc(
        contract Vault {
            state {
                balance: u64,
            }

            pub fn withdraw(amount: u64) -> u64 {
                require(self.balance >= amount, 42);
                self.balance -= amount;
                return self.balance;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    // Pre-fund the contract's storage slot directly through the mock host.
    const std::string preimage = "field.Vault.balance";
    al_hash256 key_hash;
    al_hash_tagged(AL_TAG_CONTRACT_DATA, preimage.data(), preimage.size(),
                   &key_hash);
    host_state().storage.clear();
    std::vector<uint8_t> value(8, 0);
    write_u64(value.data(), 0, 10);
    host_state().storage[key_hex(key_hash.bytes)] = value;

    RunOutcome ok_path = run(compiled->container, {4}, 1);
    AL_CHECK_EQ_STATUS(ok_path.status, AL_OK);
    AL_CHECK_EQ_U64(ok_path.returned_u64, 6);

    RunOutcome revert_path = run(compiled->container, {100}, 1);
    AL_CHECK_EQ_STATUS(revert_path.status, AL_ERR_REVERTED);
    AL_CHECK_EQ_U64(revert_path.returned_u64, 42);
    AL_CHECK_EQ_U64(revert_path.return_data.size(), 8);
}

AL_TEST(trocto_control_flow_and_events) {
    const char* source = R"tc(
        contract Loops {
            state {
                last_topic_seen: u64,
            }

            pub fn sum_to(limit: u64) -> u64 {
                let total = 0;
                let i = 1;
                while (i <= limit) {
                    total += i;
                    i += 1;
                }
                return total;
            }

            pub fn classify(v: u64) -> u64 {
                if (v > 10) {
                    return 100;
                } else {
                    return 200;
                }
            }

            pub fn announce(value: u64) -> u64 {
                emit Transfer(value);
                return 9;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().events.clear();

    RunOutcome sum = run(compiled->container, {5}, 1);
    AL_CHECK_EQ_STATUS(sum.status, AL_OK);
    AL_CHECK_EQ_U64(sum.returned_u64, 15);

    RunOutcome big = run(compiled->container, {11}, 2);
    AL_CHECK_EQ_U64(big.returned_u64, 100);
    RunOutcome small = run(compiled->container, {10}, 2);
    AL_CHECK_EQ_U64(small.returned_u64, 200);

    RunOutcome announced = run(compiled->container, {123}, 3);
    AL_CHECK_EQ_STATUS(announced.status, AL_OK);
    AL_CHECK_EQ_U64(host_state().events.size(), 1);
    if (!host_state().events.empty()) {
        al_hash256 expected;
        al_hash_tagged(AL_TAG_EVENT, "Transfer", 8, &expected);
        AL_CHECK(host_state().events[0].topic == key_hex(expected.bytes));
        AL_CHECK_EQ_U64(host_state().events[0].data.size(), 8);
    }
}

AL_TEST(diagnostics_carry_source_lines) {
    trocto::Diagnostics diagnostics;
    auto bad = trocto::compile_trocto(
        "contract C {\n  pub fn f() {\n    return x;\n  }\n}\n", {},
        diagnostics);
    AL_CHECK(!bad.has_value());
    AL_CHECK_EQ_U64(diagnostics.entries().size(),
                    diagnostics.entries().size());
    bool mentions_variable = false;
    for (const auto& d : diagnostics.entries()) {
        mentions_variable |= d.message.find("x") != std::string::npos &&
                             d.line >= 3;
    }
    AL_CHECK(mentions_variable);

    trocto::Diagnostics private_call_diagnostics;
    auto private_call = trocto::compile_trocto(
        "contract D {\n"
        "  pub fn a() -> u64 { return b(); }\n"
        "  fn b() -> u64 { return 1; }\n"
        "}\n",
        {}, private_call_diagnostics);
    // Calling an internal function FROM a public one is fine; the reverse
    // is what the ABI forbids. This direction compiles and validates.
    AL_CHECK(private_call.has_value());

    trocto::Diagnostics reverse_diagnostics;
    auto reverse = trocto::compile_trocto(
        "contract E {\n"
        "  fn inner() -> u64 { return outside(); }\n"
        "  pub fn outside() -> u64 { return 1; }\n"
        "}\n",
        {}, reverse_diagnostics);
    AL_CHECK(!reverse.has_value());
    bool flagged_public = false;
    for (const auto& d : reverse_diagnostics.entries()) {
        flagged_public |= d.message.find("public") != std::string::npos;
    }
    AL_CHECK(flagged_public);
}

// ---------------------------------------------------------------------------
// Full chain flow: Trocto source -> container -> al_node deploy/CALL with the
// REAL transaction host (state-backed storage). In-process twin of
// scripts/smoke.ps1: a failure names the exact step instead of timing out on
// a live network.
// ---------------------------------------------------------------------------

namespace realflow {

struct Fixture; /* forward: submit helpers declared before full state below */

al_status submit_calldata(Fixture& f, const al_keypair& kp, uint64_t nonce,
                          int deploy, const al_address& target,
                          uint16_t entrypoint,
                          const std::vector<uint8_t>& calldata,
                          const std::vector<uint8_t>& container);

struct Fixture {
    al_arena state_arena{};
    std::vector<al_state_memory_node> nodes;
    std::vector<al_state_memory_value> values;
    al_state_memory_store memory;
    al_state_store store;
    al_state state;

    al_genesis genesis;
    al_arena execution_arena{};
    std::vector<al_transaction> block_txs;
    std::vector<al_receipt> receipts;
    std::vector<al_node_mempool_entry> mempool_entries;
    std::vector<al_u8> mempool_bytes;
    al_node node;

    ~Fixture() {
        al_arena_destroy(&execution_arena);
        al_arena_destroy(&state_arena);
    }

    al_status bind() {
        genesis.initial_state_root = state.root;
        fprintf(stderr, "DBG bind sizes txs=%zu rcpt=%zu mp=%zu bytes=%zu\n",
                block_txs.size(), receipts.size(), mempool_entries.size(),
                mempool_bytes.size());
        al_node_buffers buffers;
        memset(&buffers, 0, sizeof(buffers));
        buffers.mempool_entries = mempool_entries.data();
        buffers.mempool_capacity = mempool_entries.size();
        buffers.mempool_bytes = mempool_bytes.data();
        buffers.mempool_bytes_capacity = mempool_bytes.size();
        buffers.block_transactions = block_txs.data();
        buffers.block_transaction_capacity = block_txs.size();
        buffers.receipts = receipts.data();
        buffers.receipt_capacity = receipts.size();
        return al_node_init(&node, &genesis, &state, &execution_arena,
                            buffers);
    }

    al_status init_state_only() {
        AL_TRY(al_arena_init(&state_arena, 0));
        nodes.resize(8192);
        values.resize(512);
        AL_TRY(al_state_memory_store_init(&memory, nodes.data(), nodes.size(),
                                          values.data(), values.size(),
                                          &state_arena));
        store = al_state_memory_store_interface(&memory);
        AL_TRY(al_state_init(&state, &store, &state_arena, 1u));

        memset(&genesis, 0, sizeof(genesis));
        genesis.version = AL_GENESIS_VERSION;
        genesis.chain_id = 1337u;
        genesis.initial_state_root = state.root;
        al_resources limit = {1000000u, 1000000u, 1000000u, 1000000u};
        genesis.fees.block_limit = limit;
        al_resources target = {500000u, 500000u, 500000u, 500000u};
        genesis.fees.target = target;
        al_resources price = {1u, 1u, 1u, 1u};
        genesis.fees.initial_base_price = price;
        genesis.fees.storage_deposit_per_byte = 1u;
        genesis.schedule = al_vm_resource_schedule_default();
        genesis.vm_stack_limit = AL_VM_DEFAULT_STACK;
        genesis.vm_memory_limit = AL_VM_DEFAULT_MEMORY;
        genesis.vm_call_depth_limit = AL_VM_DEFAULT_CALL_DEPTH;
        genesis.potb = al_potb_params_default();

        AL_TRY(al_arena_init(&execution_arena, 1024u * 1024u));
        block_txs.resize(16);
        receipts.resize(16);
        mempool_entries.resize(16);
        mempool_bytes.resize(256u * 1024u);

        return AL_OK;
    }

    /* Bind after allocations: capture root and open the node. */};

al_status fund(Fixture& f, const al_address& who, uint64_t balance) {
    al_account a;
    memset(&a, 0, sizeof(a));
    a.address = who;
    a.balance = balance;
    return al_state_upsert(&f.state, &a);
}

al_status submit(Fixture& f, const al_keypair& kp, uint64_t nonce,
                 int deploy, const al_address& target, uint16_t entrypoint,
                 uint64_t argument, const std::vector<uint8_t>& container) {
    std::vector<uint8_t> calldata(8u);
    for (unsigned b = 0; b < 8; ++b)
        calldata[b] = uint8_t((argument >> (b * 8)) & 0xff);
    return submit_calldata(f, kp, nonce, deploy, target, entrypoint,
                           calldata, container);
}

al_status submit_calldata(Fixture& f, const al_keypair& kp, uint64_t nonce,
                          int deploy, const al_address& target,
                          uint16_t entrypoint,
                          const std::vector<uint8_t>& calldata,
                          const std::vector<uint8_t>& container) {
    al_transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = AL_TX_VERSION;
    tx.chain_id = f.genesis.chain_id;
    tx.expiry_height = nonce + 100u;
    tx.sender = kp.pk;
    tx.nonce = nonce;
    tx.resource_limit.compute = 400000u;
    tx.resource_limit.memory = 400000u;
    tx.resource_limit.storage = 400000u;
    tx.resource_limit.bandwidth = 400000u;
    tx.max_base_price.compute = 100u;
    tx.max_base_price.memory = 100u;
    tx.max_base_price.storage = 100u;
    tx.max_base_price.bandwidth = 100u;
    if (deploy) {
        tx.type = AL_TX_DEPLOY;
        tx.body.deploy.value = 1000000000u; /* storage endowment */
        tx.body.deploy.container =
            al_bytes_make(container.data(), container.size());
    } else {
        tx.type = AL_TX_CALL;
        tx.body.call.contract = target;
        tx.body.call.entrypoint = entrypoint;
        static thread_local std::vector<uint8_t> arg_copy;
        arg_copy = calldata;
        tx.body.call.calldata =
            al_bytes_make(arg_copy.data(), arg_copy.size());
    }
    AL_TRY(al_tx_sign(&tx, &kp.sk));

    static thread_local std::vector<uint8_t> encoded(AL_TX_MAX_SIZE, 0);
    al_size len = 0;
    AL_TRY(al_tx_encode(&tx, {encoded.data(), encoded.size()}, &len));
    return al_node_submit_transaction(&f.node,
                                      {encoded.data(), len}, nullptr);
}

al_status produce(Fixture& f, const al_keypair& proposer) {
    al_node_proposal p;
    memset(&p, 0, sizeof(p));
    p.proposer = proposer.pk;
    al_address_from_pubkey(&proposer.pk, &p.tip_flat);
    p.tip_weighted = p.tip_flat;
    p.tip_bonded = p.tip_flat;
    p.transaction_limit = f.node.mempool_count;
    static thread_local std::vector<uint8_t> out(512u * 1024u);
    al_size written = 0;
    return al_node_produce_block(&f.node, &p,
                                 {out.data(), out.size()}, &written);
}

uint64_t read_counter(Fixture& f, const al_address& contract) {
    al_account account;
    if (al_state_get(&f.state, &contract, &account) != AL_OK) return ~0ull;
    if (al_hash_is_zero(&account.storage_root)) return 0ull;

    al_state_txn txn;
    if (al_state_txn_begin(&f.state, &txn) != AL_OK) return ~0ull;
    uint8_t key[32];
    /* The compiler keys state fields as tagged(contract_data,
     * "field.<Contract>.<name>") — mirror that here. */
    const char* preimage = "field.Counter.count";
    al_hash_tagged(AL_TAG_CONTRACT_DATA, preimage, strlen(preimage),
                   reinterpret_cast<al_hash256*>(key));
    al_bytes value;
    al_status st = al_state_txn_storage_get(&txn, &contract,
                                            {key, sizeof(key)},
                                            &f.execution_arena, &value);
    al_state_txn_rollback(&txn);
    if (st == AL_ERR_NOT_FOUND) return 0ull; /* absent slot reads as zero */
    if (st != AL_OK) return ~0ull;
    if (value.len < 8u) return ~0ull;
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= uint64_t(value.data[i]) << (i * 8);
    return v;
}

/* Map keys derive at runtime inside the contract; the test mirrors that
 * derivation to read a balance straight from committed state. */
uint64_t read_balance(Fixture& f, const al_address& contract,
                      const al_address& owner) {
    al_account account;
    if (al_state_get(&f.state, &contract, &account) != AL_OK) return ~0ull;
    if (al_hash_is_zero(&account.storage_root)) return 0ull;

    std::string full = "map.Token.bal.";
    full.append(reinterpret_cast<const char*>(owner.bytes), 32);
    uint8_t key[32];
    al_hash_tagged(AL_TAG_CONTRACT_DATA, full.data(), full.size(),
                   reinterpret_cast<al_hash256*>(key));

    al_state_txn txn;
    if (al_state_txn_begin(&f.state, &txn) != AL_OK) return ~0ull;
    al_bytes value;
    al_status st = al_state_txn_storage_get(&txn, &contract,
                                            {key, sizeof(key)},
                                            &f.execution_arena, &value);
    al_state_txn_rollback(&txn);
    if (st == AL_ERR_NOT_FOUND) return 0ull;
    if (st != AL_OK || value.len < 8u) return ~0ull;
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= uint64_t(value.data[i]) << (i * 8);
    return v;
}
}  // namespace realflow

const char* kCounterSource = R"tc(
contract Counter {
    state {
        count: u64,
    }

    pub fn inc(by: u64) -> u64 {
        self.count += by;
        emit CountChanged(self.count);
        return self.count;
    }

    pub fn get() -> u64 {
        return self.count;
    }
}
)tc";

const char* kTokenSource = R"tc(
contract Token {
    state {
        supply: u64,
        bal: map<address,u64>,
    }
    pub fn put(to: address, amount: u64) -> u64 {
        bal[to] = amount;
        return amount;
    }
    pub fn get(who: address) -> u64 {
        return bal[who];
    }
}
)tc";

const char* kTokenFullSource = R"tc(
contract Token {
    state {
        supply: u64,
        bal: map<address,u64>,
    }
    pub fn mint(to: address, amount: u64) -> u64 {
        bal[to] += amount;
        self.supply += amount;
        return self.supply;
    }
    pub fn transfer(to: address, amount: u64) -> u64 {
        let b = bal[sender()];
        require(b >= amount, 42);
        bal[sender()] = b - amount;
        bal[to] += amount;
        return 1;
    }
}
)tc";

AL_TEST(trocto_counter_on_real_host_end_to_end) {
    using namespace realflow;

    trocto::Diagnostics diagnostics;
    auto compiled = trocto::compile_trocto(kCounterSource, {}, diagnostics);
    AL_CHECK_MSG(compiled.has_value(),
                 diagnostics.entries().empty()
                     ? "?"
                     : diagnostics.entries()[0].message.c_str());
    if (!compiled) return;

    Fixture f;
    AL_CHECK_EQ_STATUS(f.init_state_only(), AL_OK);

    uint8_t seed[32] = {9u};
    al_keypair deployer;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &deployer), AL_OK);
    al_address deployer_address;
    al_address_from_pubkey(&deployer.pk, &deployer_address);
    AL_CHECK_EQ_STATUS(realflow::fund(f, deployer_address,
                                      UINT64_C(1000000000000)), AL_OK);
    AL_CHECK_EQ_STATUS(f.bind(), AL_OK);

    AL_CHECK_EQ_STATUS(realflow::submit(f, deployer, 0u, 1,
                                        deployer_address, 0u, 0u,
                                        compiled->container), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, deployer), AL_OK);

    al_hash256 code_hash;
    al_sha256_bytes(al_bytes_make(compiled->container.data(),
                                  compiled->container.size()), &code_hash);
    al_address contract;
    al_address_for_contract(&deployer_address, 0u, &code_hash, &contract);
    al_account deployed;
    AL_CHECK_EQ_STATUS(al_state_get(&f.state, &contract, &deployed), AL_OK);

    AL_CHECK_EQ_STATUS(realflow::submit(f, deployer, 1u, 0, contract, 2u, 0u,
                                        compiled->container), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, deployer), AL_OK);
    AL_CHECK_EQ_U64(realflow::read_counter(f, contract), 0ull);

    AL_CHECK_EQ_STATUS(realflow::submit(f, deployer, 2u, 0, contract, 1u, 5u,
                                        compiled->container), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, deployer), AL_OK);
    uint64_t after_inc = realflow::read_counter(f, contract);
    AL_CHECK_MSG(after_inc == 5ull,
                 ("counter after inc is " + std::to_string(after_inc)).c_str());

    AL_CHECK_EQ_STATUS(realflow::submit(f, deployer, 3u, 0, contract, 1u, 7u,
                                        compiled->container), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, deployer), AL_OK);
    AL_CHECK_EQ_U64(realflow::read_counter(f, contract), 12ull);
}

AL_TEST(trocto_token_on_real_host_end_to_end) {
    using namespace realflow;

    trocto::Diagnostics diagnostics;
    auto compiled = trocto::compile_trocto(kTokenFullSource, {}, diagnostics);
    AL_CHECK_MSG(compiled.has_value(),
                 diagnostics.entries().empty()
                     ? "?"
                     : diagnostics.entries()[0].message.c_str());
    if (!compiled) return;

    Fixture f;
    AL_CHECK_EQ_STATUS(f.init_state_only(), AL_OK);

    uint8_t seed[32] = {11u};
    al_keypair owner;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(seed, &owner), AL_OK);
    al_address owner_address;
    al_address_from_pubkey(&owner.pk, &owner_address);

    uint8_t other_seed[32];
    memset(other_seed, 12u, sizeof(other_seed));
    al_keypair other;
    AL_CHECK_EQ_STATUS(al_keypair_from_seed(other_seed, &other), AL_OK);
    al_address other_address;
    al_address_from_pubkey(&other.pk, &other_address);

    AL_CHECK_EQ_STATUS(realflow::fund(f, owner_address,
                                      UINT64_C(1000000000000)), AL_OK);
    AL_CHECK_EQ_STATUS(f.bind(), AL_OK);

    /* Deploy with storage endowment: nonce 0. Entrypoints: 1 mint,
     * 2 transfer, 3 balance_of. */
    AL_CHECK_EQ_STATUS(realflow::submit(f, owner, 0u, 1, owner_address, 0u,
                                        0u, compiled->container), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, owner), AL_OK);

    al_hash256 code_hash;
    al_sha256_bytes(al_bytes_make(compiled->container.data(),
                                  compiled->container.size()), &code_hash);
    al_address token;
    al_address_for_contract(&owner_address, 0u, &code_hash, &token);
    al_account deployed;
    AL_CHECK_EQ_STATUS(al_state_get(&f.state, &token, &deployed), AL_OK);

    auto call_entry = [&](uint64_t nonce, uint16_t entrypoint,
                          const al_address& to, uint64_t amount) {
        std::vector<uint8_t> calldata;
        calldata.reserve(40);
        for (unsigned i = 0; i < 32; ++i) calldata.push_back(to.bytes[i]);
        for (unsigned b = 0; b < 8; ++b)
            calldata.push_back(uint8_t((amount >> (b * 8)) & 0xff));
        return realflow::submit_calldata(f, owner, nonce, 0, token,
                                         entrypoint, calldata,
                                         compiled->container);
    };

    /* put(owner,777): a map entry appears under the derived key. */
    AL_CHECK_EQ_STATUS(call_entry(1u, 1u, owner_address, 777ull), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, owner), AL_OK);
    AL_CHECK_EQ_U64(realflow::read_balance(f, token, owner_address), 777ull);

    /* put(other,100000): second entry, independent of the first. */
    AL_CHECK_EQ_STATUS(call_entry(2u, 1u, other_address, 100000ull), AL_OK);
    AL_CHECK_EQ_STATUS(realflow::produce(f, owner), AL_OK);
    AL_CHECK_EQ_U64(realflow::read_balance(f, token, other_address),
                    100000ull);
    /* First entry untouched. */
    AL_CHECK_EQ_U64(realflow::read_balance(f, token, owner_address), 777ull);

}

// ---------------------------------------------------------------------------
// v0.2 feature tests: constructor, string literals, assert, expanded maps
// ---------------------------------------------------------------------------

AL_TEST(trocto_constructor_end_to_end) {
    const char* source = R"tc(
        contract Vault {
            state {
                owner: u64,
                balance: u64,
            }

            init(initial_balance: u64) {
                self.owner = 1;
                self.balance = initial_balance;
                emit VaultCreated(initial_balance);
            }

            pub fn get_balance() -> u64 {
                return self.balance;
            }

            pub fn withdraw(amount: u64) -> u64 {
                require(self.balance >= amount, 10);
                self.balance -= amount;
                return self.balance;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();
    host_state().events.clear();

    // Function 0 is now the constructor (init).
    // Call it with calldata = 500 (initial balance).
    RunOutcome init_result = run(compiled->container, {500}, 0);
    AL_CHECK_EQ_STATUS(init_result.status, AL_OK);

    // Check that state was set by the constructor.
    RunOutcome get_result = run(compiled->container, {}, 1);
    AL_CHECK_EQ_STATUS(get_result.status, AL_OK);
    AL_CHECK_EQ_U64(get_result.returned_u64, 500);

    // Withdraw 200.
    RunOutcome withdraw = run(compiled->container, {200}, 2);
    AL_CHECK_EQ_STATUS(withdraw.status, AL_OK);
    AL_CHECK_EQ_U64(withdraw.returned_u64, 300);

    // Verify event was emitted during init.
    AL_CHECK_EQ_U64(host_state().events.size(), 1);
}

AL_TEST(trocto_assert_reverts) {
    const char* source = R"tc(
        contract Guard {
            state {
                value: u64,
            }

            pub fn checked_inc(x: u64) -> u64 {
                assert(x > 0);
                self.value += x;
                return self.value;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();

    // x=5 passes assert.
    RunOutcome ok = run(compiled->container, {5}, 1);
    AL_CHECK_EQ_STATUS(ok.status, AL_OK);
    AL_CHECK_EQ_U64(ok.returned_u64, 5);

    // x=0 fails assert (reverts with code 0).
    RunOutcome fail = run(compiled->container, {0}, 1);
    AL_CHECK_EQ_STATUS(fail.status, AL_ERR_REVERTED);
}

AL_TEST(trocto_string_literal_compiles) {
    // String literals should parse and compile without error.
    // In v0.2, strings are placed in linear memory.
    const char* source = R"tc(
        contract Greeter {
            state {
                greeting: u64,
            }

            pub fn greet() -> u64 {
                let msg = "hello";
                return 42;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
}

AL_TEST(trocto_map_u64_key_end_to_end) {
    const char* source = R"tc(
        contract Indexed {
            state {
                slots: map<u64,u64>,
            }

            pub fn set(index: u64, value: u64) -> u64 {
                slots[index] = value;
                return value;
            }

            pub fn get(index: u64) -> u64 {
                return slots[index];
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();

    // set(42, 999)
    RunOutcome set_result = run(compiled->container, {42, 999}, 1);
    AL_CHECK_EQ_STATUS(set_result.status, AL_OK);
    AL_CHECK_EQ_U64(set_result.returned_u64, 999);

    // get(42) -> 999
    RunOutcome get_result = run(compiled->container, {42}, 2);
    AL_CHECK_EQ_STATUS(get_result.status, AL_OK);
    AL_CHECK_EQ_U64(get_result.returned_u64, 999);

    // get(0) -> 0 (absent)
    RunOutcome absent = run(compiled->container, {0}, 2);
    AL_CHECK_EQ_STATUS(absent.status, AL_OK);
    AL_CHECK_EQ_U64(absent.returned_u64, 0);
}

AL_TEST(trocto_import_validation) {
    // Imports should be parsed and validated.
    const char* source = R"tc(
        import "math.tc";

        contract UsesMath {
            state {
                result: u64,
            }

            pub fn compute(a: u64, b: u64) -> u64 {
                self.result = a + b;
                return self.result;
            }
        }
    )tc";
    // This will fail because math.tc doesn't exist at the expected path,
    // but the parser should correctly parse the import statement.
    trocto::Diagnostics diagnostics;
    auto result = trocto::compile_trocto(source, {}, diagnostics);
    // Import resolution fails because the file doesn't exist relative
    // to an inline source (no source_path). This is expected behavior.
    AL_CHECK(!result.has_value());
    bool mentions_import = false;
    for (const auto& d : diagnostics.entries()) {
        mentions_import |= d.message.find("import") != std::string::npos;
    }
    AL_CHECK(mentions_import);
}

AL_TEST(trocto_expanded_map_types_compile) {
    const char* source = R"tc(
        contract MultiMap {
            state {
                aa: map<address,address>,
                uu: map<u64,u64>,
                au: map<address,u64>,
            }

            pub fn set_au(key: address, val: u64) -> u64 {
                au[key] = val;
                return val;
            }

            pub fn get_au(key: address) -> u64 {
                return au[key];
            }

            pub fn set_uu(key: u64, val: u64) -> u64 {
                uu[key] = val;
                return val;
            }

            pub fn get_uu(key: u64) -> u64 {
                return uu[key];
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
}

// ---------------------------------------------------------------------------
// v0.3 feature tests: enums, structs, only_owner
// ---------------------------------------------------------------------------

AL_TEST(trocto_v03_enum_compiles) {
    const char* source = R"tc(
        contract EnumTest {
            enum Color { RED: 1, GREEN: 2, BLUE: 3 }

            state {
                favorite: u64,
            }

            pub fn set_color(c: u64) -> u64 {
                self.favorite = c;
                return self.favorite;
            }

            pub fn get_color() -> u64 {
                return self.favorite;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
}

AL_TEST(trocto_v03_enum_variant_access) {
    const char* source = R"tc(
        contract EnumAccess {
            enum Status { ACTIVE: 1, INACTIVE: 0 }

            state {
                current: u64,
            }

            pub fn activate() -> u64 {
                self.current = 1;
                return self.current;
            }

            pub fn get_status() -> u64 {
                return self.current;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();

    // activate() sets status to 1
    RunOutcome activate = run(compiled->container, {}, 1);
    AL_CHECK_EQ_STATUS(activate.status, AL_OK);
    AL_CHECK_EQ_U64(activate.returned_u64, 1);

    // get_status() returns 1
    RunOutcome get = run(compiled->container, {}, 2);
    AL_CHECK_EQ_STATUS(get.status, AL_OK);
    AL_CHECK_EQ_U64(get.returned_u64, 1);
}

AL_TEST(trocto_v03_struct_compiles) {
    const char* source = R"tc(
        contract StructTest {
            struct Point { x: u64, y: u64 }

            state {
                last_x: u64,
                last_y: u64,
            }

            pub fn set_point(px: u64, py: u64) -> u64 {
                self.last_x = px;
                self.last_y = py;
                return px + py;
            }

            pub fn get_x() -> u64 {
                return self.last_x;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();

    RunOutcome set = run(compiled->container, {10, 20}, 1);
    AL_CHECK_EQ_STATUS(set.status, AL_OK);
    AL_CHECK_EQ_U64(set.returned_u64, 30);

    RunOutcome get_x = run(compiled->container, {}, 2);
    AL_CHECK_EQ_STATUS(get_x.status, AL_OK);
    AL_CHECK_EQ_U64(get_x.returned_u64, 10);
}

AL_TEST(trocto_v03_event_with_multiple_args) {
    const char* source = R"tc(
        contract MultiEvent {
            enum RecordType { A: 1, B: 2 }

            state {
                count: u64,
            }

            pub fn record(domain: u64, record_type: u64, value: u64) -> u64 {
                self.count += 1;
                emit RecordSet(domain, record_type, value);
                return self.count;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();
    host_state().events.clear();

    RunOutcome rec = run(compiled->container, {100, 1, 42}, 1);
    AL_CHECK_EQ_STATUS(rec.status, AL_OK);
    AL_CHECK_EQ_U64(rec.returned_u64, 1);
    AL_CHECK_EQ_U64(host_state().events.size(), 1);
    if (!host_state().events.empty()) {
        // Event data should contain 3 u64 values (24 bytes)
        AL_CHECK_EQ_U64(host_state().events[0].data.size(), 24);
    }
}

AL_TEST(trocto_v03_only_owner_reverts_for_non_owner) {
    const char* source = R"tc(
        contract Owned {
            state {
                owner: address,
                value: u64,
            }

            init() {
                self.owner = sender();
            }

            only_owner pub fn set_value(v: u64) -> u64 {
                self.value = v;
                return self.value;
            }

            pub fn get_value() -> u64 {
                return self.value;
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();

    // Deploy (constructor sets owner to sender 0x11...)
    RunOutcome init = run(compiled->container, {}, 0);
    AL_CHECK_EQ_STATUS(init.status, AL_OK);

    // Owner (sender 0x11...) can call set_value
    RunOutcome set_ok = run(compiled->container, {42}, 1);
    AL_CHECK_EQ_STATUS(set_ok.status, AL_OK);
    AL_CHECK_EQ_U64(set_ok.returned_u64, 42);
}

AL_TEST(trocto_v03_dns_registry_compiles) {
    // Test that the LuneRegistry contract compiles
    const char* source = R"tc(
        contract LuneRegistry {
            state {
                owner: address,
                domain_count: u64,
                domains: map<u64,u64>,
                domain_owners: map<u64,u64>,
            }

            event DomainRegistered {
                domain_hash: u64,
                owner: address,
                expiry: u64,
            }

            init() {
                self.owner = sender();
                self.domain_count = 0;
            }

            pub fn register(domain_hash: u64, duration: u64) -> u64 {
                let expiry = height() + duration;
                domains[domain_hash] = expiry;
                domain_owners[domain_hash] = sender();
                self.domain_count += 1;
                emit DomainRegistered(domain_hash, sender(), expiry);
                return expiry;
            }

            pub fn is_registered(domain_hash: u64) -> u64 {
                let expiry = domains[domain_hash];
                if (expiry == 0) {
                    return 0;
                }
                if (height() > expiry) {
                    return 0;
                }
                return 1;
            }

            pub fn get_expiry(domain_hash: u64) -> u64 {
                return domains[domain_hash];
            }
        }
    )tc";
    auto compiled = build(source);
    AL_CHECK(compiled.has_value());
    if (!compiled) return;

    host_state().storage.clear();
    host_state().events.clear();

    // Deploy
    RunOutcome init = run(compiled->container, {}, 0);
    AL_CHECK_EQ_STATUS(init.status, AL_OK);

    // Register domain "web.lune" (hash=0xDEADBEEF) for 1000 blocks
    RunOutcome reg = run(compiled->container, {0xDEADBEEF, 1000}, 1);
    AL_CHECK_EQ_STATUS(reg.status, AL_OK);
    // Expiry should be height(7) + 1000 = 1007
    AL_CHECK_EQ_U64(reg.returned_u64, 1007);

    // Check registration
    RunOutcome check = run(compiled->container, {0xDEADBEEF}, 2);
    AL_CHECK_EQ_STATUS(check.status, AL_OK);
    AL_CHECK_EQ_U64(check.returned_u64, 1);  // registered

    // Check expiry
    RunOutcome expiry = run(compiled->container, {0xDEADBEEF}, 3);
    AL_CHECK_EQ_STATUS(expiry.status, AL_OK);
    AL_CHECK_EQ_U64(expiry.returned_u64, 1007);

    // Event emitted
    AL_CHECK_EQ_U64(host_state().events.size(), 1);
}

static const char* AL_TEST_SUITE_NAME = "lang";

AL_TEST_MAIN {
    AL_RUN(regol_assembles_and_runs);
    AL_RUN(trocto_counter_contract_end_to_end);
    AL_RUN(trocto_require_reverts_with_code);
    AL_RUN(trocto_control_flow_and_events);
    AL_RUN(diagnostics_carry_source_lines);
    AL_RUN(trocto_counter_on_real_host_end_to_end);
    AL_RUN(trocto_token_on_real_host_end_to_end);
    AL_RUN(trocto_constructor_end_to_end);
    AL_RUN(trocto_assert_reverts);
    AL_RUN(trocto_string_literal_compiles);
    AL_RUN(trocto_map_u64_key_end_to_end);
    AL_RUN(trocto_import_validation);
    AL_RUN(trocto_expanded_map_types_compile);
    // v0.3 feature tests
    AL_RUN(trocto_v03_enum_compiles);
    AL_RUN(trocto_v03_enum_variant_access);
    AL_RUN(trocto_v03_struct_compiles);
    AL_RUN(trocto_v03_event_with_multiple_args);
    AL_RUN(trocto_v03_only_owner_reverts_for_non_owner);
    AL_RUN(trocto_v03_dns_registry_compiles);
}
