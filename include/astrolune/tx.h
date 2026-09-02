/* astrolune/tx.h - canonical v1 transactions and receipt-producing execution. */

#ifndef ASTROLUNE_TX_H
#define ASTROLUNE_TX_H

#include "astrolune/arena.h"
#include "astrolune/base.h"
#include "astrolune/bytes.h"
#include "astrolune/crypto.h"
#include "astrolune/hash.h"
#include "astrolune/potb.h"
#include "astrolune/state.h"
#include "astrolune/vm.h"

AL_EXTERN_C_BEGIN

#define AL_TX_VERSION 1u
#define AL_TX_MAX_SIZE (1024u * 1024u)
#define AL_TX_MAX_PAYLOAD (AL_TX_MAX_SIZE - 256u)
#define AL_TX_MAX_EVENTS 64u

typedef enum al_tx_type {
    AL_TX_TRANSFER = 0,
    AL_TX_DEPLOY = 1,
    AL_TX_CALL = 2,
    AL_TX_POTB = 3,
    AL_TX_TYPE_SENTINEL = 0x7fffffff
} al_tx_type;

typedef enum al_potb_operation {
    AL_POTB_REGISTER = 0,
    AL_POTB_ATTEST = 1,
    AL_POTB_CHALLENGE = 2,
    AL_POTB_CHALLENGE_RESPONSE = 3,
    AL_POTB_OFFENCE_EVIDENCE = 4,
    AL_POTB_BOND_DEPOSIT = 5,
    AL_POTB_BOND_WITHDRAW = 6,
    AL_POTB_SEED_COMMIT = 7,
    AL_POTB_SEED_REVEAL = 8,
    AL_POTB_COMMITTEE_VOTE = 9,
    AL_POTB_OPERATION_SENTINEL = 0x7fffffff
} al_potb_operation;

typedef struct al_tx_transfer_body {
    al_address recipient;
    al_amount  amount;
} al_tx_transfer_body;

typedef struct al_tx_deploy_body {
    al_amount value;
    al_bytes  container;
} al_tx_deploy_body;

typedef struct al_tx_call_body {
    al_address contract;
    al_amount  value;
    al_u32     entrypoint;
    al_bytes   calldata;
} al_tx_call_body;

/* PoTB research decisions remain outside this layer. The operation tag fixes
 * the native schema while `data` carries its canonical, operation-specific
 * evidence. Native execution commits it below the reserved system account. */
typedef struct al_tx_potb_body {
    al_potb_operation operation;
    al_pubkey          target;
    al_amount          amount;
    al_bytes           data;
} al_tx_potb_body;

typedef union al_tx_body {
    al_tx_transfer_body transfer;
    al_tx_deploy_body   deploy;
    al_tx_call_body     call;
    al_tx_potb_body     potb;
} al_tx_body;

/* All cap fields are signed. `max_base_price` is per resource unit; `tip` is
 * paid in full once a transaction is included, including execution failures. */
typedef struct al_transaction {
    al_u16       version;
    al_u32       chain_id;
    al_height    expiry_height;
    al_pubkey    sender;
    al_nonce     nonce;
    al_resources resource_limit;
    al_resources max_base_price;
    al_amount    tip;
    al_tx_type   type;
    al_tx_body   body;
    al_sig       signature;
} al_transaction;

typedef struct al_event {
    al_address contract;
    al_hash256 topic;
    al_bytes   data;
} al_event;

typedef struct al_receipt {
    al_hash256   transaction_hash;
    al_status    status;
    al_resources resources;
    al_amount    base_fee_burned;
    al_amount    tip_paid;
    al_address   contract_address;
    al_bytes     return_data;
    al_event    *events;
    al_size      event_count;
} al_receipt;

typedef struct al_tx_context {
    al_u32       chain_id;
    al_height    block_height;
    al_u32       protocol_day;
    al_resources base_prices;
    /* The 60/25/15 PoTB buckets. Any rounding remainder goes to `flat`. */
    al_address   tip_flat;
    al_address   tip_weighted;
    al_address   tip_bonded;
    al_vm_config vm;
    al_arena    *arena;
    const al_potb_params *potb_params;
} al_tx_context;

AL_PUBLIC AL_NODISCARD al_status al_tx_validate_shape(
    const al_transaction *tx);
AL_PUBLIC al_size al_tx_encoded_size(const al_transaction *tx);
AL_PUBLIC AL_NODISCARD al_status al_tx_encode(
    const al_transaction *tx, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_tx_decode(al_bytes encoded,
                                              al_transaction *out);
AL_PUBLIC void al_tx_hash(const al_transaction *tx, al_hash256 *out);
AL_PUBLIC void al_tx_signing_hash(const al_transaction *tx, al_hash256 *out);
AL_PUBLIC AL_NODISCARD al_status al_tx_sign(al_transaction *tx,
                                            const al_seckey *secret_key);
AL_PUBLIC AL_NODISCARD al_status al_tx_verify(const al_transaction *tx);
AL_PUBLIC AL_NODISCARD al_status al_event_encode(
    const al_event *event, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_event_decode(al_bytes encoded,
                                                 al_event *out);
AL_PUBLIC void al_event_hash(const al_event *event, al_hash256 *out);
AL_PUBLIC AL_NODISCARD al_status al_receipt_encode(
    const al_receipt *receipt, al_bytes_mut out, al_size *written);
AL_PUBLIC AL_NODISCARD al_status al_receipt_decode(
    al_bytes encoded, al_arena *arena, al_receipt *out);
AL_PUBLIC void al_receipt_hash(const al_receipt *receipt, al_hash256 *out);

/* Pre-validation errors are returned directly and charge nothing. Once
 * execution starts this returns AL_OK and places success/revert/trap in the
 * receipt; inclusion consumes nonce, actual base fee and the full tip. */
AL_PUBLIC AL_NODISCARD al_status al_tx_apply(
    const al_transaction *tx, al_state *state, const al_tx_context *context,
    al_receipt *receipt);

AL_EXTERN_C_END
#endif /* ASTROLUNE_TX_H */
