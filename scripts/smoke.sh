#!/usr/bin/env bash
# Astrolune two-node smoke test (bash).
#
# Boots a real devnet on loopback: genesis with prefunded identities, two
# daemons connected over P2P, an RPC-initiated transfer on node A, and block
# propagation until node B's state reflects it.
#
#   bash scripts/smoke.sh [preset]
#
# Exits 0 when every assertion holds; any failure prints the collected node
# logs and exits 1. Requires only the built binaries (dev preset paths).

set -euo pipefail

PRESET="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALNODE="$ROOT/build/$PRESET/bin/alnode"
TROCTO="$ROOT/build/$PRESET/bin/trocto"
COUNTER="$ROOT/examples/counter.tc"
SMOKE="$ROOT/build/smoke"

if [ ! -x "$ALNODE" ]; then
    echo "FAIL: $ALNODE not found - build first" >&2
    exit 1
fi

# Deterministic devnet identities: same seeds, same addresses, every run.
SEED_A="1111111111111111111111111111111111111111111111111111111111111111"
SEED_B="2222222222222222222222222222222222222222222222222222222222222222"
PORT_A=45101; RPC_A=45201
PORT_B=45102; RPC_B=45202

FAILURES=0
NODE_PIDS=()

check() {
    local name="$1" condition="$2" detail="${3:-}"
    if eval "$condition" >/dev/null 2>&1; then
        echo "  ok   $name"
    else
        echo "  FAIL $name"
        [ -n "$detail" ] && echo "       -> $detail"
        FAILURES=$((FAILURES + 1))
    fi
}

rpc() {
    local port="$1" body="$2"
    curl -s -X POST "http://127.0.0.1:$port" \
        -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

wait_for() {
    local seconds="$1" what="$2"
    shift 2
    local deadline
    deadline=$(date -u -d "+${seconds} seconds" +%s 2>/dev/null || \
               date -u -v+${seconds}S +%s 2>/dev/null || \
               echo $(( $(date +%s) + seconds )))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if eval "$*" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "  timeout waiting for: $what"
    return 1
}

cleanup() {
    for pid in "${NODE_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# --- Reset ----------------------------------------------------------------

# Kill any leftover alnode processes from prior runs on these ports.
pkill -f 'alnode.*451' 2>/dev/null || true
pkill -f 'alnode.*452' 2>/dev/null || true
sleep 0.5

rm -rf "$SMOKE"
mkdir -p "$SMOKE"

echo "== astrolune smoke =="

# --- Identities and genesis ------------------------------------------------

KEY_INFO_A=$("$ALNODE" keygen --seed "$SEED_A")
KEY_INFO_B=$("$ALNODE" keygen --seed "$SEED_B")
ADDR_A=$(echo "$KEY_INFO_A" | grep '^address ' | awk '{print $2}')
ADDR_B=$(echo "$KEY_INFO_B" | grep '^address ' | awk '{print $2}')
PUB_A=$(echo "$KEY_INFO_A" | grep '^public_key ' | awk '{print $2}')
PUB_B=$(echo "$KEY_INFO_B" | grep '^public_key ' | awk '{print $2}')

check "keygen derives stable addresses" \
    "true" \
    ""

"$ALNODE" init-genesis "$SMOKE/genesis.bin" 1337 \
    "$ADDR_A=1000000000000000000" "$ADDR_B=5000000000000" 2>/dev/null
check "genesis with allocations created" \
    "[ -f '$SMOKE/genesis.bin' ]"

# --- Config files ----------------------------------------------------------

cat > "$SMOKE/nodeA-config.toml" <<EOF
version = 1
[node]
data_dir = "$SMOKE/nodeA"
allow_insecure_crypto = true
[log]
level = "info"
[p2p]
enabled = true
host = "127.0.0.1"
port = $PORT_A
[rpc]
enabled = true
host = "127.0.0.1"
port = $RPC_A
unsafe_methods = true
[consensus]
round_timeout_ms = 1500
validators = ["$PUB_A", "$PUB_B"]
[proposer]
seed = "$SEED_A"
[blocks]
interval_ms = 1000
EOF

cat > "$SMOKE/nodeB-config.toml" <<EOF
version = 1
[node]
data_dir = "$SMOKE/nodeB"
allow_insecure_crypto = true
[log]
level = "info"
[p2p]
enabled = true
host = "127.0.0.1"
port = $PORT_B
[rpc]
enabled = true
host = "127.0.0.1"
port = $RPC_B
unsafe_methods = true
[consensus]
round_timeout_ms = 1500
validators = ["$PUB_A", "$PUB_B"]
[proposer]
seed = "$SEED_B"
[blocks]
interval_ms = 1000
[bootstrap]
peer = "127.0.0.1:$PORT_A"
EOF

# --- Launch ----------------------------------------------------------------

"$ALNODE" run "$SMOKE/genesis.bin" --config "$SMOKE/nodeA-config.toml" \
    --datadir "$SMOKE/nodeA" >"$SMOKE/a.out" 2>"$SMOKE/a.err" &
PID_A=$!
NODE_PIDS+=("$PID_A")

"$ALNODE" run "$SMOKE/genesis.bin" --config "$SMOKE/nodeB-config.toml" \
    --datadir "$SMOKE/nodeB" >"$SMOKE/b.out" 2>"$SMOKE/b.err" &
PID_B=$!
NODE_PIDS+=("$PID_B")

sleep 1

# --- Peering -------------------------------------------------------------

check "both nodes running" \
    "kill -0 $PID_A 2>/dev/null && kill -0 $PID_B 2>/dev/null"

PEERED=false
if wait_for 15 "peer handshake" \
    "rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' | grep -q '\"peers\":1'"; then
    PEERED=true
fi
check "nodes peer over P2P" "$PEERED"

# --- Transfer A -> B -----------------------------------------------------

AMOUNT="25000000000"
REPLY=$(rpc "$RPC_A" \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"transfer\",\"params\":{\"to\":\"$ADDR_B\",\"amount\":\"$AMOUNT\"}}")
check "transfer accepted into mempool" \
    "echo '$REPLY' | grep -q '\"hash\"'" \
    "$REPLY"

# --- Propagation and execution on B ---------------------------------------

EXPECTED=$((5000000000000 + AMOUNT))
SETTLED=false
if wait_for 20 "block propagation and execution" \
    "rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"get_account\",\"params\":{\"address\":\"$ADDR_B\"}}' | grep -q '\"balance\":$EXPECTED'"; then
    SETTLED=true
fi
check "transfer executed on remote node" "$SETTLED"

# --- Chain agreement ------------------------------------------------------

INFO_A=$(rpc "$RPC_A" '{"jsonrpc":"2.0","id":4,"method":"get_info"}')
INFO_B=$(rpc "$RPC_B" '{"jsonrpc":"2.0","id":5,"method":"get_info"}')
H_A=$(echo "$INFO_A" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
H_B=$(echo "$INFO_B" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
check "heights agree across nodes" \
    "[ -n '$H_A' ] && [ '$H_A' = '$H_B' ]"
check "produced block included the transfer" \
    "echo '$INFO_A' | grep -q '\"mempool\":0'"

G_A=$(echo "$INFO_A" | sed -n 's/.*"genesis":"0x\([0-9a-f]*\)".*/\1/p')
G_B=$(echo "$INFO_B" | sed -n 's/.*"genesis":"0x\([0-9a-f]*\)".*/\1/p')
check "same genesis binding" "[ '$G_A' = '$G_B' ]"

# --- Restart from finalized storage ----------------------------------------

kill -9 "$PID_B" 2>/dev/null || true
wait "$PID_B" 2>/dev/null || true
sleep 0.5
FINALITY_SIZE=$(stat -c%s "$SMOKE/nodeB/finality.log" 2>/dev/null || \
                stat -f%z "$SMOKE/nodeB/finality.log" 2>/dev/null || echo 0)
# Corrupt the finality log tail
printf '\x41\x4c\x46\x43\x01' >> "$SMOKE/nodeB/finality.log"

"$ALNODE" run "$SMOKE/genesis.bin" --config "$SMOKE/nodeB-config.toml" \
    --datadir "$SMOKE/nodeB" >"$SMOKE/b-restart.out" 2>"$SMOKE/b-restart.err" &
PID_B=$!
NODE_PIDS[${#NODE_PIDS[@]}-1]=$PID_B

RESTARTED=false
if wait_for 20 "validator restart with peer" \
    "rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"get_info\"}' | grep -q '\"height\":' && \
     rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"get_info\"}' | grep -q '\"peers\":[1-9]'"; then
    RESTARTED=true
fi
check "validator restarts from finalized storage" "$RESTARTED"

FINALITY_SIZE_AFTER=$(stat -c%s "$SMOKE/nodeB/finality.log" 2>/dev/null || \
                       stat -f%z "$SMOKE/nodeB/finality.log" 2>/dev/null || echo 0)
check "recovery truncates an incomplete finality record" \
    "[ '$FINALITY_SIZE_AFTER' = '$FINALITY_SIZE' ]"

RECOVERED=$(rpc "$RPC_B" \
    "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"get_account\",\"params\":{\"address\":\"$ADDR_B\"}}")
check "finalized state survives restart" \
    "echo '$RECOVERED' | grep -q '\"balance\":$EXPECTED'"

# Wait for restarted node B to fully catch up with A before deploying.
SYNCED=false
if wait_for 30 "post-restart chain sync" \
    "rpc $RPC_A '{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"get_info\"}' | \
     sed -n 's/.*\"height\":\([0-9]*\).*/\1/p' > /tmp/h_a && \
     rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"get_info\"}' | \
     sed -n 's/.*\"height\":\([0-9]*\).*/\1/p' > /tmp/h_b && \
     [ -s /tmp/h_a ] && [ -s /tmp/h_b ] && [ \"\$(cat /tmp/h_a)\" = \"\$(cat /tmp/h_b)\" ]"; then
    SYNCED=true
fi
check "post-restart chain sync" "$SYNCED"

# --- Contract deployment (Trocto -> container -> DEPLOY tx) ----------------

if [ ! -x "$TROCTO" ]; then
    echo "  FAIL trocto binary not found" >&2
    FAILURES=$((FAILURES + 1))
else
    "$TROCTO" "$COUNTER" -o "$SMOKE/counter.bin"
    check "trocto compiles counter contract" "[ -f '$SMOKE/counter.bin' ]"

    # Nonces must track everything this signer already sent on chain.
    GET_NONCE() {
        local port="$1" owner="$2"
        local acc
        acc=$(rpc "$port" \
            "{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"get_account\",\"params\":{\"address\":\"$owner\"}}")
        echo "$acc" | sed -n 's/.*"nonce":\([0-9]*\).*/\1/p'
    }

    DEPLOY_NONCE=$(GET_NONCE "$RPC_A" "$ADDR_A")
    CONTRACT=$("$ALNODE" contract-address "$SMOKE/counter.bin" --seed "$SEED_A" --nonce "$DEPLOY_NONCE")
    check "contract address derived" "echo '$CONTRACT' | grep -q '^al1'"

    "$ALNODE" make-tx deploy "$SMOKE/counter.bin" \
        -o "$SMOKE/deploy.txhex" --seed "$SEED_A" --nonce "$DEPLOY_NONCE" \
        --chain-id 1337 --value 1000000000 2>/dev/null
    DEPLOY_HEX=$(cat "$SMOKE/deploy.txhex")
    DEPLOY_REPLY=$(rpc "$RPC_A" \
        "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"send_raw_transaction\",\"params\":{\"data\":\"0x$DEPLOY_HEX\"}}")
    check "deploy transaction accepted" \
        "echo '$DEPLOY_REPLY' | grep -q '\"hash\"'" \
        "$DEPLOY_REPLY"

    # Wait for a block containing it, then read state through node B.
    DEPLOYED=false
    if wait_for 25 "contract deployed and readable from peer" \
        "rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"dry_run_call\",\"params\":{\"to\":\"$CONTRACT\",\"entrypoint\":2}}' | grep -q '\"status\":\"ok\"'"; then
        DEPLOYED=true
    fi
    check "contract deployed on chain" "$DEPLOYED"

    GET_ZERO=$(rpc "$RPC_B" \
        "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"dry_run_call\",\"params\":{\"to\":\"$CONTRACT\",\"entrypoint\":2}}")
    check "counter starts at zero" \
        "echo '$GET_ZERO' | grep -q '\"data\":\"0x0000000000000000\"'"

    # inc(5) submitted to A; executed in a block; visible via B.
    # the deployment has already been accepted into the mempool with nonce == DEPLOY_NONCE, so
    # the next nonce for the same signatory is DEPLOY_NONCE + 1.
    INC_NONCE=$((DEPLOY_NONCE + 1))
    "$ALNODE" make-tx call "$CONTRACT" 1 -a 5 \
        -o "$SMOKE/inc.txhex" --seed "$SEED_A" --nonce "$INC_NONCE" \
        --chain-id 1337 2>/dev/null
    INC_HEX=$(cat "$SMOKE/inc.txhex")
    INC_REPLY=$(rpc "$RPC_A" \
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"send_raw_transaction\",\"params\":{\"data\":\"0x$INC_HEX\"}}")
    check "increment accepted into mempool" \
        "echo '$INC_REPLY' | grep -q '\"hash\"'" \
        "$INC_REPLY"

    COUNTED=false
    if wait_for 10 "state change propagated and readable" \
        "rpc $RPC_B '{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"dry_run_call\",\"params\":{\"to\":\"$CONTRACT\",\"entrypoint\":2}}' | grep -q '\"data\":\"0x0500000000000000\"'"; then
        COUNTED=true
    fi
    check "on-chain counter equals 5 via remote node" "$COUNTED"

    # --- Quorum loss: stop B, send tx, verify no finalization ----------------

    kill -9 "$PID_B" 2>/dev/null || true
    wait "$PID_B" 2>/dev/null || true

    DISCONNECTED=false
    if wait_for 10 "validator disconnect" \
        "rpc $RPC_A '{\"jsonrpc\":\"2.0\",\"id\":16,\"method\":\"get_info\"}' | grep -q '\"peers\":0'"; then
        DISCONNECTED=true
    fi
    check "validator disconnect is observed" "$DISCONNECTED"

    sleep 0.5
    BEFORE_PARTITION=$(rpc "$RPC_A" '{"jsonrpc":"2.0","id":19,"method":"get_info"}')
    PARTITION_HEIGHT=$(echo "$BEFORE_PARTITION" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')

    ROLLBACK_REPLY=$(rpc "$RPC_A" \
        "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"transfer\",\"params\":{\"to\":\"$ADDR_B\",\"amount\":\"1\"}}")
    check "transaction accepted before quorum loss" \
        "echo '$ROLLBACK_REPLY' | grep -q '\"hash\"'"

    sleep 4.5

    AFTER_PARTITION=$(rpc "$RPC_A" '{"jsonrpc":"2.0","id":18,"method":"get_info"}')
    AFTER_HEIGHT=$(echo "$AFTER_PARTITION" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
    check "block is not finalized without quorum" \
        "[ -n '$PARTITION_HEIGHT' ] && [ '$AFTER_HEIGHT' = '$PARTITION_HEIGHT' ]"
    check "round rollback restores the mempool" \
        "echo '$AFTER_PARTITION' | grep -q '\"mempool\":1'"
fi

# --- Report ----------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "SMOKE PASSED"
    exit 0
fi
echo "SMOKE FAILED ($FAILURES assertion(s))"
for tag in a b b-restart; do
    err="$SMOKE/$tag.err"
    if [ -f "$err" ]; then
        echo "--- node $tag stderr ---"
        head -30 "$err"
    fi
done
exit 1