#!/usr/bin/env bash
# Four-validator quorum smoke test (bash).
#
#   bash scripts/consensus-smoke.sh [preset]
#
# Exits 0 when every assertion holds; any failure prints the collected node
# logs and exits 1.

set -euo pipefail

PRESET="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALNODE="$ROOT/build/$PRESET/bin/alnode"
WORK="$ROOT/build/consensus-smoke"

if [ ! -x "$ALNODE" ]; then
    echo "FAIL: $ALNODE not found - build first" >&2
    exit 1
fi

SEEDS=("3131313131313131313131313131313131313131313131313131313131313131"
       "3232323232323232323232323232323232323232323232323232323232323232"
       "3333333333333333333333333333333333333333333333333333333333333333"
       "3434343434343434343434343434343434343434343434343434343434343434")
P2P_PORTS=(46101 46102 46103 46104)
RPC_PORTS=(46201 46202 46203 46204)

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
    deadline=$(($(date +%s) + seconds))
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
pkill -f 'alnode.*4610' 2>/dev/null || true
pkill -f 'alnode.*4620' 2>/dev/null || true
sleep 0.5

rm -rf "$WORK"
mkdir -p "$WORK"

echo "== astrolune four-validator consensus smoke =="

# --- Identities and genesis ------------------------------------------------

ADDRESSES=()
PUBLIC_KEYS=()
for i in 0 1 2 3; do
    KEY_INFO=$("$ALNODE" keygen --seed "${SEEDS[$i]}")
    ADDRESSES+=("$(echo "$KEY_INFO" | grep '^address ' | awk '{print $2}')")
    PUBLIC_KEYS+=("$(echo "$KEY_INFO" | grep '^public_key ' | awk '{print $2}')")
done

"$ALNODE" init-genesis "$WORK/genesis.bin" 7331 \
    "${ADDRESSES[0]}=1000000000000000000" \
    "${ADDRESSES[1]}=1000000000" 2>/dev/null
check "four validator identities and genesis created" \
    "[ -f '$WORK/genesis.bin' ] && [ ${#PUBLIC_KEYS[@]} -eq 4 ]"

# --- Launch validators -----------------------------------------------------
#
# NOTE: alnode accepts only the split form `--flag value` for CLI options;
# the `--flag=value` form is rejected with "unknown flag". All options below
# use the split form.

# Node 0: peers to 1, 2
ARGS_0=('run' "$WORK/genesis.bin" '--no-config' '--datadir' "$WORK/node-0"
    '--p2p' "127.0.0.1:${P2P_PORTS[0]}" '--rpc' "127.0.0.1:${RPC_PORTS[0]}"
    '--proposer-seed' "${SEEDS[0]}" '--interval' '800' '--round-timeout' '1200'
    '--allow-insecure-crypto' '--unsafe-rpc')
for pk in "${PUBLIC_KEYS[@]}"; do ARGS_0+=('--validator' "$pk"); done
ARGS_0+=('--peer' "127.0.0.1:${P2P_PORTS[1]}" '--peer' "127.0.0.1:${P2P_PORTS[2]}")

"$ALNODE" "${ARGS_0[@]}" >"$WORK/node-0.out" 2>"$WORK/node-0.err" &
PID_0=$!
NODE_PIDS+=("$PID_0")

# Node 1: peers to 0
ARGS_1=('run' "$WORK/genesis.bin" '--no-config' '--datadir' "$WORK/node-1"
    '--p2p' "127.0.0.1:${P2P_PORTS[1]}" '--rpc' "127.0.0.1:${RPC_PORTS[1]}"
    '--proposer-seed' "${SEEDS[1]}" '--interval' '800' '--round-timeout' '1200'
    '--allow-insecure-crypto' '--unsafe-rpc')
for pk in "${PUBLIC_KEYS[@]}"; do ARGS_1+=('--validator' "$pk"); done
ARGS_1+=('--peer' "127.0.0.1:${P2P_PORTS[0]}")

"$ALNODE" "${ARGS_1[@]}" >"$WORK/node-1.out" 2>"$WORK/node-1.err" &
PID_1=$!
NODE_PIDS+=("$PID_1")

# Node 2: peers to 0
ARGS_2=('run' "$WORK/genesis.bin" '--no-config' '--datadir' "$WORK/node-2"
    '--p2p' "127.0.0.1:${P2P_PORTS[2]}" '--rpc' "127.0.0.1:${RPC_PORTS[2]}"
    '--proposer-seed' "${SEEDS[2]}" '--interval' '800' '--round-timeout' '1200'
    '--allow-insecure-crypto' '--unsafe-rpc')
for pk in "${PUBLIC_KEYS[@]}"; do ARGS_2+=('--validator' "$pk"); done
ARGS_2+=('--peer' "127.0.0.1:${P2P_PORTS[0]}")

"$ALNODE" "${ARGS_2[@]}" >"$WORK/node-2.out" 2>"$WORK/node-2.err" &
PID_2=$!
NODE_PIDS+=("$PID_2")

sleep 3

RUNNING=0
for i in 0 1 2; do
    pid_var="PID_$i"
    pid="${!pid_var}"
    if kill -0 "$pid" 2>/dev/null; then
        RUNNING=$((RUNNING + 1))
    else
        echo "  WARN node-$i (pid $pid) exited early" >&2
        [ -f "$WORK/node-$i.err" ] && head -10 "$WORK/node-$i.err" >&2
    fi
done
check "three validators running" "[ '$RUNNING' -eq 3 ]"

# --- Connectivity ----------------------------------------------------------

MESHED=false
if wait_for 20 "three-validator connectivity" \
    "rpc ${RPC_PORTS[0]} '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' | grep -q '\"peers\":[1-9]' && \
     rpc ${RPC_PORTS[1]} '{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"get_info\"}' | grep -q '\"peers\":[1-9]' && \
     rpc ${RPC_PORTS[2]} '{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"get_info\"}' | grep -q '\"peers\":[1-9]'"; then
    MESHED=true
fi
check "three live validators connected" "$MESHED"

if [ "$MESHED" = "false" ]; then
    echo "--- post-connectivity debug ---" >&2
    for i in 0 1 2; do
        echo "  node-$i stderr:" >&2
        [ -f "$WORK/node-$i.err" ] && tail -5 "$WORK/node-$i.err" >&2
    done
fi

# --- Transaction with one validator offline ---------------------------------

REPLY=$(rpc "${RPC_PORTS[0]}" \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"transfer\",\"params\":{\"to\":\"${ADDRESSES[1]}\",\"amount\":\"1000\"}}")
check "transaction accepted with one validator offline" \
    "echo '$REPLY' | grep -q '\"hash\"'" \
    "$REPLY"

FINALIZED=false
if wait_for 30 "quorum finality with one validator offline" \
    "rpc ${RPC_PORTS[0]} '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"get_info\"}' | grep -q '\"mempool\":0' && \
     rpc ${RPC_PORTS[0]} '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"get_info\"}' | sed -n 's/.*\"height\":\([0-9]*\).*/\1/p' > /tmp/h0 && \
     rpc ${RPC_PORTS[2]} '{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"get_info\"}' | sed -n 's/.*\"height\":\([0-9]*\).*/\1/p' > /tmp/h2 && \
     [ -s /tmp/h0 ] && [ -s /tmp/h2 ] && [ \"\$(cat /tmp/h0)\" = \"\$(cat /tmp/h2)\" ]"; then
    FINALIZED=true
fi
check "three of four validators finalize" "$FINALIZED"

# --- Lose quorum -----------------------------------------------------------

kill -9 "$PID_2" 2>/dev/null || true
wait "$PID_2" 2>/dev/null || true
sleep 1.5

check "second validator is offline" \
    "kill -0 $PID_2 2>/dev/null; [ \$? -ne 0 ]"

BEFORE=$(rpc "${RPC_PORTS[0]}" '{"jsonrpc":"2.0","id":6,"method":"get_info"}')
HEIGHT_BEFORE=$(echo "$BEFORE" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')

REPLY=$(rpc "${RPC_PORTS[0]}" \
    "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"transfer\",\"params\":{\"to\":\"${ADDRESSES[1]}\",\"amount\":\"1\"}}")
check "transaction accepted below quorum" \
    "echo '$REPLY' | grep -q '\"hash\"'" \
    "$REPLY"

sleep 6.5

AFTER=$(rpc "${RPC_PORTS[0]}" '{"jsonrpc":"2.0","id":8,"method":"get_info"}')
HEIGHT_AFTER=$(echo "$AFTER" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
check "two of four validators do not finalize" \
    "[ -n '$HEIGHT_BEFORE' ] && [ '$HEIGHT_AFTER' = '$HEIGHT_BEFORE' ]" \
    "$AFTER"
check "transaction remains pending below quorum" \
    "echo '$AFTER' | grep -q '\"mempool\":1'" \
    "$AFTER"

# --- Report ----------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "CONSENSUS SMOKE PASSED"
    exit 0
fi
echo "CONSENSUS SMOKE FAILED ($FAILURES assertion(s))"
for i in 0 1 2; do
    err="$WORK/node-$i.err"
    if [ -f "$err" ]; then
        echo "--- validator $i stderr ---"
        head -30 "$err"
    fi
done
exit 1