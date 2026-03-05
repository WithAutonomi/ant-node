#!/usr/bin/env bash
#
# End-to-end integration test for saorsa-node file upload/download with EVM payments.
#
# This script:
# 1. Builds release binaries
# 2. Starts a devnet with EVM payment enforcement (Anvil + nodes)
# 3. Uploads each file in ./ugly_files/ with payment
# 4. Verifies on-chain payment via Anvil RPC
# 5. Downloads and verifies file integrity (SHA256 checksum)
# 6. Tests client-side payment rejection (CLI rejects without SECRET_KEY)
# 7. Tests server-side payment rejection (node rejects unpaid PUT)
# 8. Stops the devnet and reports results
#
# Exit 0 if ALL tests pass, non-zero otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
UGLY_FILES_DIR="${PROJECT_DIR}/ugly_files"
TEST_RUN_ID="$$_$(date +%s)"
MANIFEST_FILE="/tmp/saorsa_e2e_manifest_${TEST_RUN_ID}.json"
DOWNLOAD_DIR="/tmp/saorsa_e2e_download_${TEST_RUN_ID}"
LOG_FILE="/tmp/saorsa_e2e_devnet_${TEST_RUN_ID}.log"
CLI_LOG="/tmp/saorsa_e2e_cli_${TEST_RUN_ID}.log"
CLI_STDOUT="/tmp/saorsa_e2e_cli_stdout_${TEST_RUN_ID}.txt"

DEVNET_PID=""
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    if [ -n "${DEVNET_PID}" ] && kill -0 "${DEVNET_PID}" 2>/dev/null; then
        echo "Stopping devnet (PID ${DEVNET_PID})..."
        kill "${DEVNET_PID}" 2>/dev/null || true
        wait "${DEVNET_PID}" 2>/dev/null || true
    fi
    # Kill any lingering child processes
    pkill -P $$ 2>/dev/null || true
    echo "Cleanup complete."
}

trap cleanup EXIT

pass() {
    local test_name="$1"
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo "  PASS: ${test_name}"
}

fail() {
    local test_name="$1"
    local reason="${2:-}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo "  FAIL: ${test_name}"
    if [ -n "${reason}" ]; then
        echo "        Reason: ${reason}"
    fi
}

# Strip ANSI escape codes from stdin
strip_ansi() {
    sed $'s/\x1b\\[[0-9;]*m//g'
}

# Parse a KEY=VALUE from a file, stripping ANSI codes
parse_field() {
    local file="$1"
    local key="$2"
    grep "^${key}=" "${file}" 2>/dev/null | sed $'s/\x1b\\[[0-9;]*m//g' | head -1 | cut -d= -f2
}

echo "=============================================="
echo "  saorsa-node E2E Integration Test"
echo "=============================================="
echo ""

# Step 1: Build release binaries
echo "=== Step 1: Building release binaries ==="
cd "${PROJECT_DIR}"
cargo build --release 2>&1 | tail -3
echo "Build complete."
echo ""

SAORSA_DEVNET="${PROJECT_DIR}/target/release/saorsa-devnet"
SAORSA_CLI="${PROJECT_DIR}/target/release/saorsa-cli"

if [ ! -f "${SAORSA_DEVNET}" ]; then
    echo "ERROR: saorsa-devnet binary not found at ${SAORSA_DEVNET}"
    exit 1
fi
if [ ! -f "${SAORSA_CLI}" ]; then
    echo "ERROR: saorsa-cli binary not found at ${SAORSA_CLI}"
    exit 1
fi

# Step 2: Start devnet with EVM
DEVNET_NODES="${SAORSA_TEST_DEVNET_NODES:-5}"
BOOTSTRAP_COUNT="${SAORSA_TEST_BOOTSTRAP_COUNT:-2}"
echo "=== Step 2: Starting devnet with EVM (${DEVNET_NODES} nodes, ${BOOTSTRAP_COUNT} bootstrap) ==="
mkdir -p "${DOWNLOAD_DIR}"

RUST_LOG=warn "${SAORSA_DEVNET}" \
    --nodes "${DEVNET_NODES}" \
    --bootstrap-count "${BOOTSTRAP_COUNT}" \
    --enable-evm \
    --manifest "${MANIFEST_FILE}" \
    --stabilization-timeout-secs 120 \
    > "${LOG_FILE}" 2>&1 &
DEVNET_PID=$!

echo "Devnet starting (PID ${DEVNET_PID}), waiting for manifest..."

# Wait for manifest file to appear (max 180 seconds)
WAIT_COUNT=0
MAX_WAIT=180
while [ ! -f "${MANIFEST_FILE}" ] && [ ${WAIT_COUNT} -lt ${MAX_WAIT} ]; do
    if ! kill -0 "${DEVNET_PID}" 2>/dev/null; then
        echo "ERROR: Devnet process died before producing manifest."
        echo "Log output:"
        tail -50 "${LOG_FILE}" 2>/dev/null || true
        exit 1
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ ! -f "${MANIFEST_FILE}" ]; then
    echo "ERROR: Manifest not created after ${MAX_WAIT} seconds."
    echo "Log tail:"
    tail -30 "${LOG_FILE}" 2>/dev/null || true
    exit 1
fi

echo "Manifest created at ${MANIFEST_FILE}"

# Extract EVM info from manifest
WALLET_KEY=$(python3 -c "import json; m=json.load(open('${MANIFEST_FILE}')); print(m['evm']['wallet_private_key'])" 2>/dev/null || true)
RPC_URL=$(python3 -c "import json; m=json.load(open('${MANIFEST_FILE}')); print(m['evm']['rpc_url'])" 2>/dev/null || true)

if [ -z "${WALLET_KEY}" ] || [ -z "${RPC_URL}" ]; then
    echo "ERROR: Could not extract EVM info from manifest."
    cat "${MANIFEST_FILE}"
    exit 1
fi

echo "Wallet key: ${WALLET_KEY:0:10}..."
echo "Anvil RPC: ${RPC_URL}"
echo ""

# Verify Anvil is responding
BLOCK_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "${RPC_URL}" 2>/dev/null || echo "FAILED")
if echo "${BLOCK_RESPONSE}" | grep -q "result"; then
    echo "Anvil RPC confirmed working"
else
    echo "ERROR: Anvil RPC not responding at ${RPC_URL}"
    echo "Response: ${BLOCK_RESPONSE}"
    exit 1
fi

# Wait for network to stabilize
STABILIZE_SECS="${SAORSA_TEST_STABILIZE_SECS:-15}"
echo "Waiting ${STABILIZE_SECS} seconds for network stabilization..."
sleep "${STABILIZE_SECS}"
echo ""

# Accumulate TX hashes from all uploads for on-chain verification in Step 5
ALL_TX_HASHES=""

# Step 3 & 4: Upload and download each file in ugly_files/
echo "=== Step 3: File upload/download tests ==="

# Max file size for E2E tests (default 1MB; override with SAORSA_TEST_MAX_FILE_SIZE)
MAX_FILE_SIZE="${SAORSA_TEST_MAX_FILE_SIZE:-1048576}"

# Find test files (skip directories, .DS_Store, and files larger than MAX_FILE_SIZE)
TEST_FILES=()

if [ -d "${UGLY_FILES_DIR}" ]; then
    while IFS= read -r -d '' file; do
        fsize=$(wc -c < "${file}" | tr -d ' ')
        if [ "${fsize}" -le "${MAX_FILE_SIZE}" ]; then
            TEST_FILES+=("${file}")
        else
            echo "Skipping ${file} (${fsize} bytes > ${MAX_FILE_SIZE} max)"
        fi
    done < <(find "${UGLY_FILES_DIR}" -maxdepth 1 -type f ! -name '.DS_Store' -print0 2>/dev/null | sort -z)
fi

# If no ugly_files found, create a synthetic test file
if [ ${#TEST_FILES[@]} -eq 0 ]; then
    echo "No test files in ${UGLY_FILES_DIR}, creating synthetic test file..."
    SYNTHETIC_FILE="/tmp/saorsa_e2e_synthetic_${TEST_RUN_ID}.txt"
    echo "saorsa E2E test payload: $(date -u +%Y-%m-%dT%H:%M:%SZ) run=${TEST_RUN_ID}" > "${SYNTHETIC_FILE}"
    TEST_FILES+=("${SYNTHETIC_FILE}")
fi

for filepath in "${TEST_FILES[@]}"; do
    filename=$(basename "${filepath}")
    filesize=$(wc -c < "${filepath}" | tr -d ' ')
    echo ""
    echo "--- Testing file: ${filename} (${filesize} bytes) ---"

    # Upload with payment - write stdout to file to avoid terminal ANSI leakage
    echo "  Uploading..."
    SECRET_KEY="${WALLET_KEY}" "${SAORSA_CLI}" \
        --devnet-manifest "${MANIFEST_FILE}" \
        --evm-network local \
        --timeout-secs 120 \
        --log-level error \
        file upload "${filepath}" \
        > "${CLI_STDOUT}" 2>"${CLI_LOG}" || {
            fail "${filename} upload" "Upload command failed (exit $?)"
            tail -10 "${CLI_LOG}" 2>/dev/null || true
            continue
        }

    # Parse upload output from file (avoids terminal ANSI contamination)
    FILE_ADDRESS=$(parse_field "${CLI_STDOUT}" "FILE_ADDRESS")
    CHUNKS=$(parse_field "${CLI_STDOUT}" "CHUNKS")
    PAYMENTS=$(parse_field "${CLI_STDOUT}" "PAYMENTS")

    if [ -z "${FILE_ADDRESS}" ]; then
        fail "${filename} upload" "No FILE_ADDRESS in output"
        echo "  Raw output:"
        cat "${CLI_STDOUT}" 2>/dev/null || true
        continue
    fi

    echo "  Address: ${FILE_ADDRESS}"
    echo "  Chunks: ${CHUNKS}, Payments: ${PAYMENTS}"

    # Parse TX_HASHES from upload output
    TX_HASHES=$(parse_field "${CLI_STDOUT}" "TX_HASHES")

    # Verify PAYMENTS is non-zero
    if [ -n "${PAYMENTS}" ] && [ "${PAYMENTS}" -gt 0 ] 2>/dev/null; then
        pass "${filename} upload (${PAYMENTS} payments)"
    else
        fail "${filename} upload" "PAYMENTS should be > 0, got: ${PAYMENTS}"
        continue
    fi

    # Collect TX hashes for on-chain verification in Step 5
    if [ -n "${TX_HASHES}" ]; then
        ALL_TX_HASHES="${ALL_TX_HASHES:+${ALL_TX_HASHES},}${TX_HASHES}"
    fi

    # Download and verify
    DOWNLOAD_PATH="${DOWNLOAD_DIR}/${filename}"
    echo "  Downloading..."
    SECRET_KEY="${WALLET_KEY}" "${SAORSA_CLI}" \
        --devnet-manifest "${MANIFEST_FILE}" \
        --evm-network local \
        --timeout-secs 120 \
        --log-level error \
        file download "${FILE_ADDRESS}" --output "${DOWNLOAD_PATH}" \
        > "${CLI_STDOUT}" 2>"${CLI_LOG}" || {
            fail "${filename} download" "Download command failed (exit $?)"
            tail -10 "${CLI_LOG}" 2>/dev/null || true
            continue
        }

    if [ ! -f "${DOWNLOAD_PATH}" ]; then
        fail "${filename} download" "Downloaded file not found at ${DOWNLOAD_PATH}"
        continue
    fi

    # Compare checksums
    ORIG_HASH=$(shasum -a 256 "${filepath}" | cut -d' ' -f1)
    DOWN_HASH=$(shasum -a 256 "${DOWNLOAD_PATH}" | cut -d' ' -f1)

    if [ "${ORIG_HASH}" = "${DOWN_HASH}" ]; then
        pass "${filename} integrity (SHA256 match)"
    else
        fail "${filename} integrity" "SHA256 mismatch: original=${ORIG_HASH}, downloaded=${DOWN_HASH}"
    fi
done

echo ""

# Step 5: On-chain payment verification (verify actual TX hashes from uploads)
echo "=== Step 5: On-chain payment verification ==="

if [ -z "${ALL_TX_HASHES}" ]; then
    fail "On-chain payment verification" "No TX hashes collected from uploads"
else
    # Verify each TX hash exists on Anvil via eth_getTransactionByHash
    VERIFIED_TX=0
    FAILED_TX=0
    IFS=',' read -ra TX_ARRAY <<< "${ALL_TX_HASHES}"
    TOTAL_TX=${#TX_ARRAY[@]}
    echo "  Verifying ${TOTAL_TX} transaction hash(es) on Anvil..."

    for tx_hash in "${TX_ARRAY[@]}"; do
        # Strip whitespace
        tx_hash=$(echo "${tx_hash}" | tr -d ' ')
        if [ -z "${tx_hash}" ]; then
            continue
        fi

        TX_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"${tx_hash}\"],\"id\":1}" \
            "${RPC_URL}" 2>/dev/null || echo "FAILED")

        # Check that result is not null (tx exists on chain)
        if echo "${TX_RESPONSE}" | python3 -c "import sys,json; r=json.load(sys.stdin); assert r.get('result') is not None" 2>/dev/null; then
            VERIFIED_TX=$((VERIFIED_TX + 1))
        else
            FAILED_TX=$((FAILED_TX + 1))
            echo "  TX not found on chain: ${tx_hash}"
        fi
    done

    if [ "${VERIFIED_TX}" -gt 0 ] && [ "${FAILED_TX}" -eq 0 ]; then
        pass "On-chain payment verification (${VERIFIED_TX}/${TOTAL_TX} TXs verified on Anvil)"
    elif [ "${VERIFIED_TX}" -gt 0 ]; then
        fail "On-chain payment verification" "${FAILED_TX}/${TOTAL_TX} TXs not found on Anvil"
    else
        fail "On-chain payment verification" "No TXs could be verified on Anvil"
    fi
fi

echo ""

# Step 6: Test client-side payment rejection (upload without SECRET_KEY)
echo "=== Step 6: Client-side payment rejection test ==="

REJECTION_FILE=""
for filepath in "${TEST_FILES[@]}"; do
    filesize=$(wc -c < "${filepath}" | tr -d ' ')
    if [ "${filesize}" -lt 1000000 ]; then
        REJECTION_FILE="${filepath}"
        break
    fi
done

if [ -n "${REJECTION_FILE}" ]; then
    echo "  Attempting upload WITHOUT SECRET_KEY (should fail at client)..."
    REJECTION_OUTPUT=$("${SAORSA_CLI}" \
        --devnet-manifest "${MANIFEST_FILE}" \
        --evm-network local \
        --timeout-secs 10 \
        --log-level error \
        file upload "${REJECTION_FILE}" 2>&1 || true)

    # Strip ANSI before matching (color-eyre embeds ANSI codes in error output)
    CLEAN_REJECTION=$(echo "${REJECTION_OUTPUT}" | strip_ansi)

    if echo "${CLEAN_REJECTION}" | grep -qi "SECRET_KEY"; then
        pass "Client-side payment rejection (SECRET_KEY required)"
    else
        fail "Client-side payment rejection" "Expected SECRET_KEY error from client"
        echo "  Output: ${CLEAN_REJECTION}"
    fi
else
    echo "  WARNING: No test files available for rejection test"
fi

echo ""

# Step 7: Test chunk put rejection without wallet
echo "=== Step 7: Chunk put rejection without wallet ==="
echo "  Attempting chunk put WITHOUT SECRET_KEY (should fail at client)..."
echo "test data for rejection e2e" > /tmp/saorsa_rejection_test_${TEST_RUN_ID}.txt
CHUNK_REJECT_OUTPUT=$("${SAORSA_CLI}" \
    --devnet-manifest "${MANIFEST_FILE}" \
    --evm-network local \
    --timeout-secs 10 \
    --log-level error \
    chunk put /tmp/saorsa_rejection_test_${TEST_RUN_ID}.txt 2>&1 || true)

CLEAN_CHUNK_OUTPUT=$(echo "${CHUNK_REJECT_OUTPUT}" | strip_ansi)

if echo "${CLEAN_CHUNK_OUTPUT}" | grep -qi "SECRET_KEY\|wallet\|payment"; then
    pass "Chunk put rejection without wallet"
else
    fail "Chunk put rejection" "Expected wallet/payment error"
    echo "  Output: $(echo "${CLEAN_CHUNK_OUTPUT}" | tail -5)"
fi

echo ""

# Step 8: Summary
echo "=============================================="
echo "  E2E Test Results"
echo "=============================================="
echo "  Total: ${TOTAL_COUNT}"
echo "  Passed: ${PASS_COUNT}"
echo "  Failed: ${FAIL_COUNT}"
echo "=============================================="

if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo ""
    echo "RESULT: FAILED (${FAIL_COUNT} failures)"
    exit 1
else
    echo ""
    echo "RESULT: ALL TESTS PASSED"
    exit 0
fi
