#!/bin/bash
# Build ant-node on a droplet and deploy to all workers
# This avoids glibc compatibility issues by building on the target OS

set -e

# Droplet IPs
WORKERS=(
    "142.93.52.129"   # ant-worker-1
    "24.199.82.114"   # ant-worker-2
    "192.34.62.192"   # ant-worker-3
    "159.223.131.196" # ant-worker-4
)

BUILD_HOST="${WORKERS[0]}"  # Build on first worker
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building ant-node on droplet ==="
echo "Build host: $BUILD_HOST"
echo ""

# Step 1: Install Rust and dependencies on build host
echo "=== Setting up build environment ==="
ssh -o StrictHostKeyChecking=no "root@${BUILD_HOST}" "
    set -e
    apt-get update
    apt-get install -y build-essential pkg-config libssl-dev curl git

    # Install Rust if not present
    if ! command -v cargo &> /dev/null; then
        echo 'Installing Rust...'
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
    fi
    source ~/.cargo/env
    rustc --version
    cargo --version
"

# Step 2: Clone and build the project
echo "=== Building ant-node ==="
ssh -o StrictHostKeyChecking=no "root@${BUILD_HOST}" "
    set -e
    source ~/.cargo/env

    # Clone or update the repo
    if [ -d /root/ant-node ]; then
        cd /root/ant-node
        git fetch origin
        git reset --hard origin/main
    else
        git clone https://github.com/WithAutonomi/ant-node.git /root/ant-node
        cd /root/ant-node
    fi

    # Build release binary (no logging)
    cargo build --release --no-default-features

    # Verify binary
    ls -la target/release/ant-node
    ./target/release/ant-node --version
"

# Step 3: Copy binary to /usr/local/bin on build host
echo "=== Installing on build host ==="
ssh -o StrictHostKeyChecking=no "root@${BUILD_HOST}" "
    cp /root/ant-node/target/release/ant-node /usr/local/bin/
    chmod +x /usr/local/bin/ant-node
    /usr/local/bin/ant-node --version
"

# Step 4: Copy scripts and configure build host
echo "=== Configuring build host ==="
scp -o StrictHostKeyChecking=no \
    "$SCRIPT_DIR/setup-limits.sh" \
    "$SCRIPT_DIR/spawn-nodes.sh" \
    "$SCRIPT_DIR/start-nodes.sh" \
    "$SCRIPT_DIR/check-health.sh" \
    "root@${BUILD_HOST}:/usr/local/bin/"

ssh -o StrictHostKeyChecking=no "root@${BUILD_HOST}" "
    chmod +x /usr/local/bin/*.sh
    /usr/local/bin/setup-limits.sh
    /usr/local/bin/spawn-nodes.sh 0
"

# Step 5: Deploy binary to other workers
echo "=== Deploying to other workers ==="
for i in 1 2 3; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))
    START_INDEX=$((i * 50))

    echo "Deploying to ant-worker-${WORKER_NUM} ($IP)..."

    # Copy binary from build host
    ssh -o StrictHostKeyChecking=no "root@${BUILD_HOST}" \
        "scp -o StrictHostKeyChecking=no /usr/local/bin/ant-node root@${IP}:/usr/local/bin/"

    # Copy scripts
    scp -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/setup-limits.sh" \
        "$SCRIPT_DIR/spawn-nodes.sh" \
        "$SCRIPT_DIR/start-nodes.sh" \
        "$SCRIPT_DIR/check-health.sh" \
        "root@${IP}:/usr/local/bin/"

    # Configure worker
    ssh -o StrictHostKeyChecking=no "root@${IP}" "
        chmod +x /usr/local/bin/*.sh
        chmod +x /usr/local/bin/ant-node
        /usr/local/bin/setup-limits.sh
        /usr/local/bin/spawn-nodes.sh ${START_INDEX}
    "

    echo "Worker ${WORKER_NUM} ready!"
done

echo ""
echo "=== Deployment Complete ==="
echo "All 4 workers configured with 50 nodes each (200 total)"
echo ""
echo "To start all nodes: ./start-all.sh"
