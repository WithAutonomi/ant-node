#!/bin/bash
# Autonomi Node Spawner - Deploy multiple nodes on a single host
# Usage: ./spawn-nodes.sh [count] [bootstrap1] [bootstrap2] ...
# Env: ANT_VERSION=0.1.0 to download a specific version from GitHub
set -euo pipefail

# Configuration
NODE_COUNT="${1:-10}"
shift || true
BOOTSTRAP_NODES=("${@:-165.22.4.178:12000 164.92.111.156:12000}")

# Directories
BASE_DIR="/var/lib/ant/nodes"
LOG_DIR="/var/log/ant"
BINARY_PATH="${ANT_BINARY:-/usr/local/bin/ant-node}"
METRICS_BASE_PORT="${METRICS_BASE_PORT:-9100}"
ANT_VERSION="${ANT_VERSION:-}"

# Resource limits per node
MEMORY_LIMIT="350M"
CPU_QUOTA="15%"

# Download binary from GitHub releases if version specified
download_binary() {
    local version="$1"
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64) PLATFORM="linux-x64" ;;
        aarch64) PLATFORM="linux-arm64" ;;
        *) echo "Unsupported architecture: $arch"; exit 1 ;;
    esac

    local url="https://github.com/WithAutonomi/ant-node/releases/download/v${version}/ant-node-cli-${PLATFORM}.tar.gz"

    echo "Downloading ant-node v${version} for ${PLATFORM}..."
    curl -L -o /tmp/ant-node.tar.gz "$url"

    echo "Extracting..."
    tar -xzf /tmp/ant-node.tar.gz -C /tmp
    mv /tmp/ant-node "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    rm -f /tmp/ant-node.tar.gz

    echo "Installed ant-node v${version} to $BINARY_PATH"
}

echo "=== Autonomi Multi-Node Spawner ==="
echo "Nodes to spawn: $NODE_COUNT"
echo "Bootstrap nodes: ${BOOTSTRAP_NODES[*]}"
echo "Binary: $BINARY_PATH"
echo "Base directory: $BASE_DIR"
echo ""

# Download if version specified and binary missing
if [[ -n "$ANT_VERSION" ]] && [[ ! -x "$BINARY_PATH" ]]; then
    download_binary "$ANT_VERSION"
fi

# Check binary exists
if [[ ! -x "$BINARY_PATH" ]]; then
    echo "ERROR: ant-node binary not found at $BINARY_PATH"
    echo "Set ANT_VERSION to download, or ANT_BINARY to use an existing binary"
    exit 1
fi

# Create directories
mkdir -p "$BASE_DIR" "$LOG_DIR"

# Create ant user if not exists
if ! id -u ant &>/dev/null; then
    useradd -r -s /bin/false ant || true
fi

# Build bootstrap args
BOOTSTRAP_ARGS=""
for bs in "${BOOTSTRAP_NODES[@]}"; do
    BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --bootstrap $bs"
done

# Spawn nodes
for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_DIR="$BASE_DIR/node-$i"
    METRICS_PORT=$((METRICS_BASE_PORT + i))
    SERVICE_NAME="ant-node-$i"

    echo "Creating node $i..."

    # Create node directory
    mkdir -p "$NODE_DIR"
    chown ant:ant "$NODE_DIR"

    # Create systemd service
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Autonomi Node $i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ant
Group=ant
ExecStart=$BINARY_PATH \\
    --root-dir $NODE_DIR \\
    --port 0 \\
    --metrics-port $METRICS_PORT \\
    --log-level info \\
    $BOOTSTRAP_ARGS
Restart=always
RestartSec=10

# Resource limits
MemoryMax=$MEMORY_LIMIT
CPUQuota=$CPU_QUOTA

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$NODE_DIR
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Logging
StandardOutput=append:$LOG_DIR/node-$i.log
StandardError=append:$LOG_DIR/node-$i.log

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable and start service
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    echo "  Started node $i on metrics port $METRICS_PORT"

    # Stagger starts to avoid overwhelming bootstrap nodes
    sleep 0.5
done

echo ""
echo "=== Deployment Complete ==="
echo "Spawned $NODE_COUNT nodes"
echo ""
echo "Check status with:"
echo "  systemctl status 'ant-node-*'"
echo "  ./manage-nodes.sh status"
echo ""
echo "View logs:"
echo "  journalctl -u ant-node-0 -f"
echo "  tail -f $LOG_DIR/node-0.log"
