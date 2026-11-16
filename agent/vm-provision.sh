#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="${SCRIPT_DIR}/../.vms"
AGENT_DIR="${SCRIPT_DIR}"
OS="$1"

if [ -z "$OS" ]; then
    echo "Usage: $0 <os>"
    echo "  os: macos, ubuntu, windows"
    exit 1
fi

if [ "$(uname)" != "Darwin" ]; then
    echo "Error: This project must be run on macOS only"
    exit 1
fi

# Load environment variables
ENV_FILE="$SCRIPT_DIR/../secrets/.env.local"
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# Set defaults if not in .env
MACOS_IMAGE="${ZEDR_VM_MACOS_IMAGE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
MACOS_VM_NAME="${ZEDR_VM_MACOS_NAME:-zedr-macos-sequoia}"
UBUNTU_VER="${ZEDR_VM_UBUNTU_VERSION:-24.04}"
UBUNTU_RELEASE="${ZEDR_VM_UBUNTU_RELEASE:-live-server}"
WINDOWS_VER="${ZEDR_VM_WINDOWS_VERSION:-11}"

# Display args: empty lets quickemu choose best default
DISPLAY_ARGS=""

case "$OS" in
    macos)
        echo "Starting macOS VM with Tart..."
        
        export TART_HOME="$VM_DIR/tart"
        mkdir -p "$TART_HOME"
        
        if ! tart list | grep -q "^$MACOS_VM_NAME"; then
            echo "Cloning macOS image: $MACOS_IMAGE"
            tart clone "$MACOS_IMAGE" "$MACOS_VM_NAME"
        fi
        
        echo "Stopping any running VMs..."
        tart list | grep "running" | awk '{print $2}' | xargs -I {} tart stop {} 2>/dev/null || true
        
        TART_ARGS="--no-graphics"
        
        echo "Starting VM and running agent..."
        tart run $TART_ARGS --dir="$AGENT_DIR" "$MACOS_VM_NAME" &
        TART_PID=$!
        
        sleep 10
        VM_IP=$(tart ip "$MACOS_VM_NAME")
        echo "VM IP: $VM_IP"
        
        SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no"
        
        echo "Waiting for SSH..."
        for i in {1..30}; do
            if sshpass -p admin ssh $SSH_OPTS -o ConnectTimeout=2 admin@"$VM_IP" "echo connected" 2>/dev/null; then
                break
            fi
            sleep 2
        done
        
        echo "Installing Rust in VM..."
        sshpass -p admin ssh $SSH_OPTS admin@"$VM_IP" "
            if ! command -v cargo &> /dev/null; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                source ~/.cargo/env
            fi
        "
        
        echo "Building and running agent..."
        sshpass -p admin ssh $SSH_OPTS admin@"$VM_IP" "
            source ~/.cargo/env && \
            cd '/Volumes/My Shared Files' && \
            cargo build --release -p zedr-agent-macos && \
            ./target/release/zedr-agent-macos
        "
        
        tart stop "$MACOS_VM_NAME"
        ;;
        
    ubuntu)
        echo "Starting Ubuntu $UBUNTU_VER Server VM..."
        cd "$VM_DIR"
        
        VM_SUBDIR="ubuntu-server-$UBUNTU_VER"
        CLOUD_IMG="$VM_SUBDIR/ubuntu-24.04-server-cloudimg-amd64.img"
        DISK_FILE="$VM_SUBDIR/disk.qcow2"
        
        if [ ! -f "$CLOUD_IMG" ]; then
            echo "Error: Cloud image not found at $CLOUD_IMG"
            echo "Download it with:"
            echo "  curl -L -o $CLOUD_IMG https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
            exit 1
        fi
        
        if [ ! -f "$DISK_FILE" ]; then
            echo "Creating disk from cloud image..."
            mkdir -p "$VM_SUBDIR"
            qemu-img create -f qcow2 -F qcow2 -b "$CLOUD_IMG" "$DISK_FILE" 32G
            NEEDS_INSTALL=1
        else
            DISK_INFO=$(qemu-img info "$DISK_FILE" | grep "disk size:")
            if echo "$DISK_INFO" | grep -q "GiB"; then
                NEEDS_INSTALL=0
            elif echo "$DISK_INFO" | grep -qE "[0-9]+ MiB" && [ "$(echo "$DISK_INFO" | grep -oE '[0-9]+' | head -1)" -gt 500 ]; then
                NEEDS_INSTALL=0
            else
                NEEDS_INSTALL=1
            fi
        fi
        
        if [ "$NEEDS_INSTALL" -eq 1 ]; then
            echo "First boot - configuring cloud image with cloud-init..."
            
            cat > "$VM_SUBDIR/user-data" << 'EOF'
#cloud-config
password: zedr
chpasswd: { expire: False }
ssh_pwauth: True
EOF
            
            cat > "$VM_SUBDIR/meta-data" << EOF
instance-id: zedr-ubuntu
local-hostname: zedr-ubuntu
EOF
            
            genisoimage -output "$VM_SUBDIR/seed.iso" -volid cidata -joliet -rock "$VM_SUBDIR/user-data" "$VM_SUBDIR/meta-data" 2>/dev/null || \
            hdiutil makehybrid -o "$VM_SUBDIR/seed.iso" -hfs -joliet -iso -default-volume-name cidata "$VM_SUBDIR" 2>/dev/null
        fi
        
        SEED_ISO="$VM_SUBDIR/seed.iso"
        SEED_PARAM=""
        [ -f "$SEED_ISO" ] && SEED_PARAM="-drive file=$SEED_ISO,format=raw,if=virtio,readonly=on"
        
        qemu-system-x86_64 \
            -accel tcg \
            -m 4G \
            -smp 2 \
            -cpu max \
            -drive file="$DISK_FILE",format=qcow2,if=virtio \
            $SEED_PARAM \
            -nic user,model=virtio-net-pci,hostfwd=tcp::22220-:22 \
            -display none &
        
        QEMU_PID=$!
        
        cleanup() {
            echo ""
            echo "Stopping VM..."
            kill $QEMU_PID 2>/dev/null
            wait $QEMU_PID 2>/dev/null
            exit
        }
        trap cleanup INT TERM EXIT
        
        SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no"
        SSH_PORT=22220
        
        echo "Waiting for SSH on port $SSH_PORT..."
        sleep 10
        
        SSH_READY=false
        for i in {1..30}; do
            if sshpass -p zedr ssh $SSH_OPTS -o ConnectTimeout=2 -p $SSH_PORT zedr@localhost "echo connected" 2>/dev/null; then
                SSH_READY=true
                break
            fi
            echo -n "."
            sleep 2
        done
        echo ""
        
        if [ "$SSH_READY" = false ]; then
            echo ""
            echo "SSH connection failed after 60 seconds."
            echo "VM may need: sudo apt install openssh-server && sudo systemctl start ssh"
            echo ""
            echo "To manually connect: sshpass -p zedr ssh -p 22220 zedr@localhost"
            echo "VM window should be open - check with Cmd+Tab"
            echo ""
            echo "VM running. Press Ctrl+C to stop"
            wait $QEMU_PID
            exit 0
        fi
        
        echo "SSH connected! Setting up agent..."
        
        sshpass -p zedr ssh $SSH_OPTS -p $SSH_PORT zedr@localhost "test -d agent" || {
            echo "Copying agent code to VM..."
            cd "$SCRIPT_DIR/.."
            tar czf /tmp/agent.tar.gz agent/
            sshpass -p zedr scp $SSH_OPTS -P $SSH_PORT /tmp/agent.tar.gz zedr@localhost:~
            sshpass -p zedr ssh $SSH_OPTS -p $SSH_PORT zedr@localhost "tar xzf agent.tar.gz && rm agent.tar.gz"
            rm /tmp/agent.tar.gz
        }
        
        sshpass -p zedr ssh $SSH_OPTS -p $SSH_PORT zedr@localhost "test -f ~/.cargo/env" || {
            echo "Installing Rust..."
            sshpass -p zedr ssh $SSH_OPTS -p $SSH_PORT zedr@localhost "
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            "
        }
        
        echo "Building and running Linux agent..."
        sshpass -p zedr ssh $SSH_OPTS -p $SSH_PORT zedr@localhost "
            cd agent && \
            source ~/.cargo/env && \
            cargo build --release -p zedr-agent-linux && \
            ./target/release/zedr-agent-linux
        "
        
        TEST_EXIT=$?
        
        echo "Tests complete. Stopping VM..."
        kill $QEMU_PID 2>/dev/null
        wait $QEMU_PID 2>/dev/null
        
        exit $TEST_EXIT
        ;;
        
    windows)
        echo "Starting Windows $WINDOWS_VER VM..."
        cd "$VM_DIR"
        
        DISK_FILE="windows-$WINDOWS_VER/disk.qcow2"
        ISO_FILE="windows-$WINDOWS_VER/win11_25h2_english_x64.iso"
        
        if [ ! -f "$DISK_FILE" ]; then
            qemu-img create -f qcow2 "$DISK_FILE" 64G
        fi
        
        trap "pkill -f 'qemu-system-x86_64.*windows'; exit" INT TERM EXIT
        
        qemu-system-x86_64 \
            -accel tcg \
            -m 8G \
            -smp 4 \
            -cpu max \
            -drive file="$DISK_FILE",format=qcow2,if=virtio \
            -cdrom "$ISO_FILE" \
            -netdev user,id=net0,hostfwd=tcp::22222-:22 \
            -device virtio-net-pci,netdev=net0 \
            -display cocoa &
        
        QEMU_PID=$!
        sleep 2
        
        echo "Windows VM started (SSH on port 22222)"
        echo "Press Ctrl+C to stop"
        wait $QEMU_PID
        ;;
        
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac
