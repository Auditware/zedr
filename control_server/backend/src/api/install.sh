#!/bin/sh
# zedr agent installer, served by the control server with its own address filled in

set -eu

CONTROL_SERVER_URL="__ZEDR_SERVER_URL__"
AGENT_VERSION="__ZEDR_AGENT_VERSION__"
ENROLLMENT_KEY="__ZEDR_ENROLLMENT_KEY__"

BINARY_PATH="/usr/local/bin/zedr-agent"
PROVER_NAME="zedr-prover"
STATE_DIR="/var/lib/zedr"
SERVICE_NAME="zedr-agent"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"
ENROLLMENT_WAIT_SECONDS=30

fail() {
    echo "zedr install: $*" >&2
    exit 1
}

download() {
    if command -v curl >/dev/null 2>&1; then
        printf 'header = "X-Zedr-Enrollment-Key: %s"\n' "$ENROLLMENT_KEY" | curl -fsSL -K - -o "$2" "$1"
    else
        wget -q --header "X-Zedr-Enrollment-Key: $ENROLLMENT_KEY" -O "$2" "$1"
    fi
}

prepare_state_dir() {
    mkdir -p "$STATE_DIR"
    chown 0:0 "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
}

# The agent finds its prover next to itself, and the two must come from the same build, so they are replaced together or not at all.
# The prover is fetched first because the agent download uses up a one-time install key.
install_binary() {
    staged="$BINARY_PATH.download"
    prover_path="$(dirname "$BINARY_PATH")/$PROVER_NAME"
    staged_prover="$prover_path.download"
    mkdir -p "$(dirname "$BINARY_PATH")"

    if ! download "$CONTROL_SERVER_URL/api/installers/binaries/$PLATFORM-$ARCH/prover" "$staged_prover" 2>/dev/null; then
        rm -f "$staged_prover"
    fi

    if download "$CONTROL_SERVER_URL/api/installers/binaries/$PLATFORM-$ARCH" "$staged"; then
        chmod 0755 "$staged"
        mv -f "$staged" "$BINARY_PATH"
        if [ -f "$staged_prover" ]; then
            chmod 0755 "$staged_prover"
            mv -f "$staged_prover" "$prover_path"
        else
            rm -f "$prover_path"
            echo "zedr install: $CONTROL_SERVER_URL served no prover for $PLATFORM-$ARCH, this endpoint seals its telemetry without proving it" >&2
        fi
    elif [ "$MODE" = "foreground" ] && [ -x "$BINARY_PATH" ]; then
        rm -f "$staged" "$staged_prover"
        echo "zedr install: could not download the agent, starting the one installed earlier" >&2
    else
        rm -f "$staged" "$staged_prover"
        fail "could not download the agent from $CONTROL_SERVER_URL, the enrollment key was refused or the server is unreachable"
    fi
}

stage_enrollment_key() {
    (umask 077 && printf '%s' "$ENROLLMENT_KEY" > "$STATE_DIR/enrollment.key")
}

install_systemd_service() {
    if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
        fail "systemd is not running here, use --foreground under your own supervisor"
    fi

    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=zedr Endpoint Detection and Response Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=$BINARY_PATH
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null
    systemctl restart "$SERVICE_NAME"
}

wait_for_enrollment() {
    waited=0
    while [ -f "$STATE_DIR/enrollment.key" ]; do
        if ! systemctl is-active --quiet "$SERVICE_NAME"; then
            fail "the agent service is not running, see: journalctl -u $SERVICE_NAME"
        fi
        if [ "$waited" -ge "$ENROLLMENT_WAIT_SECONDS" ]; then
            fail "the agent is running but has not enrolled yet and keeps retrying, see: journalctl -u $SERVICE_NAME"
        fi
        waited=$((waited + 1))
        sleep 1
    done
}

install_macos_service() {
    download "$CONTROL_SERVER_URL/api/installers/binaries/$PLATFORM-$ARCH" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"

    cat > /Library/LaunchDaemons/com.zedr.agent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.zedr.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BINARY_PATH</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

    launchctl load /Library/LaunchDaemons/com.zedr.agent.plist

    sleep 2
    if launchctl list | grep -q com.zedr.agent; then
        echo "zedr agent $AGENT_VERSION installed, control server: $CONTROL_SERVER_URL"
    else
        fail "the agent service failed to start, check the system logs"
    fi
}

main() {
    MODE="service"
    for argument in "$@"; do
        case "$argument" in
            --foreground)
                MODE="foreground"
                BINARY_PATH="$STATE_DIR/zedr-agent"
                ;;
            *) fail "unknown option: $argument" ;;
        esac
    done

    [ "$(id -u)" -eq 0 ] || fail "must run as root"
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || fail "curl or wget is required"

    ENROLLMENT_KEY="${ENROLLMENT_KEY:-${ZEDR_ENROLLMENT_KEY:-}}"
    [ -n "$ENROLLMENT_KEY" ] \
        || fail "no enrollment key, send it in the X-Zedr-Enrollment-Key header when fetching this script or set ZEDR_ENROLLMENT_KEY"

    case "$(uname -s)" in
        Linux) PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        *) fail "unsupported operating system: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64) ARCH="x64" ;;
        aarch64 | arm64) ARCH="arm64" ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac

    if [ "$PLATFORM" = "macos" ]; then
        [ "$MODE" = "service" ] || fail "--foreground is only available on Linux"
        install_macos_service
        return
    fi

    prepare_state_dir
    install_binary
    stage_enrollment_key

    if [ "$MODE" = "foreground" ]; then
        exec "$BINARY_PATH"
    fi

    install_systemd_service
    wait_for_enrollment
    echo "zedr agent $AGENT_VERSION installed and enrolled, control server: $CONTROL_SERVER_URL"
}

main "$@"
