#!/bin/sh
set -eu

: "${ZEDR_SERVER_URL:?set ZEDR_SERVER_URL to the address of the control server}"

STATE_DIR="/var/lib/zedr"
INSTALLER="$STATE_DIR/install.sh"

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

if curl -fsSL -o "$INSTALLER.download" "$ZEDR_SERVER_URL/install.sh"; then
    mv -f "$INSTALLER.download" "$INSTALLER"
elif [ -f "$INSTALLER" ]; then
    rm -f "$INSTALLER.download"
    echo "zedr agent: control server unreachable, using the installer fetched earlier" >&2
else
    echo "zedr agent: could not fetch $ZEDR_SERVER_URL/install.sh" >&2
    exit 1
fi

exec sh "$INSTALLER" --foreground
