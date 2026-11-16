#!/bin/sh
set -eu

ZEDR_SERVER_URL="https://zedr.example.com"
ZEDR_TOKEN_PARAMETER="/zedr/enrollment-token"

ZEDR_ENROLLMENT_KEY="$(aws ssm get-parameter --name "$ZEDR_TOKEN_PARAMETER" --with-decryption --query Parameter.Value --output text)"
export ZEDR_ENROLLMENT_KEY

INSTALLER="$(mktemp)"
curl -fsSL --retry 5 --retry-delay 5 -o "$INSTALLER" "$ZEDR_SERVER_URL/install.sh"
sh "$INSTALLER"
rm -f "$INSTALLER"
