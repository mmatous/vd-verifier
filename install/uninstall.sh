#!/usr/bin/env sh

USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
MANIFEST_DIR="$USER_HOME/.mozilla/native-messaging-hosts"
EXECUTABLE_DIR="/usr/local/bin"
EXECUTABLE="vd-verifier"
MANIFEST="vd-verifier.json"

rm -f "$MANIFEST_DIR/$MANIFEST"
rm -f "$EXECUTABLE_DIR/$EXECUTABLE"
