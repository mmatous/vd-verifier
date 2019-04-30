#!/usr/bin/env sh

USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
MANIFEST_DIR="$USER_HOME/.mozilla/native-messaging-hosts"
EXECUTABLE_DIR="/usr/local/bin"
EXECUTABLE="vd-verifier"
MANIFEST="io.github.vd.json"

mkdir -p "$MANIFEST_DIR"
cp -f "io.github.vd.template.json" "$MANIFEST_DIR/$MANIFEST"
cp -f "$EXECUTABLE" "$EXECUTABLE_DIR"

sed -i "s'<INSERT_PATH_HERE>'$EXECUTABLE_DIR/$EXECUTABLE'" "$MANIFEST_DIR/$MANIFEST"
