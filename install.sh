#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
LIB_DIR="$PREFIX/share/adaptive-web-discovery"
BIN_DIR="$PREFIX/bin"

mkdir -p "$LIB_DIR" "$BIN_DIR"
cp web_discovery.py "$LIB_DIR/web_discovery.py"
cp -R web_discovery_playbooks "$LIB_DIR/web_discovery_playbooks"

cat >"$BIN_DIR/adaptive-web-discovery" <<EOF
#!/usr/bin/env bash
exec python3 "$LIB_DIR/web_discovery.py" "\$@"
EOF
chmod +x "$BIN_DIR/adaptive-web-discovery"

printf 'Installed adaptive-web-discovery to %s\n' "$BIN_DIR/adaptive-web-discovery"
printf 'Ensure %s is present in PATH.\n' "$BIN_DIR"
