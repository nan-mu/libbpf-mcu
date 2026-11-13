#!/bin/sh
# Restart xpost-agent with the P4 JIT registry so jit_* cold images are
# installable. The tracked xpost profiles.toml has no JIT entries and must not
# be modified; the agent loads its registry once at startup, so a restart with
# XPOST_PROFILES pointing at the generated registry is the supported way in.
#
# The generated registry no-ops every build.command, so flash uses the exact
# prebuilt artifacts (no rebuild touches the xpost repo at flash time). The
# just_xdp firmware was rebuilt once beforehand to bake the WiFi .env; see
# jit/reports/p4/fw-build-vv.log.
#
# To return to the canonical daemon, run: restart-agent-jit.sh --restore
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
XPOST=/Volumes/SSD/bs/xpost
AGENT_BIN=${AGENT_BIN:-/var/folders/sx/y9r434kd5g7gld19gj1wz1kc0000gn/T/cursor-sandbox-cache/d0c5fb0c5d91ab4d8ce874441868b91e/cargo-target/aarch64-apple-darwin/release/xpost-agent}
LOG_DIR="$XPOST/target/xpost-agent"

pkill -f "xpost-agent --bind" || true
sleep 2

if [ "${1:-}" = "--restore" ]; then
  # Canonical daemon: tracked profiles.toml, real build commands.
  ( cd "$XPOST" && nohup "$AGENT_BIN" --bind 0.0.0.0:9240 --log-dir "$LOG_DIR" \
      >"$ROOT/jit/reports/p4/agent.log" 2>&1 & )
  echo "restored canonical xpost-agent"
else
  python3 -I "$ROOT/jit/scripts/make-registry.py" "$XPOST" "$ROOT" "$ROOT/jit/scripts/profiles-jit.toml"
  ( cd "$XPOST" && nohup env XPOST_ROOT="$XPOST" XPOST_PROFILES="$ROOT/jit/scripts/profiles-jit.toml" \
      "$AGENT_BIN" --bind 0.0.0.0:9240 --log-dir "$LOG_DIR" \
      >"$ROOT/jit/reports/p4/agent.log" 2>&1 & )
  echo "restarted xpost-agent with JIT registry"
fi
sleep 5
curl -s http://127.0.0.1:9240/health; echo