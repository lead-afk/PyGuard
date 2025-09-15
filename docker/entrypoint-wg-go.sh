#!/usr/bin/env bash
set -euo pipefail

log() { echo "[entrypoint] $*"; }

# Ensure /dev/net/tun exists
if [ ! -e /dev/net/tun ]; then
  log "Creating /dev/net/tun"
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 || true
  chmod 600 /dev/net/tun || true
fi

export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
export WG_I_PREFER_BUGGY_USERSPACE_TO_KERNEL_IMPLEMENTATION=1

# Auto-create default interface if none present
if [ "${PYGUARD_AUTOCREATE:-1}" = "1" ]; then
  if [ -z "$(ls -1 /etc/pyguard 2>/dev/null | grep '.conf' || true)" ]; then
    log "No existing interfaces; initializing wg0"
    python /app/pyguard.py init wg0 || log "init wg0 failed (continuing)"
  fi
fi

# Optional: create extra interfaces from env comma list (manual model)
if [ -n "${PYGUARD_EXTRA_INTERFACES:-}" ]; then
  IFS=',' read -ra IFACES <<< "$PYGUARD_EXTRA_INTERFACES"
  for i in "${IFACES[@]}"; do
    if [ ! -f "/etc/pyguard/${i}.conf" ]; then
      log "Creating extra interface $i"
      python /app/pyguard.py init "$i" || log "Failed creating $i"
    fi
  done
fi

log "Starting supervisord"
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/pyguard.conf
