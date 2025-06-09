#!/bin/bash
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Run as root to uninstall SentinelRoot." >&2
    exit 1
fi

SERVICES=(sentinelroot.service sentinelboot.service)
for svc in "${SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/$svc"
done
systemctl daemon-reload

rm -rf /usr/local/share/sentinelroot
rm -f /etc/cron.d/sentinelroot_update
rm -f /var/log/sentinel_update.log

if command -v pip3 >/dev/null; then
    xargs -r pip3 uninstall -y < requirements.txt || true
fi

logger -t sentinelroot "SentinelRoot uninstalled successfully"
echo "Uninstallation complete. External scanner tools remain installed."

