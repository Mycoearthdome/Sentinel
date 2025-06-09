#!/bin/bash
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Run as root to uninstall SentinelRoot." >&2
    exit 1
fi

logger -t sentinelroot "Starting SentinelRoot uninstallation"

SERVICES=(sentinelroot.service sentinelboot.service)
for svc in "${SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    svc_path=$(systemctl show -p FragmentPath "$svc" 2>/dev/null | cut -d'=' -f2)
    if [ -n "$svc_path" ]; then
        rm -f "$svc_path"
    else
        rm -f "/etc/systemd/system/$svc" "/usr/lib/systemd/system/$svc" "/lib/systemd/system/$svc"
    fi
done
systemctl daemon-reload

# Securely shred SQLite databases before removing directories
DB_DIRS=(/usr/local/share/sentinelroot /var/lib/sentinelroot)
for dir in "${DB_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f -name '*.db' -exec shred -fuxzn7 {} \;
    fi
done

rm -rf /usr/local/share/sentinelroot
rm -rf /var/lib/sentinelroot
rm -f /usr/local/bin/sentinelboot
rm -f /etc/cron.d/sentinelroot_update
rm -f /var/log/sentinel_update.log

if command -v pip3 >/dev/null; then
    xargs -r pip3 uninstall -y < requirements.txt || true
fi

logger -t sentinelroot "SentinelRoot uninstalled successfully"
echo "Uninstallation complete. External scanner tools remain installed."
