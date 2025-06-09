#!/bin/bash
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Run as root to uninstall SentinelRoot." >&2
    exit 1
fi

logger -t sentinelroot -- "Starting SentinelRoot uninstallation"

SERVICES=(sentinelroot.service sentinelboot.service sentineltrain.service)
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

# Terminate any stray Python processes that still have
# sentinelroot modules loaded so that uninstallation can
# remove the package cleanly.
pkill -f "python.*sentinelroot" 2>/dev/null || true

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
    pip3 uninstall -y sentinelroot || true
    # Remove any remaining sentinelroot modules from all site-packages
    python3 - <<'EOF'
import site, shutil, os
for path in site.getsitepackages()+([site.getusersitepackages()] if hasattr(site, 'getusersitepackages') else []):
    pkg = os.path.join(path, 'sentinelroot')
    if os.path.isdir(pkg):
        shutil.rmtree(pkg, ignore_errors=True)
    for name in os.listdir(path):
        if name.startswith('sentinelroot-') and name.endswith('.dist-info'):
            shutil.rmtree(os.path.join(path, name), ignore_errors=True)
EOF
fi

logger -t sentinelroot -- "SentinelRoot uninstalled successfully"
echo "Uninstallation complete. External scanner tools remain installed."
