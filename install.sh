#!/bin/bash
# Exit immediately on error, treat unset variables as an error and
# propagate failures through pipes so that the script halts when any
# step fails.
set -euo pipefail
PKGS="rkhunter chkrootkit lynis maldet ossec-hids clamav clamav-freshclam"

if [ "$(id -u)" = "0" ]; then
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y $PKGS
    elif command -v yum >/dev/null; then
        yum install -y $PKGS
    elif command -v zypper >/dev/null; then
        zypper --non-interactive install $PKGS
    elif command -v aptitude >/dev/null; then
        aptitude install -y $PKGS
    else
        echo "No supported package manager found. Install $PKGS manually." >&2
    fi
    python3 -m pip install -r requirements.txt
    # Register the Python package so modules can be executed with
    # "python -m sentinelroot.*" from any directory.
    python3 -m pip install --upgrade .
else
    echo "Run as root to install system packages."
fi

if [ "$(id -u)" = "0" ]; then
    mkdir -p /usr/local/share/sentinelroot
    cp -r sentinelroot/* /usr/local/share/sentinelroot/
    # Remove any previously installed compiled version of sentinelboot
    # that may exist from older releases.
    if [ -f /usr/local/bin/sentinelboot ]; then
        rm -f /usr/local/bin/sentinelboot
    fi
    install -m 644 sentinelroot.service /etc/systemd/system/
    install -m 644 sentinelboot.service /etc/systemd/system/
    install -m 644 sentineltrain.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentinelroot.service
    systemctl enable sentinelboot.service
    systemctl enable sentineltrain.service
    systemctl start sentinelroot.service
    systemctl start sentinelboot.service
    # weekly signature update cron job
    cat >/etc/cron.d/sentinelroot_update <<'EOF'
0 3 * * 0 root /usr/bin/python3 -m sentinelroot.update_signatures >> /var/log/sentinel_update.log 2>&1
EOF
    chmod 644 /etc/cron.d/sentinelroot_update
    echo "Installed sentinelroot and enabled service"
    echo "Cron job added for weekly signature updates"
    # Notify user of successful installation and how to view logs
    logger -t sentinelroot -- "SentinelRoot installation successful"
    echo "Installation complete! SentinelRoot is now protecting your system."
    echo "Check logs with 'journalctl -t sentinelroot' or in /var/log/syslog"
    echo "Upcoming features: improved automation around signature updates and ML model retraining, and scheduled rkhunter scans."
else
    echo "Run as root to install and enable the service."
fi
