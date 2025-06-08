#!/bin/bash
set -e
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
    pip3 install -r requirements.txt
else
    echo "Run as root to install system packages."
fi
mkdir -p build
cc -O2 -Wall -o build/sentinelroot src/sentinel.c
if [ "$(id -u)" = "0" ]; then
    install -m 755 build/sentinelroot /usr/local/bin/
    install -m 755 sentinelroot/boot_protect.py /usr/local/bin/sentinelboot
    install -m 644 sentinelroot.service /etc/systemd/system/
    install -m 644 sentinelboot.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentinelroot.service
    systemctl enable sentinelboot.service
    echo "Installed sentinelroot and enabled service"
else
    echo "Build finished. Run as root to install and enable the service."
fi
