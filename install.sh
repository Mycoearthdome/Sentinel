#!/bin/bash
set -e
mkdir -p build
cc -O2 -Wall -o build/sentinelroot src/sentinel.c
if [ "$(id -u)" = "0" ]; then
    install -m 755 build/sentinelroot /usr/local/bin/
    install -m 644 sentinelroot.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentinelroot.service
    echo "Installed sentinelroot and enabled service"
else
    echo "Build finished. Run as root to install and enable the service."
fi
