#!/bin/bash
set -e
mkdir -p build
cd build
cmake ../src
make -j$(nproc)
# Install binary to /usr/local/bin if run as root
if [ "$(id -u)" = "0" ]; then
    cp sentinelrootqt /usr/local/bin/
    echo "Installed sentinelrootqt to /usr/local/bin"
else
    echo "Build finished. Run as root to install to /usr/local/bin."
fi
