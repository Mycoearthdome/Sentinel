# SentinelRoot

SentinelRoot is an experimental hybrid heuristic and machine-learning based detection engine for Linux malware and rootkits. It inspects system state and running processes to find evidence of compromise.

## Features

- **Heuristic checks** for common rootkit techniques such as:
  - Suspicious `LD_PRELOAD` usage via environment variables or `/etc/ld.so.preload`.
  - Processes executing binaries from transient locations like `/tmp`, `/dev` or `/run`.
  - Kernel modules hidden from `lsmod` output.
  - Processes present in `/proc` but not in the output of `ps`.
- **Extensible architecture** where results from heuristics can be passed to a machine learning model for further classification.

## Python Heuristic Prototype Usage

```bash
pip install -r requirements.txt
python -m sentinelroot.sentinel
```

The script prints a simple report with any suspicious findings. Elevated permissions may be required for full inspection.

## Qt Interface

The repository also includes a lightweight Qt application that displays the same
heuristic report in a GUI. To build it you need Qt 5 development packages and CMake:

```bash
sudo apt-get install qtbase5-dev qtbase5-dev-tools
./install.sh
```

Running `install.sh` will build the binary in `build/` and, if executed as root,
copy `sentinelrootqt` to `/usr/local/bin`.

## Project Goals

This repository contains only a minimal proof-of-concept. The broader project goal is a full detection engine capable of analysing static binary features, kernel integrity hooks, system behaviour, persistence techniques and network patterns. Machine learning models such as gradient boosting (e.g. XGBoost) are intended to complement rule-based heuristics for higher accuracy.

## Disclaimer

This project is provided for educational and research purposes. Use it responsibly and at your own risk.
