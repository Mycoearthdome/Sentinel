# SentinelRoot

SentinelRoot is an experimental hybrid heuristic and machine-learning based detection engine for Linux malware and rootkits. It inspects system state and running processes to find evidence of compromise.

## Features

- **Heuristic checks** for common rootkit techniques such as:
  - Suspicious `LD_PRELOAD` usage via environment variables or `/etc/ld.so.preload`.
  - Processes executing binaries from transient locations like `/tmp`, `/dev` or `/run`.
- Kernel modules hidden from `lsmod` output.
- Processes present in `/proc` but not in the output of `ps`.
- Processes creating **raw sockets**.
- Processes listening on suspicious ports such as `31337`.
- Simple checks for persistence in files like `rc.local` or user shell profiles.
- Command line inspection to flag processes launched with tools like `curl` or `nc`.
- Resource monitoring for processes consuming excessive CPU or memory.
- Reporting of processes whose names match known malicious signatures.
- **Extensible architecture** where results from heuristics can be passed to a machine learning model for further classification.
- Can automatically remove modules or kill processes when their names match
  known malicious signatures.

## Python Heuristic Prototype Usage

```bash
pip install -r requirements.txt
python -m sentinelroot.sentinel
```

The script prints a simple report with any suspicious findings. When run as
root it also attempts to kill processes or unload kernel modules whose names
match known malicious signatures. Elevated permissions may therefore be
required for full functionality.

## Command Line TUI

A simple text-based user interface is available using Python's `curses` module:

```bash
python -m sentinelroot.tui
```

Press `q` to exit the interface. This provides the same heuristic report as the
standard Python script but in a fullscreen terminal view.

## C Service

A C implementation replicates the heuristic checks and logs results to syslog. Build and install it using:`install.sh`:

```bash
./install.sh
```

When run as root the script copies `sentinelroot` to `/usr/local/bin` and enables a `sentinelroot` systemd service.


## Training the ML Heuristic

The Python module now includes a small machine learning component for classifying
binary signatures. A helper script downloads CSV datasets from the internet and
trains a model:

```bash
python -m sentinelroot.train
```

By default the script downloads the latest signature dump from
`https://bazaar.abuse.ch/export/csv/full/`, which is provided as a ZIP
archive containing a CSV file.

The CSV should include a `signature` column and optionally a `label` column.
When the label is missing, all samples are considered malicious and the label is
set to `1`. The trained model is stored as `signature_model.joblib` and used
automatically by the main heuristic script when present.

During training a **5-fold cross-validation** run is performed and the average
F1 score is printed to give an indication of model accuracy.

## Project Goals

This repository contains only a minimal proof-of-concept. The broader project goal is a full detection engine capable of analysing static binary features, kernel integrity hooks, system behaviour, persistence techniques and network patterns. Machine learning models such as gradient boosting (e.g. XGBoost) are intended to complement rule-based heuristics for higher accuracy.

## Disclaimer

This project is provided for educational and research purposes. Use it responsibly and at your own risk.
