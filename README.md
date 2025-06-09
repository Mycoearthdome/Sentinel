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
- Detection of suspicious entries in systemd service files.
- Command line inspection to flag processes launched with tools like `curl` or `nc`.
- Resource monitoring for processes consuming excessive CPU or memory.
- Reporting of processes whose names match known malicious signatures.
- Alerts when processes connect to known malicious IP addresses.
- **Extensible architecture** where results from heuristics can be passed to a machine learning model for further classification.
- Can automatically remove modules or kill processes when their names match
  known malicious signatures.
- On the first run the tool attempts to launch **rkhunter**, **chkrootkit**,
  **lynis**, **maldet**, **ClamAV** and the **OSSEC** rootcheck when available. The output
  from these scanners is forwarded to syslog for later review.
- Combining two or more of these tools (e.g. **rkhunter** with **maldet**, or
  **lynis** with **OSSEC**) provides a stronger layered defense on Linux
  systems.

## Installation

Run the provided `install.sh` script to install the Python service and all
dependencies. The script detects `apt`, `yum`, `zypper` or `aptitude` and uses
the available package manager to install `rkhunter`, `chkrootkit`, `lynis`,
`maldet`, `clamav` and `ossec-hids` along with the Python modules from
`requirements.txt`.  During installation the script calls `python3 -m pip
install --upgrade .` which executes `setup.py` and registers the
`sentinelroot` package so the command `python -m sentinelroot.report` works
from any directory.

All detections from the Python heuristics are automatically sent to syslog via
the `logger` command using the tag `sentinelroot`.  Messages can be inspected
with `dmesg` or in `/var/log/syslog`.
Log entries now include a syslog *severity* such as `emerg`, `alert`,
`crit`, `err`, `warn`, `notice`, `info` or `debug`.

```bash
sudo ./install.sh
```

## Uninstallation

Run the `uninstall.sh` script to remove the services and installed files.  The
script detects the location of the installed systemd unit files so it works
regardless of whether your distribution stores them in `/etc`, `/lib` or
`/usr/lib`.  It also kills any running `sentinelroot` Python processes and
purges the package from all Python `site-packages` directories to ensure the
modules are fully unloaded.

```bash
sudo ./uninstall.sh
```

All SentinelRoot data and systemd units are deleted while external scanners
remain installed.  A syslog message tagged `sentinelroot` confirms successful
removal so you can verify the cleanup with `journalctl -t sentinelroot`.


## Python Heuristic Prototype Usage

```bash
pip install -r requirements.txt
python -m sentinelroot.sentinel
python -m sentinelroot.sentinel --loop  # continuous monitoring
```

Running the module once prints a simple report with any suspicious findings.
When executed with `--loop` the checks repeat at one-minute intervals until
interrupted. When run as root the script may kill processes or unload kernel
modules whose names match known malicious signatures, so elevated permissions
can be required for full functionality.

## Command Line TUI

A simple text-based user interface is available using Python's `curses` module:

```bash
python -m sentinelroot.report
```

Press `q` to exit the interface. This fullscreen view now includes recent log
lines from `dmesg` tagged with `sentinelroot` so warnings and errors are easy
to spot. The module invocation works from any directory once the installer has
registered `sentinelroot` as a Python package.

Use the arrow keys or PageUp/PageDown to scroll.  Press `q` to exit.

## Systemd Service

The provided `install.sh` script installs the Python heuristics to
`/usr/local/share/sentinelroot` and configures a `sentinelroot` systemd
service. The service runs the `sentinel.py` module in looping mode
(`--loop`) with `python3` so it remains active and systemd restarts it on
failure. The unit file explicitly specifies `User=root` so the
heuristics have the permissions required to inspect system resources. The
installer also sets up a `sentinelboot` service that
runs the `boot_protect.py` module with `python3`. A `sentineltrain` oneshot
service is also installed so the `train.py` module executes on the next reboot.
On first boot the script backs up the entire `/boot` partition to a SQLite
database. This service also executes as `root` so it can access and restore the
boot partition. On every boot the checksums are verified and the partition is
restored with ``dd`` whenever any
changes are detected.

## External Scanner Integration

On its first execution the Python module attempts to run [rkhunter](http://rkhunter.sourceforge.net/), [chkrootkit](http://www.chkrootkit.org/), [lynis](https://cisofy.com/lynis/), [maldet](https://www.rfxn.com/projects/linux-malware-detect/), [ClamAV](https://www.clamav.net/) and the [OSSEC](https://www.ossec.net/) rootcheck when these tools are installed. Output from these scanners is sent to syslog via the `logger` command and can be reviewed with `dmesg` or by inspecting `/var/log/syslog`.
Before each scanner runs its binary hash is compared against a checksum stored in
`tools.db`.  When a mismatch is detected the tool is automatically reinstalled
from the package repository and the new checksum recorded.  This guards against
tampering of the external scanners themselves.

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

## Updating Signatures

Signatures are also stored in `signatures.db` for fast lookups. The
`install.sh` script automatically configures a weekly cron job to keep this
database updated, which looks like the following:

```cron
0 3 * * 0 python -m sentinelroot.update_signatures >/var/log/sentinel_update.log 2>&1
```

## Project Goals

This repository contains only a minimal proof-of-concept. The broader project goal is a full detection engine capable of analysing static binary features, kernel integrity hooks, system behaviour, persistence techniques and network patterns. The latest prototype now inspects systemd services, monitors network connections against a list of malicious IPs and can analyse static binary features using a gradient boosting model powered by **XGBoost** when available. Machine learning models complement rule-based heuristics for higher accuracy. The current release also applies this malicious IP list as an **IPS** rule set by inserting `nftables` drop rules for each address found in `malicious_ips.json`.

## Upcoming Features

- Improved automation around signature updates and ML model retraining.
- More comprehensive integration with `rkhunter` including scheduled scans.

## Disclaimer

This project is provided for educational and research purposes. Use it responsibly and at your own risk.
