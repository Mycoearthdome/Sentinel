import os
import subprocess
import psutil
import socket
import signal
import sqlite3
import hashlib
import time
import json
import argparse

# Simple lists of known malicious signatures. These can be extended or
# loaded from an external source in the future.
# Start with built-in signatures but extend from the SQLite database when
# available. This allows quick searches across distributions.
EVIL_PROCESS_SIGNATURES = ["evilproc", "badproc"]
from dataclasses import dataclass, field
from typing import List
from pathlib import Path
from .ml import SignatureClassifier, StaticFeatureClassifier
from .binary_features import BinaryFeatureExtractor
from .db import (
    store_process,
    find_paths_by_checksum,
    load_signatures,
    PROCESS_DB,
    store_tool_checksum,
    get_tool_checksum,
)
from .train import train_models
import threading

LEVELS = {
    "emerg",
    "alert",
    "crit",
    "err",
    "warn",
    "notice",
    "info",
    "debug",
}
EVIL_PROCESS_SIGNATURES.extend(load_signatures())
EVIL_MODULE_SIGNATURES = ["evilmod", "badmodule"]
import shutil

SUSPICIOUS_IPS_FILE = os.path.join(os.path.dirname(__file__), "malicious_ips.json")

LOG_TAG = "sentinelroot"

# Track whether clamav scan has completed and when low CPU state began
CLAM_SCAN_DONE = False
_CLAM_IDLE_START = None


def start_background_training() -> None:
    """Launch ML training in a background thread if no model exists."""
    model_path = os.path.join(os.path.dirname(__file__), "signature_model.joblib")
    if os.path.isfile(model_path):
        return

    def _worker() -> None:
        try:
            train_models(model_path=model_path)
            subprocess.run(
                [
                    "logger",
                    "-p",
                    "user.notice",
                    "-t",
                    LOG_TAG,
                    "--",
                    "ML training complete - model ready",
                ],
                check=False,
            )
        except Exception as e:
            subprocess.run(
                [
                    "logger",
                    "-p",
                    "user.err",
                    "-t",
                    LOG_TAG,
                    "--",
                    f"ML training failed: {e}",
                ],
                check=False,
            )

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

@dataclass
class DetectionResult:
    issue: str
    details: str

@dataclass
class SentinelReport:
    results: List[DetectionResult] = field(default_factory=list)

    def add(self, issue: str, details: str, level: str = "info"):
        level = level if level in LEVELS else "info"
        message = f"{issue}: {details}"
        self.results.append(DetectionResult(issue, details))
        try:
            subprocess.run([
                "logger",
                "-p",
                f"user.{level}",
                "-t",
                LOG_TAG,
                "--",
                message,
            ], check=False)
        except Exception:
            pass

    def summary(self) -> str:
        return "\n".join(f"{r.issue}: {r.details}" for r in self.results)


def check_ld_preload(report: SentinelReport):
    preload_env = os.environ.get("LD_PRELOAD")
    if preload_env:
        report.add("LD_PRELOAD env", preload_env, level="warn")
    try:
        with open("/etc/ld.so.preload", "r") as f:
            content = f.read().strip()
            if content:
                report.add("ld.so.preload", content, level="warn")
    except FileNotFoundError:
        pass

def check_tmp_exec(report: SentinelReport):
    for proc in psutil.process_iter(['pid', 'exe']):
        exe = proc.info.get('exe')
        if exe and any(exe.startswith(p) for p in ("/tmp", "/dev", "/run")):
            report.add(
                "Executable from tmp",
                f"PID {proc.pid}: {exe}",
                level="warn",
            )

def check_hidden_modules(report: SentinelReport):
    try:
        lsmod_output = subprocess.check_output(['lsmod'], text=True)
        listed = {line.split()[0] for line in lsmod_output.strip().splitlines()[1:]}
    except Exception as e:
        report.add("lsmod error", str(e), level="err")
        return
    try:
        with open('/proc/modules') as f:
            modules = {line.split()[0] for line in f.readlines()}
    except Exception as e:
        report.add("/proc/modules error", str(e), level="err")
        return
    hidden = modules - listed
    for mod in hidden:
        report.add("Hidden module", mod, level="warn")

def check_hidden_processes(report: SentinelReport):
    try:
        ps_output = subprocess.check_output(['ps', '-e', '-o', 'pid'], text=True)
        pids_ps = {int(pid) for pid in ps_output.strip().splitlines()[1:]}
    except Exception as e:
        report.add("ps error", str(e), level="err")
        return
    pids_proc = {int(pid) for pid in os.listdir('/proc') if pid.isdigit()}
    hidden = pids_proc - pids_ps
    for pid in sorted(hidden):
        report.add("Hidden process", f"PID {pid}", level="warn")

def check_raw_sockets(report: SentinelReport):
    seen = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.type == socket.SOCK_RAW:
                pid = conn.pid
                if pid and pid not in seen:
                    seen.add(pid)
                    try:
                        name = psutil.Process(pid).name()
                    except Exception:
                        name = 'unknown'
                    report.add("Raw socket", f"PID {pid} ({name})", level="warn")
    except Exception as e:
        report.add("raw socket check error", str(e), level="err")

def check_suspicious_ports(report: SentinelReport):
    """Check for listening ports commonly used by malware."""
    suspicious = {31337, 1337, 1338}
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN and conn.laddr.port in suspicious:
                pid = conn.pid
                try:
                    name = psutil.Process(pid).name() if pid else 'unknown'
                except Exception:
                    name = 'unknown'
                report.add(
                    "Suspicious port",
                    f"PID {pid} ({name}) listening on {conn.laddr.port}",
                    level="warn",
                )
    except Exception as e:
        report.add("port check error", str(e), level="err")

def check_persistence(report: SentinelReport):
    paths = [
        "/etc/rc.local",
        "/etc/crontab",
        os.path.expanduser("~/.bashrc"),
    ]
    suspicious = ("/tmp", "/dev", "wget", "curl")
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'r', errors='ignore') as f:
                data = f.read()
            if any(s in data for s in suspicious):
                report.add(
                    "Persistence file",
                    f"{path} contains suspicious entry",
                    level="warn",
                )
        except Exception as e:
            report.add("persistence check error", f"{path}: {e}", level="err")

def check_systemd_services(report: SentinelReport):
    """Look for suspicious commands in systemd service files."""
    service_dirs = ['/etc/systemd/system', '/usr/lib/systemd/system']
    keywords = ['wget', 'curl', '/tmp', '/dev']
    for d in service_dirs:
        if not os.path.isdir(d):
            continue
        for root_dir, _, files in os.walk(d):
            for name in files:
                if not name.endswith('.service'):
                    continue
                path = os.path.join(root_dir, name)
                try:
                    with open(path, 'r', errors='ignore') as f:
                        text = f.read()
                    if any(k in text for k in keywords):
                        report.add('Suspicious service', path, level='warn')
                except Exception:
                    continue

def load_suspicious_ips() -> set:
    try:
        with open(SUSPICIOUS_IPS_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()

def add_suspicious_ip(ip: str) -> None:
    """Append an IP to the suspicious list JSON file if not already present."""
    try:
        if os.path.exists(SUSPICIOUS_IPS_FILE):
            with open(SUSPICIOUS_IPS_FILE, "r+", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    if not isinstance(data, list):
                        data = []
                except Exception:
                    data = []
                if ip not in data:
                    data.append(ip)
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
        else:
            with open(SUSPICIOUS_IPS_FILE, "w", encoding="utf-8") as f:
                json.dump([ip], f, indent=2)
    except Exception:
        pass

def check_network_patterns(report: SentinelReport):
    bad_ips = load_suspicious_ips()
    if not bad_ips:
        return
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip in bad_ips:
            pid = conn.pid
            try:
                name = psutil.Process(pid).name() if pid else 'unknown'
            except Exception:
                name = 'unknown'
            report.add(
                'Bad IP connection',
                f'PID {pid} ({name}) -> {conn.raddr.ip}',
                level='warn',
            )

def check_kernel_kprobes(report: SentinelReport):
    path = '/sys/kernel/debug/kprobes/list'
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        for line in lines:
            report.add('kprobe', line, level='warn')
    except Exception as e:
        report.add('kprobe error', str(e), level='err')

def check_ml_signatures(report: SentinelReport):
    """Run ML classifier on running executable paths if model is available."""
    model_path = os.path.join(os.path.dirname(__file__), "signature_model.joblib")
    if not os.path.isfile(model_path):
        return
    clf = SignatureClassifier()
    try:
        clf.load(model_path)
    except Exception as e:
        report.add("ml load error", str(e), level="err")
        return
    executables = []
    for proc in psutil.process_iter(['exe']):
        exe = proc.info.get('exe')
        if exe:
            executables.append(exe)
    if not executables:
        return
    try:
        scores = clf.predict(executables)
        for exe, score in zip(executables, scores):
            if score > 0.8:
                report.add("ML suspicious", f"{exe} score={score:.2f}", level="warn")
    except Exception as e:
        report.add("ml predict error", str(e), level="err")

def check_static_binaries(report: SentinelReport):
    model_path = os.path.join(os.path.dirname(__file__), 'static_model.joblib')
    if not os.path.isfile(model_path):
        return
    clf = StaticFeatureClassifier()
    try:
        clf.load(model_path)
    except Exception as e:
        report.add('static ml load error', str(e), level='err')
        return
    extractor = BinaryFeatureExtractor()
    for proc in psutil.process_iter(['exe']):
        exe = proc.info.get('exe')
        if not exe or not os.path.isfile(exe):
            continue
        feats = extractor.extract(exe)
        if not feats:
            continue
        try:
            score = clf.predict([list(feats.values())])[0]
            if score > 0.8:
                report.add('Static suspicious', f'{exe} score={score:.2f}', level='warn')
        except Exception as e:
            report.add('static predict error', str(e), level='err')

def check_suspicious_cmdline(report: SentinelReport):
    """Detect processes started with suspicious command line arguments."""
    keywords = ["curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby", "base64"]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info.get('cmdline') or [])
            if any(k in cmdline for k in keywords):
                report.add(
                    "Suspicious cmdline",
                    f"PID {proc.pid}: {cmdline}",
                    level="warn",
                )
        except Exception:
            continue

def high_system_load(cpu_thresh: float = 90.0, mem_thresh: float = 90.0) -> bool:
    """Return True if system load is too high for heavy operations."""
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        return cpu > cpu_thresh or mem > mem_thresh
    except Exception:
        return False


def wait_for_low_cpu(
    hours: float = 3.0,
    threshold: float = 20.0,
    check_interval: int = 60,
) -> None:
    """Block until CPU load stays below ``threshold`` for ``hours`` hours."""
    duration = hours * 3600
    start = None
    while True:
        try:
            usage = psutil.cpu_percent(interval=1.0)
        except Exception:
            break
        if usage < threshold:
            if start is None:
                start = time.time()
            elif time.time() - start >= duration:
                break
        else:
            start = None
        time.sleep(max(check_interval, 1))

def check_process_resources(report: SentinelReport, cpu_thresh: float = 80.0, mem_thresh: float = 80.0):
    """Flag processes using excessive CPU or memory."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_percent()
            if cpu > cpu_thresh:
                report.add(
                    "High CPU",
                    f"PID {proc.pid} ({proc.info.get('name')}) {cpu:.1f}%",
                    level="warn",
                )
            if mem > mem_thresh:
                report.add(
                    "High memory",
                    f"PID {proc.pid} ({proc.info.get('name')}) {mem:.1f}%",
                    level="warn",
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def maybe_run_clamav(
    report: SentinelReport,
    hours: float = 3.0,
    threshold: float = 20.0,
) -> None:
    """Run clamav scan after sustained low CPU usage."""
    global CLAM_SCAN_DONE, _CLAM_IDLE_START
    if CLAM_SCAN_DONE:
        return
    try:
        usage = psutil.cpu_percent(interval=1.0)
    except Exception:
        return
    if usage < threshold:
        if _CLAM_IDLE_START is None:
            _CLAM_IDLE_START = time.time()
        elif time.time() - _CLAM_IDLE_START >= hours * 3600:
            clam = shutil.which("clamdscan") or shutil.which("clamscan")
            if not clam:
                report.add("clamav not found", "", level="notice")
                CLAM_SCAN_DONE = True
                return
            freshclam = shutil.which("freshclam")
            if freshclam:
                try:
                    subprocess.run([freshclam], check=False)
                except Exception:
                    pass
            try:
                out = subprocess.check_output(
                    [clam, "-r", "/", "--infected", "--no-summary"],
                    text=True,
                    stderr=subprocess.STDOUT,
                )
                lines = out.strip().splitlines()
                _log_lines("sentinelroot-clamav", lines)
                if lines:
                    report.add("clamav output", lines[0], level="info")
            except Exception as e:
                report.add("clamav error", str(e), level="err")
            CLAM_SCAN_DONE = True
    else:
        _CLAM_IDLE_START = None

def check_known_process_signatures(report: SentinelReport):
    """Report processes whose names match known malicious signatures."""
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            target = name + ' ' + exe
            if any(sig in target for sig in EVIL_PROCESS_SIGNATURES):
                report.add(
                    "Known bad process",
                    f"PID {proc.pid}: {target.strip()}",
                    level="warn",
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def block_remote_ips(pid: int, report: SentinelReport):
    """Block remote IPs associated with a PID using nftables."""
    if os.geteuid() != 0:
        return
    try:
        p = psutil.Process(pid)
        for conn in p.connections(kind='inet'):
            if conn.raddr:
                ip = conn.raddr.ip
                report.add("Blocked IP", ip, level="crit")
                child = os.fork()
                if child == 0:
                    rc = 0
                    try:
                        subprocess.run([
                            "nft",
                            "insert",
                            "rule",
                            "ip",
                            "filter",
                            "INPUT",
                            "ip",
                            "saddr",
                            ip,
                            "drop",
                        ], check=True)
                    except Exception:
                        rc = 1
                    finally:
                        os._exit(rc)
                else:
                    _, status = os.waitpid(child, 0)
                    if status != 0:
                        report.add("nftables error", ip, level="err")
                    else:
                        add_suspicious_ip(ip)
    except Exception as e:
        report.add("block ip error", f"PID {pid}: {e}", level="err")


def apply_ip_blocklist(report: SentinelReport) -> None:
    """Proactively block known malicious IPs using nftables."""
    if os.geteuid() != 0:
        return
    bad_ips = load_suspicious_ips()
    for ip in bad_ips:
        try:
            rc = subprocess.run(
                ["nft", "list", "chain", "ip", "filter", "INPUT"],
                capture_output=True,
                text=True,
                check=False,
            )
            if rc.returncode != 0:
                continue
            if f"ip saddr {ip} drop" not in rc.stdout:
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "filter",
                        "INPUT",
                        "ip",
                        "saddr",
                        ip,
                        "drop",
                    ],
                    check=False,
                )
                report.add("IP blocked", ip, level="crit")
        except Exception:
            continue

def kill_evil_processes(report: SentinelReport):
    """Kill processes with names or paths matching known malicious signatures."""
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            target = name + ' ' + exe
            if any(sig in target for sig in EVIL_PROCESS_SIGNATURES):
                block_remote_ips(proc.pid, report)
                os.kill(proc.pid, signal.SIGKILL)
                report.add(
                    "Killed process",
                    f"PID {proc.pid}: {target.strip()}",
                    level="crit",
                )
        except Exception as e:
            report.add("Kill error", f"PID {proc.pid}: {e}", level="err")


def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def reinstall_tool(name: str, report: SentinelReport) -> None:
    """Attempt to reinstall a tool using the system package manager."""
    apt = shutil.which("apt-get") or shutil.which("apt")
    if not apt:
        report.add("reinstall unavailable", name, level="err")
        return
    try:
        subprocess.run([apt, "install", "--reinstall", "-y", name], check=False)
    except Exception as e:
        report.add("reinstall error", f"{name}: {e}", level="err")


def verify_tool_integrity(name: str, path: str, report: SentinelReport) -> bool:
    """Check tool checksum against DB and reinstall if mismatched."""
    actual = sha256_file(path)
    if not actual:
        return False
    stored = get_tool_checksum(name)
    if not stored:
        store_tool_checksum(name, path, actual)
        return True
    if stored != actual:
        report.add("Tool checksum mismatch", name, level="warn")
        reinstall_tool(name, report)
        new = sha256_file(path)
        store_tool_checksum(name, path, new)
        return new == actual
    return True


def consolidate_process_checksums(report: SentinelReport, threshold: float = 20.0):
    """Store running process executable checksums when CPU usage is low."""
    if psutil.cpu_percent(interval=1.0) > threshold:
        return
    for proc in psutil.process_iter(['exe']):
        exe = proc.info.get('exe')
        if exe and os.path.isfile(exe):
            checksum = sha256_file(exe)
            if checksum:
                store_process(exe, checksum)


def kill_priv_escalation_ports(report: SentinelReport):
    """Kill processes that gained root and opened a listening port."""
    for proc in psutil.process_iter(['pid', 'uids', 'exe']):
        try:
            uids = proc.uids()
            if uids.effective == 0 and uids.real != 0:
                conns = proc.connections(kind='inet')
                if any(c.status == psutil.CONN_LISTEN for c in conns):
                    exe = proc.info.get('exe') or ''
                    checksum = sha256_file(exe) if exe else ''
                    if checksum:
                        store_process(exe, checksum)
                        paths = find_paths_by_checksum(checksum)
                        for p in paths:
                            if p != exe:
                                report.add('Possible copy', p, level='notice')
                    block_remote_ips(proc.pid, report)
                    os.kill(proc.pid, signal.SIGKILL)
                    report.add('Killed priv esc', f'PID {proc.pid}: {exe}', level='crit')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def remove_evil_modules(report: SentinelReport):
    """Remove loaded kernel modules matching known malicious signatures."""
    try:
        with open('/proc/modules') as f:
            modules = [line.split()[0] for line in f]
    except Exception as e:
        report.add("module list error", str(e), level="err")
        return
    for mod in modules:
        if any(sig in mod for sig in EVIL_MODULE_SIGNATURES):
            try:
                subprocess.run(['rmmod', mod], check=True)
                report.add("Removed module", mod, level="crit")
            except Exception as e:
                report.add("rmmod error", f"{mod}: {e}", level="err")


def _log_lines(prefix: str, lines: List[str]):
    """Send lines to syslog using the logger command."""
    for line in lines:
        try:
            subprocess.run(
                ["logger", "-p", "user.debug", "-t", prefix, "--", line], check=True
            )
        except Exception:
            pass


def run_external_scanners(report: SentinelReport, flag: str = "/var/lib/sentinelroot/first_run"):
    """Run additional scanners like rkhunter on first execution."""
    if os.path.exists(flag):
        return
    os.makedirs(os.path.dirname(flag), exist_ok=True)
    Path(flag).touch()
    if high_system_load():
        report.add("High system load", "Skipping external scanners", level="notice")
        return

    scanners = {
        "rkhunter": ["rkhunter", "--check", "--skip-keypress", "--rwo"],
        "chkrootkit": ["chkrootkit", "-q"],
        "lynis": ["lynis", "audit", "system", "-Q"],
        "maldet": ["maldet", "-b", "-r", "/"],
    }
    ossec_rc = shutil.which("ossec-rootcheck") or "/var/ossec/bin/ossec-rootcheck"
    if os.path.exists(ossec_rc):
        scanners["ossec-rootcheck"] = [ossec_rc]
    for name, cmd in scanners.items():
        exe = cmd[0]
        if not shutil.which(exe) and not os.path.exists(exe):
            report.add(f"{name} not found", "", level="notice")
            continue
        path = exe if os.path.isabs(exe) else shutil.which(exe) or exe
        if not verify_tool_integrity(name, path, report):
            continue
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            lines = out.strip().splitlines()
            _log_lines(f"sentinelroot-{name}", lines)
            if lines:
                report.add(f"{name} output", lines[0], level="info")
            if name == "maldet":
                scan_id = None
                for line in lines:
                    if "SCANID" in line or "SCAN ID" in line:
                        scan_id = line.split()[-1]
                        break
                if scan_id:
                    try:
                        rep = subprocess.check_output(["maldet", "--report", scan_id], text=True, stderr=subprocess.STDOUT)
                        _log_lines("sentinelroot-maldet", rep.strip().splitlines())
                    except Exception as e:
                        report.add("maldet report error", str(e), level="err")
        except Exception as e:
            report.add(f"{name} error", str(e), level="err")

    try:
        dmesg_out = subprocess.check_output(["dmesg", "--ctime", "--since", "now-1min"], text=True)
        _log_lines("sentinelroot-dmesg", dmesg_out.strip().splitlines())
    except Exception:
        pass

def run_heuristics() -> SentinelReport:
    report = SentinelReport()
    if high_system_load():
        report.add("High system load", "Skipping heuristic run", level="notice")
        return report
    check_ld_preload(report)
    check_tmp_exec(report)
    check_hidden_modules(report)
    check_hidden_processes(report)
    check_raw_sockets(report)
    check_suspicious_ports(report)
    check_persistence(report)
    check_systemd_services(report)
    check_network_patterns(report)
    apply_ip_blocklist(report)
    check_kernel_kprobes(report)
    check_ml_signatures(report)
    check_static_binaries(report)
    check_suspicious_cmdline(report)
    check_process_resources(report)
    consolidate_process_checksums(report)
    check_known_process_signatures(report)
    kill_evil_processes(report)
    kill_priv_escalation_ports(report)
    remove_evil_modules(report)
    run_external_scanners(report)
    maybe_run_clamav(report)
    return report

def main():
    parser = argparse.ArgumentParser(
        description="SentinelRoot heuristic scanner"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously and repeat checks",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds to sleep between scans when looping",
    )
    args = parser.parse_args()

    start_background_training()
    while True:
        report = run_heuristics()
        print("SentinelRoot Heuristic Report")
        print(report.summary())
        if not args.loop:
            break
        time.sleep(max(args.interval, 1))

if __name__ == "__main__":
    main()
