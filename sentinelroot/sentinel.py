import os
import subprocess
import psutil
import socket
import signal
import sqlite3
import hashlib
import time

# Simple lists of known malicious signatures. These can be extended or
# loaded from an external source in the future.
# Start with built-in signatures but extend from the SQLite database when
# available. This allows quick searches across distributions.
EVIL_PROCESS_SIGNATURES = ["evilproc", "badproc"]
EVIL_PROCESS_SIGNATURES.extend(load_signatures())
EVIL_MODULE_SIGNATURES = ["evilmod", "badmodule"]
from dataclasses import dataclass, field
from typing import List
from .ml import SignatureClassifier
from .db import store_process, find_paths_by_checksum, load_signatures, PROCESS_DB

@dataclass
class DetectionResult:
    issue: str
    details: str

@dataclass
class SentinelReport:
    results: List[DetectionResult] = field(default_factory=list)

    def add(self, issue: str, details: str):
        self.results.append(DetectionResult(issue, details))

    def summary(self) -> str:
        return "\n".join(f"{r.issue}: {r.details}" for r in self.results)


def check_ld_preload(report: SentinelReport):
    preload_env = os.environ.get("LD_PRELOAD")
    if preload_env:
        report.add("LD_PRELOAD env", preload_env)
    try:
        with open("/etc/ld.so.preload", "r") as f:
            content = f.read().strip()
            if content:
                report.add("ld.so.preload", content)
    except FileNotFoundError:
        pass

def check_tmp_exec(report: SentinelReport):
    for proc in psutil.process_iter(['pid', 'exe']):
        exe = proc.info.get('exe')
        if exe and any(exe.startswith(p) for p in ("/tmp", "/dev", "/run")):
            report.add("Executable from tmp", f"PID {proc.pid}: {exe}")

def check_hidden_modules(report: SentinelReport):
    try:
        lsmod_output = subprocess.check_output(['lsmod'], text=True)
        listed = {line.split()[0] for line in lsmod_output.strip().splitlines()[1:]}
    except Exception as e:
        report.add("lsmod error", str(e))
        return
    try:
        with open('/proc/modules') as f:
            modules = {line.split()[0] for line in f.readlines()}
    except Exception as e:
        report.add("/proc/modules error", str(e))
        return
    hidden = modules - listed
    for mod in hidden:
        report.add("Hidden module", mod)

def check_hidden_processes(report: SentinelReport):
    try:
        ps_output = subprocess.check_output(['ps', '-e', '-o', 'pid'], text=True)
        pids_ps = {int(pid) for pid in ps_output.strip().splitlines()[1:]}
    except Exception as e:
        report.add("ps error", str(e))
        return
    pids_proc = {int(pid) for pid in os.listdir('/proc') if pid.isdigit()}
    hidden = pids_proc - pids_ps
    for pid in sorted(hidden):
        report.add("Hidden process", f"PID {pid}")

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
                    report.add("Raw socket", f"PID {pid} ({name})")
    except Exception as e:
        report.add("raw socket check error", str(e))

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
                report.add("Suspicious port", f"PID {pid} ({name}) listening on {conn.laddr.port}")
    except Exception as e:
        report.add("port check error", str(e))

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
                report.add("Persistence file", f"{path} contains suspicious entry")
        except Exception as e:
            report.add("persistence check error", f"{path}: {e}")

def check_ml_signatures(report: SentinelReport):
    """Run ML classifier on running executable paths if model is available."""
    model_path = os.path.join(os.path.dirname(__file__), "signature_model.joblib")
    if not os.path.isfile(model_path):
        return
    clf = SignatureClassifier()
    try:
        clf.load(model_path)
    except Exception as e:
        report.add("ml load error", str(e))
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
                report.add("ML suspicious", f"{exe} score={score:.2f}")
    except Exception as e:
        report.add("ml predict error", str(e))

def check_suspicious_cmdline(report: SentinelReport):
    """Detect processes started with suspicious command line arguments."""
    keywords = ["curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby", "base64"]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info.get('cmdline') or [])
            if any(k in cmdline for k in keywords):
                report.add("Suspicious cmdline", f"PID {proc.pid}: {cmdline}")
        except Exception:
            continue

def check_process_resources(report: SentinelReport, cpu_thresh: float = 80.0, mem_thresh: float = 80.0):
    """Flag processes using excessive CPU or memory."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_percent()
            if cpu > cpu_thresh:
                report.add("High CPU", f"PID {proc.pid} ({proc.info.get('name')}) {cpu:.1f}%")
            if mem > mem_thresh:
                report.add("High memory", f"PID {proc.pid} ({proc.info.get('name')}) {mem:.1f}%")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def check_known_process_signatures(report: SentinelReport):
    """Report processes whose names match known malicious signatures."""
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            target = name + ' ' + exe
            if any(sig in target for sig in EVIL_PROCESS_SIGNATURES):
                report.add("Known bad process", f"PID {proc.pid}: {target.strip()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def kill_evil_processes(report: SentinelReport):
    """Kill processes with names or paths matching known malicious signatures."""
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            target = name + ' ' + exe
            if any(sig in target for sig in EVIL_PROCESS_SIGNATURES):
                os.kill(proc.pid, signal.SIGKILL)
                report.add("Killed process", f"PID {proc.pid}: {target.strip()}")
        except Exception as e:
            report.add("Kill error", f"PID {proc.pid}: {e}")


def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


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
            if uids.euid == 0 and uids.real != 0:
                conns = proc.connections(kind='inet')
                if any(c.status == psutil.CONN_LISTEN for c in conns):
                    exe = proc.info.get('exe') or ''
                    checksum = sha256_file(exe) if exe else ''
                    if checksum:
                        store_process(exe, checksum)
                        paths = find_paths_by_checksum(checksum)
                        for p in paths:
                            if p != exe:
                                report.add('Possible copy', p)
                    os.kill(proc.pid, signal.SIGKILL)
                    report.add('Killed priv esc', f'PID {proc.pid}: {exe}')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def remove_evil_modules(report: SentinelReport):
    """Remove loaded kernel modules matching known malicious signatures."""
    try:
        with open('/proc/modules') as f:
            modules = [line.split()[0] for line in f]
    except Exception as e:
        report.add("module list error", str(e))
        return
    for mod in modules:
        if any(sig in mod for sig in EVIL_MODULE_SIGNATURES):
            try:
                subprocess.run(['rmmod', mod], check=True)
                report.add("Removed module", mod)
            except Exception as e:
                report.add("rmmod error", f"{mod}: {e}")

def run_heuristics() -> SentinelReport:
    report = SentinelReport()
    check_ld_preload(report)
    check_tmp_exec(report)
    check_hidden_modules(report)
    check_hidden_processes(report)
    check_raw_sockets(report)
    check_suspicious_ports(report)
    check_persistence(report)
    check_ml_signatures(report)
    check_suspicious_cmdline(report)
    check_process_resources(report)
    consolidate_process_checksums(report)
    check_known_process_signatures(report)
    kill_evil_processes(report)
    kill_priv_escalation_ports(report)
    remove_evil_modules(report)
    return report

def main():
    report = run_heuristics()
    print("SentinelRoot Heuristic Report")
    print(report.summary())

if __name__ == "__main__":
    main()
