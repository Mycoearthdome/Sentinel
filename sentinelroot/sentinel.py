import os
import subprocess
import psutil
from dataclasses import dataclass, field
from typing import List, Dict

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

def run_heuristics() -> SentinelReport:
    report = SentinelReport()
    check_ld_preload(report)
    check_tmp_exec(report)
    check_hidden_modules(report)
    check_hidden_processes(report)
    return report

def main():
    report = run_heuristics()
    print("SentinelRoot Heuristic Report")
    print(report.summary())

if __name__ == "__main__":
    main()
