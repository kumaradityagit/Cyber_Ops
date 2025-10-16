import psutil
import os
import time
import hashlib
import datetime
from pathlib import Path

# === Config ===
SCAN_INTERVAL = 5  # seconds between scans
CPU_THRESHOLD = 30.0  # % CPU usage that’s sus
MEM_THRESHOLD_MB = 200  # RAM usage in MB that’s sus
SUS_PATH_KEYWORDS = ["AppData", "Temp", "ProgramData"]
SUS_NAMES = ["rat.exe", "keylogger.exe", "explorer_fake.exe"]  # add more
REPORT_DIR = r"C:\Users\Administrator\Documents\Capstone Reformed -"

Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

def hash_file(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "CouldNotHash"

def is_path_suspicious(path):
    return any(keyword.lower() in path.lower() for keyword in SUS_PATH_KEYWORDS)

def analyze_process(proc):
    try:
        info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cpu_percent', 'memory_info'])
        exe = info.get("exe") or ""
        mem_mb = info['memory_info'].rss / (1024 * 1024)
        cpu = info['cpu_percent']
        hash_val = hash_file(exe) if exe else "N/A"

        flags = []

        # === Rule Checks ===
        if cpu > CPU_THRESHOLD:
            flags.append("HIGH_CPU")

        if mem_mb > MEM_THRESHOLD_MB:
            flags.append("HIGH_MEMORY")

        if is_path_suspicious(exe):
            flags.append("SUSPICIOUS_PATH")

        if info['name'].lower() in SUS_NAMES:
            flags.append("KNOWN_MALWARE_NAME")

        # === Suspicious Score ===
        threat_score = len(flags) * 2.5  # basic weight logic

        return {
            "pid": info['pid'],
            "name": info['name'],
            "path": exe,
            "cpu": cpu,
            "mem_mb": round(mem_mb, 2),
            "sha256": hash_val,
            "flags": flags,
            "threat_score": threat_score
        } if flags else None

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def write_report(sus_processes):
    if not sus_processes:
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(REPORT_DIR, f"watchdog_report_{timestamp}.txt")

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=== Real-Time Process Watchdog Report ===\n")
        f.write(f"Timestamp: {timestamp}\n\n")
        for proc in sus_processes:
            f.write(f"[PID {proc['pid']}] {proc['name']}\n")
            f.write(f" Path        : {proc['path']}\n")
            f.write(f" SHA256      : {proc['sha256']}\n")
            f.write(f" CPU %       : {proc['cpu']}\n")
            f.write(f" Mem (MB)    : {proc['mem_mb']}\n")
            f.write(f" Flags       : {', '.join(proc['flags'])}\n")
            f.write(f" Threat Score: {proc['threat_score']}\n")
            f.write("-" * 40 + "\n")

    print(f"[+] 🔥 Report saved to: {report_file}")

def main():
    print("🚨 Real-Time Process Watchdog is live (will stop after 2 reports)...")
    report_count = 0

    while report_count < 2:
        sus_processes = []
        for proc in psutil.process_iter():
            result = analyze_process(proc)
            if result:
                sus_processes.append(result)

        if sus_processes:
            write_report(sus_processes)
            report_count += 1
        else:
            print("[+] No suspicious processes found in this round.")

        time.sleep(SCAN_INTERVAL)

    print("✅ 2 reports saved. Watchdog going to sleep 😴")


if __name__ == "__main__":
    main()
