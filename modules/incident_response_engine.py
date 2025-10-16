import os
import time
import psutil
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import socket

# Default path to save reports
SAVE_PATH = r"C:\Users\harsh\Documents\Reports generated"

# === MOCK THREAT DATA (you'll later get this from actual analysis)
threat_data = {
    "malicious_processes": ["badprocess.exe", "sneakymalware.exe"],
    "suspicious_ips": ["192.168.1.101"],
    "threat_score": 85
}

# === USER-SELECTABLE OPTIONS ===
def get_user_choices():
    print("\n🔥 INCIDENT RESPONSE MENU 🔥")
    print("Choose the actions to perform (y/n):\n")

    choices = {
        "kill_processes": input("🛑 Kill Malicious Processes? (y/n): ").strip().lower() == 'y',
        "disconnect_network": input("📡 Disconnect Network Adapter? (y/n): ").strip().lower() == 'y',
        "isolate_folder": input("🔐 Isolate Folder (quarantine)? (y/n): ").strip().lower() == 'y',
        "create_backup": input("💾 Backup Critical Data? (y/n): ").strip().lower() == 'y'
    }

    return choices

# === ACTIONS ===
def kill_malicious_processes():
    results = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in threat_data["malicious_processes"]:
            try:
                proc.kill()
                results.append(f"Killed: {proc.info['name']} (PID {proc.info['pid']})")
            except Exception as e:
                results.append(f"Failed to kill {proc.info['name']}: {str(e)}")
    return results

def disconnect_network():
    try:
        os.system("netsh interface set interface name=\"Wi-Fi\" admin=disabled")
        return ["Network adapter 'Wi-Fi' disabled."]
    except Exception as e:
        return [f"Failed to disconnect Wi-Fi: {str(e)}"]

def isolate_folder():
    # Just for demo: make a folder called "Quarantine"
    quarantine_path = os.path.join(SAVE_PATH, "Quarantine")
    try:
        os.makedirs(quarantine_path, exist_ok=True)
        return [f"Created quarantine folder: {quarantine_path}"]
    except Exception as e:
        return [f"Failed to isolate folder: {str(e)}"]

def backup_critical_data():
    # Demo version: pretend to backup
    try:
        # You can plug in real backup code later
        return ["Backup triggered (simulated)."]
    except Exception as e:
        return [f"Backup failed: {str(e)}"]

# === REPORT GENERATOR ===
def generate_pdf_report(actions_taken):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(SAVE_PATH, f"Incident_Response_Report_{now}.pdf")
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750

    c.drawString(100, y, f"Incident Response Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20

    # Add IP
    try:
        ip = socket.gethostbyname(socket.gethostname())
        c.drawString(100, y, f"System IP Address: {ip}")
        y -= 20
    except:
        c.drawString(100, y, f"System IP Address: [Failed to fetch]")
        y -= 20

    for action in actions_taken:
        c.drawString(100, y, f"- {action}")
        y -= 20
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750

    c.save()
    print(f"\n[✔] PDF saved at: {filename}")

# === MASTER CONTROLLER ===
def incident_response_engine():
    choices = get_user_choices()

    print("\n[⏳] Initiating response in 15 seconds. Press Ctrl+C to cancel.\n")
    time.sleep(15)

    all_actions = []

    if choices["kill_processes"]:
        all_actions.extend(kill_malicious_processes())
    if choices["disconnect_network"]:
        all_actions.extend(disconnect_network())
    if choices["isolate_folder"]:
        all_actions.extend(isolate_folder())
    if choices["create_backup"]:
        all_actions.extend(backup_critical_data())

    generate_pdf_report(all_actions)
    print("[🚨] Incident Response Completed.")

# === EXECUTE ===
if __name__ == "__main__":
    incident_response_engine()
