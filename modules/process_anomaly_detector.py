import psutil
import time
import os
from datetime import datetime
from fpdf import FPDF

# ===== 1. Monitoring Setup =====
SUSPICIOUS_PROCESSES = ['malware.exe', 'suspicious_process.exe']  # Add suspicious process names here
SUSPICIOUS_THRESHOLD = 80  # CPU or Memory usage threshold (in percentage)
COOLDOWN_PERIOD = 15  # Cooldown in seconds before the next check

# ===== 2. Process Monitor =====
def monitor_processes():
    print("🔍 Monitoring system processes for suspicious activity...")
    
    while True:
        suspicious_found = False
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                process_name = proc.info['name'].lower()
                cpu_usage = proc.info['cpu_percent']
                memory_usage = proc.info['memory_percent']
                
                # Check for suspicious processes
                if process_name in SUSPICIOUS_PROCESSES or cpu_usage > SUSPICIOUS_THRESHOLD or memory_usage > SUSPICIOUS_THRESHOLD:
                    print(f"⚠️ Suspicious process detected: {process_name} (PID: {proc.info['pid']})")
                    suspicious_found = True
                    log_suspicious_activity(proc, cpu_usage, memory_usage)

        if suspicious_found:
            print("🚨 ALERT: Suspicious activity detected!")
        else:
            print("✅ All processes are clean.")
        
        time.sleep(COOLDOWN_PERIOD)  # Cooldown before next check

# ===== 3. Log Suspicious Activity =====
def log_suspicious_activity(proc, cpu_usage, memory_usage):
    print("📄 Logging suspicious activity...")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Suspicious Activity Report", ln=1, align="C")
    pdf.cell(200, 10, txt=f"Process Name: {proc.info['name']}", ln=2)
    pdf.cell(200, 10, txt=f"PID: {proc.info['pid']}", ln=3)
    pdf.cell(200, 10, txt=f"CPU Usage: {cpu_usage}%", ln=4)
    pdf.cell(200, 10, txt=f"Memory Usage: {memory_usage}%", ln=5)
    
    # Save the report
    pdf_file = f"Suspicious_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(pdf_file)
    print(f"✅ Suspicious report saved as {pdf_file}")
    
    # Move report to the reports folder
    org_dir = r"C:\Users\harsh\Documents\Reports generated"
    if not os.path.exists(org_dir): os.mkdir(org_dir)
    os.rename(pdf_file, os.path.join(org_dir, pdf_file))

# ===== 4. Start Monitoring =====
if __name__ == "__main__":
    monitor_processes()
