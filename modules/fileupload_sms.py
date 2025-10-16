import os, hashlib, requests, shutil, pickle, threading
from datetime import datetime
from fpdf import FPDF
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from twilio.rest import Client

# ===== Config Section =====
VIRUSTOTAL_API_KEY = "f87a2619801c0a693ad2851f65e0a4693c2f3cd42de4a92141514384f42cd06c"
TWILIO_SID = "AC8b2822e2a0b8480fcb7e9d6cf486928b"
TWILIO_AUTH_TOKEN = "4245b9eeec8476c809f2dab47eaca618"
TWILIO_FROM = "+13304463770"
TWILIO_TO = "+917980729383"
SCOPES = ['https://www.googleapis.com/auth/drive.file']
ORG_DIR = r"C:\Users\Administrator\Documents\Capstone Project Code All"

# ===== 1. Fun Input Handler =====
print("🎯 Welcome to Threat Analyzer 3000™")
file_path = input("📁 Enter the path of the file you want to scan: ")

if not os.path.isfile(file_path):
    print("❌ File doesn't exist! Try again, Sherlock.")
    exit()

# ===== 2. Hash Generator =====
print("🔍 Crunching file into SHA256 hash...")
def calculate_hash(path):
    with open(path, "rb") as f:
        bytes = f.read()
        return hashlib.sha256(bytes).hexdigest()

file_hash = calculate_hash(file_path)
print(f"📡 Hash generated: {file_hash}")

# ===== 3. VirusTotal Checker =====
def check_virustotal(hash_val):
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

print("📬 Sending hash to VirusTotal HQ...")
data = check_virustotal(file_hash)

if "error" in data:
    print("❌ VirusTotal says: Not found.")
    verdict = "Not Found"
    positives = 0
else:
    positives = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    verdict = "Malicious" if positives > 0 else "Clean"
    print(f"⚠️ Detected by {positives} engines. Verdict: {verdict}")

# ===== 4. PDF Generator =====
print("📄 Generating PDF report...")
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt="Malware Threat Report", ln=1, align="C")
pdf.cell(200, 10, txt=f"File: {file_path}", ln=2)
pdf.cell(200, 10, txt=f"SHA256: {file_hash}", ln=3)
pdf.cell(200, 10, txt=f"Detection: {positives} engines", ln=4)
pdf.cell(200, 10, txt=f"Verdict: {verdict}", ln=5)
pdf_file = f"Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
pdf.output(pdf_file)
print(f"✅ Report saved as {pdf_file}")

# ===== 5. Organizer =====
print("📦 Organizing files...")
if not os.path.exists(ORG_DIR): os.mkdir(ORG_DIR)
shutil.copy(file_path, ORG_DIR)
shutil.copy(pdf_file, ORG_DIR)

# ===== 6. Google Drive Auth + PDF Upload =====
print("🔐 Authenticating with Google Drive...")
def authenticate_drive():
    if os.path.exists('token.pkl'):
        with open('token.pkl', 'rb') as token:
            creds = pickle.load(token)
    else:
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.pkl', 'wb') as token:
            pickle.dump(creds, token)
    return build('drive', 'v3', credentials=creds)

drive_service = authenticate_drive()

print("☁️ Uploading PDF report to Google Drive...")
pdf_path = os.path.join(ORG_DIR, pdf_file)
media = MediaFileUpload(pdf_path, mimetype='application/pdf')
file_metadata = {"name": pdf_file}
uploaded = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
file_id = uploaded.get("id")
print(f"✅ PDF uploaded! Google Drive File ID: {file_id}")

# ===== 7. Send Twilio SMS =====
print("📲 Sending SMS alert via Twilio...")
try:
    client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=f"📄 Threat report generated and backed up to Google Drive!\nVerdict: {verdict}, Detections: {positives} engines.",
        from_=TWILIO_FROM,
        to=TWILIO_TO
    )
    print(f"✅ SMS sent! SID: {message.sid}")
except Exception as e:
    print(f"❌ Failed to send SMS. Error: {e}")


