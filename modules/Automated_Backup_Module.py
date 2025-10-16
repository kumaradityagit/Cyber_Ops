import os
import zipfile
import datetime
import pickle
import webbrowser
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from twilio.rest import Client

# ------------------------ CONFIG ------------------------

FOLDER_TO_ZIP = "Organized_Files"
OUTPUT_ZIP = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'

# Twilio config (replace with your actual Twilio creds)
TWILIO_SID = ''
TWILIO_AUTH = ''
TWILIO_FROM = '+'
TWILIO_TO = '+'

# ------------------------ FUNCTIONS ------------------------

def zip_folder(folder_path, output_zip):
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for foldername, _, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                zipf.write(file_path, os.path.relpath(file_path, folder_path))
    return output_zip

def authenticate_drive():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)

def upload_to_drive(service, file_path):
    file_metadata = {'name': os.path.basename(file_path)}
    media = MediaFileUpload(file_path, resumable=True)
    uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    return uploaded_file.get('id')

def send_twilio_sms(message_body):
    client = Client(TWILIO_SID, TWILIO_AUTH)
    message = client.messages.create(
        body=message_body,
        from_=TWILIO_FROM,
        to=TWILIO_TO
    )
    return message.sid

# ------------------------ MAIN SCRIPT ------------------------

print("────────────────────────────────────────────")
print("💾  Auto Backup Module")
print("────────────────────────────────────────────")

print("📦  Zipping organized files...")
zip_path = zip_folder(FOLDER_TO_ZIP, OUTPUT_ZIP)

print("🔐  Authenticating with Google Drive...")
drive_service = authenticate_drive()

print("🛰️  Uploading to Google Drive...")
from googleapiclient.http import MediaFileUpload
file_id = upload_to_drive(drive_service, zip_path)

print("\n✅  Backup complete!")
print(f"📁  Your file has been safely uploaded.")
print(f"🔗  Drive File ID: {file_id}")

# Twilio message
print("\n📲  Sending Twilio SMS alert...")
twilio_msg = "Report generated and successfully backed up into your Google Drive!"
try:
    sms_id = send_twilio_sms(twilio_msg)
    print(f"✅  SMS sent successfully! Message SID: {sms_id}")
except Exception as e:
    print(f"❌  Failed to send SMS: {e}")

print("\n🎉  All done. Go have a biryani break, soldier.")
print("────────────────────────────────────────────")
