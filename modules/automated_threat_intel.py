import hashlib
import requests
import os
import time

VT_API_KEY = "f87a2619801c0a693ad2851f65e0a4693c2f3cd42de4a92141514384f42cd06c"

def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_analysis_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    return response

def upload_file_to_vt(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(url, headers=headers, files=files)
    return response

def analyze_and_report(file_path):
    print("🔍 Crunching file into SHA256 hash...")
    file_hash = get_sha256(file_path)
    print(f"📡 Hash: {file_hash}")

    print("🔎 Checking if report exists on VirusTotal...")
    response = get_analysis_report(file_hash)

    if response.status_code == 200:
        print("📊 Report found! Fetching intel...")
        print_threat_summary(response.json(), file_hash)
    elif response.status_code == 404:
        print("📁 File not found on VirusTotal. Uploading it now...")
        upload_response = upload_file_to_vt(file_path)
        if upload_response.status_code == 200:
            print("📤 File uploaded successfully. Waiting for analysis...")
            time.sleep(20)  # chill for a bit
            # VT returns a new analysis ID after upload
            uploaded_file_id = upload_response.json()["data"]["id"]
            # Wait and poll analysis result
            fetch_analysis(uploaded_file_id, file_hash)
        else:
            print("❌ Upload failed. Error:", upload_response.text)
    else:
        print("❌ Something went wrong:", response.text)

def fetch_analysis(file_id, hash_val):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"

    for _ in range(5):
        response = requests.get(url, headers=headers)
        data = response.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            file_report = get_analysis_report(hash_val)
            if file_report.status_code == 200:
                print_threat_summary(file_report.json(), hash_val)
                return
        print("⏳ Still analyzing... hang tight.")
        time.sleep(10)

    print("🚫 Timed out. Try again later.")

def print_threat_summary(data, file_hash):
    stats = data["data"]["attributes"]["last_analysis_stats"]
    print("\n🎯 Threat Intel Report")
    print("──────────────────────────────")
    print(f"🔗 SHA256: {file_hash}")
    print(f"🧪 Detection Score: {stats['malicious'] + stats['suspicious']}/{sum(stats.values())}")
    print(f"✅ Harmless: {stats['harmless']} | 🟡 Suspicious: {stats['suspicious']} | 🔴 Malicious: {stats['malicious']}")
    print("──────────────────────────────")
    if stats["malicious"] > 10:
        print("🚨 Verdict: ⚠️⚠️⚠️ HIGHLY DANGEROUS ⚠️⚠️⚠️")
    elif stats["malicious"] > 2:
        print("⚠️ Verdict: MEDIUM RISK")
    elif stats["malicious"] == 0 and stats["suspicious"] == 0:
        print("🎉 Verdict: Clean as a whistle!")
    else:
        print("😐 Verdict: Possibly sus...")

# 🚀 Main
if __name__ == "__main__":
    print("👾 Welcome to Terminal Threat Intel Scanner 9000™")
    print("───────────────────────────────────────────────")
    file_path = input("📂 Enter the file path: ").strip('"')

    if not os.path.isfile(file_path):
        print("🚫 File not found.")
    else:
        analyze_and_report(file_path)
