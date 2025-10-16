import random
import requests
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

# Path to save the PDF report
SAVE_PATH = r"C:\Users\harsh\Documents\Reports generated"

# Function to get current public IP address automatically
def get_public_ip():
    """Fetch the public IP address from an API."""
    try:
        ip_address = requests.get("https://api.ipify.org").text
        print(f"Detected public IP address: {ip_address}")
        return ip_address
    except requests.RequestException as e:
        print(f"Error retrieving public IP address: {e}")
        return "Unknown IP"

# Mock functions for external modules
def get_ai_threat_score():
    """Simulate AI-generated score (0-100) based on suspicious behavior."""
    return random.randint(0, 100)

def get_ip_reputation_score(ip_address):
    """Simulate IP reputation score (0-100) from services like AbuseIPDB/AlienVault."""
    # In real life, you'd call the API here to get the score
    return random.randint(0, 100)

def analyze_process_behavior(process_data):
    """Simulate process behavior analysis. Return a threat score based on the process data."""
    # In reality, you'd look for unusual system calls or behavior patterns
    return random.randint(0, 100)

# Consolidation function
def consolidate_threat_score(process_data):
    """
    Consolidates threat scores from AI, process behavior, and IP reputation.
    
    :param process_data: Process data from watchdog/analyzer
    :return: Final consolidated threat score
    """
    ip_address = get_public_ip()  # Automatically get the public IP address
    ai_score = get_ai_threat_score()
    ip_score = get_ip_reputation_score(ip_address)
    process_score = analyze_process_behavior(process_data)

    # Print scores for debugging
    print(f"AI Threat Score: {ai_score}")
    print(f"IP Reputation Score for {ip_address}: {ip_score}")
    print(f"Process Behavior Threat Score: {process_score}")

    # Weighted scoring logic (adjust based on your needs)
    final_score = (ai_score * 0.4) + (ip_score * 0.3) + (process_score * 0.3)
    
    print(f"Consolidated Threat Score: {final_score:.2f}")
    
    # Generate the PDF report after consolidation
    generate_pdf_report(ai_score, ip_score, process_score, final_score, ip_address)

    return final_score

# PDF Generation Function
def generate_pdf_report(ai_score, ip_score, process_score, final_score, ip_address):
    """
    Generates a PDF report with the threat scores and analysis.
    
    :param ai_score: AI-generated threat score
    :param ip_score: IP reputation score
    :param process_score: Process behavior threat score
    :param final_score: Consolidated threat score
    :param ip_address: IP address being analyzed
    """
    # Set the full file path to save
    filename = os.path.join(SAVE_PATH, f"Threat_Score_Report_{ip_address}.pdf")
    c = canvas.Canvas(filename, pagesize=letter)
    
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, f"Threat Score Report for IP: {ip_address}")
    c.drawString(100, 730, f"AI Threat Score: {ai_score}")
    c.drawString(100, 710, f"IP Reputation Score: {ip_score}")
    c.drawString(100, 690, f"Process Behavior Threat Score: {process_score}")
    c.drawString(100, 670, f"Consolidated Threat Score: {final_score:.2f}")
    
    c.save()

    print(f"[+] PDF report generated and saved at: {filename}")

# Test with sample data
process_data_sample = "Sample process data"  # Replace with actual process data

final_threat_score = consolidate_threat_score(process_data_sample)

# Determine if action is needed based on final score
if final_threat_score > 70:
    print("🚨 High threat level detected! Triggering Incident Response...")
else:
    print("✅ Threat level acceptable. No immediate action needed.")
