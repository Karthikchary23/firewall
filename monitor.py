import os
import smtplib
import sqlite3
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP

# Define attack detection thresholds
THRESHOLD_SYN = 10  # Number of SYN packets before considering an attack
tracked_ips = {}

# Trusted IP that should NEVER be blocked (Change this to your local IP)
TRUSTED_IP = "192.168.29.217 "

# Email credentials (replace with your own)
SENDER_EMAIL = "hackerantharababu@gmail.com"
SENDER_PASSWORD = "dfcv bbqd qucv shnq"  # Use App Password, NOT your main password
RECEIVER_EMAIL = "lingojikarthikchary@gmail.com"

# Ensure database tables exist
def setup_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS detected_attacks (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ip_address TEXT,
                      reason TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ip_address TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()

# Function to detect attacks
def detect_attack(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Skip blocking the trusted IP
        if src_ip == TRUSTED_IP:
            return  

        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # TCP SYN packet
            tracked_ips[src_ip] = tracked_ips.get(src_ip, 0) + 1

            if tracked_ips[src_ip] > THRESHOLD_SYN:
                log_attack(src_ip, "SYN Flood Attack")
                block_ip(src_ip)
                send_email_alert(src_ip)

# Log detected attacks in SQLite
def log_attack(ip, reason):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO detected_attacks (ip_address, reason) VALUES (?, ?)", (ip, reason))
    conn.commit()
    conn.close()
    print(f"[!] Attack Logged: {ip} ({reason})")

# Block the attacking IP using iptables
def block_ip(ip):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()

    # Check if IP is already blocked
    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=?", (ip,))
    if cursor.fetchone() is None:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (?)", (ip,))
        conn.commit()
        print(f"[🔥] Blocked IP: {ip}")

    conn.close()

# Send Email Alert with enhanced error handling
def send_email_alert(ip):
    subject = "🚨 SYN Flood Attack Detected!"
    body = f"An SYN Flood attack has been detected from IP: {ip}. The IP has been blocked."

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        # Establish the SMTP connection with Gmail
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Secure the connection
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"[📧] Email Alert Sent to {RECEIVER_EMAIL}")
    except smtplib.SMTPException as e:
        print(f"[⚠] SMTP error occurred: {e}")
    except Exception as e:
        print(f"[⚠] General error occurred while sending email: {e}")

# Start network monitoring
if __name__ == "__main__":
    setup_db()
    print("🚀 Monitoring network traffic for SYN flood attacks on localhost...")
    sniff(filter="ip", prn=detect_attack, store=0)
