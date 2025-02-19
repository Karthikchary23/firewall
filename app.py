from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import hashlib

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Used for session management

# Database setup (Run this separately once to create the admin user)
def create_admin_user():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS admin_users (username TEXT, password TEXT)")
    
    # Add default admin user (username: admin, password: admin123)
    password_hash = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute("INSERT INTO admin_users VALUES (?, ?)", ("admin", password_hash))
    
    conn.commit()
    conn.close()

def get_detected_attacks():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, reason FROM detected_attacks ORDER BY timestamp DESC LIMIT 10")
    attacks = cursor.fetchall()
    conn.close()
    return attacks

def get_blocked_ips():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blocked_ips")
    blocked = cursor.fetchall()
    conn.close()
    return [ip[0] for ip in blocked]

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    attacks = get_detected_attacks()
    blocked_ips = get_blocked_ips()
    return render_template("index.html", attacks=attacks, blocked_ips=blocked_ips)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("firewall.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?", (username, password_hash))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect(url_for("index"))
        else:
            return "Invalid credentials. Try again."

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/unblock", methods=["POST"])
def unblock():
    if "user" not in session:
        return redirect(url_for("login"))

    ip = request.form["ip"]
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")

    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

    return redirect("/")

if __name__ == "__main__":
    create_admin_user()  # Run once to ensure admin exists
    app.run(host="0.0.0.0", port=5000, debug=True)
