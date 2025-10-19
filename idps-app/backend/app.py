from flask import Flask, jsonify, send_from_directory, render_template, request, redirect, url_for, session
import json
import os
import sqlite3
import bcrypt
from init_db import initialize_database
from flask_cors import CORS

# Se initializeaza baza de date daca nu exista
initialize_database()

app = Flask(__name__, static_folder='../frontend/', static_url_path='')
CORS(app, supports_credentials=True)

app.secret_key = "idps_ss_key"

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "users.db")
ALERTS_DB_PATH = os.path.join(os.path.dirname(__file__), "db", "alert_history.db")

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"username": row[0], "password_hash": row[1], "role": row[2]}
    return None

def normalize_ip(ip):
    return ip.replace("::ffff:", "") if ip else "-"

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = get_user(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        session['username'] = username
        session['role'] = user['role']
        return jsonify({"message": "Autentificare reusita", "role": user['role']})
    return jsonify({"error": "Username sau parola invalida"}), 401

@app.route("/admin")
def admin_dashboard():
    if session.get("role") == "admin":
        return send_from_directory(app.static_folder, "public/index.html")
    return redirect("/login")

@app.route("/admin/user_devices", methods=["GET"])
def get_user_devices():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT u.username, d.ip_address
        FROM users u
        LEFT JOIN user_devices d ON u.id = d.user_id
    """)
    results = c.fetchall()
    conn.close()

    user_devices = {}
    for username, ip in results:
        user_devices.setdefault(username, []).append(ip if ip else "-")

    return jsonify(user_devices)

@app.route("/admin/add_user", methods=["POST"])
def add_user():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, hashed, role))
        conn.commit()
        return jsonify({"message": "Utilizator adaugat"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Utilizator deja existent"}), 409
    finally:
        conn.close()


@app.route("/admin/assign_ip", methods=["POST"])
def assign_ip():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403

    data = request.get_json()
    username = data.get("username")
    ip = data.get("ip")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        return jsonify({"error": "Utilizatorul nu exista"}), 404

    user_id = row[0]
    try:
        c.execute("INSERT INTO user_devices (user_id, ip_address) VALUES (?, ?)", (user_id, ip))
        conn.commit()
        return jsonify({"message": "IP asociat cu succes"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "IP deja asociat"}), 409
    finally:
        conn.close()


@app.route("/admin/delete_user", methods=["DELETE"])
def delete_user():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403

    data = request.get_json()
    username = data.get("username")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        return jsonify({"error": "Utilizatorul nu exista"}), 404

    user_id = row[0]
    c.execute("DELETE FROM user_devices WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Utilizator sters"})


@app.route("/admin/unassign_ip", methods=["DELETE"])
def unassign_ip():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403

    data = request.get_json()
    username = data.get("username")
    ip = data.get("ip")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        return jsonify({"error": "Utilizatorul nu exista"}), 404

    user_id = row[0]
    c.execute("DELETE FROM user_devices WHERE user_id = ? AND ip_address = ?", (user_id, ip))
    conn.commit()
    conn.close()
    return jsonify({"message": "IP sters din asociere"})

@app.route("/user_attacks", methods=["GET"])
def user_attacks():
    if session.get("role") != "admin":
        return jsonify({"error": "Acces interzis!"}), 403
    else:
        conn1 = sqlite3.connect(DB_PATH)
        conn2 = sqlite3.connect(ALERTS_DB_PATH)
        user_map = {}

        # Colecteaza user -> IP-uri
        c1 = conn1.cursor()
        c1.execute("""
            SELECT u.username, d.ip_address
            FROM users u
            JOIN user_devices d ON u.id = d.user_id
        """)
        for username, ip in c1.fetchall():
            user_map.setdefault(username, []).append(ip)
        conn1.close()

        # Colecteaza alertele
        c2 = conn2.cursor()
        c2.execute("SELECT timestamp, src_ip, dest_ip, proto, signature, label FROM alerts ORDER BY timestamp DESC")
        alerts = c2.fetchall()
        conn2.close()

        # Alerte per utilizator
        user_alerts = {}
        for alert in alerts:
            for username, ips in user_map.items():
                if alert[1] in ips or alert[2] in ips:
                    user_alerts.setdefault(username, []).append({
                        "timestamp": alert[0],
                        "src_ip": alert[1],
                        "dest_ip": alert[2],
                        "proto": alert[3],
                        "signature": alert[4],
                        "label": alert[5]
                    })

        return jsonify(user_alerts)

@app.route("/user")
def user_dashboard():
    if session.get("role") == "user":
        return send_from_directory(app.static_folder, "public/user.html")
    return redirect("/login")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route("/login")
def serve_login_page():
    return send_from_directory(app.static_folder, "public/login.html")

@app.route('/')
def serve_index():
    return send_from_directory(os.path.join(app.static_folder, 'public'), 'login.html')

@app.route('/alerts', methods=['GET'])
def get_alerts():
    alerts = []
    try:
        with open('/var/log/suricata/eve.json', 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alerts.append({
                            "timestamp": data.get("timestamp", "-"),
                            "src_ip": normalize_ip(data.get("src_ip", "-")),
                            "dest_ip": normalize_ip(data.get("dest_ip", "-")),
                            "proto": data.get("proto", "-"),
                            "signature": data.get("alert", {}).get("signature", "-")
                        })
                except json.JSONDecodeError:
                    continue
        #return jsonify(alerts)        # return all alerts
        return jsonify(alerts[-20:])  # ultimele 20 alerte
    except:
        return jsonify([])

@app.route("/whoami")
def whoami():
    ip = request.remote_addr
    return jsonify({"ip": ip})

# Asigura servirea fisierelor statice (css, js)
@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
