from flask_cors import CORS
import json
import os
import sqlite3
from sqlite3 import OperationalError
from flask import Flask, jsonify, request
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
import requests
import subprocess
from datetime import datetime, timedelta

WHITELIST = {
    "10.222.8.23",
    "10.222.8.24",
    "10.222.0.51",
    "10.222.0.116"
}

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "alert_history.db")
EVE_FILE =  r"\\10.222.8.23\var\log\suricata\eve.json"

block_cache = {}  # ip: datetime cand a fost blocat
blocked_ips_status = {}  # ip: datetime cand a fost blocat ultima data

BLOCK_DURATION = 120  # secunde

def maybe_block_ip(src_ip, predicted_label):
    now = datetime.now()

    if predicted_label != "malicious" or src_ip in WHITELIST:
        return

    last_block = block_cache.get(src_ip)
    if last_block and (now - last_block).total_seconds() < BLOCK_DURATION:
        print(f"[~] IP-ul {src_ip} a fost deja blocat recent. Ignor...")
        return

    print(f"[!] Cer blocarea IP-ului {src_ip} pe serverul HP...")
    subprocess.Popen([
        "ssh",
        "eduard@10.222.8.23",
        f"/home/eduard/block_ip.sh {src_ip}"
    ])
    block_cache[src_ip] = now
    blocked_ips_status[src_ip] = now

def sync_block_status():
    for ip, ts in block_cache.items():
        blocked_ips_status[ip] = ts

# Creeaza tabela daca nu exista (cu coloana label)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            proto TEXT,
            signature TEXT,
            label TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Salveaza alerta in DB cu eticheta
def save_alert_to_db(alert):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        signature = alert.get("alert", {}).get("signature", "-")
        try:
            # Trimite alerta catre Lenovo pentru clasificare
            res = requests.post("http://10.222.8.24:5002/predict_label", json=alert, timeout=1)
            if res.ok:
                label = res.json().get("predicted_label", "necunoscut")
            else:
                label = "necunoscut"
        except Exception as e:
            print("Eroare la cererea catre Lenovo:", e)
            label = "necunoscut"

        c.execute('''
            INSERT INTO alerts (timestamp, src_ip, dest_ip, proto, signature, label)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert.get("timestamp", "-"),
            alert.get("src_ip", "-").replace("::ffff:", ""),
            alert.get("dest_ip", "-").replace("::ffff:", ""),
            alert.get("proto", "-"),
            signature,
            label
        ))
        conn.commit()
        conn.close()
    except OperationalError as e:
        print("Database locked:", e)

def cleanup_expired_blocks():
    now = datetime.now()
    expired = [ip for ip, t in blocked_ips_status.items() if (now - t).total_seconds() > BLOCK_DURATION]
    for ip in expired:
        del blocked_ips_status[ip]
        del block_cache[ip]

@app.route("/simulate_block", methods=["POST"])
def simulate_block():
    data = request.get_json()
    ip = data.get("ip")
    now = datetime.now()
    block_cache[ip] = now
    blocked_ips_status[ip] = now
    return jsonify({"status": "ok"})
    

@app.route("/blocked_ips", methods=["GET"])
def get_blocked_ips():
    cleanup_expired_blocks()
    response = []
    now = datetime.now()
    to_delete = []

    for ip, block_time in blocked_ips_status.items():
        remaining = (block_time + timedelta(seconds=BLOCK_DURATION)) - now
        if remaining.total_seconds() > 0:
            status = "Blocked"
        else:
            status = "Unblocked"
            to_delete.append(ip)

        response.append({
            "ip": ip,
            "blocked_at": block_time.strftime("%H:%M:%S"),
            "status": status
        })

    # Curatam IP-urile expirate
    for ip in to_delete:
        del blocked_ips_status[ip]
        if ip in block_cache:
            del block_cache[ip]

    return jsonify(response)

@app.route("/alerts/daily", methods=['GET'])
def get_alerts_by_day():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp FROM alerts")
    timestamps = [row[0] for row in cursor.fetchall()]
    conn.close()

    daily_counts = {}
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts)
            day_label = dt.strftime("%Y-%m-%d")
            daily_counts[day_label] = daily_counts.get(day_label, 0) + 1
        except Exception:
            continue

    return jsonify(daily_counts)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    alerts = []
    seen_keys = set()
    try:
        with open(EVE_FILE, "r") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            f.seek(max(file_size - 50000, 0), os.SEEK_SET)  # Citim doar ultimele 50KB
            lines = f.readlines()

            for line in lines:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alert = {
                            "timestamp": data.get("timestamp", "-"),
                            "src_ip": data.get("src_ip", "-").replace("::ffff:", ""),
                            "dest_ip": data.get("dest_ip", "-").replace("::ffff:", ""),
                            "proto": data.get("proto", "-"),
                            "signature": data.get("alert", {}).get("signature", "-")
                        }
                        key = (alert["timestamp"], alert["src_ip"], alert["dest_ip"], alert["signature"])
                        if key not in seen_keys:
                            seen_keys.add(key)

                            #Predictie AI                            
                            try:
                                res = requests.post("http://10.222.8.24:5002/predict_label", json=alert, timeout=1)
                                if res.ok:
                                    alert["predicted_label"] = res.json().get("predicted_label", "necunoscut")
                                else:
                                    alert["predicted_label"] = "necunoscut"
                            
                                if alert["predicted_label"] == "malicious" and alert["src_ip"] not in block_cache:
                                    maybe_block_ip(alert["src_ip"], alert["predicted_label"])

                            except Exception as e:
                                print(f"Eroare la cererea AI in /alerts: {e}")
                                alert["predicted_label"] = "necunoscut"

                            save_alert_to_db(data)
                            alerts.append(alert)
                except json.JSONDecodeError:
                    continue
        return jsonify(alerts[-20:])
    except Exception as e:
        print(f"Error reading eve.json: {e}")
    return jsonify([])

@app.route('/alert_history', methods=['GET'])
def get_alert_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT timestamp, src_ip, dest_ip, proto, signature, label FROM alerts ORDER BY id DESC')
        rows = c.fetchall()
        conn.close()

        alerts = []
        for row in rows:
            alerts.append({
                "timestamp": row[0],
                "src_ip": row[1],
                "dest_ip": row[2],
                "proto": row[3],
                "signature": row[4],
                "predicted_label": row[5]
            })

        return jsonify(alerts)
    except Exception as e:
        print(f"Error reading alert_history.db: {e}")
        return jsonify([])

@app.route('/historical_alerts')
def historical_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, src_ip, dest_ip, proto, signature, label FROM alerts")
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "timestamp": row[0],
            "src_ip": row[1],
            "dest_ip": row[2],
            "proto": row[3],
            "signature": row[4],
            "label": row[5]
        })
    return jsonify(alerts)

if __name__ == '__main__':
    init_db()
    sync_block_status()
    app.run(host='0.0.0.0', port=5003, debug=False)

