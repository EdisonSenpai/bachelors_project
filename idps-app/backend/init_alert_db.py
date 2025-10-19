import sqlite3
import os

def init_alert_history_db():
    db_path = "db/alert_history.db"
    if not os.path.exists("db"):
        os.makedirs("db")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            proto TEXT,
            signature TEXT
            label TEXT,
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Baza de date pentru istoric alerte a fost creata cu succes.")

if __name__ == "__main__":
    init_alert_history_db()
