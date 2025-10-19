import os
import sqlite3
import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "users.db")

def initialize_database():
    if not os.path.exists(DB_PATH):
        print("🔄 Baza de date nu exista. Se creeaza...")
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
        )
        ''')

        # Criptare parola admin
        hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ('admin', hashed, 'admin'))

        conn.commit()
        conn.close()
        print("✅ Baza de date a fost creata cu succes.")
    else:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        ''')
        conn.commit()
        conn.close()
        print("✔️ Baza de date deja exista.")

if __name__ == "__main__":
    initialize_database()
