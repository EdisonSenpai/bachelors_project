import sqlite3

def get_user_id(username):
    conn = sqlite3.connect("db/users.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def add_device(username, ip_address):
    user_id = get_user_id(username)
    if user_id is None:
        print("⚠️ Utilizatorul nu exista.")
        return

    conn = sqlite3.connect("db/users.db")
    c = conn.cursor()
    c.execute("INSERT INTO user_devices (user_id, ip_address) VALUES (?, ?)", (user_id, ip_address))
    conn.commit()
    conn.close()
    print(f"✅ IP-ul {ip_address} a fost asociat cu utilizatorul {username}.")

def list_devices(username):
    user_id = get_user_id(username)
    conn = sqlite3.connect("db/users.db")
    c = conn.cursor()
    c.execute("SELECT ip_address FROM user_devices WHERE user_id = ?", (user_id,))
    devices = [row[0] for row in c.fetchall()]
    conn.close()
    return devices

if __name__ == "__main__":
    add_device("user1", "10.222.8.24")
    print(list_devices("user1"))
