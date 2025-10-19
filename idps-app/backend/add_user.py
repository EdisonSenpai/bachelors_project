import sqlite3
import bcrypt

def add_user(username, password, role):
    conn = sqlite3.connect("../backend/db/users.db")
    cursor = conn.cursor()

    # Criptare parola
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    try:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
               (username, hashed_password, role))
        conn.commit()
        print(f"Utilizatorul '{username}' cu rolul '{role}' a fost adaugat cu succes.")
    except sqlite3.IntegrityError:
        print("⚠️  Utilizatorul exista deja.")
    finally:
        conn.close()

if __name__ == "__main__":
    import getpass
    username = input("Introdu username-ul: ")
    password = getpass.getpass("Introdu parola: ")
    role = input("Rol (admin/user): ").lower()
    if role not in ['admin', 'user']:
        print("Rol invalid. Foloseste 'admin' sau 'user'.")
    else:
        add_user(username, password, role)
