import sqlite3

conn = sqlite3.connect('salao.db')
cur = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        fullname TEXT NO NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        phone TEXT NOT NULL,
        birthday TEXT NOT NULL
    )
""")
cur.execute("""
    CREATE TABLE IF NOT EXISTS agendas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        datetime TEXT NOT NULL,
        service TEXT NOT NULL,
        user_email TEXT NOT NULL,

        FOREIGN KEY (user_email) REFERENCES users(email)
    )
""")

conn.commit()
conn.close()