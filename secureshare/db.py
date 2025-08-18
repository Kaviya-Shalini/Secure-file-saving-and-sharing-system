import mysql.connector
from mysql.connector import Error

def connect_db():
    try:
        print("🔍 Attempting MySQL connection...")
        conn = mysql.connector.connect(
            host="localhost",
            port=3307,
            user="root",
            password="5218kaviya",
            database="secureshare"
        )
        print("✅ Connected successfully.")
        return conn
    except Error as e:
        print("❌ Connection error:", e)
        return None
