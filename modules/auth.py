# modules/auth.py
import sqlite3
import hashlib
import streamlit as st
import pandas as pd

def initialize_auth_db():
    """Initialize authentication database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin")
        )
    
    conn.commit()
    conn.close()

def verify_password(password, password_hash):
    """Verify password against hash"""
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def authenticate_user(username, password):
    """Authenticate user credentials"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT password_hash, role FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if result and verify_password(password, result[0]):
        return {"username": username, "role": result[1]}
    return None

def register_user(username, password, role="user"):
    """Register new user"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_all_users():
    """Get all users"""
    import pandas as pd
    conn = sqlite3.connect('users.db')
    df = pd.read_sql_query("SELECT id, username, role, created_at FROM users", conn)
    conn.close()
    return df

def delete_user(user_id):
    """Delete user by ID"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def update_password(username, new_password):
    """Update user password"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )
        conn.commit()
        conn.close()
        return True
    except:
        return False