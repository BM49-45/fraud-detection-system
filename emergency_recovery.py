# emergency_recovery.py
# 🚨 EMERGENCY ADMIN PASSWORD RECOVERY - COMMAND LINE VERSION

import sqlite3
import hashlib
import os
import sys

def print_colored(text, color_code):
    """Print colored text in terminal"""
    print(f"\033[{color_code}m{text}\033[0m")

def emergency_admin_recovery():
    """Emergency recovery for forgotten admin password - COMMAND LINE VERSION"""
    
    print_colored("🚨 EMERGENCY ADMIN PASSWORD RECOVERY TOOL", "1;33")  # Yellow
    print_colored("=" * 50, "1;33")
    print_colored("DEVELOPER USE ONLY - This will reset admin password!", "1;31")  # Red
    
    # Warning message
    print_colored("\n⚠️  WARNING: This tool will:", "1;31")
    print_colored("   • Reset admin password", "1;31")
    print_colored("   • Keep existing users and transactions", "1;31")
    print_colored("   • NOT delete any data", "1;31")
    
    # Security confirmation
    print_colored("\n🛡️  SECURITY VERIFICATION", "1;36")  # Cyan
    developer_code = input("Enter developer security code: ")
    
    if developer_code != "BM25":
        print_colored("❌ ACCESS DENIED: Invalid security code", "1;31")
        input("Press Enter to exit...")
        return
    
    # Get new password
    print_colored("\n🔐 PASSWORD SETUP", "1;36")
    new_password = input("Enter new admin password: ")
    
    if len(new_password) < 6:
        print_colored("❌ Password must be at least 6 characters", "1;31")
        input("Press Enter to exit...")
        return
    
    confirm_password = input("Confirm new password: ")
    
    if new_password != confirm_password:
        print_colored("❌ Passwords do not match", "1;31")
        input("Press Enter to exit...")
        return
    
    try:
        # Check if database exists
        if not os.path.exists('users.db'):
            print_colored("❌ Database not found. Please run the main app first.", "1;31")
            input("Press Enter to exit...")
            return
        
        # Connect to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT username FROM users WHERE username='admin'")
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            print_colored("❌ Admin user not found. Creating new admin account...", "1;33")
            # Create admin user
            admin_hash = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", admin_hash, "admin")
            )
        else:
            # Update existing admin password
            admin_hash = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (admin_hash, "admin")
            )
        
        conn.commit()
        
        # Verify the change
        cursor.execute("SELECT username, role FROM users WHERE username='admin'")
        result = cursor.fetchone()
        conn.close()
        
        if result:
            print_colored("\n PASSWORD RESET SUCCESSFUL!", "1;32")  # Green
            print_colored("=" * 40, "1;32")
            print_colored(f"👤 Username: admin", "1;37")
            print_colored(f"🔒 Password: {new_password}", "1;37")
            print_colored(f"🎯 Role: {result[1]}", "1;37")
            print_colored("\n💡 Next steps:", "1;36")
            print_colored("   1. Use these credentials to login", "1;37")
            print_colored("   2. Change password in Admin Panel", "1;37")
            print_colored("   3. Keep this password secure!", "1;37")
        else:
            print_colored("❌ Password reset failed", "1;31")
            
    except Exception as e:
        print_colored(f"❌ Error: {e}", "1;31")
    
    print_colored("\nPress Enter to exit...", "1;33")
    input()

def reset_entire_system():
    """Nuclear option - reset entire system"""
    print_colored("\n💣 NUCLEAR OPTION - RESET ENTIRE SYSTEM", "1;31")
    print_colored("This will delete ALL data and create fresh system!", "1;31")
    
    confirm = input("Type 'RESET_ALL' to confirm: ")
    
    if confirm != "RESET_ALL":
        print_colored("Reset cancelled", "1;33")
        return
    
    try:
        # Delete databases
        if os.path.exists('users.db'):
            os.remove('users.db')
        if os.path.exists('fraud_detection.db'):
            os.remove('fraud_detection.db')
        
        # Recreate databases
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
        
        # Create default admin
        admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin")
        )
        
        conn.commit()
        conn.close()
        
        print_colored("✅ SYSTEM COMPLETELY RESET!", "1;32")
        print_colored("Default credentials: admin / admin123", "1;37")
        
    except Exception as e:
        print_colored(f"❌ Reset failed: {e}", "1;31")

if __name__ == "__main__":
    try:
        print_colored("🔧 Developer Recovery Menu", "1;36")
        print("1. Reset Admin Password (Keeps data)")
        print("2. Nuclear Reset (Delete ALL data)")
        print("3. Exit")
        
        choice = input("\nChoose option (1-3): ")
        
        if choice == "1":
            emergency_admin_recovery()
        elif choice == "2":
            reset_entire_system()
        elif choice == "3":
            print_colored("Goodbye! 👋", "1;33")
        else:
            print_colored("Invalid choice", "1;31")
            
    except KeyboardInterrupt:
        print_colored("\n\nOperation cancelled by user", "1;33")
    except Exception as e:
        print_colored(f"Unexpected error: {e}", "1;31")
    
    input("Press Enter to close...")