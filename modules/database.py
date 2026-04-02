# modules/database.py
import sqlite3
import pandas as pd
import streamlit as st
import os
from datetime import datetime

def init_database(db_name="fraud_detection.db"):
    """Initialize database for storing transactions"""
    try:
        if os.path.exists(db_name):
            try:
                test_conn = sqlite3.connect(db_name)
                test_conn.execute("SELECT 1")
                test_conn.close()
            except:
                os.remove(db_name)
        
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE,
                transaction_date TEXT,
                amount REAL,
                vendor_type TEXT,
                payment_method TEXT,
                department_code TEXT,
                procurement_method TEXT,
                approval_level TEXT,
                account_category TEXT,
                ml_prediction INTEGER,
                ml_confidence REAL,
                business_risk_score INTEGER,
                final_decision TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Database error: {e}")
        return False

def save_transaction(transaction_data):
    """Save transaction to database"""
    try:
        conn = sqlite3.connect('fraud_detection.db')
        
        data = {
            'transaction_id': transaction_data.get('Transaction ID', f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}"),
            'transaction_date': transaction_data.get('Transaction Date', datetime.now().strftime('%Y-%m-%d')),
            'amount': transaction_data.get('Amount (TZS)', 0),
            'vendor_type': transaction_data.get('Vendor Type', 'Unknown'),
            'payment_method': transaction_data.get('Payment Method', 'Unknown'),
            'department_code': transaction_data.get('Department Code', 'Unknown'),
            'procurement_method': transaction_data.get('Procurement Method', 'Unknown'),
            'approval_level': transaction_data.get('Approval Level', 'Unknown'),
            'account_category': transaction_data.get('Account Category', 'Unknown'),
            'ml_prediction': transaction_data.get('ML_Prediction', -1),
            'ml_confidence': transaction_data.get('ML_Confidence', 0),
            'business_risk_score': transaction_data.get('Business_Risk_Score', 0),
            'final_decision': transaction_data.get('Final_Decision', 'Unknown')
        }
        
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO transactions 
            (transaction_id, transaction_date, amount, vendor_type, payment_method, 
             department_code, procurement_method, approval_level, account_category,
             ml_prediction, ml_confidence, business_risk_score, final_decision)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(data.values()))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error saving: {e}")
        return False

def get_all_transactions():
    """Get all transactions"""
    try:
        conn = sqlite3.connect('fraud_detection.db')
        df = pd.read_sql_query("SELECT * FROM transactions ORDER BY created_at DESC", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def get_performance_stats():
    """Get system statistics"""
    try:
        conn = sqlite3.connect('fraud_detection.db')
        
        total_tx = pd.read_sql_query("SELECT COUNT(*) as total FROM transactions", conn).iloc[0]['total']
        
        fraud_stats = pd.read_sql_query('''
            SELECT final_decision, COUNT(*) as count, AVG(ml_confidence) as avg_confidence
            FROM transactions GROUP BY final_decision
        ''', conn)
        
        recent = pd.read_sql_query('''
            SELECT DATE(created_at) as date, COUNT(*) as daily_count
            FROM transactions GROUP BY DATE(created_at) ORDER BY date DESC LIMIT 7
        ''', conn)
        
        conn.close()
        return {
            'total_transactions': total_tx,
            'fraud_stats': fraud_stats.to_dict('records'),
            'recent_activity': recent.to_dict('records')
        }
    except:
        return {'total_transactions': 0, 'fraud_stats': [], 'recent_activity': []}
    
def log_activity(username, action, details):
    """Log user activity for audit trail"""
    try:
        conn = sqlite3.connect('fraud_detection.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO activity_log (username, action, details)
            VALUES (?, ?, ?)
        ''', (username, action, details))
        
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_activity_log(limit=50):
    """Get recent activity log"""
    try:
        conn = sqlite3.connect('fraud_detection.db')
        df = pd.read_sql_query(f"SELECT * FROM activity_log ORDER BY created_at DESC LIMIT {limit}", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()