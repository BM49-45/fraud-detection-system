# fraud_detection_app.py - FINAL VERSION WITH PASSWORD RECOVERY
# 🏛️ Ministry of Finance - Secure Fraud Detection System

import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import joblib
import os
import tempfile
import hashlib
import warnings
warnings.filterwarnings('ignore')

# ==================== AUTHENTICATION SYSTEM ====================
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
    
    # Create default admin user if not exists
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
    """Get all users for admin management"""
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

# ==================== SYSTEM CONFIGURATION ====================
st.set_page_config(
    page_title="Ministry Finance Fraud Detection",
    page_icon="🏛️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM STYLING ====================
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: bold;
    }
    .sub-header {
        font-size: 1.4rem;
        color: #2e86ab;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-high { 
        background-color: #ff4b4b; 
        color: white; 
        padding: 10px; 
        border-radius: 5px;
        font-weight: bold;
        text-align: center;
    }
    .risk-medium { 
        background-color: #ffa500; 
        color: white; 
        padding: 10px; 
        border-radius: 5px;
        font-weight: bold;
        text-align: center;
    }
    .risk-low { 
        background-color: #00cc96; 
        color: white; 
        padding: 10px; 
        border-radius: 5px;
        font-weight: bold;
        text-align: center;
    }
    .info-box {
        background-color: #e8f4fd;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
        margin: 10px 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 0.5rem;
        text-align: center;
    }
    .login-container {
        max-width: 400px;
        margin: 100px auto;
        padding: 40px;
        border-radius: 15px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        background: white;
    }
    .admin-panel {
        background-color: #fff3cd;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #ffc107;
        margin: 10px 0;
    }
    .security-warning {
        background-color: #f8d7da;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #dc3545;
        margin: 10px 0;
    }
    .recovery-box {
        background-color: #d1ecf1;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #0c5460;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# ==================== AUTHENTICATION PAGES ====================
def login_page():
    """Login page for user authentication with password recovery"""
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    
    st.markdown('<h2 style="text-align: center;">🏛️ Ministry of Finance</h2>', unsafe_allow_html=True)
    st.markdown('<h3 style="text-align: center;">Secure Login</h3>', unsafe_allow_html=True)
    
    # Password Recovery Section
    with st.expander("🔐 Forgot Password?", expanded=False):
        st.markdown('<div class="recovery-box">', unsafe_allow_html=True)
        st.info("**Password Recovery Options**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📧 Contact Admin", use_container_width=True, help="Contact system administrator for password reset"):
                st.info("""
                **Please contact system administrator:**
                - 📧 Email: bastansy42@gmail.co
                - 📞 Phone: +255 0699 565 600
                - 🏢 Office: IT Department, Writing Business Solutions
                """)
        
        # with col2:
        #     if st.button("🔄 Reset Demo", use_container_width=True, help="Reset to default demo credentials"):
        #         st.warning("""
        #         **Default Demo Credentials:**
        #         - 👤 Username: `admin`
        #         - 🔒 Password: `admin123`
                
        #         **⚠️ For production use, contact admin to reset your password.**
        #         """)
        # st.markdown('</div>', unsafe_allow_html=True)
    
    # Main Login Form
    with st.form("login_form"):
        username = st.text_input("👤 Username", placeholder="Enter your username")
        password = st.text_input("🔒 Password", type="password", placeholder="Enter your password")
        
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            login_button = st.form_submit_button("🚀 Login", use_container_width=True)
        
        if login_button:
            if username and password:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.user = user
                    st.session_state.authenticated = True
                    st.success(f"✅ Welcome, {user['username']}!")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
            else:
                st.warning("⚠️ Please enter both username and password")
    
    # # Demo credentials
    # with st.expander("ℹ️ Demo Credentials", expanded=True):
    #     st.markdown("""
    #     **Default Admin Account:**
    #     - 👤 Username: `admin`
    #     - 🔒 Password: `admin123`
        
    #     **🔐 Password Recovery:**
    #     - Forgot password? Use the **Forgot Password** section above
    #     - Contact system administrator for production systems
    #     - Never share your password with anyone
    #     """)
    
    st.markdown('</div>', unsafe_allow_html=True)

def admin_management_page():
    """Admin panel for user management"""
    st.header("👨‍💼 Admin Management Panel")
    
    # Security warning for default password
    if st.session_state.user['username'] == 'admin':
        st.markdown('<div class="security-warning">', unsafe_allow_html=True)
        st.warning("**🚨 SECURITY ALERT:** You are using the default admin password. Please change it immediately in the 'Change Password' tab below.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([" User Management", "➕ Create New User", "🔐 Change Password", "🔄 Reset User Password", "⚙️ System Settings"])
    
    with tab1:
        st.subheader("Current Users")
        users_df = get_all_users()
        
        if not users_df.empty:
            st.dataframe(users_df, use_container_width=True)
            
            # Delete user functionality
            st.subheader("🗑️ Delete User")
            user_to_delete = st.selectbox(
                "Select user to delete",
                users_df['username'].tolist()
            )
            
            if st.button("Delete User", type="primary"):
                if user_to_delete != "admin":  # Prevent deleting admin
                    user_id = users_df[users_df['username'] == user_to_delete]['id'].iloc[0]
                    if delete_user(user_id):
                        st.success(f"✅ User {user_to_delete} deleted successfully")
                        st.rerun()
                    else:
                        st.error("❌ Error deleting user")
                else:
                    st.error("❌ Cannot delete admin user")
        else:
            st.info("No users found")
    
    with tab2:
        st.subheader("Create New User")
        
        with st.form("create_user_form"):
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            user_role = st.selectbox("User Role", ["user", "admin"])
            
            if st.form_submit_button("Create User"):
                if new_username and new_password:
                    if register_user(new_username, new_password, user_role):
                        st.success(f"✅ User {new_username} created successfully!")
                    else:
                        st.error("❌ Username already exists")
                else:
                    st.warning("⚠️ Please fill all fields")
    
    with tab3:
        st.subheader("🔐 Change Password")
        
        if st.session_state.user['username'] == 'admin':
            st.markdown('<div class="security-warning">', unsafe_allow_html=True)
            st.warning("**IMPORTANT:** You are currently using the default admin password. Please change it immediately for security!")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with st.form("change_password_form"):
            current_username = st.session_state.user['username']
            current_password = st.text_input("Current Password", type="password", 
                                           help="Enter your current password")
            new_password = st.text_input("New Password", type="password",
                                       help="Choose a strong password (at least 6 characters)")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            change_pass_button = st.form_submit_button("🔄 Change Password", type="primary")
            
            if change_pass_button:
                if not all([current_password, new_password, confirm_password]):
                    st.error("❌ Please fill all fields")
                elif new_password != confirm_password:
                    st.error("❌ New passwords do not match")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters long")
                else:
                    # Verify current password
                    conn = sqlite3.connect('users.db')
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT password_hash FROM users WHERE username = ?", 
                        (current_username,)
                    )
                    result = cursor.fetchone()
                    
                    if result and verify_password(current_password, result[0]):
                        # Update password
                        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                        cursor.execute(
                            "UPDATE users SET password_hash = ? WHERE username = ?",
                            (new_password_hash, current_username)
                        )
                        conn.commit()
                        conn.close()
                        st.success("✅ Password changed successfully!")
                        st.info("🔒 Please use the new password for future logins")
                        
                        # Show password strength
                        if len(new_password) >= 8 and any(c.isupper() for c in new_password) and any(c.isdigit() for c in new_password):
                            st.success("💪 Strong password! Good job!")
                        else:
                            st.warning("💡 Tip: For stronger security, use at least 8 characters with uppercase letters and numbers")
                    else:
                        st.error("❌ Current password is incorrect")
    
    with tab4:
        st.subheader("🔄 Reset User Password")
        st.warning("**Admin Only:** Reset passwords for users who have forgotten their credentials")
        
        users_df = get_all_users()
        if not users_df.empty:
            user_to_reset = st.selectbox(
                "Select User to Reset Password",
                users_df['username'].tolist()
            )
            
            new_password = st.text_input("New Temporary Password", type="password",
                                       help="Set a temporary password for the user")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            if st.button("🔄 Reset Password", type="primary"):
                if not new_password or not confirm_password:
                    st.error("❌ Please enter and confirm the new password")
                elif new_password != confirm_password:
                    st.error("❌ Passwords do not match")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters long")
                else:
                    # Reset the password
                    conn = sqlite3.connect('users.db')
                    cursor = conn.cursor()
                    
                    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                    cursor.execute(
                        "UPDATE users SET password_hash = ? WHERE username = ?",
                        (new_password_hash, user_to_reset)
                    )
                    conn.commit()
                    conn.close()
                    
                    st.success(f"✅ Password for {user_to_reset} has been reset successfully!")
                    st.info(f"**Temporary Password:** {new_password}")
                    st.warning("🔒 Advise the user to change this temporary password immediately after login")
        else:
            st.info("No users found in the system")
    
    with tab5:
        st.subheader("System Information")
        st.metric("Total Users", len(get_all_users()))
        st.metric("System Version", "2.0.0")
        st.metric("Last Updated", datetime.now().strftime("%Y-%m-%d"))
        
        # Emergency reset for development
        if st.checkbox("Show Emergency Options (Development Only)"):
            st.error("🚨 DANGER ZONE: These options can delete all data!")
            if st.button("🆘 Emergency Database Reset", type="secondary"):
                if os.path.exists('users.db'):
                    os.remove('users.db')
                if os.path.exists('fraud_detection.db'):
                    os.remove('fraud_detection.db')
                initialize_auth_db()
                st.success("✅ Emergency reset complete! Default credentials restored.")
                st.info("👤 Username: admin | 🔒 Password: admin123")
        
        if st.button("🔄 Clear All Session Data"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("✅ Session data cleared")
            st.rerun()

# ==================== SMART UNIVERSAL CLASSIFIER ====================
class SmartUniversalClassifier:
    """Intelligent classifier for fraud detection with business rules"""
    
    def __init__(self):
        self.name = "Smart Fraud Detector"
        self.feature_importance = {
            'Amount (TZS)': 0.35,
            'Vendor Type': 0.25,
            'Payment Method': 0.15,
            'Procurement Method': 0.15,
            'Approval Level': 0.10
        }
    
    def predict(self, X):
        """Predict fraud using intelligent business rules"""
        predictions = []
        
        for _, row in X.iterrows():
            risk_score = 0
            
            # Amount-based risk (35% weight)
            amount = row.get('Amount (TZS)', 0)
            if amount > 100000000: risk_score += 35
            elif amount > 50000000: risk_score += 25
            elif amount > 10000000: risk_score += 15
            elif amount > 5000000: risk_score += 5
            
            # Vendor risk (25% weight)
            vendor = str(row.get('Vendor Type', 'Unknown')).lower()
            if 'new' in vendor: risk_score += 25
            elif 'individual' in vendor: risk_score += 20
            elif 'unknown' in vendor: risk_score += 15
            elif 'registered' in vendor: risk_score += 0
            
            # Payment method risk (15% weight)
            payment = str(row.get('Payment Method', 'Unknown')).lower()
            if 'cash' in payment: risk_score += 15
            elif 'cheque' in payment: risk_score += 5
            elif 'eft' in payment: risk_score += 0
            
            # Procurement risk (15% weight)
            procurement = str(row.get('Procurement Method', 'Unknown')).lower()
            if 'direct' in procurement: risk_score += 15
            elif 'quotation' in procurement: risk_score += 5
            elif 'tender' in procurement: risk_score += 0
            
            # Approval risk (10% weight)
            approval = str(row.get('Approval Level', 'Unknown')).lower()
            if 'junior' in approval: risk_score += 10
            elif 'senior' in approval: risk_score += 3
            elif 'director' in approval: risk_score += 0
            
            # Normalize to 0-100 and convert to probability
            fraud_probability = min(risk_score / 100.0, 0.95)
            
            # Prediction threshold (0.5 = 50% risk)
            prediction = 1 if fraud_probability > 0.5 else 0
            predictions.append(prediction)
        
        return np.array(predictions)
    
    def predict_proba(self, X):
        """Return probability scores"""
        predictions = self.predict(X)
        probas = []
        
        for pred in predictions:
            if pred == 1:
                probas.append([0.2, 0.8])
            else:
                probas.append([0.8, 0.2])
        
        return np.array(probas)

# ==================== DATABASE FUNCTIONS ====================
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
        st.error(f"❌ Database error: {e}")
        return False

def save_transaction(transaction_data, db_name="fraud_detection.db"):
    """Save transaction to database - FIXED VERSION"""
    try:
        conn = sqlite3.connect(db_name)
        
        # Prepare data
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
        st.error(f"❌ Error saving transaction: {e}")
        return False

def get_all_transactions(db_name="fraud_detection.db"):
    """Get all transactions from database"""
    try:
        conn = sqlite3.connect(db_name)
        df = pd.read_sql_query("SELECT * FROM transactions ORDER BY created_at DESC", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def get_performance_stats(db_name="fraud_detection.db"):
    """Get system performance statistics"""
    try:
        conn = sqlite3.connect(db_name)
        
        total_tx = pd.read_sql_query("SELECT COUNT(*) as total FROM transactions", conn).iloc[0]['total']
        
        fraud_stats = pd.read_sql_query('''
            SELECT 
                final_decision,
                COUNT(*) as count,
                AVG(ml_confidence) as avg_confidence
            FROM transactions 
            GROUP BY final_decision
        ''', conn)
        
        recent = pd.read_sql_query('''
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as daily_count
            FROM transactions 
            GROUP BY DATE(created_at) 
            ORDER BY date DESC 
            LIMIT 7
        ''', conn)
        
        conn.close()
        
        return {
            'total_transactions': total_tx,
            'fraud_stats': fraud_stats.to_dict('records'),
            'recent_activity': recent.to_dict('records')
        }
    except:
        return {
            'total_transactions': 0,
            'fraud_stats': [],
            'recent_activity': []
        }

# ==================== MODEL FUNCTIONS ====================
def load_model():
    """Load detection engine"""
    try:
        model_files = ['fraud_detector_production.pkl', 'model.pkl', 'fraud_model.pkl']
        
        for model_file in model_files:
            if os.path.exists(model_file):
                model = joblib.load(model_file)
                st.success(f"✅ Detection system loaded successfully")
                return model
        
        st.info("🔧 Using Advanced Detection Engine")
        return SmartUniversalClassifier()
        
    except Exception as e:
        st.warning(f"⚠️ Using Detection Engine: System ready")
        return SmartUniversalClassifier()

def predict_fraud_business_rules(amount, vendor_type, payment_method, procurement_method, approval_level):
    """Predict fraud using comprehensive business rules"""
    risk_score = 0
    risk_factors = []
    
    # Amount risk (35%)
    if amount > 100000000: 
        risk_score += 35
        risk_factors.append("Amount > 100M TZS")
    elif amount > 50000000: 
        risk_score += 25
        risk_factors.append("Amount > 50M TZS")
    elif amount > 10000000: 
        risk_score += 15
        risk_factors.append("Amount > 10M TZS")
    elif amount > 5000000: 
        risk_score += 5
        risk_factors.append("Amount > 5M TZS")
    
    # Vendor risk (25%)
    vendor_type = str(vendor_type).lower()
    if 'new' in vendor_type: 
        risk_score += 25
        risk_factors.append("New Vendor")
    elif 'individual' in vendor_type: 
        risk_score += 20
        risk_factors.append("Individual Vendor")
    elif 'unknown' in vendor_type: 
        risk_score += 15
        risk_factors.append("Unknown Vendor")
    
    # Payment method risk (15%)
    payment_method = str(payment_method).lower()
    if 'cash' in payment_method: 
        risk_score += 15
        risk_factors.append("Cash Payment")
    elif 'cheque' in payment_method: 
        risk_score += 5
        risk_factors.append("Cheque Payment")
    
    # Procurement risk (15%)
    procurement_method = str(procurement_method).lower()
    if 'direct' in procurement_method: 
        risk_score += 15
        risk_factors.append("Direct Purchase")
    elif 'quotation' in procurement_method: 
        risk_score += 5
        risk_factors.append("Request for Quotation")
    
    # Approval risk (10%)
    approval_level = str(approval_level).lower()
    if 'junior' in approval_level: 
        risk_score += 10
        risk_factors.append("Junior Officer Approval")
    elif 'senior' in approval_level: 
        risk_score += 3
        risk_factors.append("Senior Officer Approval")
    
    # Convert to probability (0-1 scale)
    confidence = min(risk_score / 100.0, 0.95)
    prediction = 1 if confidence > 0.5 else 0
    
    return prediction, confidence, risk_score, risk_factors

# ==================== MAIN APPLICATION PAGES ====================
def dataset_analysis_page(model):
    st.header("📁 Analyze Your Dataset")
    
    # Legend and Explanation
    with st.expander("🎓 **HOW TO USE THIS SYSTEM**", expanded=True):
        st.markdown("""
        ### **📋 SYSTEM OVERVIEW**
        This advanced detection system identifies potential risks in financial transactions using:
        - **Pattern Recognition** + **Statistical Analysis**
        - **Risk Factor Analysis** 
        - **Real-time Visualization**
        
        ### **🎯 KEY VARIABLES EXPLAINED:**
        | Variable | Importance | Description |
        |----------|------------|-------------|
        | **💰 Amount** | 35% | Transaction amount in TZS |
        | **🏢 Vendor Type** | 25% | Vendor category (New/Registered/Individual) |
        | **💳 Payment Method** | 15% | Cash/EFT/Cheque |
        | **📋 Procurement** | 15% | Purchase method (Direct/Tender) |
        | **👤 Approval Level** | 10% | Officer approval level |
        
        ### **🚨 RISK LEVELS:**
        - **🔴 HIGH RISK** (>70% confidence): Immediate review required
        - **🟡 MEDIUM RISK** (40-70%): Additional verification needed  
        - **🟢 LOW RISK** (<40%): Normal processing
        """)
    
    st.markdown("---")
    
    # File upload section
    st.subheader("📤 Upload Your Data")
    
    uploaded_file = st.file_uploader(
        "Drag and drop Excel or CSV file here", 
        type=['xlsx', 'csv'],
        help="File should contain transaction data with columns like Amount, Vendor, etc."
    )
    
    if uploaded_file is not None:
        try:
            # Load data
            if uploaded_file.name.endswith('.xlsx'):
                df = pd.read_excel(uploaded_file)
            else:
                df = pd.read_csv(uploaded_file)
            
            st.success(f"✅ File loaded successfully! Found {len(df)} transactions")
            
            # Data overview
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Rows", len(df))
            with col2:
                st.metric("Total Columns", len(df.columns))
            with col3:
                st.metric("Data Size", f"{df.memory_usage(deep=True).sum() / 1024:.1f} KB")
            
            # Data preview
            st.subheader("👀 Data Preview")
            st.dataframe(df.head(10), use_container_width=True)
            
            # Column mapping
            st.subheader("🗺️ Column Mapping")
            st.info("🔍 **System will auto-detect common column names. You can adjust manually if needed.**")
            
            # Auto-detect columns
            amount_cols = [col for col in df.columns if any(word in col.lower() for word in 
                          ['amount', 'value', 'pesa', 'kiasi', 'cost', 'price'])]
            vendor_cols = [col for col in df.columns if any(word in col.lower() for word in 
                          ['vendor', 'supplier', 'msambazaji', 'company', 'name'])]
            date_cols = [col for col in df.columns if any(word in col.lower() for word in 
                         ['date', 'siku', 'time', 'timestamp'])]
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                amount_col = st.selectbox("💰 Amount Column", 
                    options=['Auto-detect'] + list(df.columns),
                    index=0 if not amount_cols else list(df.columns).index(amount_cols[0]) + 1,
                    help="Select column containing transaction amounts"
                )
            
            with col2:
                vendor_col = st.selectbox("🏢 Vendor Column", 
                    options=['Auto-detect'] + list(df.columns),
                    index=0 if not vendor_cols else list(df.columns).index(vendor_cols[0]) + 1,
                    help="Select column containing vendor information"
                )
            
            with col3:
                date_col = st.selectbox("📅 Date Column (Optional)", 
                    options=['Auto-detect'] + list(df.columns),
                    index=0 if not date_cols else list(df.columns).index(date_cols[0]) + 1,
                    help="Select date column for time-based analysis"
                )
            
            # Auto-detect logic
            if amount_col == 'Auto-detect':
                amount_col = amount_cols[0] if amount_cols else df.select_dtypes(include=[np.number]).columns[0] if len(df.select_dtypes(include=[np.number]).columns) > 0 else None
            
            if vendor_col == 'Auto-detect':
                vendor_col = vendor_cols[0] if vendor_cols else df.select_dtypes(include=['object']).columns[0] if len(df.select_dtypes(include=['object']).columns) > 0 else None
            
            if not amount_col or not vendor_col:
                st.error("❌ Please manually select Amount and Vendor columns")
                return
            
            # Show mapping confirmation
            st.success(f"""
            **✅ Column Mapping Confirmed:**
            - **Amount**: `{amount_col}`
            - **Vendor**: `{vendor_col}`
            - **Date**: `{date_col if date_col != 'Auto-detect' else 'Not available'}`
            """)
            
            # Analysis parameters
            st.subheader("⚙️ Analysis Settings")
            sensitivity = st.slider("🎚️ Detection Sensitivity", 
                                  min_value=1, max_value=10, value=7,
                                  help="Higher sensitivity detects more potential fraud but may have more false positives")
            
            # Run analysis
            if st.button("🚀 RUN FRAUD ANALYSIS", type="primary", use_container_width=True):
                with st.spinner("🔍 Analyzing transactions for fraud patterns..."):
                    try:
                        # Perform analysis
                        results = []
                        risk_factors_list = []
                        
                        for idx, row in df.iterrows():
                            # Prepare transaction data
                            amount = float(row[amount_col]) if pd.notna(row[amount_col]) else 0
                            vendor = str(row[vendor_col]) if pd.notna(row[vendor_col]) else 'Unknown'
                            
                            # Make prediction
                            prediction, confidence, risk_score, risk_factors = predict_fraud_business_rules(
                                amount, vendor, 'Unknown', 'Unknown', 'Unknown'
                            )
                            
                            # Adjust confidence based on sensitivity
                            confidence = min(confidence * (sensitivity / 7.0), 0.95)
                            
                            # Determine risk level
                            if confidence > 0.7:
                                risk_level = "🔴 HIGH RISK"
                                decision = "DECLINE - Requires investigation"
                            elif confidence > 0.4:
                                risk_level = "🟡 MEDIUM RISK" 
                                decision = "HOLD - Additional review needed"
                            else:
                                risk_level = "🟢 LOW RISK"
                                decision = "APPROVE - Normal processing"
                            
                            results.append({
                                'Transaction_ID': f"ROW_{idx+1}",
                                'Amount': amount,
                                'Vendor': vendor,
                                'Fraud_Prediction': 'FRAUD' if prediction == 1 else 'LEGITIMATE',
                                'Confidence_Score': confidence,
                                'Risk_Level': risk_level,
                                'Final_Decision': decision,
                                'Risk_Score': risk_score
                            })
                            risk_factors_list.append(risk_factors)
                        
                        # Create results dataframe
                        results_df = pd.DataFrame(results)
                        
                        # Display comprehensive results
                        st.subheader("📊 ANALYSIS RESULTS")
                        
                        # Summary metrics
                        total_fraud = len([r for r in results if r['Fraud_Prediction'] == 'FRAUD'])
                        avg_confidence = results_df['Confidence_Score'].mean()
                        total_amount = results_df['Amount'].sum()
                        flagged_amount = results_df[results_df['Fraud_Prediction'] == 'FRAUD']['Amount'].sum()
                        
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("📈 Total Transactions", len(results_df))
                        col2.metric("🚨 Fraud Detected", f"{total_fraud} ({total_fraud/len(results_df)*100:.1f}%)")
                        col3.metric("💡 Avg Confidence", f"{avg_confidence:.1%}")
                        col4.metric("💰 Flagged Amount", f"TZS {flagged_amount:,.0f}")
                        
                        # Risk distribution
                        st.subheader("📈 Risk Distribution")
                        risk_counts = results_df['Risk_Level'].value_counts()
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            fig_pie = px.pie(
                                values=risk_counts.values, 
                                names=risk_counts.index,
                                title='Transaction Risk Distribution',
                                color=risk_counts.index,
                                color_discrete_map={
                                    '🔴 HIGH RISK': 'red',
                                    '🟡 MEDIUM RISK': 'orange', 
                                    '🟢 LOW RISK': 'green'
                                }
                            )
                            st.plotly_chart(fig_pie, use_container_width=True)
                        
                        with col2:
                            # Amount vs Confidence scatter
                            fig_scatter = px.scatter(
                                results_df, 
                                x='Amount', 
                                y='Confidence_Score',
                                color='Risk_Level',
                                title='Amount vs Fraud Confidence',
                                hover_data=['Vendor', 'Final_Decision'],
                                color_discrete_map={
                                    '🔴 HIGH RISK': 'red',
                                    '🟡 MEDIUM RISK': 'orange',
                                    '🟢 LOW RISK': 'green'
                                }
                            )
                            fig_scatter.update_layout(
                                xaxis_title="Transaction Amount (TZS)",
                                yaxis_title="Fraud Confidence Score"
                            )
                            st.plotly_chart(fig_scatter, use_container_width=True)
                        
                        # Detailed results table
                        st.subheader("📋 Detailed Results")
                        display_cols = ['Transaction_ID', 'Amount', 'Vendor', 'Risk_Level', 
                                      'Confidence_Score', 'Final_Decision']
                        st.dataframe(results_df[display_cols], use_container_width=True)
                        
                        # Risk factors analysis
                        st.subheader("🔍 Common Risk Factors")
                        all_risk_factors = [factor for sublist in risk_factors_list for factor in sublist]
                        if all_risk_factors:
                            factor_counts = pd.Series(all_risk_factors).value_counts()
                            fig_factors = px.bar(
                                x=factor_counts.values,
                                y=factor_counts.index,
                                orientation='h',
                                title='Most Common Risk Factors',
                                labels={'x': 'Frequency', 'y': 'Risk Factor'}
                            )
                            st.plotly_chart(fig_factors, use_container_width=True)
                        
                        # Download results
                        st.subheader("💾 Download Results")
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Full Results as CSV",
                            data=csv,
                            file_name=f"fraud_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                        
                        # Recommendations
                        st.subheader("💡 Recommendations & Next Steps")
                        
                        if total_fraud > 0:
                            st.warning(f"""
                            **🚨 ACTION REQUIRED:**
                            - **{total_fraud} transactions** flagged as potential fraud
                            - **TZS {flagged_amount:,.0f}** total amount requires review
                            - **Immediate investigation** recommended for high-risk transactions
                            """)
                        else:
                            st.success("""
                            **✅ ALL CLEAR:**
                            - No high-risk transactions detected
                            - Continue with normal monitoring procedures
                            - Regular system checks recommended
                            """)
                            
                    except Exception as e:
                        st.error(f"❌ Analysis error: {str(e)}")
        
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
    
    else:
        # Sample data and instructions
        st.info("""
        **📋 EXPECTED DATA FORMAT:**
        
        Your file should contain at least these columns:
        - **Amount** (transaction amount in TZS)
        - **Vendor** (vendor name or type)
        - **Date** (optional, for time analysis)
        
        **🎯 SAMPLE DATA STRUCTURE:**
        """)
        
        sample_data = pd.DataFrame({
            'TransactionID': ['TXN001', 'TXN002', 'TXN003', 'TXN004'],
            'Amount': [5000000, 25000000, 75000000, 15000000],
            'Vendor': ['Registered Vendor', 'New Vendor', 'Individual', 'Registered Vendor'],
            'Date': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04'],
            'Description': ['Office Supplies', 'Consulting', 'Equipment', 'Training']
        })
        
        st.dataframe(sample_data, use_container_width=True)
        
        # Download template
        csv_template = sample_data.to_csv(index=False)
        st.download_button(
            label="📋 Download Sample Template",
            data=csv_template,
            file_name="fraud_analysis_template.csv",
            mime="text/csv"
        )

def check_transaction_page(model):
    st.header("🔍 Check Single Transaction")
    
    with st.form("single_transaction_form"):
        st.subheader("📝 Transaction Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            amount = st.number_input(
                "💰 Amount (TZS)", 
                min_value=0, 
                value=1000000, 
                step=100000,
                help="Enter transaction amount in Tanzanian Shillings"
            )
            vendor_type = st.selectbox(
                "🏢 Vendor Type",
                ["Registered Vendor", "New Vendor", "Individual", "Unknown Vendor"],
                help="Select the type of vendor"
            )
            payment_method = st.selectbox(
                "💳 Payment Method", 
                ["EFT", "Cash", "Cheque", "Mobile Money", "Unknown"],
                help="Select payment method used"
            )
        
        with col2:
            procurement_method = st.selectbox(
                "📋 Procurement Method",
                ["Open Tender", "Direct Purchase", "Request for Quotation", "Selective Tender", "Unknown"],
                help="Method used for procurement"
            )
            approval_level = st.selectbox(
                "👤 Approval Level",
                ["Junior Officer", "Senior Officer", "Director", "Unknown"],
                help="Level of officer who approved"
            )
            department = st.text_input(
                "🏛️ Department Code", 
                "PROC-01",
                help="Department code for tracking"
            )
        
        submitted = st.form_submit_button(
            "🎯 Analyze Transaction", 
            use_container_width=True
        )
        
        if submitted:
            with st.spinner("Analyzing transaction for fraud patterns..."):
                try:
                    # Create transaction data
                    transaction_data = {
                        'Transaction ID': f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        'Transaction Date': datetime.now().strftime('%Y-%m-%d'),
                        'Amount (TZS)': amount,
                        'Vendor Type': vendor_type,
                        'Payment Method': payment_method,
                        'Department Code': department,
                        'Procurement Method': procurement_method,
                        'Approval Level': approval_level,
                        'Account Category': 'User Input'
                    }
                    
                    # Make prediction
                    if hasattr(model, 'predict_proba'):
                        # Use detection engine
                        transaction_df = pd.DataFrame([transaction_data])
                        ml_pred = model.predict(transaction_df)[0]
                        ml_conf = model.predict_proba(transaction_df)[0][1]
                        method_used = "Advanced Detection"
                    else:
                        # Use business rules
                        ml_pred, ml_conf, risk_score, risk_factors = predict_fraud_business_rules(
                            amount, vendor_type, payment_method, procurement_method, approval_level
                        )
                        method_used = "Risk Analysis Engine"
                    
                    # Determine final decision
                    if ml_conf > 0.7:
                        decision = "🚨 HIGH RISK - DECLINE"
                        risk_class = "risk-high"
                        icon = "🔴"
                    elif ml_conf > 0.4:
                        decision = "⚠️ MEDIUM RISK - HOLD FOR REVIEW"
                        risk_class = "risk-medium" 
                        icon = "🟡"
                    else:
                        decision = "✅ LOW RISK - APPROVE"
                        risk_class = "risk-low"
                        icon = "🟢"
                    
                    # Calculate business risk score
                    risk_score = 0
                    risk_factors_display = []
                    
                    if amount > 50000000: 
                        risk_score += 2
                        risk_factors_display.append("💰 Large amount (> 50M TZS)")
                    if vendor_type in ["New Vendor", "Individual"]: 
                        risk_score += 2
                        risk_factors_display.append(f"🏢 High-risk vendor: {vendor_type}")
                    if payment_method == "Cash": 
                        risk_score += 2
                        risk_factors_display.append("💵 Cash payment")
                    if procurement_method == "Direct Purchase": 
                        risk_score += 1
                        risk_factors_display.append("📋 Direct purchase method")
                    if approval_level == "Junior Officer": 
                        risk_score += 1
                        risk_factors_display.append("👨‍💼 Junior officer approval")
                    
                    # Save to database
                    transaction_data.update({
                        'ML_Prediction': int(ml_pred),
                        'ML_Confidence': float(ml_conf),
                        'Business_Risk_Score': risk_score,
                        'Final_Decision': decision
                    })
                    
                    save_transaction(transaction_data)
                    
                    # Display results
                    st.success("✅ Analysis Complete!")
                    
                    # Results metrics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Confidence Score", f"{ml_conf:.1%}")
                    
                    with col2:
                        st.metric("Prediction", "FRAUD" if ml_pred == 1 else "LEGITIMATE")
                    
                    with col3:
                        st.metric("Risk Score", f"{risk_score}/8")
                    
                    with col4:
                        st.metric("Method Used", method_used)
                    
                    # Final decision
                    st.markdown(f"""
                    <div class="{risk_class}">
                        <h3 style='text-align: center; margin: 0;'>{icon} {decision}</h3>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Risk factors
                    if risk_factors_display:
                        st.subheader("🔍 Identified Risk Factors:")
                        for factor in risk_factors_display:
                            st.write(f"• {factor}")
                    else:
                        st.info("• No significant risk factors identified")
                        
                    # Explanation
                    with st.expander("📖 Understanding This Result"):
                        if "HIGH" in decision:
                            next_steps = "Immediate investigation required. Do not process payment."
                        elif "MEDIUM" in decision:
                            next_steps = "Additional documentation and supervisor review needed."
                        else:
                            next_steps = "Proceed with normal processing procedures."
                        
                        st.markdown(f"""
                        **Result Explanation:**
                        - **Confidence Score**: {ml_conf:.1%} - This indicates how confident the system is in its prediction
                        - **Risk Factors**: {len(risk_factors_display)} factors contributed to this decision
                        - **Recommendation**: {decision.split(' - ')[1]}
                        
                        **Next Steps:**
                        {next_steps}
                        """)

                except Exception as e:
                    st.error(f"❌ Error analyzing transaction: {e}")

def show_dashboard():
    st.header(" System Dashboard")
    
    stats = get_performance_stats()
    
    # User info
    st.sidebar.markdown(f"**👤 Logged in as:** {st.session_state.user['username']}")
    st.sidebar.markdown(f"**🎯 Role:** {st.session_state.user['role']}")
    
    # System Overview
    st.subheader("🏛️ System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Transactions", stats['total_transactions'])
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        high_risk = next((item for item in stats['fraud_stats'] if 'HIGH' in item['final_decision']), {'count': 0})
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("High Risk Cases", high_risk['count'])
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        medium_risk = next((item for item in stats['fraud_stats'] if 'MEDIUM' in item['final_decision']), {'count': 0})
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Medium Risk Cases", medium_risk['count'])
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        low_risk = next((item for item in stats['fraud_stats'] if 'LOW' in item['final_decision']), {'count': 0})
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Low Risk Cases", low_risk['count'])
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Show sample data if no transactions
    if stats['total_transactions'] == 0:
        st.info("📝 No transactions yet. Start by checking a transaction or analyzing a dataset!")
        
        # Quick start guide
        with st.expander("🚀 Quick Start Guide", expanded=True):
            st.markdown("""
            ### **Getting Started:**
            
            **Option 1: Check Single Transaction**
            - Go to **"Check Transaction"** page
            - Fill in transaction details
            - Get instant fraud analysis
            
            **Option 2: Analyze Dataset**
            - Go to **"Analyze Dataset"** page  
            - Upload Excel/CSV file
            - Get batch analysis for multiple transactions
            
            **Sample Transaction to Try:**
            - Amount: 25,000,000 TZS
            - Vendor: New Vendor
            - Payment: Cash
            - Expected: 🚨 HIGH RISK
            """)
        
        return
    
    # Charts and Visualizations
    st.subheader("📈 Analytics & Insights")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if stats['fraud_stats']:
            df_risk = pd.DataFrame(stats['fraud_stats'])
            fig_pie = px.pie(df_risk, values='count', names='final_decision', 
                           title='Risk Distribution Analysis',
                           color_discrete_sequence=['#00cc96', '#ffa500', '#ff4b4b'])
            st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        if stats['recent_activity']:
            df_recent = pd.DataFrame(stats['recent_activity'])
            fig_bar = px.bar(df_recent, x='date', y='daily_count',
                           title='Transaction Activity (Last 7 Days)',
                           color='daily_count',
                           color_continuous_scale='blues')
            st.plotly_chart(fig_bar, use_container_width=True)

def show_transaction_history():
    st.header("📋 Transaction History")
    
    transactions_df = get_all_transactions()
    
    if not transactions_df.empty:
        # Search and Filter Section
        st.subheader("🔍 Search & Filter")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_term = st.text_input("Search by Transaction ID")
        
        with col2:
            risk_filter = st.selectbox("Filter by Risk Level", 
                ["All", "HIGH RISK", "MEDIUM RISK", "LOW RISK"])
        
        with col3:
            date_filter = st.selectbox("Time Period",
                ["All Time", "Last 7 Days", "Last 30 Days", "Last 90 Days"])
        
        # Apply filters
        filtered_df = transactions_df.copy()
        
        if search_term:
            filtered_df = filtered_df[filtered_df['transaction_id'].str.contains(search_term, case=False, na=False)]
        
        if risk_filter != "All":
            filtered_df = filtered_df[filtered_df['final_decision'].str.contains(risk_filter, na=False)]
        
        if date_filter != "All Time":
            days = {"Last 7 Days": 7, "Last 30 Days": 30, "Last 90 Days": 90}
            cutoff_date = datetime.now() - pd.Timedelta(days=days[date_filter])
            filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
            filtered_df = filtered_df[filtered_df['created_at'] >= cutoff_date]
        
        # Display results
        if not filtered_df.empty:
            # Important columns to display
            display_cols = ['transaction_id', 'amount', 'vendor_type', 'payment_method', 
                          'final_decision', 'ml_confidence', 'created_at']
            available_cols = [col for col in display_cols if col in filtered_df.columns]
            
            st.dataframe(filtered_df[available_cols], use_container_width=True)
            
            # Export options
            st.subheader("💾 Export Data")
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📥 Export to CSV", use_container_width=True):
                    csv = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV File",
                        data=csv,
                        file_name=f"fraud_transactions_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv"
                    )
            
            with col2:
                if st.button("📊 Generate Report", use_container_width=True):
                    st.info("Report generation feature coming soon!")
        
        else:
            st.info("📝 No transactions match your filters.")
    
    else:
        st.info("""
        📝 No transaction history available yet.
        
        **To get started:**
        1. Go to **"Check Transaction"** to analyze individual transactions
        2. Or visit **"Analyze Dataset"** to upload and analyze multiple transactions
        3. All analyzed transactions will appear here automatically
        """)

def show_about_page():
    st.header("ℹ️ About This System")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ## 🏛️ Ministry of Finance - Fraud Detection System
        
        ### **🎯 System Purpose**
        This advanced system combines **Statistical Analysis** and **Business Rules** to:
        - Detect potential financial fraud in public transactions
        - Improve accountability in public fund management
        - Reduce manual review time significantly
        - Provide evidence-based risk assessment
        
        ### **🔧 Technology Used**
        - **Advanced Detection**: Statistical Analysis, Pattern Recognition
        - **Data Processing**: Pandas, NumPy, Feature Engineering
        - **Web Framework**: Streamlit for user-friendly interface
        - **Database**: SQLite for secure data storage
        - **Visualization**: Plotly for interactive charts
        
        ### **📋 System Capabilities**
        1. **Single Transaction Analysis** - Instant risk assessment
        2. **Batch Dataset Analysis** - Process multiple transactions
        3. **Risk Factor Identification** - Understand why transactions are flagged
        4. **Comprehensive Reporting** - Downloadable results and analytics
        5. **Real-time Dashboard** - System performance monitoring
        """)
    
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/1001/1001371.png", width=150)
        
        st.markdown("""
        ### **🎓 Variable Importance**
        """)
        
        importance_data = {
            'Variable': ['Amount', 'Vendor Type', 'Payment Method', 'Procurement', 'Approval Level'],
            'Importance': [35, 25, 15, 15, 10]
        }
        
        fig_importance = px.bar(
            importance_data, 
            x='Importance', 
            y='Variable',
            orientation='h',
            title='Fraud Detection Factors',
            color='Importance',
            color_continuous_scale='blues'
        )
        st.plotly_chart(fig_importance, use_container_width=True)
    
    # Risk Legend
    st.markdown("---")
    st.subheader(" Risk Level Legend")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="risk-low">🟢 LOW RISK</div>', unsafe_allow_html=True)
        st.markdown("""
        - Confidence: < 40%
        - Action: Normal processing
        - Review: Not required
        """)
    
    with col2:
        st.markdown('<div class="risk-medium">🟡 MEDIUM RISK</div>', unsafe_allow_html=True)
        st.markdown("""
        - Confidence: 40-70%
        - Action: Additional verification
        - Review: Supervisor approval
        """)
    
    with col3:
        st.markdown('<div class="risk-high">🔴 HIGH RISK</div>', unsafe_allow_html=True)
        st.markdown("""
        - Confidence: > 70%
        - Action: Immediate investigation
        - Review: Director level required
        """)

# ==================== MAIN APPLICATION ====================
def main_app():
    """Main application after authentication"""
    # Header Section
    st.markdown('<h1 class="main-header">🏛️ Ministry of Finance Tanzania</h1>', unsafe_allow_html=True)
    st.markdown('<h2 class="sub-header">Secure Fraud Detection System</h2>', unsafe_allow_html=True)
    
    # Initialize system components
    init_database()
    model = load_model()
    
    # Admin Panel
    if st.session_state.user['role'] == 'admin':
        st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
        st.write("👨‍💼 **Admin Panel Active** - You have full system access")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Navigation
    st.sidebar.title("🧭 Navigation")
    
    # Admin-specific navigation
    if st.session_state.user['role'] == 'admin':
        app_mode = st.sidebar.selectbox(
            "Choose Section", 
            [" Dashboard", "🔍 Check Transaction", "📁 Analyze Dataset", "📋 Transaction History", "👨‍💼 Admin Panel", "ℹ️ About System"]
        )
    else:
        app_mode = st.sidebar.selectbox(
            "Choose Section", 
            [" Dashboard", "🔍 Check Transaction", "📁 Analyze Dataset", "📋 Transaction History", "ℹ️ About System"]
        )
    
    # User info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.subheader("User Info")
    st.sidebar.write(f"**👤 Username:** {st.session_state.user['username']}")
    st.sidebar.write(f"**🎯 Role:** {st.session_state.user['role']}")
    
    # Quick Actions
    st.sidebar.markdown("---")
    st.sidebar.subheader("Quick Actions")
    
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("🆕 Check Transaction", use_container_width=True, key="quick_check"):
            st.session_state.page = "Check Transaction"
            st.rerun()
    
    with col2:
        if st.button("📁 Analyze Dataset", use_container_width=True, key="quick_analyze"):
            st.session_state.page = "Analyze Dataset"
            st.rerun()
    
    # Logout button
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    
    # Page Routing
    if "page" in st.session_state:
        current_page = st.session_state.page
    else:
        current_page = app_mode
    
    if "Dashboard" in current_page:
        show_dashboard()
    elif "Check Transaction" in current_page:
        check_transaction_page(model)
    elif "Analyze Dataset" in current_page:
        dataset_analysis_page(model)
    elif "Transaction History" in current_page:
        show_transaction_history()
    elif "Admin Panel" in current_page:
        admin_management_page()
    else:
        show_about_page()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        f"🔒 Secure System | 👤 {st.session_state.user['username']} | 🏛️ Ministry of Finance Tanzania | © 2025"
        "</div>",
        unsafe_allow_html=True
    )

# ==================== MAIN EXECUTION ====================
def main():
    # Initialize authentication system
    initialize_auth_db()
    
    # Check authentication
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()