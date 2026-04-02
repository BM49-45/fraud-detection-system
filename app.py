# app.py - PAGE PERSISTENCE WITH SESSION STATE ONLY
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from modules.styles import apply_custom_styles
from modules.auth import initialize_auth_db, authenticate_user
from modules.database import init_database
from modules.pages.dashboard import show_dashboard
from modules.pages.transaction import check_transaction_page
from modules.pages.dataset import dataset_analysis_page
from modules.pages.history import show_transaction_history
from modules.pages.admin import admin_management_page
from modules.pages.about import show_about_page
from modules.models import load_model

st.set_page_config(
    page_title="Ministry of Finance - Fraud Detection System",
    page_icon="🏛️",
    layout="wide",
    initial_sidebar_state="expanded"
)

apply_custom_styles()

def login_page():
    st.markdown('<div style="height: 80px;"></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 0.45, 1])
    
    with col2:
        st.markdown("""
        <div style="
            background: white;
            border-radius: 20px;
            padding: 40px 35px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            border: 1px solid #e0e0e0;
        ">
            <div style="text-align: center; margin-bottom: 30px;">
                <div style="background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); width: 65px; height: 65px; border-radius: 33px; display: flex; align-items: center; justify-content: center; margin: 0 auto 18px auto;">
                    <i class="fas fa-shield-alt" style="font-size: 30px; color: white;"></i>
                </div>
                <h2 style="margin: 0; color: #1e3c72; font-size: 26px;">Ministry of Finance</h2>
                <p style="color: #6c757d; margin: 8px 0 0 0; font-size: 14px;">Fraud Detection System</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Forgot password section
        st.markdown('<div style="margin-top: 25px;"></div>', unsafe_allow_html=True)
        
        with st.expander("Forgot Password?"):
            st.markdown("""
            <div style="background: #e8f4fd; padding: 16px; border-radius: 15px;">
                <i class="fas fa-envelope"></i> <strong>Contact Administrator</strong><br>
                Email: bastansy42@gmail.com<br>
                Phone: +255 0699 565 600
            </div>
            """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.text_input("Username", placeholder="Enter your username", key="login_username")
            st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
            
            submitted = st.form_submit_button("Sign In", use_container_width=True)
            
            if submitted:
                username = st.session_state.get("login_username", "")
                password = st.session_state.get("login_password", "")
                if username and password:
                    user = authenticate_user(username, password)
                    if user:
                        st.session_state.user = user
                        st.session_state.authenticated = True
                        
                        # Initialize current page if not exists
                        if 'current_page' not in st.session_state:
                            st.session_state.current_page = "Dashboard"
                        
                        st.success(f"Welcome, {user['username']}!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.warning("Please enter both fields")
        
        st.markdown("</div>", unsafe_allow_html=True)

def main_app():
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); padding: 20px 35px; border-radius: 18px; margin-bottom: 28px;">
        <h1 style="color: white; margin: 0; font-size: 24px;"><i class="fas fa-landmark"></i> Ministry of Finance Tanzania</h1>
        <p style="color: rgba(255,255,255,0.85); margin: 5px 0 0 0; font-size: 13px;">Advanced Financial Fraud Detection & Prevention System</p>
    </div>
    """, unsafe_allow_html=True)
    
    init_database()
    model = load_model()
    
    # Sidebar
    with st.sidebar:
        st.markdown(f"""
        <div style="text-align: center; padding: 16px 0 12px 0; border-bottom: 1px solid #e0e0e0;">
            <div style="background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); width: 55px; height: 55px; border-radius: 28px; display: flex; align-items: center; justify-content: center; margin: 0 auto;">
                <i class="fas fa-user" style="font-size: 26px; color: white;"></i>
            </div>
            <h4 style="margin: 12px 0 4px 0; color: #1e3c72;">{st.session_state.user['username']}</h4>
            <p style="color: #6c757d; font-size: 11px; margin: 0;">{st.session_state.user['role'].upper()}</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div style="margin: 15px 0 8px 0;"><p style="font-weight: 600; color: #1e3c72; font-size: 12px;">NAVIGATION</p></div>', unsafe_allow_html=True)
        
        # Page selection - Get current page from session state
        if st.session_state.user['role'] == 'admin':
            pages = ["Dashboard", "Check Transaction", "Analyze Dataset", "Transaction History", "Admin Panel", "About"]
        else:
            pages = ["Dashboard", "Check Transaction", "Analyze Dataset", "Transaction History", "About"]
        
        # Get current page from session state (default to Dashboard)
        current_page = st.session_state.get("current_page", "Dashboard")
        
        # Ensure current_page is valid
        if current_page not in pages:
            current_page = "Dashboard"
        
        # Find index of current page for selectbox
        page_index = pages.index(current_page)
        
        # Create selectbox with current page preselected
        selected_page = st.selectbox("", pages, index=page_index, label_visibility="collapsed")
        
        # Update session state only if page changed
        if selected_page != st.session_state.get("current_page", ""):
            st.session_state.current_page = selected_page
            st.rerun()
        
        st.markdown("---")
        
        # Quick Actions Section
        st.markdown('<p style="font-weight: 600; color: #1e3c72; font-size: 12px;">QUICK ACTIONS</p>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("New", use_container_width=True):
                st.session_state.current_page = "Check Transaction"
                st.rerun()
        with col2:
            if st.button("Upload", use_container_width=True):
                st.session_state.current_page = "Analyze Dataset"
                st.rerun()
        
        st.markdown("---")
        
        # System Status Section
        st.markdown('<p style="font-weight: 600; color: #1e3c72; font-size: 12px;">SYSTEM STATUS</p>', unsafe_allow_html=True)
        st.markdown("""
        <div style="background: #f0f2f6; padding: 10px; border-radius: 10px;">
            <p style="margin: 4px 0; font-size: 12px;"><span style="color: #28a745;">●</span> Operational</p>
            <p style="margin: 4px 0; font-size: 12px;"><i class="fas fa-lock"></i> Secure</p>
            <p style="margin: 4px 0; font-size: 12px;"><i class="fas fa-clock"></i> 24/7 Monitoring</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        if st.button("Logout", use_container_width=True):
            # Clear all session data
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Get the page to display from session state
    display_page = st.session_state.get("current_page", "Dashboard")
    
    # Page routing
    if display_page == "Dashboard":
        show_dashboard()
    elif display_page == "Check Transaction":
        check_transaction_page(model)
    elif display_page == "Analyze Dataset":
        dataset_analysis_page(model)
    elif display_page == "Transaction History":
        show_transaction_history()
    elif display_page == "Admin Panel":
        admin_management_page()
    else:
        show_about_page()
    
    st.markdown("""
    <div style="text-align: center; padding: 20px; margin-top: 30px; border-top: 1px solid #e0e0e0; color: #6c757d; font-size: 12px;">
        <i class="fas fa-lock"></i> Secure System | Ministry of Finance Tanzania | 2025
    </div>
    """, unsafe_allow_html=True)

def main():
    initialize_auth_db()
    
    # Initialize session state variables
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    # Initialize current page if not exists
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Dashboard"
    
    if not st.session_state.authenticated:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()