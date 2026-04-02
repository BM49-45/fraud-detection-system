# modules/pages/about.py
import streamlit as st

def show_about_page():
    st.header("ℹ️ About This System")
    
    st.markdown("""
    ## 🏛️ Ministry of Finance - Fraud Detection System
    
    ### System Purpose
    This system detects potential financial fraud using statistical analysis and business rules.
    
    ### Features
    - Single Transaction Analysis
    - Batch Dataset Processing  
    - Risk Factor Identification
    - Real-time Dashboard
    - User Management
    
    ### Contact
    - 📧 Email: bastansy42@gmail.com
    - 📞 Phone: +255 0699 565 600
    
    **Version:** 2.0.0
    """)