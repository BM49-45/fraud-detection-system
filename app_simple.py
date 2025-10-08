# app_simple.py - BASIC WORKING VERSION
import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Fraud Detection", page_icon="🏛️", layout="wide")

st.title("🏛️ Ministry of Finance - Fraud Detection")
st.write("Basic working version - Authentication removed")

# Simple fraud detection function
def simple_fraud_check(amount, vendor_type):
    risk_score = 0
    if amount > 50000000: risk_score += 2
    if vendor_type == "New Vendor": risk_score += 2
    if vendor_type == "Individual": risk_score += 2
    
    if risk_score >= 3:
        return "🚨 HIGH RISK"
    elif risk_score >= 1:
        return "⚠️ MEDIUM RISK"
    else:
        return "✅ LOW RISK"

# Simple interface
st.header("🔍 Check Transaction")
amount = st.number_input("Amount (TZS)", value=1000000)
vendor_type = st.selectbox("Vendor Type", ["Registered Vendor", "New Vendor", "Individual"])

if st.button("Analyze"):
    result = simple_fraud_check(amount, vendor_type)
    st.success(f"Result: {result}")
    
    # Simple chart
    data = pd.DataFrame({
        'Risk Level': ['LOW', 'MEDIUM', 'HIGH'],
        'Count': [10, 5, 2]
    })
    fig = px.bar(data, x='Risk Level', y='Count', title='Risk Distribution')
    st.plotly_chart(fig)

st.info("✅ Basic version working! You can now add features gradually.")