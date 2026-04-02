# modules/pages/dataset.py
import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
from datetime import datetime
from modules.models import predict_fraud_business_rules

def dataset_analysis_page(model):
    st.header("📁 Analyze Your Dataset")
    
    uploaded_file = st.file_uploader("Upload Excel or CSV file", type=['xlsx', 'csv'])
    
    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith('.xlsx'):
                df = pd.read_excel(uploaded_file)
            else:
                df = pd.read_csv(uploaded_file)
            
            st.success(f"✅ Loaded {len(df)} transactions")
            st.dataframe(df.head(), use_container_width=True)
            
            # Column mapping
            amount_cols = [col for col in df.columns if 'amount' in col.lower() or 'value' in col.lower()]
            vendor_cols = [col for col in df.columns if 'vendor' in col.lower() or 'supplier' in col.lower()]
            
            amount_col = st.selectbox("Amount Column", options=amount_cols if amount_cols else df.columns)
            vendor_col = st.selectbox("Vendor Column", options=vendor_cols if vendor_cols else df.columns)
            
            if st.button("Run Analysis", type="primary"):
                with st.spinner("Analyzing..."):
                    results = []
                    for idx, row in df.iterrows():
                        amount = float(row[amount_col]) if pd.notna(row[amount_col]) else 0
                        vendor = str(row[vendor_col]) if pd.notna(row[vendor_col]) else 'Unknown'
                        
                        prediction, confidence, risk_score, _ = predict_fraud_business_rules(
                            amount, vendor, 'Unknown', 'Unknown', 'Unknown'
                        )
                        
                        if confidence > 0.7:
                            risk_level = "HIGH RISK"
                        elif confidence > 0.4:
                            risk_level = "MEDIUM RISK"
                        else:
                            risk_level = "LOW RISK"
                        
                        results.append({
                            'Amount': amount,
                            'Vendor': vendor,
                            'Fraud_Prediction': 'FRAUD' if prediction == 1 else 'LEGITIMATE',
                            'Confidence': f"{confidence:.1%}",
                            'Risk': risk_level
                        })
                    
                    results_df = pd.DataFrame(results)
                    st.dataframe(results_df, use_container_width=True)
                    
                    # Download
                    csv = results_df.to_csv(index=False)
                    st.download_button("Download Results", csv, f"analysis_{datetime.now().strftime('%Y%m%d')}.csv")
                    
        except Exception as e:
            st.error(f"Error: {e}")