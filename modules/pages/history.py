# modules/pages/history.py 
import streamlit as st
import pandas as pd
from datetime import datetime  
from modules.database import get_all_transactions
import io

def show_transaction_history():
    st.markdown("""
    <div style="margin-bottom: 20px;">
        <h2 style="color: #1e3c72; margin: 0;"><i class="fas fa-history"></i> Transaction History</h2>
        <p style="color: #6c757d;">View and export all analyzed transactions</p>
    </div>
    """, unsafe_allow_html=True)
    
    df = get_all_transactions()
    
    if df.empty:
        st.info("No transactions yet. Start by checking a transaction!")
        return
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        risk_filter = st.selectbox("Filter by Risk", ["All", "HIGH", "MEDIUM", "LOW"])
    
    with col2:
        vendor_filter = st.selectbox("Filter by Vendor", ["All"] + list(df['vendor_type'].unique()))
    
    with col3:
        date_filter = st.selectbox("Time Period", ["All", "Last 7 Days", "Last 30 Days", "Last 90 Days"])
    
    # Apply filters
    filtered_df = df.copy()
    
    if risk_filter != "All":
        filtered_df = filtered_df[filtered_df['final_decision'].str.contains(risk_filter, na=False)]
    
    if vendor_filter != "All":
        filtered_df = filtered_df[filtered_df['vendor_type'] == vendor_filter]
    
    if date_filter != "All":
        days = {"Last 7 Days": 7, "Last 30 Days": 30, "Last 90 Days": 90}
        cutoff = datetime.now() - pd.Timedelta(days=days[date_filter])
        filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
        filtered_df = filtered_df[filtered_df['created_at'] >= cutoff]
    
    # Display stats
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total", len(filtered_df))
    with col2:
        high_count = len(filtered_df[filtered_df['final_decision'].str.contains('HIGH', na=False)])
        st.metric("High Risk", high_count)
    with col3:
        total_amount = filtered_df['amount'].sum()
        st.metric("Total Amount", f"TZS {total_amount:,.0f}")
    with col4:
        avg_confidence = filtered_df['ml_confidence'].mean()
        st.metric("Avg Confidence", f"{avg_confidence:.1%}")
    
    # Display table
    display_cols = ['transaction_id', 'amount', 'vendor_type', 'payment_method', 
                   'procurement_method', 'approval_level', 'ml_confidence', 'final_decision', 'created_at']
    
    available_cols = [col for col in display_cols if col in filtered_df.columns]
    st.dataframe(filtered_df[available_cols], use_container_width=True)
    
    # Export section
    st.markdown("---")
    st.markdown('<p style="font-weight: 600; color: #1e3c72;">Export Data</p>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export to CSV
        csv = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download as CSV",
            data=csv,
            file_name=f"fraud_transactions_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col2:
        # Export to Excel
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            filtered_df.to_excel(writer, sheet_name='Transactions', index=False)
        excel_data = output.getvalue()
        
        st.download_button(
            label="Download as Excel",
            data=excel_data,
            file_name=f"fraud_transactions_{datetime.now().strftime('%Y%m%d')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True
        )