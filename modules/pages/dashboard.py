# modules/pages/dashboard.py 
import streamlit as st
import plotly.express as px
import pandas as pd
from modules.database import get_all_transactions, get_performance_stats

def show_dashboard():
    """Display analytics dashboard"""
    st.markdown("""
    <div style="margin-bottom: 20px;">
        <h2 style="color: #1e3c72; margin: 0;"> Analytics Dashboard</h2>
        <p style="color: #6c757d;">Real-time fraud detection metrics and insights</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Get data
    df = get_all_transactions()
    stats = get_performance_stats()
    
    # KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); padding: 15px; border-radius: 12px; color: white;">
            <p style="margin: 0; font-size: 12px;"> Total Transactions</p>
            <h2 style="margin: 5px 0; font-size: 28px;">{stats['total_transactions']}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        fraud_count = len(df[df['final_decision'].str.contains('HIGH', na=False)]) if not df.empty else 0
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); padding: 15px; border-radius: 12px; color: white;">
            <p style="margin: 0; font-size: 12px;"> High Risk</p>
            <h2 style="margin: 5px 0; font-size: 28px;">{fraud_count}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        medium_count = len(df[df['final_decision'].str.contains('MEDIUM', na=False)]) if not df.empty else 0
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); padding: 15px; border-radius: 12px; color: white;">
            <p style="margin: 0; font-size: 12px;"> Medium Risk</p>
            <h2 style="margin: 5px 0; font-size: 28px;">{medium_count}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        low_count = len(df[df['final_decision'].str.contains('LOW', na=False)]) if not df.empty else 0
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #28a745 0%, #218838 100%); padding: 15px; border-radius: 12px; color: white;">
            <p style="margin: 0; font-size: 12px;"> Low Risk</p>
            <h2 style="margin: 5px 0; font-size: 28px;">{low_count}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    if df.empty:
        st.info(" No data available. Start by analyzing transactions to see insights.")
        return
    
    st.markdown("---")
    
    # Charts Row 1
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<p style="font-weight: 600; color: #1e3c72;">Risk Distribution</p>', unsafe_allow_html=True)
        
        risk_data = df['final_decision'].value_counts().reset_index()
        risk_data.columns = ['Risk Level', 'Count']
        
        fig_pie = px.pie(risk_data, values='Count', names='Risk Level', 
                        title='Fraud Risk Distribution',
                        hole=0.4)
        fig_pie.update_layout(title_x=0.5, height=400)
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        st.markdown('<p style="font-weight: 600; color: #1e3c72;">Amount vs Risk Level</p>', unsafe_allow_html=True)
        
        fig_scatter = px.scatter(df, x='amount', y='ml_confidence', 
                                color='final_decision',
                                title='Transaction Amount vs Fraud Confidence',
                                labels={'amount': 'Amount (TZS)', 'ml_confidence': 'Confidence Score'})
        fig_scatter.update_layout(title_x=0.5, height=400)
        st.plotly_chart(fig_scatter, use_container_width=True)
    
    # Charts Row 2
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<p style="font-weight: 600; color: #1e3c72;">Transaction Trend</p>', unsafe_allow_html=True)
        
        if 'created_at' in df.columns:
            df['date'] = pd.to_datetime(df['created_at']).dt.date
            trend_data = df.groupby('date').size().reset_index(name='count')
            fig_line = px.line(trend_data, x='date', y='count', 
                              title='Daily Transaction Volume',
                              markers=True)
            fig_line.update_layout(title_x=0.5, height=350)
            st.plotly_chart(fig_line, use_container_width=True)
    
    with col2:
        st.markdown('<p style="font-weight: 600; color: #1e3c72;">Vendor Risk Analysis</p>', unsafe_allow_html=True)
        
        if 'vendor_type' in df.columns:
            vendor_risk = df.groupby('vendor_type').size().reset_index(name='count')
            if not vendor_risk.empty:
                fig_bar = px.bar(vendor_risk, x='vendor_type', y='count',
                                title='Transactions by Vendor Type',
                                color='count',
                                color_continuous_scale='Blues')
                fig_bar.update_layout(title_x=0.5, height=350)
                st.plotly_chart(fig_bar, use_container_width=True)
    
    st.markdown("---")
    
    # Recent Transactions Table
    st.markdown('<p style="font-weight: 600; color: #1e3c72;">Recent Transactions</p>', unsafe_allow_html=True)
    
    display_cols = ['transaction_id', 'amount', 'vendor_type', 'final_decision', 'ml_confidence', 'created_at']
    available_cols = [col for col in display_cols if col in df.columns]
    
    if available_cols:
        recent_df = df.head(10)[available_cols]
        recent_df.columns = ['Transaction ID', 'Amount', 'Vendor', 'Risk Level', 'Confidence', 'Date']
        st.dataframe(recent_df, use_container_width=True)
    else:
        st.info("No transaction data to display")