# modules/pages/transaction.py - FINAL VERSION
import streamlit as st
from datetime import datetime
from modules.models import predict_fraud_business_rules
from modules.database import save_transaction

def check_transaction_page(model):
    st.markdown("""
    <div style="margin-bottom: 20px;">
        <h2 style="color: #1e3c72; margin: 0; font-size: 22px;">Transaction Analysis</h2>
        <p style="color: #6c757d; margin: 5px 0 0 0;">Real-time fraud risk assessment</p>
    </div>
    """, unsafe_allow_html=True)
    
    col_left, col_right = st.columns([2.5, 1.5])
    
    with col_left:
        with st.form("single_transaction_form"):
            st.markdown('<p style="font-weight: 600; color: #1e3c72; margin-bottom: 15px; font-size: 16px;">Transaction Details</p>', unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                amount = st.number_input("Amount (TZS)", min_value=0, value=1000000, step=100000)
                vendor_type = st.selectbox("Vendor Type", ["Registered Vendor", "New Vendor", "Individual", "Unknown Vendor"])
                payment_method = st.selectbox("Payment Method", ["EFT", "Cash", "Cheque", "Mobile Money", "Unknown"])
            
            with col2:
                procurement_method = st.selectbox("Procurement Method", ["Open Tender", "Direct Purchase", "Request for Quotation", "Selective Tender", "Unknown"])
                approval_level = st.selectbox("Approval Level", ["Junior Officer", "Senior Officer", "Director", "Unknown"])
                department = st.text_input("Department Code", "PROC-01")
            
            submitted = st.form_submit_button("Analyze Transaction", use_container_width=True)
            
            if submitted:
                with st.spinner("Processing..."):
                    try:
                        ml_pred, ml_conf, risk_score, risk_factors = predict_fraud_business_rules(
                            amount, vendor_type, payment_method, procurement_method, approval_level
                        )
                        
                        if ml_conf > 0.7:
                            decision = "HIGH RISK - DECLINE"
                            bg_color = "#dc3545"
                            text_color = "white"
                        elif ml_conf > 0.4:
                            decision = "MEDIUM RISK - HOLD"
                            bg_color = "#fd7e14"
                            text_color = "white"
                        else:
                            decision = "LOW RISK - APPROVE"
                            bg_color = "#28a745"
                            text_color = "white"
                        
                        transaction_data = {
                            'Transaction ID': f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                            'Transaction Date': datetime.now().strftime('%Y-%m-%d'),
                            'Amount (TZS)': amount,
                            'Vendor Type': vendor_type,
                            'Payment Method': payment_method,
                            'Department Code': department,
                            'Procurement Method': procurement_method,
                            'Approval Level': approval_level,
                            'ML_Prediction': int(ml_pred),
                            'ML_Confidence': float(ml_conf),
                            'Business_Risk_Score': risk_score,
                            'Final_Decision': decision
                        }
                        
                        save_transaction(transaction_data)
                        
                        st.markdown(f"""
                        <div style="background: {bg_color}; padding: 16px; border-radius: 10px; text-align: center; margin: 15px 0;">
                            <h3 style="margin: 0; color: {text_color};">{decision}</h3>
                            <p style="margin: 6px 0 0 0; color: {text_color}; opacity: 0.9;">ID: {transaction_data['Transaction ID']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        m1, m2, m3 = st.columns(3)
                        m1.metric("Confidence", f"{ml_conf:.1%}")
                        m2.metric("Prediction", "FRAUD" if ml_pred == 1 else "LEGITIMATE")
                        m3.metric("Risk Score", f"{risk_score}/8")
                        
                        if risk_factors:
                            st.markdown('<p style="font-weight: 600; margin: 12px 0 6px 0;">Risk Factors Identified</p>', unsafe_allow_html=True)
                            for factor in risk_factors:
                                st.warning(factor)
                        
                        c1, c2 = st.columns(2)
                        if c1.button("New Transaction", use_container_width=True):
                            st.rerun()
                        if c2.button("View History", use_container_width=True):
                            st.session_state.page = "Transaction History"
                            st.rerun()
                        
                    except Exception as e:
                        st.error(f"Error: {e}")
    
    with col_right:
        st.markdown('<p style="font-weight: 600; color: #1e3c72; margin-bottom: 12px; font-size: 16px;">Risk Assessment Guide</p>', unsafe_allow_html=True)
        
        # Amount Risk - No arrows
        with st.expander("Amount Risk (35% Weight)"):
            st.markdown("""
            <div style="padding: 5px 0;">
                <p><strong>Above 100M TZS</strong> <span style="color: #dc3545;">High Risk</span></p>
                <p><strong>50M to 100M TZS</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
                <p><strong>10M to 50M TZS</strong> <span style="color: #ffc107;">Low Risk</span></p>
                <p><strong>Below 10M TZS</strong> <span style="color: #28a745;">Very Low Risk</span></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Vendor Risk
        with st.expander("Vendor Risk (25% Weight)"):
            st.markdown("""
            <div style="padding: 5px 0;">
                <p><strong>New Vendor</strong> <span style="color: #dc3545;">High Risk</span></p>
                <p><strong>Individual Vendor</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
                <p><strong>Registered Vendor</strong> <span style="color: #28a745;">Low Risk</span></p>
                <p><strong>Unknown Vendor</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Payment Method Risk
        with st.expander("Payment Method Risk (15% Weight)"):
            st.markdown("""
            <div style="padding: 5px 0;">
                <p><strong>Cash</strong> <span style="color: #dc3545;">High Risk</span></p>
                <p><strong>Cheque</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
                <p><strong>EFT</strong> <span style="color: #28a745;">Low Risk</span></p>
                <p><strong>Mobile Money</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Procurement Method Risk
        with st.expander("Procurement Method Risk (15% Weight)"):
            st.markdown("""
            <div style="padding: 5px 0;">
                <p><strong>Direct Purchase</strong> <span style="color: #dc3545;">High Risk</span></p>
                <p><strong>Request for Quotation</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
                <p><strong>Open Tender</strong> <span style="color: #28a745;">Low Risk</span></p>
                <p><strong>Selective Tender</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Approval Level Risk
        with st.expander("Approval Level Risk (10% Weight)"):
            st.markdown("""
            <div style="padding: 5px 0;">
                <p><strong>Junior Officer</strong> <span style="color: #dc3545;">High Risk</span></p>
                <p><strong>Senior Officer</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
                <p><strong>Director</strong> <span style="color: #28a745;">Low Risk</span></p>
                <p><strong>Unknown</strong> <span style="color: #fd7e14;">Medium Risk</span></p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Tips Section
        st.markdown("""
        <div style="background: #f0f2f6; padding: 14px; border-radius: 10px; margin-top: 10px;">
            <p style="font-weight: 600; margin: 0 0 8px 0;">Verification Checklist</p>
            <p style="margin: 4px 0; font-size: 12px;">✓ Vendor registration documents</p>
            <p style="margin: 4px 0; font-size: 12px;">✓ Procurement approval chain</p>
            <p style="margin: 4px 0; font-size: 12px;">✓ Payment method justification</p>
            <p style="margin: 4px 0; font-size: 12px;">✓ Budget allocation verification</p>
        </div>
        """, unsafe_allow_html=True)