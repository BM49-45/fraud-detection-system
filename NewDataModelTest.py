# TEST MODEL KWA DATA MPYA
def test_with_new_data(model):
    """Test model kwa transactions mpya"""
    print("\n🧪 TESTING WITH NEW TRANSACTIONS")
    
    # Create new sample transactions
    new_transactions = pd.DataFrame([
        {
            'Transaction ID': 'TXN-TEST-001',
            'Transaction Date': '2024-03-20',
            'Amount (TZS)': 50000000,  # 50M - suspicious
            'Vendor Type': 'New Vendor',
            'Payment Method': 'Cash',
            'Department Code': 'PROC-02',
            'Procurement Method': 'Direct Purchase',
            'Approval Level': 'Junior Officer',
            'Account Category': 'Capital Equipment',
            'Audit Report ID': 'N/A'
        },
        {
            'Transaction ID': 'TXN-TEST-002', 
            'Transaction Date': '2024-03-21',
            'Amount (TZS)': 1500000,  # 1.5M - normal
            'Vendor Type': 'Registered Vendor',
            'Payment Method': 'EFT',
            'Department Code': 'FIN-01',
            'Procurement Method': 'Open Tender',
            'Approval Level': 'Senior Officer',
            'Account Category': 'Office Supplies',
            'Audit Report ID': 'N/A'
        }
    ])
    
    predictions = model.predict(new_transactions)
    probabilities = model.predict_proba(new_transactions)
    
    for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
        status = "🚨 FRAUD" if pred == 1 else "✅ LEGITIMATE"
        fraud_prob = prob[1]
        print(f"Transaction {i+1}: {status} ({fraud_prob:.1%} confidence)")
        
        # Business rules validation
        amount = new_transactions.iloc[i]['Amount (TZS)']
        vendor = new_transactions.iloc[i]['Vendor Type']
        method = new_transactions.iloc[i]['Procurement Method']
        
        print(f"   Amount: {amount:,} | Vendor: {vendor} | Method: {method}")

# Test the model with new data
test_with_new_data(model)