# modules/models.py - COMPLETE ROBUST VERSION
import numpy as np
import pandas as pd
import streamlit as st
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

class SmartUniversalClassifier:
    """Intelligent classifier for fraud detection with business rules"""
    
    def __init__(self):
        self.name = "Fraud Detection Engine"
        self.feature_importance = {
            'Amount (TZS)': 0.35,
            'Vendor Type': 0.25,
            'Payment Method': 0.15,
            'Procurement Method': 0.15,
            'Approval Level': 0.10
        }
        self.model_loaded = False
    
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
    
    def get_feature_importance(self):
        return self.feature_importance


class HybridDetector:
    """Hybrid detector that combines ML model and business rules"""
    
    def __init__(self):
        self.ml_model = None
        self.rules_engine = SmartUniversalClassifier()
        self.mode = "rules"  # rules, ml, hybrid
        self.load_ml_model()
    
    def load_ml_model(self):
        """Try to load ML model silently"""
        try:
            model_files = ['fraud_detector_production.pkl', 'model.pkl', 'fraud_model.pkl']
            for model_file in model_files:
                if os.path.exists(model_file):
                    self.ml_model = joblib.load(model_file)
                    self.mode = "hybrid"
                    return True
            return False
        except:
            return False
    
    def predict(self, X):
        """Predict using hybrid approach"""
        if self.mode == "hybrid" and self.ml_model is not None:
            try:
                # Try ML prediction first
                ml_pred = self.ml_model.predict(X)
                ml_proba = self.ml_model.predict_proba(X)
                
                # Also get rules prediction
                rules_pred = self.rules_engine.predict(X)
                
                # Combine predictions (weighted average)
                final_pred = []
                for i in range(len(X)):
                    # If ML and rules agree, use that
                    if ml_pred[i] == rules_pred[i]:
                        final_pred.append(ml_pred[i])
                    else:
                        # If they disagree, use the one with higher confidence
                        ml_conf = ml_proba[i][1]
                        rules_conf = self.rules_engine.predict_proba(X.iloc[i:i+1])[0][1]
                        final_pred.append(1 if max(ml_conf, rules_conf) > 0.5 else 0)
                
                return np.array(final_pred)
            except:
                # Fallback to rules engine
                return self.rules_engine.predict(X)
        else:
            # Use rules engine only
            return self.rules_engine.predict(X)
    
    def predict_proba(self, X):
        """Predict probabilities using hybrid approach"""
        if self.mode == "hybrid" and self.ml_model is not None:
            try:
                ml_proba = self.ml_model.predict_proba(X)
                rules_proba = self.rules_engine.predict_proba(X)
                
                # Weighted average (60% ML, 40% rules)
                combined_proba = []
                for i in range(len(X)):
                    weighted = [ml_proba[i][0] * 0.6 + rules_proba[i][0] * 0.4,
                               ml_proba[i][1] * 0.6 + rules_proba[i][1] * 0.4]
                    combined_proba.append(weighted)
                return np.array(combined_proba)
            except:
                return self.rules_engine.predict_proba(X)
        else:
            return self.rules_engine.predict_proba(X)
    
    def get_mode(self):
        """Get current detection mode"""
        if self.mode == "hybrid":
            return "Hybrid (ML + Rules)"
        else:
            return "Business Rules Engine"
    
    def get_status(self):
        """Get system status"""
        if self.mode == "hybrid":
            return "ready", "success"
        else:
            return "ready", "info"


# Global detector instance
_detector = None

def get_detector():
    """Get or create the global detector instance (singleton)"""
    global _detector
    if _detector is None:
        _detector = HybridDetector()
    return _detector

def load_model():
    """Load detection engine - returns hybrid detector"""
    return get_detector()

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