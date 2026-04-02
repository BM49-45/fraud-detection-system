# modules/styles.py - UPDATED
import streamlit as st

def apply_custom_styles():
    st.markdown("""
    <style>
        @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css');
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        * {
            font-family: 'Inter', sans-serif;
        }
        
        .stApp {
            background-color: #f8f9fa;
        }
        
        .stButton > button {
            background: linear-gradient(135deg, #2a5298 0%, #1e3c72 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .stButton > button:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(42,82,152,0.3);
        }
        
        .stTextInput > div > div > input {
            border-radius: 8px;
            border: 1px solid #ced4da;
        }
        
        .stSelectbox > div > div {
            border-radius: 8px;
        }
        
        .stNumberInput > div > div > input {
            border-radius: 8px;
        }
        
        .stAlert {
            border-radius: 8px;
        }
        
        .stExpander {
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }
        
        .stMetric {
            background: white;
            padding: 12px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        
        .stMetric label {
            color: #6c757d;
        }
        
        .stDataFrame {
            border-radius: 10px;
            overflow: hidden;
        }
        
        hr {
            margin: 12px 0;
        }
    </style>
    """, unsafe_allow_html=True)