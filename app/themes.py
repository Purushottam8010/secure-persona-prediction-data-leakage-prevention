# app/themes.py
import streamlit as st

class ThemeManager:
    @staticmethod
    def apply_admin_theme():
        st.markdown("""
        <style>
        /* Admin Theme - Dark Professional */
        :root {
            --primary: #2563eb;
            --secondary: #1e293b;
            --accent: #f59e0b;
            --danger: #ef4444;
            --success: #10b981;
        }
        
        .admin-header {
            background: linear-gradient(135deg, var(--primary) 0%, #1e40af 100%);
            padding: 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            color: white;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }
        
        .admin-card {
            background: var(--secondary);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
        }
        
        .admin-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.4);
        }
        
        .risk-high { border-left: 4px solid var(--danger); }
        .risk-medium { border-left: 4px solid var(--accent); }
        .risk-low { border-left: 4px solid var(--success); }
        </style>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def apply_user_theme():
        st.markdown("""
        <style>
        /* User Theme - Light Professional */
        :root {
            --primary: #3b82f6;
            --background: #f8fafc;
            --surface: #ffffff;
            --text: #1e293b;
        }
        
        .stApp {
            background: var(--background) !important;
        }
        
        .user-header {
            background: linear-gradient(135deg, var(--primary) 0%, #1d4ed8 100%);
            padding: 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            color: white;
        }
        
        .user-card {
            background: var(--surface);
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
        }
        
        /* Accessibility */
        * {
            font-family: 'Inter', -apple-system, sans-serif;
            line-height: 1.6;
        }
        
        h1 { font-size: 2.5rem; font-weight: 700; }
        h2 { font-size: 2rem; font-weight: 600; }
        h3 { font-size: 1.5rem; font-weight: 600; }
        
        /* Contrast fixes */
        .stTextInput label, .stTextArea label, .stSelectbox label {
            color: var(--text) !important;
            font-weight: 500;
        }
        </style>
        """, unsafe_allow_html=True)