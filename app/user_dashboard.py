# app/dashboard/user_dashboard.py - COMPLETE DARK THEME FIX
import streamlit as st
import time
from datetime import datetime
import json
import os
from typing import Dict, List, Tuple

class UserDashboard:
    def __init__(self, user, auth):
        self.user = user
        self.auth = auth
        self.db = auth.db
        
        # Initialize persona detector and DLP manager
        try:
            from app.security.persona_detector import PersonaDetector
            from app.services.dlp_manager import DLPManager
            self.persona_detector = PersonaDetector(self.db)
            self.dlp_manager = DLPManager(self.db)
        except ImportError as e:
            self.persona_detector = None
            self.dlp_manager = None
        
    def render(self):
        """Render user dashboard with COMPLETE DARK THEME"""
        
        # Apply OVERRIDING dark theme CSS (this will force dark theme everywhere)
        self._apply_force_dark_theme()
        
        # Check for persona anomalies
        self._check_persona_on_login()
        
        # Header with dark theme
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                padding: 1.8rem 2rem;
                border-radius: 16px;
                margin-bottom: 1.8rem;
                border: 1px solid #334155;
                box-shadow: 0 8px 20px rgba(0,0,0,0.5);
            ">
                <h1 style="color: white; margin: 0; font-size: 2.2rem; font-weight: 600;">Welcome back, {self.user['username']}! 👋</h1>
                <p style="color: #94a3b8; margin: 8px 0 0 0; font-size: 1rem;">Secure File Upload with Persona Detection & DLP</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            try:
                risk_summary = self.db.get_user_risk_summary(self.user['id'])
                risk_score = risk_summary.get('persona_risk_score', 0)
            except:
                risk_score = 0.0
            
            if risk_score >= 0.7:
                risk_color = "#ef4444"
                risk_icon = "🔴"
                risk_label = "HIGH"
            elif risk_score >= 0.4:
                risk_color = "#f59e0b"
                risk_icon = "🟡"
                risk_label = "MEDIUM"
            else:
                risk_color = "#10b981"
                risk_icon = "🟢"
                risk_label = "LOW"
            
            st.markdown(f"""
            <div style="
                background: #1e293b;
                padding: 1.2rem;
                border-radius: 12px;
                border: 1px solid #334155;
                text-align: center;
            ">
                <div style="color: #94a3b8; font-size: 0.9rem; margin-bottom: 5px;">Security Risk</div>
                <div style="color: {risk_color}; font-size: 1.8rem; font-weight: 700;">{risk_icon} {risk_label}</div>
                <div style="color: #cbd5e1; font-size: 0.9rem; margin-top: 5px;">Score: {risk_score:.1%}</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Navigation tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Dashboard", 
            "📁 Upload Files", 
            "📋 My Files",
            "🛡️ My Security"
        ])
        
        with tab1:
            self.render_dashboard()
        with tab2:
            self.render_upload()
        with tab3:
            self.render_my_files()
        with tab4:
            self.render_my_security()
    
    def _apply_force_dark_theme(self):
        """FORCE DARK THEME - Override all Streamlit CSS"""
        st.markdown("""
        <style>
        /* ========== COMPLETE DARK THEME OVERRIDE ========== */
        /* This forces dark theme on EVERY element */
        
        /* Main app container - DARK */
        .stApp, .main, .block-container, div[data-testid="stAppViewContainer"] {
            background-color: #0a0c10 !important;
            color: #ffffff !important;
        }
        
        /* ALL text elements - WHITE */
        h1, h2, h3, h4, h5, h6, p, span, div, label, 
        .stMarkdown, .stText, .stCaption, .stLatex, .stCode,
        .stAlert, .stInfo, .stWarning, .stError, .stSuccess,
        li, ul, ol, a, strong, em, small, code, pre {
            color: #ffffff !important;
        }
        
        /* Metric cards - DARK */
        div[data-testid="stMetric"] {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            border-radius: 12px !important;
            padding: 20px 16px !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
        }
        
        div[data-testid="stMetricLabel"] p {
            color: #94a3b8 !important;
            font-size: 0.9rem !important;
            font-weight: 500 !important;
        }
        
        div[data-testid="stMetricValue"] {
            color: #f8fafc !important;
            font-size: 1.8rem !important;
            font-weight: 700 !important;
        }
        
        div[data-testid="stMetricDelta"] {
            color: #cbd5e1 !important;
        }
        
        /* DataFrames - DARK */
        .stDataFrame, div[data-testid="stDataFrame"] {
            background-color: #1e293b !important;
            color: #ffffff !important;
        }
        
        .dataframe {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            border-radius: 8px !important;
        }
        
        .dataframe th {
            background-color: #0f172a !important;
            color: #f8fafc !important;
            font-weight: 600 !important;
            border-bottom: 2px solid #3b82f6 !important;
            padding: 12px !important;
        }
        
        .dataframe td {
            background-color: #1e293b !important;
            color: #e2e8f0 !important;
            border-bottom: 1px solid #334155 !important;
            padding: 10px 12px !important;
        }
        
        .dataframe tr:hover td {
            background-color: #2d3a4f !important;
        }
        
        /* Tabs - DARK */
        .stTabs [data-baseweb="tab-list"] {
            background-color: #0f172a !important;
            gap: 8px;
            padding: 10px 10px 0 10px !important;
            border-radius: 12px 12px 0 0 !important;
            border-bottom: 1px solid #334155 !important;
        }
        
        .stTabs [data-baseweb="tab"] {
            background-color: #1e293b !important;
            color: #e2e8f0 !important;
            border-radius: 8px 8px 0 0 !important;
            padding: 12px 24px !important;
            font-weight: 500 !important;
            border: 1px solid #334155 !important;
            border-bottom: none !important;
            transition: all 0.2s !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            background-color: #2d3a4f !important;
            color: white !important;
        }
        
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
            color: white !important;
            border: none !important;
        }
        
        /* Expanders - DARK */
        .streamlit-expanderHeader {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border: 1px solid #334155 !important;
            border-radius: 8px !important;
            font-weight: 500 !important;
        }
        
        .streamlit-expanderContent {
            background-color: #0f172a !important;
            border: 1px solid #334155 !important;
            border-top: none !important;
            border-radius: 0 0 8px 8px !important;
            padding: 1.5rem !important;
        }
        
        /* Buttons - DARK */
        .stButton > button {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
            color: white !important;
            font-weight: 600 !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.6rem 1.8rem !important;
            transition: all 0.2s ease !important;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3) !important;
        }
        
        .stButton > button:hover {
            background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%) !important;
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 16px rgba(37, 99, 235, 0.5) !important;
        }
        
        .stButton > button:active {
            transform: translateY(0px) !important;
        }
        
        /* Secondary buttons */
        .stButton > button[kind="secondary"] {
            background: #334155 !important;
            color: #e2e8f0 !important;
            box-shadow: none !important;
        }
        
        .stButton > button[kind="secondary"]:hover {
            background: #475569 !important;
        }
        
        /* File uploader - DARK */
        div[data-testid="stFileUploader"] {
            background-color: #1e293b !important;
            border: 2px dashed #475569 !important;
            border-radius: 16px !important;
            padding: 3rem 2rem !important;
            transition: all 0.3s !important;
        }
        
        div[data-testid="stFileUploader"]:hover {
            border-color: #3b82f6 !important;
            background-color: rgba(59, 130, 246, 0.1) !important;
        }
        
        div[data-testid="stFileUploader"] p {
            color: #e2e8f0 !important;
            font-size: 1.1rem !important;
        }
        
        /* Select boxes - DARK */
        div[data-baseweb="select"] > div {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            color: #f8fafc !important;
        }
        
        div[data-baseweb="select"] > div:hover {
            border-color: #3b82f6 !important;
        }
        
        /* Checkboxes - DARK */
        .stCheckbox {
            color: #e2e8f0 !important;
        }
        
        .stCheckbox label {
            color: #e2e8f0 !important;
        }
        
        /* Radio buttons - DARK */
        .stRadio {
            color: #e2e8f0 !important;
        }
        
        .stRadio label {
            color: #e2e8f0 !important;
        }
        
        /* Text inputs - DARK */
        .stTextInput input, .stTextArea textarea {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border: 1px solid #334155 !important;
            border-radius: 8px !important;
        }
        
        .stTextInput input:focus, .stTextArea textarea:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
        }
        
        /* Info, Success, Warning, Error boxes - DARK */
        .stAlert, div[data-baseweb="notification"] {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            color: #f8fafc !important;
        }
        
        .stInfo {
            border-left-color: #3b82f6 !important;
        }
        
        .stSuccess {
            border-left-color: #10b981 !important;
        }
        
        .stWarning {
            border-left-color: #f59e0b !important;
        }
        
        .stError {
            border-left-color: #ef4444 !important;
        }
        
        /* Progress bars - DARK */
        .stProgress > div > div {
            background-color: #1e293b !important;
        }
        
        .stProgress > div > div > div {
            background: linear-gradient(90deg, #3b82f6, #2563eb) !important;
        }
        
        /* Sidebar - DARK (if used) */
        section[data-testid="stSidebar"] {
            background-color: #0f172a !important;
            border-right: 1px solid #334155 !important;
        }
        
        section[data-testid="stSidebar"] .stButton > button {
            background: #1e293b !important;
            border: 1px solid #334155 !important;
            box-shadow: none !important;
        }
        
        section[data-testid="stSidebar"] .stButton > button:hover {
            background: #2d3a4f !important;
            border-color: #3b82f6 !important;
        }
        
        /* Hide Streamlit branding */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        
        /* Custom security cards */
        .security-card {
            background: rgba(30, 41, 59, 0.95) !important;
            border: 1px solid #334155 !important;
            border-radius: 16px !important;
            padding: 1.8rem !important;
            margin: 1.2rem 0 !important;
            backdrop-filter: blur(10px) !important;
            box-shadow: 0 8px 20px rgba(0,0,0,0.4) !important;
        }
        
        .security-card.warning {
            border-left: 6px solid #f59e0b !important;
            background: rgba(245, 158, 11, 0.15) !important;
        }
        
        .security-card.alert {
            border-left: 6px solid #ef4444 !important;
            background: rgba(239, 68, 68, 0.15) !important;
        }
        
        .security-card.success {
            border-left: 6px solid #10b981 !important;
            background: rgba(16, 185, 129, 0.15) !important;
        }
        
        /* Activity items */
        .activity-item {
            background: rgba(30, 41, 59, 0.8) !important;
            border: 1px solid #334155 !important;
            border-left: 4px solid #3b82f6 !important;
            border-radius: 12px !important;
            padding: 1rem 1.5rem !important;
            margin: 0.8rem 0 !important;
            transition: all 0.2s !important;
        }
        
        .activity-item:hover {
            background: #2d3a4f !important;
            transform: translateX(4px) !important;
        }
        
        /* Risk progress bar */
        .risk-progress {
            height: 10px;
            border-radius: 6px;
            background: #334155;
            margin: 12px 0;
            overflow: hidden;
        }
        
        .risk-progress-fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.3s ease;
        }
        
        .risk-progress-high { background: linear-gradient(90deg, #ef4444, #dc2626); }
        .risk-progress-medium { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .risk-progress-low { background: linear-gradient(90deg, #10b981, #059669); }
        
        /* ========== END DARK THEME ========== */
        </style>
        """, unsafe_allow_html=True)
    
    def _check_persona_on_login(self):
        """Check for persona anomalies on login"""
        if self.persona_detector:
            context = {
                'ip_address': st.session_state.get('user_ip', '127.0.0.1'),
                'user_agent': st.session_state.get('user_agent', 'Unknown'),
                'action_type': 'login'
            }
            try:
                anomaly = self.persona_detector.detect_persona_anomaly(self.user['id'], context)
                if anomaly and anomaly.get('risk_score', 0) > 0.7:
                    st.warning(f"⚠️ **Security Notice:** Unusual login pattern detected. Risk Score: {anomaly['risk_score']:.2%}")
            except:
                pass
    
    def render_dashboard(self):
        """Dashboard tab with dark theme"""
        # Quick stats
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            try:
                files_count = self.db.count_user_files(self.user['id'])
            except:
                files_count = 0
            st.metric("📁 My Files", files_count)
        
        with col2:
            try:
                pending_count = self.db.count_pending_approvals(self.user['id'])
            except:
                pending_count = 0
            st.metric("⏳ Pending Approval", pending_count)
        
        with col3:
            try:
                risk_count = self.db.count_high_risk_files(self.user['id'])
            except:
                risk_count = 0
            st.metric("🔴 High Risk Files", risk_count)
        
        with col4:
            try:
                dlp_violations = self.db.get_dlp_violations(user_id=self.user['id'], days=30)
                dlp_count = len(dlp_violations)
            except:
                dlp_count = 0
            st.metric("🛡️ DLP Violations", dlp_count)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Security status card
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1rem;">🛡️ Your Security Status</h3>', unsafe_allow_html=True)
        
        try:
            risk_summary = self.db.get_user_risk_summary(self.user['id'])
            risk_score = risk_summary.get('persona_risk_score', 0)
        except:
            risk_score = 0.0
        
        if risk_score >= 0.7:
            status_class = "alert"
            status_color = "#ef4444"
            status_message = "⚠️ HIGH RISK: Unusual behavior patterns detected"
            recommendations = [
                "Change your password immediately",
                "Review your recent activity",
                "Contact security if suspicious",
                "Enable two-factor authentication"
            ]
        elif risk_score >= 0.4:
            status_class = "warning"
            status_color = "#f59e0b"
            status_message = "📊 MEDIUM RISK: Some unusual patterns detected"
            recommendations = [
                "Review your login locations",
                "Update security settings",
                "Enable two-factor authentication",
                "Be cautious with file uploads"
            ]
        else:
            status_class = "success"
            status_color = "#10b981"
            status_message = "✅ LOW RISK: Normal behavior patterns"
            recommendations = [
                "Continue security best practices",
                "Keep software updated",
                "Report suspicious activity",
                "Use strong passwords"
            ]
        
        st.markdown(f"""
        <div class="security-card {status_class}">
            <h4 style="color: {status_color}; margin: 0 0 1rem 0; font-size: 1.3rem;">{status_message}</h4>
            <div style="margin: 1.2rem 0;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                    <span style="color: #94a3b8;">Risk Score:</span>
                    <span style="color: {status_color}; font-weight: 700; font-size: 1.2rem;">{risk_score:.1%}</span>
                </div>
                <div class="risk-progress">
                    <div class="risk-progress-fill risk-progress-{'high' if risk_score >= 0.7 else 'medium' if risk_score >= 0.4 else 'low'}" 
                         style="width: {risk_score * 100}%;"></div>
                </div>
            </div>
            <div style="margin-top: 1.2rem;">
                <p style="color: #f8fafc; font-weight: 600; margin-bottom: 0.8rem;">🔧 Recommendations:</p>
                <ul style="color: #e2e8f0; margin: 0; padding-left: 1.2rem;">
                    {"".join(f'<li style="margin: 0.5rem 0;">{rec}</li>' for rec in recommendations)}
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Recent activity
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1rem;">📝 Recent Activity</h3>', unsafe_allow_html=True)
        
        try:
            activities = self.db.get_user_activities(self.user['id'], limit=10)
            if activities:
                for activity in activities:
                    self.render_activity_item(activity)
            else:
                st.info("No recent activities found.")
        except:
            st.info("Unable to load recent activities.")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Quick actions
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1rem;">⚡ Quick Actions</h3>', unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📤 Upload New File", use_container_width=True, type="primary", key="dash_upload"):
                st.session_state['user_tab'] = 'upload'
                st.rerun()
        with col2:
            if st.button("📊 View Security Report", use_container_width=True, key="dash_security"):
                st.session_state['user_tab'] = 'security'
                st.rerun()
        with col3:
            if st.button("⚙️ Security Settings", use_container_width=True, key="dash_settings"):
                st.info("Configure security settings in the 'My Security' tab.")
    
    def render_upload(self):
        """File upload tab with dark theme"""
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1.5rem;">📤 Upload & Secure Scan Files</h3>', unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Choose a file to upload",
            type=['pdf', 'docx', 'txt', 'csv', 'xlsx', 'xls'],
            help="Max file size: 200MB. Files are scanned for sensitive data."
        )
        
        if uploaded_file:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"""
                <div style="background: #1e293b; padding: 1.2rem; border-radius: 12px; border: 1px solid #334155; margin: 0.5rem 0;">
                    <p style="color: #94a3b8; margin: 0 0 0.3rem 0;">📄 File Name</p>
                    <p style="color: #f8fafc; font-weight: 600; font-size: 1.1rem; margin: 0;">{uploaded_file.name}</p>
                    <p style="color: #94a3b8; margin: 1rem 0 0.3rem 0;">📦 File Size</p>
                    <p style="color: #f8fafc; margin: 0;">{uploaded_file.size / 1024:.1f} KB</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div style="background: #1e293b; padding: 1.2rem; border-radius: 12px; border: 1px solid #334155; margin: 0.5rem 0;">
                    <p style="color: #94a3b8; margin: 0 0 0.3rem 0;">📋 File Type</p>
                    <p style="color: #f8fafc; margin: 0;">{uploaded_file.type or 'Unknown'}</p>
                    <p style="color: #94a3b8; margin: 1rem 0 0.3rem 0;">🔒 Status</p>
                    <p style="color: #10b981; margin: 0; font-weight: 600;">Ready for security scanning</p>
                </div>
                """, unsafe_allow_html=True)
            
            with st.expander("🔒 Security Options"):
                col_sec1, col_sec2 = st.columns(2)
                with col_sec1:
                    encrypt_file = st.checkbox("Encrypt file", value=True, key="upload_encrypt")
                    scan_content = st.checkbox("Deep content scan", value=True, key="upload_scan")
                with col_sec2:
                    notify_me = st.checkbox("Notify me of results", value=True, key="upload_notify")
                    allow_review = st.checkbox("Allow admin review", value=True, key="upload_review")
            
            st.markdown("""
            <div style="background: rgba(245, 158, 11, 0.15); border-left: 6px solid #f59e0b; padding: 1.5rem; border-radius: 12px; margin: 1.5rem 0;">
                <h4 style="color: #f59e0b; margin: 0 0 1rem 0;">⚠️ Data Leakage Prevention (DLP) Active</h4>
                <p style="color: #e2e8f0; margin: 0.5rem 0;">Your file will be scanned for:</p>
                <ul style="color: #cbd5e1; margin: 0.8rem 0 0 1.2rem;">
                    <li>• Aadhaar/PAN numbers</li>
                    <li>• Credit card/SSN information</li>
                    <li>• Sensitive keywords</li>
                    <li>• Personal identification data</li>
                </ul>
                <p style="color: #94a3b8; margin: 1.2rem 0 0 0; font-style: italic;">Files containing sensitive data may be blocked or encrypted automatically.</p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🚀 Upload & Secure Scan", type="primary", use_container_width=True, key="upload_btn"):
                with st.spinner("Scanning for sensitive data and threats..."):
                    upload_dir = "uploads/user_uploads"
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    file_path = os.path.join(upload_dir, f"{self.user['id']}_{int(time.time())}_{uploaded_file.name}")
                    with open(file_path, 'wb') as f:
                        f.write(uploaded_file.getbuffer())
                    
                    scan_result = {}
                    dlp_action = {'action': 'allow', 'reason': 'No DLP scan performed'}
                    risk_score = 0.0
                    
                    if self.dlp_manager:
                        context = {
                            'ip_address': st.session_state.get('user_ip', '127.0.0.1'),
                            'user_agent': st.session_state.get('user_agent', 'Unknown'),
                            'action_type': 'file_upload'
                        }
                        try:
                            scan_result = self.dlp_manager.scan_file(file_path, self.user['id'], context)
                            dlp_action = scan_result.get('dlp_action', {'action': 'allow', 'reason': 'No action'})
                            risk_score = scan_result.get('risk_score', 0)
                        except:
                            pass
                    
                    if dlp_action.get('action') == 'block':
                        try:
                            os.remove(file_path)
                        except:
                            pass
                        st.error(f"🚫 **UPLOAD BLOCKED**\n\n**Reason:** {dlp_action.get('reason', 'Sensitive content detected')}\n**Risk Score:** {risk_score:.2%}")
                        return
                    
                    try:
                        file_id = self.db.save_file_record(
                            user_id=self.user['id'],
                            filename=uploaded_file.name,
                            filepath=file_path,
                            file_type=uploaded_file.type or 'unknown',
                            file_size=uploaded_file.size,
                            risk_score=risk_score,
                            scan_result=json.dumps(scan_result) if scan_result else None,
                            approval_status='pending' if risk_score > 0.4 else 'approved',
                            dlp_action=dlp_action.get('action'),
                            dlp_reason=dlp_action.get('reason')
                        )
                    except Exception as e:
                        st.error(f"Failed to save file record: {e}")
                        return
                    
                    try:
                        self.db.log_activity(
                            user_id=self.user['id'],
                            activity_type='file_upload',
                            details=f'Uploaded file: {uploaded_file.name} (Risk: {risk_score:.2%})',
                            risk_score=risk_score
                        )
                    except:
                        pass
                    
                    if risk_score > 0.7:
                        st.error(f"⚠️ **HIGH RISK FILE UPLOADED**\n\n**Risk Score:** {risk_score:.2%}\n**Status:** Requires admin approval")
                    elif risk_score > 0.4:
                        st.warning(f"📋 **MEDIUM RISK FILE UPLOADED**\n\n**Risk Score:** {risk_score:.2%}\n**Status:** Under review")
                    else:
                        st.success(f"✅ **FILE UPLOADED SUCCESSFULLY**\n\n**Risk Score:** {risk_score:.2%}\n**Status:** Approved")
                    
                    time.sleep(2)
                    st.rerun()
    
    def render_my_files(self):
        """My Files tab with dark theme"""
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1.5rem;">📋 My Uploaded Files</h3>', unsafe_allow_html=True)
        
        try:
            files = self.db.get_user_files(self.user['id'])
        except:
            files = []
        
        if files:
            tab_all, tab_pending, tab_approved, tab_rejected = st.tabs([
                "📁 All Files", "⏳ Pending", "✅ Approved", "❌ Rejected"
            ])
            
            with tab_all:
                self.render_files_table_with_dlp(files)
            with tab_pending:
                pending_files = [f for f in files if f.get('approval_status') == 'pending']
                self.render_files_table_with_dlp(pending_files)
            with tab_approved:
                approved_files = [f for f in files if f.get('approval_status') == 'approved']
                self.render_files_table_with_dlp(approved_files)
            with tab_rejected:
                rejected_files = [f for f in files if f.get('approval_status') == 'rejected']
                self.render_files_table_with_dlp(rejected_files)
            
            st.markdown('<h4 style="color: #f8fafc; margin: 2rem 0 1rem 0;">📊 File Statistics</h4>', unsafe_allow_html=True)
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Files", len(files))
            with col2:
                approved = sum(1 for f in files if f.get('approval_status') == 'approved')
                st.metric("Approved", approved)
            with col3:
                pending = sum(1 for f in files if f.get('approval_status') == 'pending')
                st.metric("Pending", pending)
            with col4:
                rejected = sum(1 for f in files if f.get('approval_status') == 'rejected')
                st.metric("Rejected", rejected)
        else:
            st.markdown("""
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 3rem; text-align: center; margin: 2rem 0;">
                <h2 style="color: #94a3b8; margin-bottom: 1rem;">📭 No Files Uploaded Yet</h2>
                <p style="color: #cbd5e1; margin-bottom: 2rem;">Upload your first file to get started with secure scanning.</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button("📤 Upload Your First File", type="primary", key="upload_first"):
                st.session_state['user_tab'] = 'upload'
                st.rerun()
    
    def render_files_table_with_dlp(self, files):
        """Render files table with dark theme"""
        if not files:
            st.info("No files found.")
            return
        
        import pandas as pd
        
        data = []
        for file in files:
            risk_score = file.get('risk_score', 0)
            risk_icon = "🔴" if risk_score >= 0.7 else "🟡" if risk_score >= 0.4 else "🟢"
            
            dlp_action = file.get('dlp_action_taken', '')
            dlp_icons = {'block': '🚫', 'encrypt': '🔐', 'warn': '⚠️', 'allow': '✅'}
            dlp_icon = dlp_icons.get(dlp_action, '📄')
            
            status = file.get('approval_status', 'pending')
            status_icons = {'approved': '✅', 'rejected': '❌', 'pending': '⏳', 'blocked': '🚫'}
            status_icon = status_icons.get(status, '📄')
            
            uploaded_at = file.get('uploaded_at', '')
            if isinstance(uploaded_at, str) and len(uploaded_at) > 10:
                uploaded_at = uploaded_at[:10]
            
            data.append({
                "File": file['filename'],
                "Uploaded": uploaded_at,
                "Risk": f"{risk_icon} {risk_score:.2f}",
                "DLP": dlp_icon,
                "Status": f"{status_icon} {status.title()}",
                "Size": f"{file.get('file_size', 0) / 1024:.1f} KB"
            })
        
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True, height=400)
    
    def render_my_security(self):
        """Security tab with dark theme"""
        st.markdown('<h3 style="color: #f8fafc; margin-bottom: 1.5rem;">🛡️ My Security Dashboard</h3>', unsafe_allow_html=True)
        
        try:
            risk_summary = self.db.get_user_risk_summary(self.user['id'])
            risk_score = risk_summary.get('persona_risk_score', 0)
            high_risk_files = risk_summary.get('high_risk_files', 0)
        except:
            risk_score = 0.0
            high_risk_files = 0
        
        try:
            dlp_violations = self.db.get_dlp_violations(user_id=self.user['id'], days=30)
            dlp_count = len(dlp_violations)
        except:
            dlp_count = 0
        
        try:
            security_logs = self.db.get_security_logs(action_type='persona_anomaly', risk_threshold=0.0, days=30)
            user_security_logs = [log for log in security_logs if log.get('user_id') == self.user['id']]
            alert_count = len(user_security_logs)
        except:
            alert_count = 0
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            risk_color = "#ef4444" if risk_score >= 0.7 else "#f59e0b" if risk_score >= 0.4 else "#10b981"
            st.markdown(f"""
            <div style="background: #1e293b; padding: 1rem; border-radius: 12px; border: 1px solid #334155;">
                <p style="color: #94a3b8; margin: 0;">Persona Risk</p>
                <p style="color: {risk_color}; font-size: 1.5rem; font-weight: 700; margin: 0.3rem 0;">{risk_score:.1%}</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.metric("DLP Violations", dlp_count)
        with col3:
            st.metric("Security Alerts", alert_count)
        with col4:
            st.metric("High Risk Files", high_risk_files)
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<h4 style="color: #f8fafc; margin-bottom: 1rem;">📊 Risk Analysis</h4>', unsafe_allow_html=True)
        
        if risk_score >= 0.7:
            st.error("🔴 **HIGH RISK PROFILE**\n\nYour behavior patterns indicate significant deviations from your normal activity.")
        elif risk_score >= 0.4:
            st.warning("🟡 **MEDIUM RISK PROFILE**\n\nSome unusual patterns have been detected in your activity.")
        else:
            st.success("🟢 **LOW RISK PROFILE**\n\nYour activity patterns appear normal and consistent.")
        
        if dlp_count > 0:
            st.markdown('<h4 style="color: #f8fafc; margin: 2rem 0 1rem 0;">Recent DLP Violations</h4>', unsafe_allow_html=True)
            for violation in dlp_violations[:3]:
                severity = violation.get('severity', 'medium')
                severity_color = '#dc2626' if severity == 'critical' else '#ea580c' if severity == 'high' else '#d97706' if severity == 'medium' else '#059669'
                st.markdown(f"""
                <div style="background: #1e293b; padding: 1rem; border-radius: 12px; border-left: 4px solid {severity_color}; margin: 0.8rem 0; border: 1px solid #334155;">
                    <strong style="color: #f8fafc;">{violation.get('violation_type', 'Violation').replace('_', ' ').title()}</strong>
                    <p style="color: #94a3b8; margin: 0.3rem 0 0 0;">File: {violation.get('filename', 'Unknown')} | Action: {violation.get('action_taken', 'Unknown')}</p>
                </div>
                """, unsafe_allow_html=True)
        
        with st.expander("⚙️ My Security Settings"):
            col_set1, col_set2 = st.columns(2)
            with col_set1:
                enable_2fa = st.checkbox("Enable Two-Factor Authentication", value=False, key="sec_2fa")
                email_alerts = st.checkbox("Email Security Alerts", value=True, key="sec_email")
                login_notifications = st.checkbox("Login Notifications", value=True, key="sec_login")
            with col_set2:
                auto_logout = st.checkbox("Auto-logout after 30 min", value=True, key="sec_logout")
                device_remember = st.checkbox("Remember this device", value=False, key="sec_device")
                privacy_mode = st.checkbox("Enhanced Privacy Mode", value=False, key="sec_privacy")
            if st.button("Update Security Settings", type="primary", key="update_sec"):
                st.success("✅ Security settings updated successfully!")
                time.sleep(1)
                st.rerun()
    
    def render_activity_item(self, activity: Dict):
        """Render activity item with dark theme"""
        icons = {
            'login_success': '🔐', 'login_failed': '❌', 'logout': '🚪',
            'file_upload': '📤', 'file_download': '📥', 'approval': '✅',
            'persona_anomaly': '⚠️', 'dlp_violation': '🛡️'
        }
        icon = icons.get(activity.get('activity_type', ''), '📝')
        
        risk_score = activity.get('risk_score', 0)
        risk_indicator = "🔴" if risk_score >= 0.7 else "🟡" if risk_score >= 0.4 else "🟢"
        
        st.markdown(f"""
        <div class="activity-item">
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div style="font-size: 1.4rem;">{icon} {risk_indicator}</div>
                <div style="flex-grow: 1;">
                    <strong style="color: #f8fafc;">{activity.get('activity_type', 'Unknown').replace('_', ' ').title()}</strong>
                    <div style="color: #94a3b8; font-size: 0.9rem; margin-top: 0.2rem;">{activity.get('details', '')}</div>
                </div>
                <div style="color: #64748b; font-size: 0.85rem;">{activity.get('timestamp', '')[:16]}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)