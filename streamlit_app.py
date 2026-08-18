import os
import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from pathlib import Path
import time
import inspect
import sqlite3

# Set up path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Add these imports
from app.services.notification_service import NotificationService, render_notification_center
from app.services.encryption_service import FileEncryptionService, encrypt_uploaded_file
from app.components.analytics_dashboard import AnalyticsDashboard
from app.security.session_manager import SessionManager, session_middleware

# Initialize services
notification_service = NotificationService()
notification_service.create_tables()

encryption_service = FileEncryptionService()
analytics_dashboard = AnalyticsDashboard()
session_manager = SessionManager()

# Initialize single database instance first
from database import DatabaseManager
db_manager = DatabaseManager()

from app.services.admin_agent import AIAdminAgent
from app.services.auto_processor import AutoFileProcessor
from app.services.chatbot import SupportChatbot

ai_agent = AIAdminAgent(db_manager)
auto_processor = AutoFileProcessor(ai_agent)
chatbot = SupportChatbot(db_manager)

# Import authentication AFTER db_manager is created
from auth import AuthenticationSystem
auth_system = AuthenticationSystem(db_manager)  # Pass db instance correctly

# Import other modules
from file_scanner import FileScanner
from threat_detector import ThreatDetector
from email_alert import EmailAlertSystem

from app.components.ai_admin_panel import render_ai_admin_panel
from app.components.chatbot_widget import render_chatbot_widget, render_chatbot_sidebar


# ===== NEW IMPORTS FOR PERSONA DETECTION & DLP =====
HAS_PERSONA_DETECTOR = False
HAS_DLP_MANAGER = False

try:
    from app.security.persona_detector import PersonaDetector
    HAS_PERSONA_DETECTOR = True
except ImportError:
    pass  # Silently handle

try:
    from app.services.dlp_manager import DLPManager
    HAS_DLP_MANAGER = True
except ImportError:
    pass  # Silently handle

# Import custom modules - FIXED IMPORTS
HAS_ADMIN_DASHBOARD = False
HAS_USER_DASHBOARD = False
HAS_THEME_MANAGER = False
HAS_KEYWORD_SCANNER = False
HAS_APPROVAL_WORKFLOW = False

# Try to import AdminDashboard
try:
    from app.admin_dashboard import AdminDashboard
    HAS_ADMIN_DASHBOARD = True
except ImportError:
    # Define a simple fallback AdminDashboard class
    class AdminDashboard:
        def __init__(self, user, auth):
            self.user = user
            self.auth = auth
        def render(self):
            st.write("AdminDashboard module not available. Using basic admin dashboard.")

try:
    from app.user_dashboard import UserDashboard
    HAS_USER_DASHBOARD = True
except ImportError:
    # Define a simple fallback UserDashboard class
    class UserDashboard:
        def __init__(self, user, auth):
            self.user = user
            self.auth = auth
        def render(self):
            st.write("UserDashboard module not available. Using basic user dashboard.")

try:
    from app.themes import ThemeManager
    HAS_THEME_MANAGER = True
    theme_manager = ThemeManager()
except ImportError:
    class ThemeManager:
        def apply_admin_theme(self):
            pass
        def apply_user_theme(self):
            pass
    theme_manager = ThemeManager()

try:
    from keyword_scanner import KeywordScanner
    HAS_KEYWORD_SCANNER = True
    keyword_scanner = KeywordScanner()
except ImportError:
    class KeywordScanner:
        def __init__(self):
            pass
    keyword_scanner = KeywordScanner()

# Try to import ApprovalWorkflow
try:
    from app.services.approval_workflow import ApprovalWorkflow
    HAS_APPROVAL_WORKFLOW = True
except ImportError:
    HAS_APPROVAL_WORKFLOW = False
    # Create a dummy class that will show an error message
    class ApprovalWorkflow:
        def __init__(self, db_manager):
            self.db = db_manager
            print("WARNING: ApprovalWorkflow module not found. Using fallback.")
        
        def get_pending_approvals(self, admin_id=None):
            return []
        
        def approve_file(self, file_id, approver_id, notes=""):
            return False
        
        def reject_file(self, file_id, approver_id, reason):
            return False
            """Get pending approvals"""
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                query = '''
                    SELECT 
                        fa.id as approval_id,
                        fa.file_id,
                        fa.user_id,
                        fa.requested_at,
                        fa.risk_level,
                        f.filename,
                        f.file_type,
                        f.file_size,
                        f.risk_score,
                        f.scan_result,
                        f.dlp_action_taken,
                        f.dlp_reason,
                        u.username,
                        u.email,
                        u.full_name
                    FROM file_approvals fa
                    JOIN files f ON fa.file_id = f.id
                    JOIN users u ON fa.user_id = u.id
                    WHERE fa.status = 'pending'
                '''
                
                if admin_id:
                    query += ' AND fa.approver_id IS NULL'
                
                query += ' ORDER BY fa.requested_at DESC'
                
                cursor.execute(query)
                approvals = []
                for row in cursor.fetchall():
                    approval = dict(row)
                    if approval.get('scan_result'):
                        try:
                            approval['scan_result'] = json.loads(approval['scan_result'])
                        except:
                            approval['scan_result'] = {}
                    approvals.append(approval)
                
                return approvals
            except Exception as e:
                print(f"Error getting pending approvals: {e}")
                return []
        
        def approve_file(self, file_id, approver_id, notes=""):
            """Approve a file"""
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE file_approvals 
                    SET status = 'approved', 
                        approver_id = ?,
                        approval_notes = ?,
                        reviewed_at = datetime('now')
                    WHERE file_id = ? AND status = 'pending'
                ''', (approver_id, notes, file_id))
                
                cursor.execute('''
                    UPDATE files 
                    SET approval_status = 'approved'
                    WHERE id = ?
                ''', (file_id,))
                
                # Create alert
                cursor.execute('SELECT user_id, filename FROM files WHERE id = ?', (file_id,))
                file_info = cursor.fetchone()
                
                if file_info:
                    self.db.create_alert(
                        alert_type='approval_update',
                        user_id=file_info['user_id'],
                        file_id=file_id,
                        severity='low',
                        title='File Approved',
                        message=f'Your file "{file_info["filename"]}" has been approved by admin'
                    )
                
                conn.commit()
                return True
            except Exception as e:
                print(f"Error approving file: {e}")
                if conn:
                    conn.rollback()
                return False
        
        def reject_file(self, file_id, approver_id, reason):
            """Reject a file"""
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE file_approvals 
                    SET status = 'rejected', 
                        approver_id = ?,
                        approval_notes = ?,
                        reviewed_at = datetime('now')
                    WHERE file_id = ? AND status = 'pending'
                ''', (approver_id, reason, file_id))
                
                cursor.execute('''
                    UPDATE files 
                    SET approval_status = 'rejected'
                    WHERE id = ?
                ''', (file_id,))
                
                # Create alert
                cursor.execute('SELECT user_id, filename FROM files WHERE id = ?', (file_id,))
                file_info = cursor.fetchone()
                
                if file_info:
                    self.db.create_alert(
                        alert_type='approval_update',
                        user_id=file_info['user_id'],
                        file_id=file_id,
                        severity='medium',
                        title='File Rejected',
                        message=f'Your file "{file_info["filename"]}" was rejected: {reason}'
                    )
                
                conn.commit()
                return True
            except Exception as e:
                print(f"Error rejecting file: {e}")
                if conn:
                    conn.rollback()
                return False

# Initialize ApprovalWorkflow
approval_workflow = ApprovalWorkflow(db_manager)

# Initialize systems
@st.cache_resource
def init_systems():
    """Initialize all systems"""
    scanner = FileScanner()
    threat_detector = ThreatDetector(db_manager)
    email_system = EmailAlertSystem()
    
    # Initialize persona detector and DLP manager if available
    persona_detector = None
    dlp_manager = None
    
    try:
        if HAS_PERSONA_DETECTOR:
            from app.security.persona_detector import PersonaDetector
            persona_detector = PersonaDetector(db_manager)
    except Exception as e:
        pass
    
    try:
        if HAS_DLP_MANAGER:
            from app.services.dlp_manager import DLPManager
            dlp_manager = DLPManager(db_manager)
    except Exception as e:
        pass
    
    return scanner, threat_detector, email_system, persona_detector, dlp_manager

# Initialize systems
scanner, threat_detector, email_system, persona_detector, dlp_manager = init_systems()

def login_page():
    """Login/Registration page with persona detection"""
    st.markdown('<h1 class="main-header">🔒 Secure Persona Detection & DLP System</h1>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login to Your Account")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            col1, col2 = st.columns([1, 3])
            with col1:
                login_btn = st.form_submit_button("Login", type="primary")
            
            if login_btn:
                if not username or not password:
                    st.error("Please enter both username and password")
                else:
                    # Get client IP and user agent for persona detection
                    client_ip = _get_client_ip()
                    user_agent = _get_user_agent()
                    
                    success, message = auth_system.login_user(username, password, client_ip, user_agent)
                    
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
    
    with tab2:
        st.subheader("Create New Account")
        
        with st.form("register_form"):
            col1, col2 = st.columns(2)
            with col1:
                reg_username = st.text_input("Choose Username")
                reg_password = st.text_input("Choose Password", type="password")
            with col2:
                reg_email = st.text_input("Email Address")
                reg_confirm = st.text_input("Confirm Password", type="password")
            
            reg_fullname = st.text_input("Full Name")
            reg_department = st.selectbox("Department", ["IT", "HR", "Finance", "Sales", "Engineering", "Other"])
            
            register_btn = st.form_submit_button("Register", type="primary")
            
            if register_btn:
                success, message = auth_system.register_user(
                    reg_username, reg_email, reg_password, reg_confirm,
                    role='user', full_name=reg_fullname, department=reg_department
                )
                
                if success:
                    st.success(message)
                else:
                    st.error(message)

def _get_client_ip():
    """Get client IP address (simplified for Streamlit)"""
    return '127.0.0.1'

def _get_user_agent():
    """Get user agent (simplified for Streamlit)"""
    return 'Streamlit-Client'

def _render_admin_approval_tab():
    """Render admin approval queue tab"""
    st.subheader("📋 Approval Queue")
    
    pending_approvals = approval_workflow.get_pending_approvals()
    
    if not pending_approvals:
        st.info("✅ No pending approvals")
        return
    
    for approval in pending_approvals:
        file_id = approval['file_id']
        
        with st.container():
            st.markdown(f"""
            <div style="background: #1e293b; padding: 1rem; border-radius: 8px; border: 1px solid #334155; margin: 1rem 0;">
                <h4 style="margin: 0;">📄 {approval['filename']} - {approval['username']} - Risk: {approval['risk_score']:.2%}</h4>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**User:** {approval['username']} ({approval['email']})")
                st.write(f"**File:** {approval['filename']}")
                st.write(f"**Risk Score:** {approval['risk_score']:.2%}")
                st.write(f"**Risk Level:** {approval['risk_level'].upper()}")
                st.write(f"**Uploaded:** {approval['requested_at']}")
            
            with col2:
                action_col1, action_col2 = st.columns(2)
                
                with action_col1:
                    if st.button("✅ Approve", key=f"approve_{file_id}", use_container_width=True):
                        st.session_state[f'approve_mode_{file_id}'] = True
                
                with action_col2:
                    if st.button("❌ Reject", key=f"reject_{file_id}", use_container_width=True):
                        st.session_state[f'reject_mode_{file_id}'] = True
            
            if st.session_state.get(f'approve_mode_{file_id}', False):
                notes = st.text_input("Approval notes:", key=f"approve_notes_{file_id}")
                if st.button("Confirm Approval", key=f"confirm_approve_{file_id}"):
                    user = auth_system.get_current_user()
                    if user and approval_workflow.approve_file(file_id, user['id'], notes):
                        st.success("✅ File approved!")
                        st.session_state[f'approve_mode_{file_id}'] = False
                        time.sleep(1)
                        st.rerun()
            
            if st.session_state.get(f'reject_mode_{file_id}', False):
                reason = st.text_input("Rejection reason:", key=f"reject_reason_{file_id}")
                if st.button("Confirm Rejection", key=f"confirm_reject_{file_id}"):
                    user = auth_system.get_current_user()
                    if user and approval_workflow.reject_file(file_id, user['id'], reason):
                        st.success("✅ File rejected!")
                        st.session_state[f'reject_mode_{file_id}'] = False
                        time.sleep(1)
                        st.rerun()
            
            st.markdown("---")

def _render_user_upload_tab(user):
    """Render user upload tab with email alerts integration"""
    st.subheader("📤 File Upload & Scanning")
    
    # Show user's previous history if exists
    if 'user_history' in st.session_state:
        history = st.session_state['user_history']
        if history['blocked_count'] > 0 or history['high_risk_count'] > 0:
            st.warning(f"⚠️ Your history: {history['blocked_count']} blocked files, {history['high_risk_count']} high-risk files")
        elif history['total_uploads'] > 0:
            st.info(f"📊 You have uploaded {history['total_uploads']} files previously")
    
    # Clear session state on tab switch to force refresh
    if 'upload_complete' in st.session_state:
        del st.session_state['upload_complete']
    
    uploaded_file = st.file_uploader(
        "Choose a file to upload",
        type=['pdf', 'docx', 'csv', 'txt', 'xlsx', 'xls'],
        help="Supported formats: PDF, Word, Excel, CSV, Text"
    )
    
    if uploaded_file and not st.session_state.get('upload_complete', False):
        # Display file info
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**File:** {uploaded_file.name}")
            st.info(f"**Size:** {uploaded_file.size / 1024:.1f} KB")
            st.info(f"**Type:** {uploaded_file.type}")
        
        with col2:
            st.warning("""
            ⚠️ **Data Leakage Prevention Active**
            
            Your file will be scanned for:
            • Aadhaar/PAN numbers
            • Credit card/SSN information  
            • Sensitive keywords
            • Personal identification data
            """)
        
        with st.expander("🔒 Security Options"):
            col1, col2 = st.columns(2)
            with col1:
                scan_content = st.checkbox("Scan for sensitive content", value=True)
                encrypt_file = st.checkbox("Encrypt if sensitive", value=False)
            with col2:
                notify_admin = st.checkbox("Notify admin if high risk", value=True)
                require_approval = st.checkbox("Require approval if risky", value=True)
        
        if st.button("Upload & Scan", type="primary", key="upload_button"):
            # Save file
            upload_dir = Path("uploads/user_uploads")
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = upload_dir / f"{user['id']}_{int(time.time())}_{uploaded_file.name}"
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Perform DLP scan if available
            risk_score = 0.0
            scan_results = {}
            dlp_findings = []
            
            with st.spinner("Scanning for sensitive data..."):
                if HAS_DLP_MANAGER and dlp_manager:
                    context = {
                        'ip_address': _get_client_ip(),
                        'user_agent': _get_user_agent(),
                        'action_type': 'file_upload'
                    }
                    
                    try:
                        scan_results = dlp_manager.scan_file(str(file_path), user['id'], context)
                        dlp_action = scan_results.get('dlp_action', {'action': 'allow', 'reason': 'No action'})
                        risk_score = scan_results.get('risk_score', 0)
                        
                        if 'indian_detections' in scan_results:
                            for pattern, details in scan_results['indian_detections'].items():
                                if details.get('count', 0) > 0:
                                    dlp_findings.append(f"{pattern}: {details.get('count')} instances")
                        
                        if 'detections' in scan_results:
                            for detection in scan_results['detections']:
                                if detection.get('count', 0) > 0:
                                    dlp_findings.append(f"{detection.get('type', 'Unknown')}: {detection.get('count')} instances")
                        
                        if dlp_action.get('action') == 'block':
                            db_manager.save_file_record(
                                user_id=user['id'],
                                filename=uploaded_file.name,
                                filepath="BLOCKED",
                                file_type=uploaded_file.type,
                                file_size=uploaded_file.size,
                                risk_score=risk_score,
                                scan_result=scan_results,
                                approval_status='blocked',
                                dlp_action=dlp_action.get('action'),
                                dlp_reason=dlp_action.get('reason')
                            )
                            
                            if notify_admin:
                                user_info = {
                                    'id': user['id'],
                                    'username': user['username'],
                                    'email': user.get('email', ''),
                                    'full_name': user.get('full_name', user['username'])
                                }
                                
                                file_info = {
                                    'filename': uploaded_file.name,
                                    'size': uploaded_file.size,
                                    'file_type': uploaded_file.type
                                }
                                
                                email_sent = email_system.send_instant_admin_alert(
                                    user_info=user_info,
                                    file_info=file_info,
                                    risk_score=risk_score,
                                    dlp_findings=dlp_findings
                                )
                                
                                if email_sent:
                                    st.success("📧 Admin alerted immediately")
                                else:
                                    st.warning("⚠️ Admin alert failed - check email config")
                                
                                user_warning_sent = email_system.send_user_warning(
                                    user_info=user_info,
                                    file_info=file_info,
                                    risk_score=risk_score,
                                    reason=dlp_action.get('reason', 'File contains sensitive information')
                                )
                                
                                if user_warning_sent:
                                    st.info("📧 Warning email sent to your registered email")
                            
                            try:
                                os.remove(file_path)
                            except:
                                pass
                            
                            st.error(f"🚫 Upload blocked: {dlp_action.get('reason')}")
                            return
                    except Exception as e:
                        st.warning(f"DLP scan failed: {e}")
                        scan_results = scanner.scan_file(str(file_path))
                        risk_score = scan_results.get('risk_score', 0.5)
                
                else:
                    try:
                        scan_results = scanner.scan_file(str(file_path))
                        risk_score = scan_results.get('risk_score', 0)
                        
                        if 'indian_detections' in scan_results:
                            for pattern, details in scan_results['indian_detections'].items():
                                if details.get('count', 0) > 0:
                                    dlp_findings.append(f"{pattern}: {details.get('count')} instances")
                        
                        if 'detections' in scan_results:
                            for detection in scan_results['detections']:
                                if detection.get('count', 0) > 0:
                                    dlp_findings.append(f"{detection.get('type', 'Unknown')}: {detection.get('count')} instances")
                    except Exception as e:
                        st.warning(f"Basic scan failed: {e}")
                        risk_score = 0.5
            
            if risk_score >= 0.7:
                approval_status = 'pending'
            elif risk_score >= 0.4:
                approval_status = 'pending'
            else:
                approval_status = 'approved'
            
            file_id = db_manager.save_file_record(
                user_id=user['id'],
                filename=uploaded_file.name,
                filepath=str(file_path),
                file_type=uploaded_file.type,
                file_size=uploaded_file.size,
                risk_score=risk_score,
                scan_result=scan_results,
                approval_status=approval_status,
                dlp_action=scan_results.get('dlp_action', {}).get('action') if isinstance(scan_results.get('dlp_action'), dict) else None,
                dlp_reason=scan_results.get('dlp_action', {}).get('reason') if isinstance(scan_results.get('dlp_action'), dict) else None
            )
            
            if file_id > 0:
                auth_system.update_user_upload_history(user['id'], risk_score, dlp_action if 'dlp_action' in locals() else None)
            
            if file_id and file_id > 0:
                if risk_score >= 0.4 and notify_admin:
                    user_info = {
                        'id': user['id'],
                        'username': user['username'],
                        'email': user.get('email', ''),
                        'full_name': user.get('full_name', user['username'])
                    }
                    
                    file_info = {
                        'filename': uploaded_file.name,
                        'size': uploaded_file.size,
                        'file_type': uploaded_file.type
                    }
                    
                    email_sent = email_system.send_instant_admin_alert(
                        user_info=user_info,
                        file_info=file_info,
                        risk_score=risk_score,
                        dlp_findings=dlp_findings
                    )
                    
                    if email_sent:
                        st.success("📧 Admin alerted about this upload")
                    else:
                        st.warning("⚠️ Could not send admin alert - check email config")
                    
                    if risk_score >= 0.7:
                        user_warning_sent = email_system.send_user_warning(
                            user_info=user_info,
                            file_info=file_info,
                            risk_score=risk_score,
                            reason=f"Your file contains sensitive information (Risk Score: {risk_score:.2%})"
                        )
                        
                        if user_warning_sent:
                            st.info("📧 Warning email sent to your registered email")
                
                db_manager.log_activity(
                    user['id'], 'file_upload',
                    f'Uploaded file: {uploaded_file.name} (Risk: {risk_score:.2%})',
                    ip_address=_get_client_ip(),
                    user_agent=_get_user_agent(),
                    risk_score=risk_score
                )
                
                if approval_status == 'pending':
                    db_manager.create_approval_request({
                        'file_id': file_id,
                        'user_id': user['id'],
                        'risk_level': 'high' if risk_score >= 0.7 else 'medium',
                        'scan_summary': scan_results,
                        'status': 'pending'
                    })
                
                if HAS_PERSONA_DETECTOR and persona_detector:
                    context = {
                        'ip_address': _get_client_ip(),
                        'user_agent': _get_user_agent(),
                        'action_type': 'file_upload',
                        'file_name': uploaded_file.name,
                        'risk_score': risk_score,
                        'file_id': file_id
                    }
                    try:
                        persona_detector.detect_persona_anomaly(user['id'], context)
                    except Exception as e:
                        pass
                
                if ai_agent:
                    with st.spinner("🤖 AI Agent is reviewing your file..."):
                        try:
                            results = ai_agent.scan_and_process_pending_files()
                            for approved in results.get('auto_approved', []):
                                if approved['file_id'] == file_id:
                                    st.success(f"✅ {approved['reason']}")
                                    approval_status = 'approved'
                                    
                                    if user.get('email'):
                                        email_system.send_file_approved_notification(
                                            user_info=user_info,
                                            file_info=file_info,
                                            notes=approved.get('reason', 'File approved by AI Agent')
                                        )
                                    break
                            for rejected in results.get('auto_rejected', []):
                                if rejected['file_id'] == file_id:
                                    st.error(f"❌ {rejected['reason']}")
                                    approval_status = 'rejected'
                                    
                                    if user.get('email'):
                                        email_system.send_file_rejected_notification(
                                            user_info=user_info,
                                            file_info=file_info,
                                            reason=rejected.get('reason', 'File rejected by AI Agent')
                                        )
                                    break
                        except Exception as e:
                            st.info("AI Agent will process your file shortly.")
                
                st.session_state['upload_complete'] = True
                st.session_state['last_file_id'] = file_id
                st.session_state.refresh_dashboard = True
                
                if approval_status == 'rejected':
                    st.error(f"⚠️ File rejected by AI Agent! Risk score: {risk_score:.2%}")
                elif risk_score > 0.7:
                    st.error(f"⚠️ High risk detected! Risk score: {risk_score:.2%}")
                    st.info("File requires admin approval. Admin has been notified via email.")
                elif risk_score > 0.4:
                    st.warning(f"📋 Medium risk detected. Risk score: {risk_score:.2%}")
                    st.info("File is under review. Admin has been notified.")
                else:
                    st.success(f"✅ File uploaded successfully! Risk score: {risk_score:.2%}")
                
                st.rerun()
            else:
                st.error("❌ Failed to save file record to database")

def _render_user_files_tab(user):
    """Render user files tab - Shows all uploaded files"""
    st.subheader("📋 My Uploaded Files")
    
    files = db_manager.get_user_files(user['id'])
    
    if files and len(files) > 0:
        total = len(files)
        approved = sum(1 for f in files if f.get('approval_status') == 'approved')
        pending = sum(1 for f in files if f.get('approval_status') == 'pending')
        rejected = sum(1 for f in files if f.get('approval_status') == 'rejected')
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📁 Total Files", total)
        with col2:
            st.metric("✅ Approved", approved)
        with col3:
            st.metric("⏳ Pending", pending)
        with col4:
            st.metric("❌ Rejected", rejected)
        
        st.markdown("---")
        
        data = []
        for file in files:
            risk_score = file.get('risk_score', 0)
            if risk_score >= 0.7:
                risk_display = f"🔴 {risk_score:.2%}"
            elif risk_score >= 0.4:
                risk_display = f"🟡 {risk_score:.2%}"
            else:
                risk_display = f"🟢 {risk_score:.2%}"
            
            status = file.get('approval_status', 'pending')
            status_display = {
                'approved': '✅ Approved',
                'pending': '⏳ Pending',
                'rejected': '❌ Rejected',
                'blocked': '🚫 Blocked'
            }.get(status, status)
            
            uploaded_at = file.get('uploaded_at', '')
            if isinstance(uploaded_at, str) and len(uploaded_at) > 16:
                uploaded_at = uploaded_at[:16]
            
            data.append({
                "File Name": file.get('filename', 'Unknown'),
                "Uploaded": uploaded_at,
                "Risk": risk_display,
                "Status": status_display,
                "Size": f"{file.get('file_size', 0) / 1024:.1f} KB"
            })
        
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("📭 You haven't uploaded any files yet.")
        if st.button("📤 Upload Your First File"):
            st.session_state.user_tab = 'upload'
            st.rerun()

def _render_user_security_tab(user):
    """Render user security tab"""
    st.subheader("🛡️ Your Security Status")
    
    if HAS_PERSONA_DETECTOR and hasattr(db_manager, 'get_user_risk_summary'):
        try:
            risk_summary = db_manager.get_user_risk_summary(user['id'])
            if risk_summary:
                risk_score = risk_summary.get('persona_risk_score', 0)
                
                if risk_score >= 0.7:
                    st.error(f"""
                    🔴 **HIGH RISK PROFILE** ({risk_score:.2%})
                    
                    Your behavior patterns indicate significant deviations from your normal activity.
                    
                    **Recommended Actions:**
                    1. Change your password immediately
                    2. Review your recent activity
                    3. Contact security if you notice suspicious activity
                    """)
                elif risk_score >= 0.4:
                    st.warning(f"""
                    🟡 **MEDIUM RISK PROFILE** ({risk_score:.2%})
                    
                    Some unusual patterns have been detected in your activity.
                    
                    **Review these areas:**
                    1. Check login locations
                    2. Review file upload times
                    3. Verify device usage patterns
                    """)
                else:
                    st.success(f"""
                    🟢 **LOW RISK PROFILE** ({risk_score:.2%})
                    
                    Your activity patterns appear normal and consistent.
                    
                    **Keep up the good security practices!**
                    """)
                
                if hasattr(db_manager, 'get_dlp_violations'):
                    try:
                        dlp_violations = db_manager.get_dlp_violations(user_id=user['id'], days=30)
                        if dlp_violations:
                            st.subheader("Recent DLP Violations")
                            for idx, violation in enumerate(dlp_violations[:3]):
                                severity = violation.get('severity', 'medium')
                                severity_colors = {
                                    'critical': '#dc2626',
                                    'high': '#ea580c',
                                    'medium': '#d97706',
                                    'low': '#059669'
                                }
                                severity_color = severity_colors.get(severity, '#d97706')
                                
                                st.markdown(f"""
                                <div style="background: rgba(30, 41, 59, 0.8); padding: 12px; border-radius: 8px; 
                                            border-left: 4px solid {severity_color}; margin: 8px 0;">
                                    <strong>{violation.get('violation_type', 'Violation').replace('_', ' ').title()}</strong>
                                    <br>
                                    <small>File: {violation.get('filename', 'Unknown')} | 
                                           Action: {violation.get('action_taken', 'Unknown')}</small>
                                </div>
                                """, unsafe_allow_html=True)
                    except Exception as e:
                        pass
        except Exception as e:
            st.info("Security status information is currently unavailable.")
    else:
        st.info("Persona detection is not enabled. Contact your administrator for security status.")

def _render_admin_overview(stats):
    """Render admin overview tab"""
    col1, col2 = st.columns(2)
    
    with col1:
        if hasattr(db_manager, 'get_risk_distribution'):
            try:
                risk_data = db_manager.get_risk_distribution()
                if risk_data and len(risk_data) > 0:
                    df = pd.DataFrame(risk_data)
                    fig = px.pie(df, values='count', names='risk_level',
                                title='File Risk Distribution',
                                color='risk_level',
                                color_discrete_map={
                                    'low': '#10b981',
                                    'medium': '#f59e0b',
                                    'high': '#ef4444'
                                })
                    st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.info("Risk distribution data not available")
    
    with col2:
        if hasattr(db_manager, 'get_upload_trends'):
            try:
                trend_data = db_manager.get_upload_trends(7)
                if trend_data and len(trend_data) > 0:
                    df = pd.DataFrame(trend_data)
                    if 'date' in df.columns:
                        df['date'] = pd.to_datetime(df['date'])
                        fig = px.line(df, x='date', y='count',
                                     title='Uploads (Last 7 Days)',
                                     labels={'value': 'Count', 'variable': 'Type'},
                                     color_discrete_sequence=['#3b82f6'])
                        st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.info("Upload trend data not available")
    
    st.subheader("🔴 Recent Security Events")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if hasattr(db_manager, 'get_all_incidents'):
            try:
                incidents = db_manager.get_all_incidents(limit=5, status='open')
                if incidents:
                    critical_incidents = [i for i in incidents if i.get('severity') in ['critical', 'high']]
                    
                    if critical_incidents:
                        for incident in critical_incidents[:3]:
                            severity_color = '#dc3545' if incident.get('severity') == 'critical' else '#fd7e14'
                            st.markdown(f"""
                            <div style="background: rgba(220, 53, 69, 0.1); padding: 12px; border-radius: 8px; 
                                        border-left: 4px solid {severity_color}; margin: 8px 0;">
                                <strong>{incident.get('incident_type', 'Unknown')}</strong><br>
                                <small>User: {incident.get('username', 'Unknown')} | 
                                       Severity: {incident.get('severity', 'unknown')}</small><br>
                                <span style="font-size: 0.9em;">{incident.get('description', 'No description')[:100]}...</span>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No critical incidents")
                else:
                    st.info("No open incidents")
            except Exception as e:
                st.info("Incident data not available")
    
    with col2:
        if hasattr(db_manager, 'get_dlp_violations'):
            try:
                violations = db_manager.get_dlp_violations(days=1, limit=3)
                if violations:
                    for violation in violations:
                        severity = violation.get('severity', 'medium')
                        severity_color = '#dc3545' if severity == 'critical' else '#fd7e14' if severity == 'high' else '#ffc107'
                        st.markdown(f"""
                        <div style="background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; 
                                    border-left: 4px solid {severity_color}; margin: 8px 0;">
                            <strong>DLP Violation: {violation.get('violation_type', 'Unknown').replace('_', ' ').title()}</strong><br>
                            <small>User: {violation.get('username', 'Unknown')} | 
                                   Action: {violation.get('action_taken', 'Unknown')}</small><br>
                            <span style="font-size: 0.9em;">File: {violation.get('filename', 'Unknown')}</span>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("No DLP violations today")
            except Exception as e:
                st.info("DLP violation data not available")

def _render_persona_detection_tab():
    """Render persona detection tab"""
    st.subheader("👤 Persona Detection & Behavioral Analysis")
    
    if not HAS_PERSONA_DETECTOR:
        st.info("Persona detector module is not available. Persona detection features are disabled.")
        return
    
    st.write("### User Persona Profiles")
    
    if hasattr(db_manager, 'get_all_persona_profiles'):
        try:
            persona_profiles = db_manager.get_all_persona_profiles()
            
            if persona_profiles:
                col1, col2 = st.columns(2)
                with col1:
                    risk_filter = st.selectbox("Filter by Risk", ["All", "High (≥0.7)", "Medium (0.4-0.7)", "Low (<0.4)"])
                
                with col2:
                    all_users = []
                    if hasattr(db_manager, 'get_all_users'):
                        try:
                            all_users = db_manager.get_all_users()
                        except:
                            all_users = []
                    user_filter = st.selectbox("Filter by User", ["All Users"] + all_users)
                
                filtered_profiles = persona_profiles
                
                if risk_filter != "All":
                    min_risk = 0.7 if "High" in risk_filter else 0.4 if "Medium" in risk_filter else 0
                    max_risk = 1.0 if "High" in risk_filter else 0.7 if "Medium" in risk_filter else 0.4
                    filtered_profiles = [p for p in filtered_profiles if min_risk <= p.get('risk_score', 0) < max_risk]
                
                if user_filter != "All Users":
                    filtered_profiles = [p for p in filtered_profiles if p.get('username') == user_filter]
                
                for idx, profile in enumerate(filtered_profiles):
                    _render_persona_profile_card(profile, idx)
                
                st.write("### 📈 Statistics")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Profiles", len(persona_profiles))
                
                with col2:
                    high_risk = sum(1 for p in persona_profiles if p.get('risk_score', 0) >= 0.7)
                    st.metric("High Risk Profiles", high_risk)
                
                with col3:
                    avg_risk = sum(p.get('risk_score', 0) for p in persona_profiles) / len(persona_profiles) if persona_profiles else 0
                    st.metric("Average Risk", f"{avg_risk:.2%}")
            
            else:
                st.info("No persona profiles available. Profiles are built automatically as users interact with the system.")
        except Exception as e:
            st.info("Persona profile data is currently unavailable.")
    else:
        st.info("Persona profiles feature not available in database.")

def _render_persona_profile_card(profile, idx):
    """Render a persona profile card"""
    risk_score = profile.get('risk_score', 0)
    
    if risk_score >= 0.7:
        risk_class = "high"
        risk_color = "#ef4444"
        risk_label = "🔴 HIGH"
    elif risk_score >= 0.4:
        risk_class = "medium"
        risk_color = "#f59e0b"
        risk_label = "🟡 MEDIUM"
    else:
        risk_class = "low"
        risk_color = "#10b981"
        risk_label = "🟢 LOW"
    
    profile_data = profile.get('profile_data', {})
    if isinstance(profile_data, str):
        try:
            profile_data = json.loads(profile_data)
        except:
            profile_data = {}
    
    user_id = profile.get('user_id', 'unknown')
    username = profile.get('username', 'Unknown')
    
    with st.expander(f"{username} - {risk_label} Risk ({risk_score:.2%})", key=f"persona_{user_id}_{idx}"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**User Information:**")
            st.write(f"Email: {profile.get('email', 'N/A')}")
            st.write(f"Role: {profile.get('role', 'N/A')}")
            st.write(f"Last Updated: {profile.get('last_updated', 'N/A')}")
        
        with col2:
            st.write("**Behavioral Patterns:**")
            if profile_data:
                login_pattern = profile_data.get('login_time_pattern', {})
                st.write(f"Typical Login Hours: {login_pattern.get('typical_hours', 'Unknown')}")
                
                upload_pattern = profile_data.get('upload_pattern', {})
                st.write(f"Avg Uploads/Day: {upload_pattern.get('avg_per_day', 0):.1f}")
                
                common_ips = profile_data.get('common_ips', [])
                st.write(f"Common IPs: {len(common_ips)}")
            else:
                st.write("No detailed profile data available")
        
        st.markdown(f"""
        <div style="margin: 10px 0;">
            <div style="display: flex; justify-content: space-between;">
                <span>Risk Score:</span>
                <span style="color: {risk_color}; font-weight: bold;">{risk_score:.2%}</span>
            </div>
            <div class="risk-progress">
                <div class="risk-progress-fill risk-progress-{risk_class}" style="width: {risk_score * 100}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Rebuild Profile", key=f"rebuild_{user_id}_{idx}", use_container_width=True):
                if persona_detector:
                    try:
                        persona_detector.build_persona_profile(profile['user_id'])
                        st.success("Profile rebuild requested!")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error("Failed to rebuild profile")
        
        with col2:
            if st.button("View Details", key=f"details_{user_id}_{idx}", use_container_width=True):
                st.session_state['selected_user_id'] = profile['user_id']
                st.rerun()

def _render_dlp_management_tab():
    """Render DLP management tab"""
    st.subheader("🛡️ Data Leakage Prevention (DLP)")
    
    if not HAS_DLP_MANAGER:
        st.info("DLP manager module is not available. DLP features are disabled.")
        return
    
    st.write("### Recent DLP Violations")
    
    if hasattr(db_manager, 'get_dlp_violations'):
        try:
            violations = db_manager.get_dlp_violations(days=7, limit=20)
            
            if violations:
                col1, col2 = st.columns(2)
                with col1:
                    severity_filter = st.selectbox("Filter by Severity", ["All", "Critical", "High", "Medium", "Low"])
                
                with col2:
                    action_filter = st.selectbox("Filter by Action", ["All", "Block", "Encrypt", "Warn", "Allow"])
                
                filtered_violations = violations
                
                if severity_filter != "All":
                    filtered_violations = [v for v in filtered_violations if v.get('severity') == severity_filter.lower()]
                
                if action_filter != "All":
                    filtered_violations = [v for v in filtered_violations if v.get('action_taken') == action_filter.lower()]
                
                for idx, violation in enumerate(filtered_violations):
                    _render_dlp_violation_card(violation, idx)
                
                st.write("### 📊 DLP Statistics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    total_violations = len(violations)
                    st.metric("Total Violations", total_violations)
                
                with col2:
                    blocked = sum(1 for v in violations if v.get('action_taken') == 'block')
                    st.metric("Blocked Files", blocked)
                
                with col3:
                    encrypted = sum(1 for v in violations if v.get('action_taken') == 'encrypt')
                    st.metric("Encrypted Files", encrypted)
                
                with col4:
                    critical = sum(1 for v in violations if v.get('severity') == 'critical')
                    st.metric("Critical Violations", critical)
            
            else:
                st.info("No DLP violations detected in the last 7 days.")
        except Exception as e:
            st.info("DLP violation data is currently unavailable.")
    else:
        st.info("DLP violations feature not available in database.")

def _render_dlp_violation_card(violation, idx):
    """Render a DLP violation card"""
    severity = violation.get('severity', 'medium')
    action = violation.get('action_taken', 'unknown')
    
    severity_colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#d97706',
        'low': '#059669'
    }
    
    action_icons = {
        'block': '🚫',
        'encrypt': '🔐',
        'warn': '⚠️',
        'allow': '✅'
    }
    
    severity_color = severity_colors.get(severity, '#d97706')
    action_icon = action_icons.get(action, '📝')
    
    st.markdown(f"""
    <div style="background: rgba(30, 41, 59, 0.8); padding: 12px; border-radius: 8px; 
                border-left: 4px solid {severity_color}; margin: 8px 0;">
        <div style="display: flex; justify-content: space-between; align-items: start;">
            <div>
                <strong>{violation.get('violation_type', 'Violation').replace('_', ' ').title()}</strong>
                <br>
                <small>User: {violation.get('username', 'Unknown')} | File: {violation.get('filename', 'Unknown')}</small>
            </div>
            <div style="text-align: right;">
                <span style="color: {severity_color}; font-weight: bold;">{severity.upper()}</span>
                <br>
                <small>{action_icon} {action.upper()}</small>
            </div>
        </div>
        
        <div style="margin-top: 8px; font-size: 0.9em;">
            <small>Pattern: {violation.get('detected_pattern', 'Unknown')}</small>
            <br>
            <small>Time: {violation.get('timestamp', 'Unknown')}</small>
        </div>
    </div>
    """, unsafe_allow_html=True)

def _render_file_scanner_tab():
    """Render file scanner tab"""
    st.subheader("📁 Manual File Scanner")
    
    uploaded_file = st.file_uploader("Upload file for scanning", 
                                   type=['pdf', 'docx', 'csv', 'txt', 'xlsx', 'xls'])
    
    if uploaded_file:
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        
        file_path = upload_dir / uploaded_file.name
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        with st.spinner("Scanning file for data leakage..."):
            scan_results = scanner.scan_file(str(file_path))
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Scan Results")
            risk_score = scan_results.get('risk_score', 0)
            pii_count = scan_results.get('pii_count', 0)
            keyword_count = scan_results.get('keyword_count', 0)
            
            st.metric("Risk Score", f"{risk_score:.2%}")
            st.metric("PII Found", pii_count)
            st.metric("Keywords Found", keyword_count)
            
            if 'indian_detections' in scan_results:
                indian_detections = scan_results.get('indian_detections', {})
                if indian_detections:
                    st.write("**Indian Patterns Detected:**")
                    for pattern, details in indian_detections.items():
                        st.write(f"- {pattern}: {details.get('count', 0)} instances")
        
        with col2:
            st.subheader("Details")
            detections = scan_results.get('detections', [])
            if detections:
                for detection in detections:
                    st.write(f"**{detection.get('type', 'Unknown')}**: {detection.get('count', 0)} instances")
            else:
                st.success("No sensitive data detected")
        
        if hasattr(scanner, 'generate_scan_report'):
            report = scanner.generate_scan_report(scan_results)
            with st.expander("View Detailed Report"):
                st.text(report)
        
        if HAS_DLP_MANAGER and dlp_manager:
            user = auth_system.get_current_user()
            if user:
                context = {
                    'ip_address': _get_client_ip(),
                    'user_agent': _get_user_agent(),
                    'action_type': 'manual_scan'
                }
                
                try:
                    dlp_scan = dlp_manager.scan_file(str(file_path), user['id'], context)
                    dlp_action = dlp_scan.get('dlp_action', {})
                    
                    if dlp_action.get('action') != 'allow':
                        st.warning(f"**DLP Action Recommended:** {dlp_action.get('action', 'Unknown').upper()}")
                        st.write(f"**Reason:** {dlp_action.get('reason', 'No reason provided')}")
                except Exception as e:
                    st.warning(f"DLP scan failed: {e}")
        
        if st.button("Save Scan Result"):
            user = auth_system.get_current_user()
            if user and hasattr(db_manager, 'save_file_record'):
                file_id = db_manager.save_file_record(
                    user['id'], uploaded_file.name, str(file_path),
                    uploaded_file.type, uploaded_file.size,
                    risk_score, json.dumps(scan_results)
                )
                if file_id > 0:
                    st.success(f"Scan result saved (File ID: {file_id})")
                else:
                    st.error("Failed to save scan result")

def _render_alerts_tab():
    """Render alerts tab"""
    st.subheader("🚨 Security Alerts")
    
    if hasattr(db_manager, 'get_alerts'):
        try:
            alerts = db_manager.get_alerts(limit=50)
            
            if alerts:
                col1, col2 = st.columns(2)
                with col1:
                    alert_type = st.selectbox("Filter by Type", ["All", "dlp_violation", "approval_update", "persona_anomaly", "security_incident"])
                
                with col2:
                    severity_filter = st.selectbox("Filter by Severity", ["All", "critical", "high", "medium", "low"])
                
                filtered_alerts = alerts
                
                if alert_type != "All":
                    filtered_alerts = [a for a in filtered_alerts if a.get('alert_type') == alert_type]
                
                if severity_filter != "All":
                    filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]
                
                for alert in filtered_alerts:
                    severity = alert.get('severity', 'medium')
                    severity_colors = {
                        'critical': '#dc2626',
                        'high': '#ea580c',
                        'medium': '#d97706',
                        'low': '#059669'
                    }
                    severity_color = severity_colors.get(severity, '#d97706')
                    
                    st.markdown(f"""
                    <div style="background: rgba(30, 41, 59, 0.8); padding: 12px; border-radius: 8px; 
                                border-left: 4px solid {severity_color}; margin: 8px 0;">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div>
                                <strong>{alert.get('title', 'Alert')}</strong>
                                <br>
                                <small>Type: {alert.get('alert_type', 'unknown')} | 
                                       User: {alert.get('username', 'System')} | 
                                       Time: {alert.get('created_at', 'Unknown')}</small>
                            </div>
                            <div style="text-align: right;">
                                <span style="color: {severity_color}; font-weight: bold;">{severity.upper()}</span>
                            </div>
                        </div>
                        
                        <div style="margin-top: 8px;">
                            {alert.get('message', 'No message')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                if st.button("Clear All Read Alerts"):
                    st.info("Alert clearing feature not implemented")
            else:
                st.info("✅ No alerts")
        except Exception as e:
            st.info("Alert data not available")
    else:
        st.info("Alerts feature not available")

def _render_settings_tab(user):
    """Render settings tab"""
    st.subheader("⚙️ System Configuration")
    
    with st.expander("🛡️ Security Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            risk_threshold = st.slider(
                "High Risk Threshold",
                0.0, 1.0, 0.7, 0.05,
                help="Files above this score require admin approval"
            )
            
            persona_enabled = st.checkbox(
                "Enable Persona Detection",
                value=True,
                help="Monitor user behavior for anomalies"
            )
            
            dlp_enabled = st.checkbox(
                "Enable DLP Scanning",
                value=True,
                help="Scan files for sensitive data"
            )
        
        with col2:
            auto_approve = st.checkbox(
                "Auto-approve low risk files",
                value=True,
                help="Files below threshold are automatically approved"
            )
            
            email_alerts = st.checkbox(
                "Email Alerts",
                value=True,
                help="Send email alerts for security incidents"
            )
            
            encryption_enabled = st.checkbox(
                "Enable Encryption",
                value=False,
                help="Encrypt sensitive files automatically"
            )
        
        if st.button("Save Security Settings", type="primary"):
            settings_to_save = [
                ('high_risk_threshold', str(risk_threshold)),
                ('enable_persona_detection', '1' if persona_enabled else '0'),
                ('dlp_enabled', '1' if dlp_enabled else '0'),
                ('auto_approve_low_risk', '1' if auto_approve else '0'),
                ('email_alerts_enabled', '1' if email_alerts else '0'),
                ('encryption_enabled', '1' if encryption_enabled else '0')
            ]
            
            try:
                with db_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    for key, value in settings_to_save:
                        cursor.execute('''
                            INSERT OR REPLACE INTO settings (key, value, updated_at)
                            VALUES (?, ?, datetime('now'))
                        ''', (key, value))
                    st.success("✅ Security settings saved!")
            except Exception as e:
                st.error(f"❌ Failed to save settings: {e}")
    
    with st.expander("📧 Email Configuration", expanded=True):
        st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem;">
            <h4 style="color: #f8fafc; margin-top: 0;">SMTP Server Settings</h4>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            smtp_host = st.text_input("SMTP Host", value="smtp.gmail.com", key="smtp_host")
            smtp_port = st.number_input("SMTP Port", value=587, min_value=1, max_value=65535, key="smtp_port")
            smtp_username = st.text_input("SMTP Username", value="pthombre200@gmail.com", key="smtp_username")
        
        with col2:
            smtp_password = st.text_input("SMTP Password", type="password", value="szkj oghq qdaw bffu", key="smtp_password")
            use_tls = st.checkbox("Use TLS (Recommended)", value=True, key="use_tls")
            use_ssl = st.checkbox("Use SSL", value=False, key="use_ssl")
        
        st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
            <h4 style="color: #f8fafc; margin-top: 0;">Notification Settings</h4>
        </div>
        """, unsafe_allow_html=True)
        
        col3, col4 = st.columns(2)
        
        with col3:
            admin_email = st.text_input("Admin Email", value="pthombre200@gmail.com", key="admin_email")
            from_email = st.text_input("From Email", value="pthombre200@gmail.com", key="from_email")
        
        with col4:
            security_team = st.text_area("Security Team Emails", value="pthombre200@gmail.com", key="security_team", help="Comma-separated list of email addresses")
            email_prefix = st.text_input("Email Subject Prefix", value="[SECURITY ALERT]", key="email_prefix")
        
        col_save1, col_save2 = st.columns([1, 3])
        with col_save1:
            if st.button("💾 Save Email Settings", type="primary", use_container_width=True):
                settings_to_save = [
                    ('smtp_host', smtp_host), ('smtp_port', str(smtp_port)),
                    ('smtp_username', smtp_username), ('smtp_password', smtp_password),
                    ('smtp_use_tls', '1' if use_tls else '0'), ('smtp_use_ssl', '1' if use_ssl else '0'),
                    ('admin_email', admin_email), ('from_email', from_email),
                    ('security_team_emails', security_team), ('email_subject_prefix', email_prefix)
                ]
                
                try:
                    with db_manager.get_connection() as conn:
                        cursor = conn.cursor()
                        for key, value in settings_to_save:
                            cursor.execute('''INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))''', (key, value))
                    st.success("✅ Email settings saved successfully!")
                except Exception as e:
                    st.error(f"❌ Failed to save settings: {e}")
        
        st.markdown("---")
        st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
            <h4 style="color: #f8fafc; margin-top: 0;">📧 Test Email System</h4>
        </div>
        """, unsafe_allow_html=True)
        
        test_recipient = st.text_input("Test Email Recipient", value=admin_email, key="test_recipient_email")
        
        col_test1, col_test2, col_test3 = st.columns(3)
        
        with col_test1:
            if st.button("📧 Send Test Email", use_container_width=True, key="send_test_email_btn"):
                if not smtp_username or not smtp_password:
                    st.error("❌ Please enter SMTP Username and Password first")
                else:
                    with st.spinner("📨 Sending test email..."):
                        try:
                            import smtplib
                            from email.message import EmailMessage
                            from datetime import datetime
                            
                            msg = EmailMessage()
                            msg.set_content(f"""Test email from Secure Persona Detection & DLP System.\n\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nSMTP Host: {smtp_host}\nSMTP Port: {smtp_port}\nUsername: {smtp_username}""")
                            msg['Subject'] = f"{email_prefix} Test Email - Secure DLP System"
                            msg['From'] = from_email
                            msg['To'] = test_recipient
                            
                            if use_ssl:
                                server = smtplib.SMTP_SSL(smtp_host, smtp_port)
                            else:
                                server = smtplib.SMTP(smtp_host, smtp_port)
                                if use_tls:
                                    server.starttls()
                            
                            server.login(smtp_username, smtp_password)
                            server.send_message(msg)
                            server.quit()
                            
                            st.success(f"✅ Test email successfully sent to {test_recipient}!")
                        except Exception as e:
                            st.error(f"❌ Failed to send email: {str(e)}")
        
        with col_test2:
            if st.button("🔌 Test Connection", use_container_width=True, key="test_connection_btn"):
                if not smtp_username or not smtp_password:
                    st.error("❌ Please enter SMTP Username and Password first")
                else:
                    with st.spinner("🔌 Testing connection..."):
                        try:
                            import smtplib
                            if use_ssl:
                                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
                            else:
                                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                                if use_tls:
                                    server.starttls()
                            server.login(smtp_username, smtp_password)
                            server.quit()
                            st.success(f"✅ Connection successful!")
                        except Exception as e:
                            st.error(f"❌ Connection failed: {str(e)}")
        
        with col_test3:
            if st.button("📋 View Email Logs", use_container_width=True, key="view_email_logs"):
                try:
                    with db_manager.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT id, alert_type, recipient, status, sent_at, created_at FROM email_alerts ORDER BY created_at DESC LIMIT 10')
                        logs = cursor.fetchall()
                        if logs:
                            for log in logs:
                                status_icon = "✅" if log['status'] == 'sent' else "❌" if log['status'] == 'failed' else "⏳"
                                st.markdown(f"<div style='background:#1e293b;padding:8px;border-radius:5px;margin:5px 0;'><small>{status_icon} <strong>{log['alert_type']}</strong> → {log['recipient']}<br>Status: {log['status']}</small></div>", unsafe_allow_html=True)
                        else:
                            st.info("No email logs found")
                except Exception as e:
                    st.info("Email logging not available")
        
        with st.expander("📧 Email Alert Types", expanded=False):
            st.markdown("""
            ### Configured Email Alerts:
            | Alert Type | Recipient | Trigger Condition |
            |------------|-----------|-------------------|
            | 🚨 **Instant Admin Alert** | Admin | High-risk file upload (Risk ≥ 70%) |
            | ⚠️ **User Warning** | User | File blocked due to DLP violation |
            | ✅ **File Approved** | User | File approved by Admin/AI Agent |
            | ❌ **File Rejected** | User | File rejected with reason |
            """)
    
    with st.expander("🔔 Notification Preferences", expanded=False):
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (user['id'],))
                prefs = cursor.fetchone()
                if not prefs:
                    prefs = {'email_notifications': 1, 'in_app_notifications': 1, 'file_approved': 1, 'file_rejected': 1, 'dlp_alert': 1, 'system_alert': 1}
                else:
                    prefs = dict(prefs)
        except:
            prefs = {'email_notifications': 1, 'in_app_notifications': 1, 'file_approved': 1, 'file_rejected': 1, 'dlp_alert': 1, 'system_alert': 1}
        
        col_notif1, col_notif2 = st.columns(2)
        with col_notif1:
            email_notif = st.checkbox("📧 Email Notifications", value=bool(prefs.get('email_notifications', 1)))
            file_approved_notif = st.checkbox("✅ File Approved", value=bool(prefs.get('file_approved', 1)))
            dlp_alert_notif = st.checkbox("⚠️ DLP Alerts", value=bool(prefs.get('dlp_alert', 1)))
        with col_notif2:
            in_app_notif = st.checkbox("🔔 In-App Notifications", value=bool(prefs.get('in_app_notifications', 1)))
            file_rejected_notif = st.checkbox("❌ File Rejected", value=bool(prefs.get('file_rejected', 1)))
            system_alert_notif = st.checkbox("ℹ️ System Alerts", value=bool(prefs.get('system_alert', 1)))
        
        if st.button("💾 Save Notification Preferences"):
            try:
                with db_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT OR REPLACE INTO notification_preferences (user_id, email_notifications, in_app_notifications, file_approved, file_rejected, dlp_alert, system_alert) VALUES (?, ?, ?, ?, ?, ?, ?)''', (user['id'], 1 if email_notif else 0, 1 if in_app_notif else 0, 1 if file_approved_notif else 0, 1 if file_rejected_notif else 0, 1 if dlp_alert_notif else 0, 1 if system_alert_notif else 0))
                st.success("✅ Notification preferences saved!")
            except Exception as e:
                st.error(f"❌ Failed to save preferences: {e}")

def _render_basic_admin_dashboard(user):
    """Basic admin dashboard fallback when AdminDashboard module is not available"""
    st.markdown('<h1 class="main-header">👑 Admin Security Dashboard</h1>', unsafe_allow_html=True)
    
    stats = {}
    if hasattr(db_manager, 'get_system_stats'):
        try:
            stats = db_manager.get_system_stats()
        except Exception as e:
            stats = {}
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_users = stats.get('total_users', 0)
        admin_users = stats.get('admin_users', 0)
        regular_users = stats.get('regular_users', 0)
        st.metric("👥 Users", total_users, f"{admin_users} admin, {regular_users} regular")
    
    with col2:
        open_incidents = stats.get('open_incidents', 0)
        incidents_by_severity = stats.get('incidents_by_severity', {})
        critical_count = incidents_by_severity.get('critical', 0)
        st.metric("🚨 Open Incidents", open_incidents, f"{critical_count} critical")
    
    with col3:
        total_files = stats.get('total_files', 0)
        high_risk_files = stats.get('high_risk_files', 0)
        st.metric("📁 Files Scanned", total_files, f"{high_risk_files} high risk")
    
    with col4:
        persona_alerts = stats.get('persona_alerts_today', 0)
        dlp_violations = stats.get('dlp_violations_today', 0)
        st.metric("🛡️ Security Events", persona_alerts + dlp_violations, f"{persona_alerts} persona, {dlp_violations} DLP")
    
    st.markdown("---")
    
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["📊 Overview", "👤 Persona Detection", "🛡️ DLP Management", "📋 Approvals", "🤖 AI Agent", "🚨 Alerts", "⚙️ Settings"])
    
    with tab1:
        _render_admin_overview(stats)
    with tab2:
        _render_persona_detection_tab()
    with tab3:
        _render_dlp_management_tab()
    with tab4:
        _render_admin_approval_tab()
    with tab5:
        render_ai_admin_panel(ai_agent, auto_processor)
    with tab6:
        _render_alerts_tab()
    with tab7:
        _render_settings_tab(user)

def _render_basic_user_dashboard(user):
    """User dashboard - Shows files correctly"""
    st.markdown('<h1 class="main-header">👤 User Dashboard</h1>', unsafe_allow_html=True)
    
    # Get files directly from database
    user_files = db_manager.get_user_files(user['id'])
    
    # Calculate stats
    total_files = len(user_files)
    pending_files = sum(1 for f in user_files if f.get('approval_status') == 'pending')
    approved_files = sum(1 for f in user_files if f.get('approval_status') == 'approved')
    rejected_files = sum(1 for f in user_files if f.get('approval_status') == 'rejected')
    high_risk_files = sum(1 for f in user_files if f.get('risk_score', 0) >= 0.7)
    
    # Welcome
    col1, col2 = st.columns([3, 1])
    with col1:
        st.success(f"Welcome back, {user.get('full_name', user.get('username', 'User'))}! 👋")
    with col2:
        if user.get('email'):
            st.info(f"📧 {user.get('email')}")
    
    st.markdown("---")
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("📁 Total Files", total_files)
    with col2:
        st.metric("⏳ Pending", pending_files)
    with col3:
        st.metric("✅ Approved", approved_files)
    with col4:
        st.metric("❌ Rejected", rejected_files)
    with col5:
        st.metric("⚠️ High Risk", high_risk_files)
    
    st.markdown("---")
    
    # Display files
    st.markdown("### 📁 Your Files")
    
    if user_files and len(user_files) > 0:
        for file in user_files:
            risk_score = file.get('risk_score', 0)
            status = file.get('approval_status', 'pending')
            
            if risk_score >= 0.7:
                risk_badge = "🔴 HIGH"
                risk_color = "#ef4444"
            elif risk_score >= 0.4:
                risk_badge = "🟡 MEDIUM"
                risk_color = "#f59e0b"
            else:
                risk_badge = "🟢 LOW"
                risk_color = "#10b981"
            
            if status == 'approved':
                status_badge = "✅ Approved"
                status_color = "#10b981"
            elif status == 'pending':
                status_badge = "⏳ Pending"
                status_color = "#f59e0b"
            elif status == 'rejected':
                status_badge = "❌ Rejected"
                status_color = "#ef4444"
            else:
                status_badge = f"📄 {status}"
                status_color = "#6b7280"
            
            st.markdown(f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid {status_color};">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <div style="flex: 2;"><strong>📄 {file.get('filename', 'Unknown')}</strong></div>
                    <div style="flex: 1;"><span style="background: {risk_color}; padding: 2px 8px; border-radius: 12px; font-size: 0.75em;">{risk_badge}</span></div>
                    <div style="flex: 1;"><span style="color: #94a3b8;">{status_badge}</span></div>
                    <div style="flex: 1;"><span style="color: #94a3b8; font-size: 0.8em;">{file.get('file_size', 0) / 1024:.1f} KB</span></div>
                </div>
                <div style="margin-top: 6px; font-size: 0.75em; color: #64748b;">Uploaded: {str(file.get('uploaded_at', 'Unknown'))[:16]}</div>
            </div>
            """, unsafe_allow_html=True)
        
        if st.button("📋 View All Files in My Files Tab", use_container_width=True):
            st.session_state.user_tab = 'files'
            st.rerun()
    else:
        st.info("📭 No files uploaded yet")
        if st.button("📤 Upload Your First File", use_container_width=True):
            st.session_state.user_tab = 'upload'
            st.rerun()
    
    st.markdown("---")
    
    # Recent Activity
    st.markdown("### 📋 Recent Activity")
    try:
        activities = db_manager.get_user_activities(user['id'], limit=5)
        if activities:
            for act in activities:
                st.caption(f"• {str(act.get('timestamp', ''))[:16]}: {act.get('details', '')[:100]}")
        else:
            st.info("No recent activity")
    except:
        st.info("Activity log unavailable")
    
    # Quick Actions
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📤 Upload", use_container_width=True):
            st.session_state.user_tab = 'upload'
            st.rerun()
    with col2:
        if st.button("📋 My Files", use_container_width=True):
            st.session_state.user_tab = 'files'
            st.rerun()
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

def _get_time_ago_helper(dt):
    """Helper function to get time ago string"""
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} year(s) ago"
    elif diff.days > 30:
        return f"{diff.days // 30} month(s) ago"
    elif diff.days > 0:
        return f"{diff.days} day(s) ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hour(s) ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} minute(s) ago"
    else:
        return "Just now"

def main():
    """Main application entry point with enhanced security features"""
    st.set_page_config(
        page_title="Secure Persona Detection & DLP",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.markdown("""
    <style>
    .stApp { background-color: #0E1117 !important; }
    h1, h2, h3, h4, h5, h6, p, div, span, label { color: #FAFAFA !important; }
    .stButton > button { background-color: #2E86AB; color: white; font-weight: bold; border: none; border-radius: 5px; }
    .stButton > button:hover { background-color: #1a5a7a; }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)
    
    if 'startup_time' not in st.session_state:
        st.session_state.startup_time = datetime.now()
    
    user = auth_system.get_current_user()
    
    if not user:
        login_page()
        return
    
    if HAS_THEME_MANAGER:
        if user.get('role') == 'admin':
            theme_manager.apply_admin_theme()
        else:
            theme_manager.apply_user_theme()
    
    if 'current_tab' not in st.session_state:
        st.session_state.current_tab = 'overview'
    if 'user_tab' not in st.session_state:
        st.session_state.user_tab = 'upload'
    if 'admin_tab' not in st.session_state:
        st.session_state.admin_tab = 'overview'
    
    with st.sidebar:
        st.markdown(f"""
        <div style="background: #1e293b; padding: 1rem; border-radius: 10px; margin-bottom: 1rem;">
            <h4>👋 Welcome, {user.get('username', 'User')}</h4>
            <p><strong>Role:</strong> {user.get('role', 'user').title()}</p>
        </div>
        """, unsafe_allow_html=True)
        
        if HAS_PERSONA_DETECTOR and hasattr(db_manager, 'get_user_risk_summary'):
            try:
                risk_summary = db_manager.get_user_risk_summary(user['id'])
                if risk_summary:
                    risk_score = risk_summary.get('persona_risk_score', 0)
                    risk_level = "High" if risk_score >= 0.7 else "Medium" if risk_score >= 0.4 else "Low"
                    risk_color = "#ef4444" if risk_score >= 0.7 else "#f59e0b" if risk_score >= 0.4 else "#10b981"
                    st.markdown(f"""
                    <div style="background: #1e293b; padding: 1rem; border-radius: 10px; margin-bottom: 1rem;">
                        <h5>🛡️ Security Status</h5>
                        <div>Risk Level: <span style="color: {risk_color}; font-weight: bold;">{risk_level}</span></div>
                        <div>Score: {risk_score:.2%}</div>
                    </div>
                    """, unsafe_allow_html=True)
            except:
                pass
        
        st.markdown("### ⚡ Quick Actions")
        
        if user.get('role') == 'admin':
            for tab_id, label in [('overview', '📊 Overview'), ('persona', '👤 Persona'), ('dlp', '🛡️ DLP'), ('approvals', '📋 Approvals'), ('ai_agent', '🤖 AI Agent'), ('alerts', '🚨 Alerts'), ('settings', '⚙️ Settings')]:
                if st.button(label, key=f"admin_quick_{tab_id}", use_container_width=True):
                    st.session_state.admin_tab = tab_id
                    st.rerun()
        else:
            for tab_id, label in [('upload', '📤 Upload File'), ('files', '📋 My Files'), ('security', '🛡️ Security')]:
                if st.button(label, key=f"user_quick_{tab_id}", use_container_width=True):
                    st.session_state.user_tab = tab_id
                    st.rerun()
        
        st.markdown("---")
        
        # AI Agent Status - ONLY FOR ADMIN
        if user.get('role') == 'admin':
            if auto_processor and auto_processor.is_running:
                st.success("🤖 AI Agent: **ACTIVE**")
                st.caption("Auto-scanning files every 30 seconds")
            else:
                st.warning("🤖 AI Agent: **STOPPED**")
                st.caption("Click 'Start Auto-Processing' in AI Agent tab")
            st.markdown("---")
        
        st.markdown("### ℹ️ System Info")
        st.caption(f"Version: 2.0.0")
        st.caption(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        st.markdown("---")
        st.markdown("### 🔐 Account")
        if st.button("🚪 Logout", key="logout_button", use_container_width=True):
            st.session_state.clear()
            st.rerun()
    
    if user.get('role') == 'admin':
        if 'auto_processor_started' not in st.session_state:
            auto_processor.start_background_processing(30)
            st.session_state.auto_processor_started = True
        
        admin_tabs = st.tabs(["📊 Overview", "👤 Persona", "🛡️ DLP", "📋 Approvals", "🤖 AI Agent", "🚨 Alerts", "⚙️ Settings"])
        tab_mapping = {0: 'overview', 1: 'persona', 2: 'dlp', 3: 'approvals', 4: 'ai_agent', 5: 'alerts', 6: 'settings'}
        current_tab = st.session_state.get('admin_tab', 'overview')
        current_tab_idx = next((idx for idx, name in tab_mapping.items() if name == current_tab), 0)
        
        with admin_tabs[current_tab_idx]:
            if current_tab == 'overview':
                stats = db_manager.get_system_stats() if hasattr(db_manager, 'get_system_stats') else {}
                _render_admin_overview(stats)
            elif current_tab == 'persona':
                _render_persona_detection_tab()
            elif current_tab == 'dlp':
                _render_dlp_management_tab()
            elif current_tab == 'approvals':
                _render_admin_approval_tab()
            elif current_tab == 'ai_agent':
                render_ai_admin_panel(ai_agent, auto_processor)
            elif current_tab == 'alerts':
                _render_alerts_tab()
            elif current_tab == 'settings':
                _render_settings_tab(user)
    else:
        try:
            from app.user_dashboard import UserDashboard
            user_dashboard = UserDashboard(user, auth_system)
            user_dashboard.render()
        except Exception as e:
            _render_basic_user_dashboard(user)
        
        render_chatbot_widget(chatbot)

if __name__ == "__main__":
    for dir_name in ["data", "uploads", "uploads/user_uploads", "logs", "templates", "app/security", "app/services", "app/dashboard", "app/components", "config"]:
        Path(dir_name).mkdir(parents=True, exist_ok=True)
    
    blocked_dir = Path("data/blocked_files")
    blocked_dir.mkdir(parents=True, exist_ok=True)
    
    main()