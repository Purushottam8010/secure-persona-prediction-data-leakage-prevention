# app/dashboard/admin_dashboard.py
import streamlit as st
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import json
import re
from typing import Dict, List, Tuple


class AdminDashboard:
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
        except ImportError:
            self.persona_detector = None
            self.dlp_manager = None
        
    def render(self):
        """Render complete admin dashboard with Persona Detection & DLP"""
        
        # Apply CSS fixes for visibility
        self._apply_css_fixes()
        
        # Header with persona risk indicator
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown('<div class="admin-header">', unsafe_allow_html=True)
            st.title("🛡️ Security Command Center")
            st.caption(f"Admin: {self.user['username']} | Secure Persona Detection & DLP System")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            stats = self.db.get_system_stats()
            persona_alerts = stats.get('persona_alerts_today', 0)
            st.metric("Persona Alerts", persona_alerts, 
                     delta="↑" if persona_alerts > 0 else None,
                     delta_color="inverse")
        
        with col3:
            dlp_violations = stats.get('dlp_violations_today', 0)
            st.metric("DLP Violations", dlp_violations,
                     delta="↑" if dlp_violations > 0 else None,
                     delta_color="inverse")
        
        # Navigation tabs - ADDED PERSONA & DLP TABS
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "📊 Overview", 
            "👤 Persona Detection", 
            "🛡️ DLP Management", 
            "📁 File Management", 
            "👥 User Activity", 
            "🚨 Alerts", 
            "⚙️ Settings"
        ])
        
        with tab1:
            self.render_overview()
        
        with tab2:
            self.render_persona_detection()
        
        with tab3:
            self.render_dlp_management()
        
        with tab4:
            self.render_file_management()
        
        with tab5:
            self.render_user_activity()
        
        with tab6:
            self.render_alerts()
        
        with tab7:
            self.render_settings()
    
    def _apply_css_fixes(self):
        """Apply CSS fixes for visibility issues"""
        st.markdown("""
        <style>
        /* Fix all text visibility issues */
        .stApp {
            background-color: #0E1117 !important;
        }
        
        /* Fix headers and text */
        h1, h2, h3, h4, h5, h6 {
            color: #FAFAFA !important;
        }
        
        p, div, span, label {
            color: #FAFAFA !important;
        }
        
        /* Fix metric cards */
        div[data-testid="stMetricValue"], 
        div[data-testid="stMetricLabel"] {
            color: #FAFAFA !important;
        }
        
        /* Fix Streamlit widget labels */
        .stTextInput > label,
        .stSelectbox > label,
        .stSlider > label,
        .stCheckbox > label {
            color: #FAFAFA !important;
        }
        
        /* Fix widget backgrounds */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea,
        .stSelectbox > div > div > select {
            color: #000000 !important;
            background-color: #FFFFFF !important;
        }
        
        /* Admin header styling */
        .admin-header {
            background: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%);
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            color: white;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        /* Persona risk cards */
        .persona-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .persona-card.high-risk {
            border-left: 4px solid #ef4444;
        }
        
        .persona-card.medium-risk {
            border-left: 4px solid #f59e0b;
        }
        
        .persona-card.low-risk {
            border-left: 4px solid #10b981;
        }
        
        /* DLP violation cards */
        .dlp-violation-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .dlp-critical {
            border-left: 4px solid #dc2626;
            background: rgba(220, 38, 38, 0.1);
        }
        
        .dlp-high {
            border-left: 4px solid #ea580c;
            background: rgba(234, 88, 12, 0.1);
        }
        
        .dlp-medium {
            border-left: 4px solid #d97706;
            background: rgba(217, 119, 6, 0.1);
        }
        
        /* Table improvements */
        .dataframe {
            background-color: #1e293b !important;
        }
        
        .dataframe th {
            background-color: #334155 !important;
            color: #f8fafc !important;
        }
        
        .dataframe td {
            color: #cbd5e1 !important;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_overview(self):
        """Enhanced overview with persona and DLP metrics"""
        st.subheader("📊 Security Overview")
        
        # Get system stats
        stats = self.db.get_system_stats()
        
        # Top row metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", stats.get('total_users', 0))
        
        with col2:
            st.metric("Active Threats", stats.get('open_incidents', 0))
        
        with col3:
            st.metric("DLP Violations Today", stats.get('dlp_violations_today', 0))
        
        with col4:
            st.metric("Persona Alerts", stats.get('persona_alerts_today', 0))
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk distribution with DLP violations
            risk_data = self.db.get_risk_distribution()
            dlp_violations = self.db.get_dlp_violations(days=1, limit=100)
            
            if risk_data:
                df = pd.DataFrame(risk_data)
                fig = px.pie(
                    df, 
                    values='count', 
                    names='risk_level',
                    title="File Risk Distribution",
                    color='risk_level',
                    color_discrete_map={
                        'low': '#10b981',
                        'medium': '#f59e0b',
                        'high': '#ef4444'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Show recent DLP violations
            if dlp_violations:
                st.subheader("Recent DLP Violations")
                for violation in dlp_violations[:3]:
                    self._render_dlp_violation_card(violation)
        
        with col2:
            # Upload trends with DLP actions
            trend_data = self.db.get_upload_trends(7)
            if trend_data:
                df = pd.DataFrame(trend_data)
                fig = px.bar(
                    df,
                    x='date',
                    y=['upload_count', 'dlp_action_count'],
                    title="Uploads vs DLP Actions (Last 7 Days)",
                    barmode='group',
                    labels={'value': 'Count', 'variable': 'Type'},
                    color_discrete_map={
                        'upload_count': '#3b82f6',
                        'dlp_action_count': '#ef4444'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # Recent high-risk incidents with persona anomalies
        st.subheader("🔴 Recent High-Risk Events")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Critical incidents
            incidents = self.db.get_all_incidents(limit=5, status='open')
            critical_incidents = [i for i in incidents if i.get('severity') in ['critical', 'high']]
            
            if critical_incidents:
                for incident in critical_incidents:
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
        
        with col2:
            # Recent persona anomalies
            security_logs = self.db.get_security_logs(action_type='persona_anomaly', 
                                                     risk_threshold=0.7, days=1, limit=5)
            if security_logs:
                for log in security_logs:
                    risk_score = log.get('persona_anomaly_score', log.get('risk_score', 0))
                    risk_color = '#ef4444' if risk_score > 0.8 else '#f59e0b'
                    st.markdown(f"""
                    <div style="background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; 
                                border-left: 4px solid {risk_color}; margin: 8px 0;">
                        <strong>Persona Anomaly</strong><br>
                        <small>User: {log.get('username', 'Unknown')} | 
                               Risk: {risk_score:.2%}</small><br>
                        <span style="font-size: 0.9em;">IP: {log.get('ip_address', 'Unknown')}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No persona anomalies detected")
    
    def render_persona_detection(self):
        """Persona detection and behavioral analysis dashboard"""
        st.subheader("👤 Persona Detection & Behavioral Analysis")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            user_filter = st.selectbox(
                "Select User",
                ["All Users"] + self.db.get_all_users()
            )
        
        with col2:
            risk_filter = st.selectbox(
                "Minimum Risk Score",
                ["All", "High (≥0.7)", "Medium (≥0.4)", "Low (≥0)"]
            )
        
        with col3:
            days_filter = st.slider("Last N Days", 1, 30, 7)
        
        # Get persona profiles
        persona_profiles = self.db.get_all_persona_profiles()
        
        if user_filter != "All Users":
            persona_profiles = [p for p in persona_profiles if p.get('username') == user_filter]
        
        # Apply risk filter
        if risk_filter != "All":
            min_risk = 0.7 if "High" in risk_filter else 0.4 if "Medium" in risk_filter else 0
            persona_profiles = [p for p in persona_profiles if p.get('risk_score', 0) >= min_risk]
        
        if persona_profiles:
            # Display persona profiles
            for profile in persona_profiles:
                self._render_persona_profile_card(profile, days_filter)
        else:
            st.info("No persona profiles found matching the criteria.")
        
        # Persona statistics
        st.subheader("📈 Persona Statistics")
        
        if persona_profiles:
            # Calculate statistics
            risk_scores = [p.get('risk_score', 0) for p in persona_profiles]
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Profiles", len(persona_profiles))
            with col2:
                high_risk_count = sum(1 for score in risk_scores if score >= 0.7)
                st.metric("High Risk Profiles", high_risk_count)
            with col3:
                st.metric("Average Risk Score", f"{avg_risk:.2%}")
            
            # Risk distribution chart
            if risk_scores:
                risk_df = pd.DataFrame({
                    'Risk Level': ['Low (<0.4)', 'Medium (0.4-0.7)', 'High (≥0.7)'],
                    'Count': [
                        sum(1 for score in risk_scores if score < 0.4),
                        sum(1 for score in risk_scores if 0.4 <= score < 0.7),
                        sum(1 for score in risk_scores if score >= 0.7)
                    ]
                })
                
                fig = px.bar(risk_df, x='Risk Level', y='Count', 
                            title="Persona Risk Distribution",
                            color='Risk Level',
                            color_discrete_map={
                                'Low (<0.4)': '#10b981',
                                'Medium (0.4-0.7)': '#f59e0b',
                                'High (≥0.7)': '#ef4444'
                            })
                st.plotly_chart(fig, use_container_width=True)
        
        # Persona detection configuration
        with st.expander("⚙️ Persona Detection Configuration"):
            col1, col2 = st.columns(2)
            
            with col1:
                persona_enabled = st.checkbox("Enable Persona Detection", value=True)
                risk_threshold = st.slider("Risk Threshold", 0.0, 1.0, 0.7, 0.05)
                alert_on_anomaly = st.checkbox("Alert on Anomaly", value=True)
            
            with col2:
                behavior_weights = {
                    'Login Time': st.slider("Login Time Weight", 0.0, 1.0, 0.25, 0.05),
                    'IP Consistency': st.slider("IP Consistency Weight", 0.0, 1.0, 0.20, 0.05),
                    'Upload Frequency': st.slider("Upload Frequency Weight", 0.0, 1.0, 0.30, 0.05),
                    'Device Consistency': st.slider("Device Consistency Weight", 0.0, 1.0, 0.15, 0.05)
                }
            
            if st.button("Save Configuration", type="primary"):
                st.success("Persona detection configuration saved!")
    
    def _render_persona_profile_card(self, profile: Dict, days_filter: int):
        """Render persona profile card"""
        risk_score = profile.get('risk_score', 0)
        
        # Determine risk class
        if risk_score >= 0.7:
            risk_class = "high-risk"
            risk_label = "🔴 HIGH RISK"
        elif risk_score >= 0.4:
            risk_class = "medium-risk"
            risk_label = "🟡 MEDIUM RISK"
        else:
            risk_class = "low-risk"
            risk_label = "🟢 LOW RISK"
        
        # Get profile data
        profile_data = profile.get('profile_data', {})
        if isinstance(profile_data, str):
            try:
                profile_data = json.loads(profile_data)
            except:
                profile_data = {}
        
        # Get user's recent security logs
        security_logs = self.db.get_security_logs(action_type='persona_anomaly',
                                                 risk_threshold=0.0,
                                                 days=days_filter)
        user_logs = [log for log in security_logs if log.get('user_id') == profile.get('user_id')]
        
        st.markdown(f"""
        <div class="persona-card {risk_class}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h4 style="margin: 0;">{profile.get('username', 'Unknown User')}</h4>
                    <p style="margin: 4px 0; font-size: 0.9em; color: #94a3b8;">
                        {profile.get('email', 'No email')} | Role: {profile.get('role', 'user')}
                    </p>
                </div>
                <div style="text-align: right;">
                    <strong style="color: {'#ef4444' if risk_score >= 0.7 else '#f59e0b' if risk_score >= 0.4 else '#10b981'};">
                        {risk_score:.2%}
                    </strong>
                    <br>
                    <small>{risk_label}</small>
                </div>
            </div>
            
            <div style="margin-top: 12px; font-size: 0.9em;">
                <strong>Behavioral Profile:</strong>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;">
                    <div>
                        <small>📅 Typical Login: {profile_data.get('login_time_pattern', {}).get('typical_hours', 'Unknown')[:20]}</small>
                    </div>
                    <div>
                        <small>📊 Uploads/Day: {profile_data.get('upload_pattern', {}).get('avg_per_day', 0):.1f}</small>
                    </div>
                    <div>
                        <small>🌐 Common IPs: {len(profile_data.get('common_ips', []))}</small>
                    </div>
                    <div>
                        <small>💻 Devices: {len(profile_data.get('common_devices', []))}</small>
                    </div>
                </div>
            </div>
            
            <div style="margin-top: 12px;">
                <small>📈 Recent Anomalies: {len(user_logs)} in last {days_filter} days</small>
                <br>
                <small>🕒 Last Updated: {profile.get('last_updated', 'Never')}</small>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("View Details", key=f"view_{profile['user_id']}", use_container_width=True):
                st.session_state['selected_user_id'] = profile['user_id']
                st.session_state['show_user_details'] = True
        
        with col2:
            if st.button("Force Rebuild", key=f"rebuild_{profile['user_id']}", use_container_width=True):
                if self.persona_detector:
                    self.persona_detector.build_persona_profile(profile['user_id'])
                    st.success(f"Persona profile rebuilt for {profile.get('username')}")
                    st.rerun()
        
        with col3:
            if risk_score >= 0.7:
                if st.button("Require MFA", key=f"mfa_{profile['user_id']}", use_container_width=True):
                    st.warning(f"MFA required for {profile.get('username')}")
        
        st.write("")  # Spacing
    
    def render_dlp_management(self):
        """DLP rule management and violation monitoring"""
        st.subheader("🛡️ Data Leakage Prevention (DLP)")
        
        # DLP violation statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            today_violations = self.db.get_dlp_violations(days=1)
            st.metric("Violations Today", len(today_violations))
        
        with col2:
            week_violations = self.db.get_dlp_violations(days=7)
            st.metric("Last 7 Days", len(week_violations))
        
        with col3:
            blocked_count = sum(1 for v in week_violations if v.get('action_taken') == 'block')
            st.metric("Blocked Files", blocked_count)
        
        with col4:
            encrypted_count = sum(1 for v in week_violations if v.get('action_taken') == 'encrypt')
            st.metric("Encrypted Files", encrypted_count)
        
        # Tabs for DLP management
        tab1, tab2, tab3 = st.tabs(["📋 Violations", "⚖️ Rules", "📊 Analytics"])
        
        with tab1:
            self._render_dlp_violations_tab()
        
        with tab2:
            self._render_dlp_rules_tab()
        
        with tab3:
            self._render_dlp_analytics_tab()
    
    def _render_dlp_violations_tab(self):
        """Render DLP violations tab"""
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            violation_type = st.selectbox(
                "Violation Type",
                ["All", "aadhaar_leak", "pan_leak", "pii_leak", "keyword_violation", "sensitive_data_leak"]
            )
        
        with col2:
            action_filter = st.selectbox(
                "Action Taken",
                ["All", "block", "encrypt", "warn", "allow"]
            )
        
        with col3:
            days_filter = st.slider("Time Period (days)", 1, 90, 7, key="dlp_days")
        
        # Get violations
        violations = self.db.get_dlp_violations(days=days_filter)
        
        # Apply filters
        if violation_type != "All":
            violations = [v for v in violations if v.get('violation_type') == violation_type]
        
        if action_filter != "All":
            violations = [v for v in violations if v.get('action_taken') == action_filter]
        
        if violations:
            # Display violations
            for violation in violations:
                self._render_dlp_violation_card(violation)
            
            # Export option
            if st.button("Export to CSV"):
                df = pd.DataFrame(violations)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"dlp_violations_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        else:
            st.info("No DLP violations found matching the criteria.")
    
    def _render_dlp_violation_card(self, violation: Dict):
        """Render DLP violation card"""
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
        <div class="dlp-violation-card dlp-{severity}">
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
        
        # Action buttons for each violation
        col1, col2 = st.columns(2)
        with col1:
            if st.button("View Details", key=f"view_violation_{violation['id']}", use_container_width=True):
                st.session_state['selected_violation_id'] = violation['id']
        
        with col2:
            if st.button("Rescan File", key=f"rescan_{violation['id']}", use_container_width=True):
                st.info(f"Rescanning file: {violation.get('filename')}")
        
        st.write("")  # Spacing
    
    def _render_dlp_rules_tab(self):
        """Render DLP rules management tab"""
        st.subheader("DLP Rule Configuration")
        
        # Create new rule
        with st.expander("➕ Add New DLP Rule", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                rule_name = st.text_input("Rule Name")
                pattern_type = st.selectbox("Pattern Type", ["regex", "keyword", "ml_model"])
                severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
            
            with col2:
                pattern = st.text_area("Pattern/Keyword")
                action = st.selectbox("Action", ["block", "encrypt", "warn", "allow"])
                is_active = st.checkbox("Active", value=True)
            
            if st.button("Create Rule", type="primary"):
                # Validate pattern
                if pattern_type == "regex":
                    try:
                        re.compile(pattern)
                        valid_pattern = True
                    except:
                        valid_pattern = False
                        st.error("Invalid regex pattern")
                else:
                    valid_pattern = bool(pattern.strip())
                
                if valid_pattern and rule_name:
                    # Save rule to database
                    conn = self.db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO dlp_rules (rule_name, pattern_type, pattern, action, severity, is_active)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (rule_name, pattern_type, pattern, action, severity, 1 if is_active else 0))
                    conn.commit()
                    st.success(f"Rule '{rule_name}' created successfully!")
                    st.rerun()
        
        # Existing rules
        st.subheader("Existing DLP Rules")
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dlp_rules ORDER BY severity DESC, rule_name')
        rules = [dict(row) for row in cursor.fetchall()]
        
        if rules:
            for rule in rules:
                self._render_dlp_rule_card(rule)
        else:
            st.info("No DLP rules configured.")
    
    def _render_dlp_rule_card(self, rule: Dict):
        """Render DLP rule card"""
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
        
        severity_color = severity_colors.get(rule.get('severity', 'medium'), '#d97706')
        action_icon = action_icons.get(rule.get('action', 'warn'), '⚠️')
        is_active = rule.get('is_active', 1)
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown(f"""
            <div style="background: rgba(30, 41, 59, 0.8); padding: 12px; border-radius: 8px; 
                        border-left: 4px solid {severity_color}; margin: 4px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>{rule.get('rule_name', 'Unnamed Rule')}</strong>
                        <br>
                        <small>Type: {rule.get('pattern_type', 'unknown')} | 
                               Pattern: {rule.get('pattern', '')[:50]}...</small>
                    </div>
                    <div style="text-align: right;">
                        <span style="color: {severity_color}; font-weight: bold;">
                            {rule.get('severity', 'medium').upper()}
                        </span>
                        <br>
                        <small>{action_icon} {rule.get('action', 'warn').upper()}</small>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            col_toggle, col_delete = st.columns(2)
            with col_toggle:
                if st.button("🔁" if is_active else "⚪", 
                           key=f"toggle_{rule['id']}",
                           help="Toggle Active/Inactive"):
                    new_status = 0 if is_active else 1
                    cursor = self.db.get_connection().cursor()
                    cursor.execute('UPDATE dlp_rules SET is_active = ? WHERE id = ?', 
                                 (new_status, rule['id']))
                    self.db.get_connection().commit()
                    st.rerun()
            
            with col_delete:
                if st.button("🗑️", key=f"delete_{rule['id']}", help="Delete Rule"):
                    cursor = self.db.get_connection().cursor()
                    cursor.execute('DELETE FROM dlp_rules WHERE id = ?', (rule['id'],))
                    self.db.get_connection().commit()
                    st.rerun()
    
    def _render_dlp_analytics_tab(self):
        """Render DLP analytics tab"""
        # Get violations for analytics
        violations = self.db.get_dlp_violations(days=30)
        
        if violations:
            # Convert to DataFrame
            df = pd.DataFrame(violations)
            
            # Analytics charts
            col1, col2 = st.columns(2)
            
            with col1:
                # Violations by type
                violation_counts = df['violation_type'].value_counts()
                fig1 = px.pie(
                    values=violation_counts.values,
                    names=violation_counts.index,
                    title="Violations by Type"
                )
                st.plotly_chart(fig1, use_container_width=True)
            
            with col2:
                # Actions taken
                action_counts = df['action_taken'].value_counts()
                fig2 = px.bar(
                    x=action_counts.index,
                    y=action_counts.values,
                    title="Actions Taken",
                    color=action_counts.index,
                    color_discrete_map={
                        'block': '#ef4444',
                        'encrypt': '#3b82f6',
                        'warn': '#f59e0b',
                        'allow': '#10b981'
                    }
                )
                st.plotly_chart(fig2, use_container_width=True)
            
            # Time series analysis
            st.subheader("Violations Over Time")
            df['date'] = pd.to_datetime(df['timestamp']).dt.date
            daily_counts = df.groupby('date').size().reset_index(name='count')
            
            fig3 = px.line(
                daily_counts,
                x='date',
                y='count',
                title="Daily DLP Violations",
                markers=True
            )
            st.plotly_chart(fig3, use_container_width=True)
            
            # Top users with violations
            st.subheader("Top Users by Violations")
            user_counts = df['username'].value_counts().head(10)
            
            fig4 = px.bar(
                x=user_counts.values,
                y=user_counts.index,
                orientation='h',
                title="Top 10 Users with DLP Violations",
                color=user_counts.values,
                color_continuous_scale='reds'
            )
            st.plotly_chart(fig4, use_container_width=True)
        
        else:
            st.info("No DLP violation data available for analytics.")
    
    # Existing methods from the original admin_dashboard.py continue below...
    # I'll show the modifications needed for the remaining methods:

    def render_file_management(self):
        """Centralized file view for admin - ENHANCED with DLP info"""
        st.subheader("📁 Centralized File Management")
        
        # Filters - ADDED DLP FILTER
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            risk_filter = st.selectbox(
                "Risk Level",
                ["All", "Low", "Medium", "High", "Critical"],
                key="risk_filter"
            )
        
        with col2:
            status_filter = st.selectbox(
                "Status",
                ["All", "Pending", "Approved", "Rejected"],
                key="status_filter"
            )
        
        with col3:
            dlp_filter = st.selectbox(
                "DLP Action",
                ["All", "Blocked", "Encrypted", "Warned", "Allowed"],
                key="dlp_filter"
            )
        
        with col4:
            days_filter = st.slider(
                "Last N Days",
                1, 30, 7,
                key="days_filter"
            )
        
        # Get files - MODIFIED to include DLP info
        files = self.db.get_files_with_details(
            risk_level=risk_filter if risk_filter != "All" else None,
            status=status_filter if status_filter != "All" else None,
            days=days_filter
        )
        
        # Apply DLP filter
        if dlp_filter != "All":
            dlp_action_map = {
                "Blocked": "block",
                "Encrypted": "encrypt",
                "Warned": "warn",
                "Allowed": "allow"
            }
            target_action = dlp_action_map.get(dlp_filter)
            files = [f for f in files if f.get('dlp_action_taken') == target_action]
        
        if files:
            # Display with enhanced information
            self._render_files_table_with_dlp(files)
            
            # File details section - ENHANCED
            st.subheader("📄 File Details with Security Analysis")
            selected_file = st.selectbox(
                "Select file for detailed view",
                [f"{f['filename']} (by {f['username']} - Risk: {f.get('risk_score', 0):.2f})" 
                 for f in files]
            )
            
            if selected_file:
                self._render_enhanced_file_details(selected_file, files)
        else:
            st.info("No files found matching the criteria.")
    
    def _render_files_table_with_dlp(self, files: List[Dict]):
        """Render files table with DLP information"""
        # Create DataFrame with relevant columns
        data = []
        for file in files:
            # Determine risk color
            risk_score = file.get('risk_score', 0)
            if risk_score >= 0.7:
                risk_color = "🔴"
                risk_text = f"{risk_score:.2f}"
            elif risk_score >= 0.4:
                risk_color = "🟡"
                risk_text = f"{risk_score:.2f}"
            else:
                risk_color = "🟢"
                risk_text = f"{risk_score:.2f}"
            
            # Determine DLP action icon
            dlp_action = file.get('dlp_action_taken', '')
            dlp_icons = {
                'block': '🚫',
                'encrypt': '🔐',
                'warn': '⚠️',
                'allow': '✅'
            }
            dlp_icon = dlp_icons.get(dlp_action, '📄')
            
            data.append({
                "File": file['filename'],
                "User": file['username'],
                "Upload Time": file.get('upload_time', ''),
                "Risk": f"{risk_color} {risk_text}",
                "DLP Action": dlp_icon,
                "Status": file.get('status', 'pending'),
                "Size": f"{file.get('file_size', 0) / 1024:.1f} KB"
            })
        
        df = pd.DataFrame(data)
        
        # Display as interactive table
        st.dataframe(
            df,
            column_config={
                "File": st.column_config.TextColumn("File Name", width="medium"),
                "User": st.column_config.TextColumn("Uploaded By", width="small"),
                "Upload Time": st.column_config.DatetimeColumn("Upload Time"),
                "Risk": st.column_config.TextColumn("Risk Score", width="small"),
                "DLP Action": st.column_config.TextColumn("DLP", width="small"),
                "Status": st.column_config.TextColumn("Status", width="small"),
                "Size": st.column_config.NumberColumn("Size (KB)", format="%.1f")
            },
            use_container_width=True,
            height=400
        )
    
    def _render_enhanced_file_details(self, selected_file: str, files: List[Dict]):
        """Render enhanced file details with security analysis"""
        # Extract file from selection
        file_info = next(f for f in files if 
                        f"{f['filename']} (by {f['username']} - Risk: {f.get('risk_score', 0):.2f})" == selected_file)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: rgba(30, 41, 59, 0.8); padding: 1rem; border-radius: 8px; border: 1px solid #334155;">
            <h4>📋 File Information</h4>
            """, unsafe_allow_html=True)
            
            st.write(f"**File Name:** {file_info['filename']}")
            st.write(f"**Uploaded By:** {file_info['username']}")
            st.write(f"**Upload Time:** {file_info.get('upload_time', 'Unknown')}")
            st.write(f"**File Type:** {file_info.get('file_type', 'Unknown')}")
            st.write(f"**File Size:** {file_info.get('file_size', 0):,} bytes")
            
            # Risk indicator with color
            risk_score = file_info.get('risk_score', 0)
            if risk_score >= 0.7:
                st.error(f"**Risk Score:** {risk_score:.2f} (High Risk)")
            elif risk_score >= 0.4:
                st.warning(f"**Risk Score:** {risk_score:.2f} (Medium Risk)")
            else:
                st.success(f"**Risk Score:** {risk_score:.2f} (Low Risk)")
            
            # DLP action info
            dlp_action = file_info.get('dlp_action_taken')
            dlp_reason = file_info.get('dlp_reason')
            if dlp_action:
                if dlp_action == 'block':
                    st.error(f"**DLP Action:** Blocked - {dlp_reason}")
                elif dlp_action == 'encrypt':
                    st.warning(f"**DLP Action:** Encrypted - {dlp_reason}")
                elif dlp_action == 'warn':
                    st.info(f"**DLP Action:** Warning Issued - {dlp_reason}")
                else:
                    st.success(f"**DLP Action:** Allowed - {dlp_reason}")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: rgba(30, 41, 59, 0.8); padding: 1rem; border-radius: 8px; border: 1px solid #334155;">
            <h4>🛡️ Security Analysis</h4>
            """, unsafe_allow_html=True)
            
            # Scan results
            scan_result = file_info.get('scan_result', '{}')
            if scan_result and scan_result != '{}':
                try:
                    if isinstance(scan_result, str):
                        scan_data = json.loads(scan_result)
                    else:
                        scan_data = scan_result
                    
                    st.write("**Scan Results:**")
                    
                    # Show pattern detections
                    if 'pattern_detections' in scan_data:
                        st.write("Detected Patterns:")
                        for pattern, details in scan_data['pattern_detections'].items():
                            st.write(f"  - {pattern}: {details.get('count', 0)} instances")
                    
                    # Show keyword detections
                    if 'keyword_detections' in scan_data:
                        keyword_count = sum(scan_data['keyword_detections'].values())
                        if keyword_count > 0:
                            st.write(f"Sensitive Keywords: {keyword_count} found")
                    
                    # Show DLP analysis
                    if 'dlp_action' in scan_data:
                        dlp_info = scan_data['dlp_action']
                        if isinstance(dlp_info, dict):
                            st.write(f"DLP Decision: {dlp_info.get('action', 'unknown')}")
                            st.write(f"Reason: {dlp_info.get('reason', 'No reason')}")
                
                except json.JSONDecodeError:
                    st.write("Scan results unavailable")
            
            # Approval status and actions
            status = file_info.get('approval_status', 'pending')
            if status == 'approved':
                st.success(f"**Status:** Approved ✅")
            elif status == 'rejected':
                st.error(f"**Status:** Rejected ❌")
            else:
                st.warning(f"**Status:** Pending Review ⏳")
            
            # Actions
            if status == 'pending':
                col_approve, col_reject = st.columns(2)
                with col_approve:
                    if st.button("✅ Approve", key=f"approve_{file_info['id']}", use_container_width=True):
                        self.db.update_approval_status(
                            file_info['id'], 
                            'approved',
                            self.user['id']
                        )
                        st.success("File approved!")
                        st.rerun()
                
                with col_reject:
                    if st.button("❌ Reject", key=f"reject_{file_info['id']}", use_container_width=True):
                        self.db.update_approval_status(
                            file_info['id'], 
                            'rejected',
                            self.user['id']
                        )
                        st.error("File rejected!")
                        st.rerun()
            
            # Additional security actions
            st.write("**Security Actions:**")
            col_rescan, col_quarantine = st.columns(2)
            with col_rescan:
                if st.button("🔄 Rescan", key=f"rescan_file_{file_info['id']}", use_container_width=True):
                    st.info("Rescan initiated...")
            
            with col_quarantine:
                if dlp_action != 'block' and risk_score >= 0.7:
                    if st.button("🚫 Quarantine", key=f"quarantine_{file_info['id']}", use_container_width=True):
                        self.db.update_file_dlp_action(
                            file_info['id'], 
                            'block', 
                            'Manually quarantined by admin'
                        )
                        st.error("File quarantined!")
                        st.rerun()
            
            st.markdown("</div>", unsafe_allow_html=True)
    
    def render_user_activity(self):
        """Show user activity logs - ENHANCED with persona risk"""
        st.subheader("👥 User Activity & Behavior Analysis")
        
        # Get recent activities
        activities = self.db.get_recent_activities(limit=100)
        
        if activities:
            # Add risk score indicators
            enhanced_activities = []
            for activity in activities:
                # Calculate or get risk score
                risk_score = activity.get('risk_score', 0)
                
                # Determine risk icon
                if risk_score >= 0.7:
                    risk_icon = "🔴"
                elif risk_score >= 0.4:
                    risk_icon = "🟡"
                else:
                    risk_icon = "🟢"
                
                enhanced_activity = activity.copy()
                enhanced_activity['risk_indicator'] = f"{risk_icon} {risk_score:.2f}"
                enhanced_activities.append(enhanced_activity)
            
            # Create DataFrame
            df = pd.DataFrame(enhanced_activities)
            
            # Format timestamp
            df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Display with risk indicators
            st.dataframe(
                df[['username', 'activity_type', 'details', 'ip_address', 
                    'timestamp', 'risk_indicator']],
                column_config={
                    "username": "User",
                    "activity_type": "Activity",
                    "details": "Details",
                    "ip_address": "IP Address",
                    "timestamp": "Time",
                    "risk_indicator": "Risk"
                },
                use_container_width=True,
                height=300
            )
            
            # Activity statistics with risk analysis
            st.subheader("📊 Activity Risk Analysis")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                high_risk_count = sum(1 for a in activities if a.get('risk_score', 0) >= 0.7)
                st.metric("High Risk Activities", high_risk_count)
            
            with col2:
                login_count = len([a for a in activities if a['activity_type'] == 'login_success'])
                st.metric("Login Events", login_count)
            
            with col3:
                upload_count = len([a for a in activities if 'upload' in a['activity_type'].lower()])
                st.metric("Upload Events", upload_count)
            
            with col4:
                unique_users = len(set(a['username'] for a in activities))
                st.metric("Active Users", unique_users)
            
            # Risk trend chart
            if len(activities) > 10:
                risk_df = pd.DataFrame([
                    {'hour': pd.to_datetime(a['timestamp']).hour, 'risk': a.get('risk_score', 0)}
                    for a in activities if 'timestamp' in a
                ])
                
                if not risk_df.empty:
                    hourly_risk = risk_df.groupby('hour')['risk'].mean().reset_index()
                    fig = px.line(hourly_risk, x='hour', y='risk', 
                                title="Average Risk by Hour of Day",
                                markers=True)
                    st.plotly_chart(fig, use_container_width=True)
        
        else:
            st.info("No recent activities found.")
    
    def render_alerts(self):
        """Display and manage alerts - ENHANCED with persona/DLP alerts"""
        st.subheader("🚨 Security Alerts & Notifications")
        
        # Alert filters - ADDED PERSONA/DLP FILTERS
        col1, col2, col3 = st.columns(3)
        
        with col1:
            alert_type = st.selectbox(
                "Alert Type",
                ["All", "persona_anomaly", "dlp_violation", "threat_detected", 
                 "file_upload", "user_activity", "system"],
                key="alert_type"
            )
        
        with col2:
            severity = st.selectbox(
                "Severity",
                ["All", "Critical", "High", "Medium", "Low"],
                key="alert_severity"
            )
        
        with col3:
            days_limit = st.slider("Last N Days", 1, 30, 7, key="alert_days")
        
        # Get alerts
        alerts = self.db.get_alerts(
            alert_type=alert_type if alert_type != "All" else None,
            severity=severity.lower() if severity != "All" else None,
            limit=50
        )
        
        # Filter by date
        if days_limit < 30:
            cutoff_date = (datetime.now() - timedelta(days=days_limit)).isoformat()
            alerts = [a for a in alerts if a.get('created_at', '') >= cutoff_date]
        
        if alerts:
            # Categorize alerts
            persona_alerts = [a for a in alerts if a.get('alert_type') == 'persona_anomaly']
            dlp_alerts = [a for a in alerts if a.get('alert_type') == 'dlp_violation']
            other_alerts = [a for a in alerts if a.get('alert_type') not in ['persona_anomaly', 'dlp_violation']]
            
            # Display categorized alerts
            if persona_alerts:
                st.subheader("👤 Persona Anomaly Alerts")
                for alert in persona_alerts:
                    self._render_enhanced_alert_card(alert)
            
            if dlp_alerts:
                st.subheader("🛡️ DLP Violation Alerts")
                for alert in dlp_alerts:
                    self._render_enhanced_alert_card(alert)
            
            if other_alerts:
                st.subheader("📢 Other Alerts")
                for alert in other_alerts:
                    self._render_enhanced_alert_card(alert)
            
            # Alert statistics
            st.subheader("📈 Alert Statistics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Alerts", len(alerts))
            
            with col2:
                st.metric("Persona Alerts", len(persona_alerts))
            
            with col3:
                st.metric("DLP Alerts", len(dlp_alerts))
            
            with col4:
                unread_count = sum(1 for a in alerts if not a.get('read', 0))
                st.metric("Unread Alerts", unread_count)
        
        else:
            st.info("No alerts found matching the criteria.")
        
        # Alert management
        st.subheader("🔧 Alert Management")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Mark All as Read", type="secondary"):
                # Update all alerts as read
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE alerts SET read = 1 WHERE read = 0')
                conn.commit()
                st.success("All alerts marked as read!")
                st.rerun()
        
        with col2:
            if st.button("Send Test Persona Alert", type="secondary"):
                self._send_test_persona_alert()
                st.success("Test persona alert sent!")
        
        # Test DLP alert
        if st.button("Send Test DLP Alert", type="secondary"):
            self._send_test_dlp_alert()
            st.success("Test DLP alert sent!")
    
    def _render_enhanced_alert_card(self, alert: Dict):
        """Render enhanced alert card with type-specific formatting"""
        severity = alert.get('severity', 'medium').lower()
        alert_type = alert.get('alert_type', '')
        
        severity_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#d97706',
            'low': '#059669'
        }
        
        # Type-specific icons and colors
        type_config = {
            'persona_anomaly': {'icon': '👤', 'bg_color': 'rgba(59, 130, 246, 0.1)'},
            'dlp_violation': {'icon': '🛡️', 'bg_color': 'rgba(239, 68, 68, 0.1)'},
            'threat_detected': {'icon': '🚨', 'bg_color': 'rgba(220, 38, 38, 0.1)'},
            'file_upload': {'icon': '📁', 'bg_color': 'rgba(34, 197, 94, 0.1)'},
            'default': {'icon': '📢', 'bg_color': 'rgba(148, 163, 184, 0.1)'}
        }
        
        config = type_config.get(alert_type, type_config['default'])
        severity_color = severity_colors.get(severity, '#d97706')
        
        # Determine if alert is read
        is_read = alert.get('read', 0)
        read_style = "opacity: 0.7;" if is_read else ""
        
        st.markdown(f"""
        <div style="background: {config['bg_color']}; padding: 12px; border-radius: 8px; 
                    border-left: 4px solid {severity_color}; margin: 8px 0; {read_style}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.2rem;">{config['icon']}</span>
                    <div>
                        <strong>{alert.get('title', 'Alert')}</strong>
                        <div style="font-size: 0.9em; color: #64748b;">
                            {alert.get('message', '')}
                        </div>
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="color: {severity_color}; font-weight: bold; font-size: 0.9em;">
                        {severity.upper()}
                    </span>
                    <br>
                    <small style="color: #94a3b8;">{alert.get('created_at', '')}</small>
                </div>
            </div>
            
            <div style="display: flex; justify-content: space-between; margin-top: 8px;">
                <small style="color: #64748b;">
                    👤 {alert.get('username', 'System')} 
                    {f"| 📁 {alert.get('filename', '')}" if alert.get('filename') else ''}
                </small>
                <small>
                    {f"🕒 {alert.get('timestamp', '')}" if alert.get('timestamp') else ''}
                </small>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Action buttons for each alert
        col1, col2 = st.columns(2)
        with col1:
            if not is_read and st.button("Mark as Read", key=f"read_{alert['id']}", 
                                       use_container_width=True):
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE alerts SET read = 1 WHERE id = ?', (alert['id'],))
                conn.commit()
                st.rerun()
        
        with col2:
            if st.button("View Details", key=f"details_{alert['id']}", 
                        use_container_width=True):
                st.session_state['selected_alert_id'] = alert['id']
        
        st.write("")  # Spacing
    
    def _send_test_persona_alert(self):
        """Send test persona anomaly alert"""
        test_alert = {
            'alert_type': 'persona_anomaly',
            'user_id': self.user['id'],
            'severity': 'high',
            'title': 'Test Persona Anomaly Detected',
            'message': 'This is a test alert for persona anomaly detection system.',
            'read': 0
        }
        self.db.create_alert(**test_alert)
    
    def _send_test_dlp_alert(self):
        """Send test DLP violation alert"""
        test_alert = {
            'alert_type': 'dlp_violation',
            'user_id': self.user['id'],
            'severity': 'critical',
            'title': 'Test DLP Violation - Aadhaar Number Detected',
            'message': 'Test file contained Aadhaar numbers. File blocked.',
            'read': 0
        }
        self.db.create_alert(**test_alert)
    
    def render_settings(self):
        """System settings - ENHANCED with Persona/DLP settings"""
        st.subheader("⚙️ System Configuration")
        
        # Tabs for different settings
        tab1, tab2, tab3, tab4 = st.tabs([
            "Persona Detection", 
            "DLP Rules", 
            "Email & Notifications", 
            "General Settings"
        ])
        
        with tab1:
            self._render_persona_settings()
        
        with tab2:
            self._render_dlp_settings()
        
        with tab3:
            self._render_email_settings()
        
        with tab4:
            self._render_general_settings()
    
    def _render_persona_settings(self):
        """Persona detection settings"""
        st.subheader("👤 Persona Detection Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            persona_enabled = st.checkbox(
                "Enable Persona Detection", 
                value=True,
                help="Monitor user behavior for anomalies"
            )
            
            risk_threshold = st.slider(
                "Risk Threshold for Alerts",
                0.0, 1.0, 0.7, 0.05,
                help="Score above this triggers alerts"
            )
            
            auto_profile = st.checkbox(
                "Auto-build Profiles",
                value=True,
                help="Automatically build persona profiles for new users"
            )
            
            session_tracking = st.checkbox(
                "Track Session Duration",
                value=True,
                help="Monitor user session times for anomalies"
            )
        
        with col2:
            st.write("**Behavior Weights:**")
            
            login_weight = st.slider("Login Time", 0.0, 1.0, 0.25, 0.05)
            ip_weight = st.slider("IP Consistency", 0.0, 1.0, 0.20, 0.05)
            upload_weight = st.slider("Upload Frequency", 0.0, 1.0, 0.30, 0.05)
            device_weight = st.slider("Device Consistency", 0.0, 1.0, 0.15, 0.05)
            session_weight = st.slider("Session Duration", 0.0, 1.0, 0.10, 0.05)
            
            # Validate weights sum to 1
            total_weight = login_weight + ip_weight + upload_weight + device_weight + session_weight
            if abs(total_weight - 1.0) > 0.01:
                st.warning(f"Weights sum to {total_weight:.2f}. Normalizing to 1.0")
        
        st.write("**Alert Actions:**")
        col_alert1, col_alert2, col_alert3 = st.columns(3)
        
        with col_alert1:
            alert_email = st.checkbox("Email Alerts", value=True)
            alert_dashboard = st.checkbox("Dashboard Alerts", value=True)
        
        with col_alert2:
            require_mfa = st.checkbox(
                "Require MFA for High Risk",
                value=False,
                help="Force MFA for high-risk persona anomalies"
            )
            
            temporary_lock = st.checkbox(
                "Temporary Account Lock",
                value=False,
                help="Temporarily lock accounts on critical anomalies"
            )
        
        with col_alert3:
            review_period = st.number_input(
                "Review Period (hours)",
                min_value=1,
                max_value=168,
                value=24,
                help="Time window for anomaly review"
            )
            
            data_retention = st.number_input(
                "Data Retention (days)",
                min_value=30,
                max_value=365,
                value=90,
                help="Days to keep persona data"
            )
        
        if st.button("Save Persona Settings", type="primary"):
            # Save settings to database
            settings_to_save = [
                ('enable_persona_detection', '1' if persona_enabled else '0'),
                ('persona_risk_threshold', str(risk_threshold)),
                ('persona_auto_profile', '1' if auto_profile else '0'),
                ('persona_session_tracking', '1' if session_tracking else '0'),
                ('persona_login_weight', str(login_weight)),
                ('persona_ip_weight', str(ip_weight)),
                ('persona_upload_weight', str(upload_weight)),
                ('persona_device_weight', str(device_weight)),
                ('persona_session_weight', str(session_weight)),
                ('persona_alert_email', '1' if alert_email else '0'),
                ('persona_alert_dashboard', '1' if alert_dashboard else '0'),
                ('persona_require_mfa', '1' if require_mfa else '0'),
                ('persona_temp_lock', '1' if temporary_lock else '0'),
                ('persona_review_hours', str(review_period)),
                ('persona_data_retention', str(data_retention))
            ]
            
            conn = self.db.get_connection()
            cursor = conn.cursor()
            for key, value in settings_to_save:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                ''', (key, value))
            conn.commit()
            
            st.success("Persona detection settings saved!")
    
    def _render_dlp_settings(self):
        """DLP system settings"""
        st.subheader("🛡️ Data Leakage Prevention Configuration")
        
        # Basic DLP settings
        col1, col2 = st.columns(2)
        
        with col1:
            dlp_enabled = st.checkbox(
                "Enable DLP System",
                value=True,
                help="Enable data leakage prevention"
            )
            
            scan_on_upload = st.checkbox(
                "Scan on Upload",
                value=True,
                help="Automatically scan files during upload"
            )
            
            realtime_scanning = st.checkbox(
                "Real-time Scanning",
                value=True,
                help="Scan files in real-time"
            )
            
            deep_scan = st.checkbox(
                "Deep Content Analysis",
                value=False,
                help="Perform deep content analysis (slower)"
            )
        
        with col2:
            max_file_size = st.number_input(
                "Max File Size (MB)",
                min_value=1,
                max_value=1024,
                value=200,
                help="Maximum file size for scanning"
            )
            
            encryption_enabled = st.checkbox(
                "Enable Encryption",
                value=True,
                help="Encrypt sensitive files automatically"
            )
            
            auto_block = st.checkbox(
                "Auto-block High Risk",
                value=True,
                help="Automatically block high-risk files"
            )
            
            quarantine_period = st.number_input(
                "Quarantine Period (days)",
                min_value=1,
                max_value=30,
                value=7,
                help="Days to keep quarantined files"
            )
        
        # Pattern-specific actions
        st.subheader("Pattern Detection Actions")
        
        patterns = ['aadhaar', 'pan', 'credit_card', 'ssn', 'upi_id', 'indian_mobile']
        
        for pattern in patterns:
            col_action, col_thresh = st.columns([2, 1])
            with col_action:
                action = st.selectbox(
                    f"{pattern.replace('_', ' ').title()} Action",
                    ['block', 'encrypt', 'warn', 'allow'],
                    key=f"dlp_action_{pattern}"
                )
            with col_thresh:
                threshold = st.number_input(
                    "Threshold",
                    min_value=1,
                    max_value=100,
                    value=1,
                    key=f"dlp_thresh_{pattern}"
                )
        
        # Compliance settings
        st.subheader("Compliance & Reporting")
        
        col_comp1, col_comp2 = st.columns(2)
        
        with col_comp1:
            gdpr_compliance = st.checkbox("GDPR Compliance", value=True)
            pdpb_compliance = st.checkbox("India PDPB Compliance", value=True)
            hipaa_compliance = st.checkbox("HIPAA Compliance", value=False)
        
        with col_comp2:
            audit_logging = st.checkbox("Audit Logging", value=True)
            monthly_reports = st.checkbox("Monthly Reports", value=True)
            alert_regulators = st.checkbox("Alert Regulators", value=False)
        
        # Save button
        if st.button("Save DLP Settings", type="primary"):
            # Save DLP settings to database
            settings_to_save = [
                ('dlp_enabled', '1' if dlp_enabled else '0'),
                ('dlp_scan_on_upload', '1' if scan_on_upload else '0'),
                ('dlp_realtime', '1' if realtime_scanning else '0'),
                ('dlp_deep_scan', '1' if deep_scan else '0'),
                ('dlp_max_file_size', str(max_file_size)),
                ('dlp_encryption_enabled', '1' if encryption_enabled else '0'),
                ('dlp_auto_block', '1' if auto_block else '0'),
                ('dlp_quarantine_days', str(quarantine_period)),
                ('dlp_gdpr_compliance', '1' if gdpr_compliance else '0'),
                ('dlp_pdpb_compliance', '1' if pdpb_compliance else '0'),
                ('dlp_audit_logging', '1' if audit_logging else '0')
            ]
            
            conn = self.db.get_connection()
            cursor = conn.cursor()
            for key, value in settings_to_save:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                ''', (key, value))
            conn.commit()
            
            st.success("DLP settings saved!")
    
    def _render_email_settings(self):
        """Email and notification settings"""
        st.subheader("📧 Email & Notification Configuration")
        
        # Email server settings
        st.write("**SMTP Server Configuration:**")
        
        col_smtp1, col_smtp2 = st.columns(2)
        
        with col_smtp1:
            smtp_host = st.text_input("SMTP Host", value="smtp.gmail.com")
            smtp_port = st.number_input("SMTP Port", value=587, min_value=1, max_value=65535)
            smtp_username = st.text_input("SMTP Username", value="security@company.com")
        
        with col_smtp2:
            smtp_password = st.text_input("SMTP Password", type="password")
            use_tls = st.checkbox("Use TLS", value=True)
            use_ssl = st.checkbox("Use SSL", value=False)
        
        # Notification recipients
        st.write("**Notification Recipients:**")
        
        admin_email = st.text_input("Admin Email", value="admin@company.com")
        security_team = st.text_area(
            "Security Team Emails (comma-separated)",
            value="security-team@company.com,infosec@company.com"
        )
        
        # Alert types
        st.write("**Alert Types to Send:**")
        
        col_alert1, col_alert2 = st.columns(2)
        
        with col_alert1:
            send_persona_alerts = st.checkbox("Persona Anomalies", value=True)
            send_dlp_alerts = st.checkbox("DLP Violations", value=True)
            send_critical_alerts = st.checkbox("Critical Incidents", value=True)
        
        with col_alert2:
            send_daily_reports = st.checkbox("Daily Reports", value=True)
            send_weekly_summary = st.checkbox("Weekly Summary", value=True)
            send_monthly_audit = st.checkbox("Monthly Audit", value=False)
        
        # Test email
        st.write("**Test Configuration:**")
        
        test_email = st.text_input("Test Email Address", value=admin_email)
        
        if st.button("Send Test Email", type="secondary"):
            try:
                from email_alert import EmailAlertSystem
                email_system = EmailAlertSystem()
                email_system.send_test_email(test_email)
                st.success("Test email sent successfully!")
            except Exception as e:
                st.error(f"Failed to send test email: {e}")
        
        if st.button("Save Email Settings", type="primary"):
            # Save email settings
            settings_to_save = [
                ('smtp_host', smtp_host),
                ('smtp_port', str(smtp_port)),
                ('smtp_username', smtp_username),
                ('smtp_use_tls', '1' if use_tls else '0'),
                ('smtp_use_ssl', '1' if use_ssl else '0'),
                ('admin_email', admin_email),
                ('security_team_emails', security_team),
                ('send_persona_alerts', '1' if send_persona_alerts else '0'),
                ('send_dlp_alerts', '1' if send_dlp_alerts else '0'),
                ('send_daily_reports', '1' if send_daily_reports else '0')
            ]
            
            conn = self.db.get_connection()
            cursor = conn.cursor()
            for key, value in settings_to_save:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                ''', (key, value))
            
            # Don't save password in plain text (in real app, use encryption)
            if smtp_password:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                ''', ('smtp_password_encrypted', '***ENCRYPTED***',))
            
            conn.commit()
            st.success("Email settings saved!")
    
    def _render_general_settings(self):
        """General system settings"""
        st.subheader("⚙️ General System Configuration")
        
        # System preferences
        col_gen1, col_gen2 = st.columns(2)
        
        with col_gen1:
            system_name = st.text_input("System Name", value="Secure Persona Detection System")
            timezone = st.selectbox(
                "Timezone",
                ["UTC", "Asia/Kolkata", "America/New_York", "Europe/London", "Asia/Tokyo"],
                index=1
            )
            
            date_format = st.selectbox(
                "Date Format",
                ["YYYY-MM-DD", "DD/MM/YYYY", "MM/DD/YYYY"],
                index=0
            )
            
            language = st.selectbox(
                "Language",
                ["English", "Hindi", "Spanish", "French"],
                index=0
            )
        
        with col_gen2:
            session_timeout = st.number_input(
                "Session Timeout (minutes)",
                min_value=5,
                max_value=480,
                value=30,
                help="Auto-logout after inactivity"
            )
            
            max_login_attempts = st.number_input(
                "Max Login Attempts",
                min_value=1,
                max_value=10,
                value=5,
                help="Maximum failed attempts before lockout"
            )
            
            lockout_duration = st.number_input(
                "Lockout Duration (minutes)",
                min_value=1,
                max_value=1440,
                value=30,
                help="Account lockout duration after max attempts"
            )
            
            require_strong_passwords = st.checkbox(
                "Require Strong Passwords",
                value=True,
                help="Enforce password complexity rules"
            )
        
        # Dashboard settings
        st.subheader("📊 Dashboard Settings")
        
        col_dash1, col_dash2 = st.columns(2)
        
        with col_dash1:
            refresh_rate = st.selectbox(
                "Dashboard Refresh Rate",
                ["Realtime", "30 seconds", "1 minute", "5 minutes", "Manual"],
                index=2
            )
            
            chart_style = st.selectbox(
                "Chart Style",
                ["Plotly", "Streamlit Native", "Matplotlib"],
                index=0
            )
            
            default_view = st.selectbox(
                "Default View",
                ["Overview", "Persona Detection", "DLP Management", "File Management"],
                index=0
            )
        
        with col_dash2:
            show_metrics = st.checkbox("Show Metrics Cards", value=True)
            show_charts = st.checkbox("Show Charts", value=True)
            show_alerts = st.checkbox("Show Recent Alerts", value=True)
            dark_mode = st.checkbox("Dark Mode", value=True)
        
        # Data retention
        st.subheader("🗃️ Data Retention")
        
        col_ret1, col_ret2 = st.columns(2)
        
        with col_ret1:
            logs_retention = st.number_input(
                "Logs Retention (days)",
                min_value=7,
                max_value=365,
                value=90,
                help="Days to keep activity logs"
            )
            
            files_retention = st.number_input(
                "Files Retention (days)",
                min_value=30,
                max_value=730,
                value=365,
                help="Days to keep uploaded files"
            )
        
        with col_ret2:
            backups_enabled = st.checkbox("Enable Backups", value=True)
            backup_frequency = st.selectbox(
                "Backup Frequency",
                ["Daily", "Weekly", "Monthly"],
                index=0
            )
            
            auto_cleanup = st.checkbox(
                "Auto Cleanup Old Data",
                value=True,
                help="Automatically delete data older than retention period"
            )
        
        # Save button
        if st.button("Save General Settings", type="primary"):
            # Save general settings
            settings_to_save = [
                ('system_name', system_name),
                ('timezone', timezone),
                ('date_format', date_format),
                ('language', language),
                ('session_timeout_minutes', str(session_timeout)),
                ('max_login_attempts', str(max_login_attempts)),
                ('lockout_duration_minutes', str(lockout_duration)),
                ('require_strong_passwords', '1' if require_strong_passwords else '0'),
                ('dashboard_refresh_rate', refresh_rate),
                ('dashboard_chart_style', chart_style),
                ('dashboard_default_view', default_view),
                ('dashboard_show_metrics', '1' if show_metrics else '0'),
                ('dashboard_show_charts', '1' if show_charts else '0'),
                ('dashboard_dark_mode', '1' if dark_mode else '0'),
                ('logs_retention_days', str(logs_retention)),
                ('files_retention_days', str(files_retention)),
                ('backups_enabled', '1' if backups_enabled else '0'),
                ('backup_frequency', backup_frequency),
                ('auto_cleanup', '1' if auto_cleanup else '0')
            ]
            
            conn = self.db.get_connection()
            cursor = conn.cursor()
            for key, value in settings_to_save:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, datetime('now'))
                ''', (key, value))
            conn.commit()
            
            st.success("General settings saved!")