import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import json
from datetime import datetime

class EmailAlertSystem:
    def __init__(self):
        # Email configuration with your provided credentials
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.smtp_username = "pthombre200@gmail.com"
        self.smtp_password = "ssmb psrj ftad dbqy"  # Your app password
        self.admin_email = "pthombre200@gmail.com"  # Admin email
        
    def send_email(self, to_email, subject, body, html_body=None):
        """Send email to specified recipient"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.smtp_username
            msg['To'] = to_email
            
            # Attach plain text body
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach HTML body if provided
            if html_body:
                msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Email sending failed: {e}")
            return False
    
    def send_incident_alert(self, incident_data):
        """Send alert email for security incident"""
        subject = f"[SECURITY ALERT] {incident_data.get('incident_type', 'Incident')} - {incident_data.get('severity', 'unknown').upper()}"
        
        body = f"""
        SECURITY INCIDENT ALERT
        
        Type: {incident_data.get('incident_type', 'Unknown')}
        Severity: {incident_data.get('severity', 'Unknown').upper()}
        User: {incident_data.get('username', 'Unknown')}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Description: {incident_data.get('description', 'No description')}
        
        Recommended Action: {incident_data.get('recommended_action', 'Review incident immediately')}
        
        ---
        Secure Persona Detection System
        """
        
        return self.send_email(self.admin_email, subject, body)
    
    def send_persona_alert(self, user_info: dict, risk_data: dict, context: dict):
        """Send alert for persona anomaly"""
        subject = f"[PERSONA ALERT] Suspicious behavior detected: {user_info.get('username', 'Unknown')}"
        
        body = f"""
        PERSONA ANOMALY DETECTED
        
        User: {user_info.get('username', 'Unknown')} ({user_info.get('email', 'Unknown')})
        Risk Score: {risk_data.get('combined_score', 0):.2%}
        Risk Level: {risk_data.get('risk_level', 'unknown').upper()}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Context:
        - IP Address: {context.get('ip_address', 'Unknown')}
        - Device: {context.get('user_agent', 'Unknown')}
        - Action: {context.get('action_type', 'Unknown')}
        
        Risk Factors:
        {json.dumps(risk_data.get('persona_factors', {}), indent=2)}
        
        Detected Threats:
        {json.dumps(risk_data.get('threats', []), indent=2)}
        
        Recommendations:
        {chr(10).join(risk_data.get('recommendations', ['No specific recommendations']))}
        
        ---
        Secure Persona Detection System
        Automated Security Alert
        """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #dc3545;">🔴 PERSONA ANOMALY DETECTED</h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;">
                <h3>User Details</h3>
                <p><strong>User:</strong> {user_info.get('username', 'Unknown')} ({user_info.get('email', 'Unknown')})</p>
                <p><strong>Risk Score:</strong> <span style="color: #dc3545; font-weight: bold;">{risk_data.get('combined_score', 0):.2%}</span></p>
                <p><strong>Risk Level:</strong> <span style="color: #dc3545; font-weight: bold;">{risk_data.get('risk_level', 'unknown').upper()}</span></p>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h4>Context</h4>
                <ul>
                    <li><strong>IP Address:</strong> {context.get('ip_address', 'Unknown')}</li>
                    <li><strong>Device:</strong> {context.get('user_agent', 'Unknown')}</li>
                    <li><strong>Action:</strong> {context.get('action_type', 'Unknown')}</li>
                </ul>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #fff3cd; border-radius: 5px;">
                <h4>Risk Factors</h4>
                <pre style="background-color: white; padding: 10px; border-radius: 3px;">{json.dumps(risk_data.get('persona_factors', {}), indent=2)}</pre>
            </div>
            
            <div style="margin-top: 20px;">
                <h4>Recommendations</h4>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in risk_data.get('recommendations', ['No specific recommendations']))}
                </ul>
            </div>
            
            <hr>
            <p style="color: #6c757d; font-size: 0.9em;">
                Secure Persona Detection System<br>
                Automated Security Alert
            </p>
        </body>
        </html>
        """
        
        return self.send_email(self.admin_email, subject, body, html_body)
    
    def send_dlp_alert(self, user_info: dict, file_info: dict, dlp_action: dict, scan_results: dict):
        """Send alert for DLP violation"""
        subject = f"[DLP VIOLATION] {dlp_action.get('action', 'violation').upper()}: {file_info.get('filename', 'Unknown')}"
        
        body = f"""
        DATA LEAKAGE PREVENTION ALERT
        
        User: {user_info.get('username', 'Unknown')}
        File: {file_info.get('filename', 'Unknown')}
        Action Taken: {dlp_action.get('action', 'unknown').upper()}
        Reason: {dlp_action.get('reason', 'Unknown')}
        Severity: {dlp_action.get('severity', 'unknown').upper()}
        
        Scan Results:
        - Risk Score: {scan_results.get('risk_score', 0):.2%}
        - PII Count: {scan_results.get('pii_count', 0)}
        - Keywords Found: {scan_results.get('keyword_count', 0)}
        
        Detected Indian Patterns:
        {json.dumps(scan_results.get('indian_detections', {}), indent=2)}
        
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        ---
        Data Leakage Prevention System
        Automated Security Alert
        """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: {'#dc3545' if dlp_action.get('severity') in ['critical', 'high'] else '#fd7e14'}">
                🛡️ DLP VIOLATION DETECTED
            </h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid {'#dc3545' if dlp_action.get('severity') == 'critical' else '#fd7e14' if dlp_action.get('severity') == 'high' else '#ffc107'}">
                <h3>Violation Details</h3>
                <p><strong>User:</strong> {user_info.get('username', 'Unknown')}</p>
                <p><strong>File:</strong> {file_info.get('filename', 'Unknown')}</p>
                <p><strong>Action Taken:</strong> <span style="color: {'#dc3545' if dlp_action.get('action') == 'block' else '#fd7e14'}">{dlp_action.get('action', 'unknown').upper()}</span></p>
                <p><strong>Reason:</strong> {dlp_action.get('reason', 'Unknown')}</p>
                <p><strong>Severity:</strong> {dlp_action.get('severity', 'unknown').upper()}</p>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #e7f3ff; border-radius: 5px;">
                <h4>Scan Results</h4>
                <ul>
                    <li><strong>Risk Score:</strong> {scan_results.get('risk_score', 0):.2%}</li>
                    <li><strong>PII Count:</strong> {scan_results.get('pii_count', 0)}</li>
                    <li><strong>Keywords Found:</strong> {scan_results.get('keyword_count', 0)}</li>
                </ul>
            </div>
            
            <hr>
            <p style="color: #6c757d; font-size: 0.9em;">
                Data Leakage Prevention System<br>
                Automated Security Alert
            </p>
        </body>
        </html>
        """
        
        return self.send_email(self.admin_email, subject, body, html_body)
    
    def send_user_warning(self, user_info: dict, file_info: dict, risk_score: float, reason: str):
        """Send warning email to user about blocked/risky file"""
        subject = "⚠️ Security Alert: Your File Upload Was Blocked"
        
        body = f"""
        SECURITY NOTICE - FILE UPLOAD BLOCKED
        
        Dear {user_info.get('full_name', user_info.get('username', 'User'))},
        
        Your recent file upload has been BLOCKED by our Data Leakage Prevention (DLP) system.
        
        File Details:
        - Filename: {file_info.get('filename', 'Unknown')}
        - Upload Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        - Risk Score: {risk_score:.2%}
        
        Reason for Block:
        {reason}
        
        What You Can Do:
        1. Remove sensitive information from the file
        2. Re-upload after cleaning sensitive data
        3. Contact your administrator if you believe this is an error
        
        Repeated violations may result in account restrictions.
        
        ---
        Secure Persona Detection System
        Automated Security Alert - Do Not Reply
        """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #dc3545;">⚠️ Security Alert: File Upload Blocked</h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;">
                <p>Dear <strong>{user_info.get('full_name', user_info.get('username', 'User'))}</strong>,</p>
                
                <p>Your recent file upload has been <strong style="color: #dc3545;">BLOCKED</strong> by our Data Leakage Prevention (DLP) system because it contains sensitive information.</p>
                
                <h3>File Details:</h3>
                <ul>
                    <li><strong>Filename:</strong> {file_info.get('filename', 'Unknown')}</li>
                    <li><strong>Upload Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                    <li><strong>Risk Score:</strong> {risk_score:.2%}</li>
                </ul>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #fff3cd; border-radius: 5px;">
                <h3 style="color: #856404;">Reason for Block:</h3>
                <p>{reason}</p>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #d1ecf1; border-radius: 5px;">
                <h3>What You Can Do:</h3>
                <ul>
                    <li>Remove sensitive information from the file</li>
                    <li>Re-upload after cleaning sensitive data</li>
                    <li>Contact your administrator if you believe this is an error</li>
                </ul>
                <p><strong>Note:</strong> Repeated violations may result in account restrictions.</p>
            </div>
            
            <hr>
            <p style="color: #6c757d; font-size: 0.9em;">
                Secure Persona Detection System<br>
                Automated Security Alert - Do Not Reply
            </p>
        </body>
        </html>
        """
        
        user_email = user_info.get('email')
        if not user_email:
            print(f"No email found for user {user_info.get('username')}")
            return False
        
        return self.send_email(user_email, subject, body, html_body)
    
    def send_file_approved_notification(self, user_info: dict, file_info: dict, notes: str = None):
        """Send notification to user when file is approved"""
        subject = "✅ File Approved: Your upload has been approved"
        
        body = f"""
        FILE APPROVED
        
        Dear {user_info.get('full_name', user_info.get('username', 'User'))},
        
        Your file has been approved by the administrator.
        
        File: {file_info.get('filename', 'Unknown')}
        Approved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        {f'Notes: {notes}' if notes else ''}
        
        Thank you for following security policies.
        
        ---
        Secure Persona Detection System
        """
        
        user_email = user_info.get('email')
        if user_email:
            return self.send_email(user_email, subject, body)
        return False
    
    def send_file_rejected_notification(self, user_info: dict, file_info: dict, reason: str):
        """Send notification to user when file is rejected"""
        subject = "❌ File Rejected: Your upload requires attention"
        
        body = f"""
        FILE REJECTED
        
        Dear {user_info.get('full_name', user_info.get('username', 'User'))},
        
        Your file has been rejected by the administrator.
        
        File: {file_info.get('filename', 'Unknown')}
        Rejected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Reason: {reason}
        
        Please review the file and ensure it complies with security policies before re-uploading.
        
        ---
        Secure Persona Detection System
        """
        
        user_email = user_info.get('email')
        if user_email:
            return self.send_email(user_email, subject, body)
        return False
    
    def send_instant_admin_alert(self, user_info: dict, file_info: dict, risk_score: float, dlp_findings: list):
        """Send instant alert to admin for high-risk upload"""
        subject = f"🚨 URGENT: High-Risk File Upload Alert - {file_info.get('filename')}"
        
        findings_text = "\n".join([f"- {finding}" for finding in dlp_findings]) if dlp_findings else "- No specific findings"
        
        body = f"""
        URGENT SECURITY ALERT - HIGH RISK FILE UPLOAD
        
        A high-risk file has been uploaded and requires immediate attention.
        
        User Details:
        - Username: {user_info.get('username', 'Unknown')}
        - Email: {user_info.get('email', 'Unknown')}
        - User ID: {user_info.get('id', 'Unknown')}
        
        File Details:
        - Filename: {file_info.get('filename', 'Unknown')}
        - File Size: {file_info.get('size', 0)} bytes
        - File Type: {file_info.get('file_type', 'Unknown')}
        - Risk Score: {risk_score:.2%}
        
        DLP Findings:
        {findings_text}
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Action Required:
        1. Log into the Admin Dashboard
        2. Go to Approvals tab
        3. Review this file immediately
        4. Take appropriate action (Approve/Reject)
        
        ---
        Secure Persona Detection System - Automated Security Alert
        """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #dc3545;">🚨 URGENT SECURITY ALERT</h2>
            
            <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;">
                <h3>High-Risk File Upload Detected</h3>
                <p>A high-risk file has been uploaded and requires immediate attention.</p>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>👤 User Details</h3>
                <ul>
                    <li><strong>Username:</strong> {user_info.get('username', 'Unknown')}</li>
                    <li><strong>Email:</strong> {user_info.get('email', 'Unknown')}</li>
                    <li><strong>User ID:</strong> {user_info.get('id', 'Unknown')}</li>
                </ul>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>📄 File Details</h3>
                <ul>
                    <li><strong>Filename:</strong> {file_info.get('filename', 'Unknown')}</li>
                    <li><strong>File Size:</strong> {file_info.get('size', 0)} bytes</li>
                    <li><strong>File Type:</strong> {file_info.get('file_type', 'Unknown')}</li>
                    <li><strong>Risk Score:</strong> <span style="color: #dc3545; font-weight: bold;">{risk_score:.2%}</span></li>
                </ul>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #fff3cd; border-radius: 5px;">
                <h3>🔍 DLP Findings</h3>
                <ul>
                    {''.join(f'<li>{finding}</li>' for finding in dlp_findings) if dlp_findings else '<li>No specific findings</li>'}
                </ul>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #d1ecf1; border-radius: 5px;">
                <h3>⚡ Action Required</h3>
                <ol>
                    <li>Log into the Admin Dashboard</li>
                    <li>Go to Approvals tab</li>
                    <li>Review this file immediately</li>
                    <li>Take appropriate action (Approve/Reject)</li>
                </ol>
            </div>
            
            <hr>
            <p style="color: #6c757d; font-size: 0.9em;">
                Secure Persona Detection System - Automated Security Alert<br>
                Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </body>
        </html>
        """
        
        return self.send_email(self.admin_email, subject, body, html_body)
    
    def send_user_notification(self, user_email, user_name, notification_type, details):
        """Send notification to user"""
        subject_map = {
            'file_approved': '✅ File Approved - Secure DLP System',
            'file_rejected': '❌ File Rejected - Secure DLP System',
            'dlp_warning': '⚠️ DLP Warning - Secure DLP System'
        }
        
        subject = subject_map.get(notification_type, f'{notification_type.replace("_", " ").title()} - Secure DLP System')
        
        body = f"""
        SECURITY NOTIFICATION
        
        Dear {user_name},
        
        {details}
        
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        For more details, please log into your account.
        
        ---
        Secure Persona Detection System
        """
        
        return self.send_email(user_email, subject, body)
    
    def send_daily_report(self, report_data, recipient_email=None):
        """Send daily security report"""
        if recipient_email is None:
            recipient_email = self.admin_email
        
        date = datetime.now().strftime('%Y-%m-%d')
        subject = f"Daily Security Report - {date}"
        
        body = f"""
        DAILY SECURITY REPORT
        
        Date: {date}
        
        Summary Statistics:
        - Total Uploads: {report_data.get('total_uploads', 0)}
        - High Risk Files: {report_data.get('high_risk_files', 0)}
        - Medium Risk Files: {report_data.get('medium_risk_files', 0)}
        - Low Risk Files: {report_data.get('low_risk_files', 0)}
        - DLP Violations: {report_data.get('dlp_violations', 0)}
        - Persona Alerts: {report_data.get('persona_alerts', 0)}
        - Active Users: {report_data.get('active_users', 0)}
        
        Top Violations:
        {json.dumps(report_data.get('top_violations', []), indent=2)}
        
        ---
        Secure Persona Detection System - Daily Report
        """
        
        return self.send_email(recipient_email, subject, body)
    
    def test_connection(self):
        """Test email connection and authentication"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                return True, "Connection successful"
        except Exception as e:
            return False, str(e)
    
    def send_test_email(self, to_email=None):
        """Send a test email to verify configuration"""
        if to_email is None:
            to_email = self.admin_email
        
        subject = "Test Email - Secure Persona DLP System"
        body = f"""
        TEST EMAIL
        
        This is a test email from your Secure Persona Detection & DLP System.
        
        Your email configuration is working correctly!
        
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        SMTP Server: {self.smtp_server}
        SMTP Username: {self.smtp_username}
        
        If you received this email, your email system is properly configured.
        
        ---
        Secure Persona Detection System
        """
        
        return self.send_email(to_email, subject, body)


# Helper functions for backward compatibility
def send_incident_alert(incident_data):
    """Legacy function for sending incident alerts"""
    email_system = EmailAlertSystem()
    return email_system.send_incident_alert(incident_data)

def send_persona_alert(user_info, risk_data, context):
    """Helper function for sending persona alerts"""
    email_system = EmailAlertSystem()
    return email_system.send_persona_alert(user_info, risk_data, context)

def send_dlp_alert(user_info, file_info, dlp_action, scan_results):
    """Helper function for sending DLP alerts"""
    email_system = EmailAlertSystem()
    return email_system.send_dlp_alert(user_info, file_info, dlp_action, scan_results)

def send_user_warning(user_info, file_info, risk_score, reason):
    """Helper function for sending user warnings"""
    email_system = EmailAlertSystem()
    return email_system.send_user_warning(user_info, file_info, risk_score, reason)

def send_instant_admin_alert(user_info, file_info, risk_score, dlp_findings):
    """Helper function for sending instant admin alerts"""
    email_system = EmailAlertSystem()
    return email_system.send_instant_admin_alert(user_info, file_info, risk_score, dlp_findings)