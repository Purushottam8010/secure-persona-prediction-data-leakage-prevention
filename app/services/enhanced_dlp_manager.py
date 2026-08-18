# Create new file: app/services/enhanced_dlp_manager.py
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import re

class EnhancedDLPManager:
    """Complete DLP management with alerting and persistence"""
    
    def __init__(self, db_manager, email_system=None):
        self.db = db_manager
        self.email_system = email_system
        self.blocked_files_dir = Path("data/blocked_files")
        self.blocked_files_dir.mkdir(parents=True, exist_ok=True)
        
        # Indian-specific patterns
        self.patterns = {
            'aadhaar': re.compile(r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b'),
            'pan': re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
            'upi_id': re.compile(r'\b[\w\.-]+@(okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl)\b'),
            'indian_mobile': re.compile(r'\b(\+91|0)?[6789]\d{9}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        }
    
    def scan_and_block(self, file_path: str, user_id: int, context: Dict) -> Dict:
        """Complete DLP scan with blocking and alerting"""
        # Extract text
        text = self._extract_text(file_path)
        
        # Check patterns
        violations = {}
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                violations[pattern_name] = {
                    'count': len(matches),
                    'samples': matches[:3]  # Don't expose all data
                }
        
        # Determine action
        if violations:
            # Save blocked file copy
            blocked_path = self._save_blocked_copy(file_path, user_id)
            
            # Determine severity
            severity = self._determine_severity(violations)
            action = 'block'
            
            # Log violation
            file_id = self._log_violation(
                user_id, file_path, violations, 
                action, severity, context
            )
            
            # Trigger admin alert
            self._trigger_admin_alert(user_id, file_id, violations, severity)
            
            # Delete original if blocked
            if action == 'block':
                try:
                    os.remove(file_path)
                except:
                    pass
            
            return {
                'blocked': True,
                'violations': violations,
                'severity': severity,
                'file_id': file_id,
                'blocked_path': str(blocked_path)
            }
        
        return {'blocked': False, 'violations': {}}
    
    def _save_blocked_copy(self, file_path: str, user_id: int) -> Path:
        """Save a copy of blocked file for audit trail"""
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        blocked_filename = f"{user_id}_{timestamp}_{filename}"
        blocked_path = self.blocked_files_dir / blocked_filename
        
        try:
            with open(file_path, 'rb') as src, open(blocked_path, 'wb') as dst:
                dst.write(src.read())
            return blocked_path
        except Exception as e:
            print(f"Failed to save blocked copy: {e}")
            return Path(file_path)
    
    def _log_violation(self, user_id: int, file_path: str, 
                      violations: Dict, action: str, 
                      severity: str, context: Dict) -> int:
        """Log DLP violation to database"""
        try:
            # First save file record as blocked
            file_id = self.db.save_file_record(
                user_id=user_id,
                filename=os.path.basename(file_path),
                filepath=str(self.blocked_files_dir),
                file_type='blocked',
                file_size=0,
                risk_score=1.0,  # Maximum risk
                scan_result=violations,
                approval_status='blocked',
                dlp_action=action,
                dlp_reason=f"DLP violation: {', '.join(violations.keys())}"
            )
            
            # Log to dlp_violations table
            self.db.log_dlp_violation(
                user_id=user_id,
                violation_type='dlp_pattern_match',
                action_taken=action,
                severity=severity,
                file_id=file_id,
                detected_pattern=json.dumps(list(violations.keys())),
                matched_content=json.dumps(violations)
            )
            
            # Log security event
            self.db.log_security_event(
                user_id=user_id,
                action_type='dlp_violation_blocked',
                risk_score=1.0,
                file_name=os.path.basename(file_path),
                file_path=str(file_path),
                ip_address=context.get('ip_address'),
                user_agent=context.get('user_agent'),
                dlp_action=action,
                detection_details=violations
            )
            
            # Create alert
            self.db.create_alert(
                alert_type='dlp_violation',
                user_id=user_id,
                file_id=file_id,
                severity=severity,
                title=f'DLP Violation Blocked: {severity.upper()}',
                message=f'File blocked due to {len(violations)} DLP violations'
            )
            
            return file_id
        except Exception as e:
            print(f"Error logging violation: {e}")
            return -1
    
    def _trigger_admin_alert(self, user_id: int, file_id: int, 
                           violations: Dict, severity: str):
        """Trigger email alert to admin"""
        if self.email_system:
            try:
                # Get user info
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT username, email FROM users WHERE id = ?', (user_id,))
                user = cursor.fetchone()
                
                # Get file info
                cursor.execute('SELECT filename FROM files WHERE id = ?', (file_id,))
                file_info = cursor.fetchone()
                
                # Send email
                self.email_system.send_dlp_alert(
                    user_info={'username': user['username'], 'email': user['email']},
                    file_info={'filename': file_info['filename'] if file_info else 'Unknown'},
                    dlp_action={'action': 'block', 'severity': severity},
                    scan_results={'violations': violations}
                )
            except Exception as e:
                print(f"Failed to send admin alert: {e}")
    
    def _extract_text(self, file_path: str) -> str:
        """Extract text from file (simplified)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            return ""
    
    def _determine_severity(self, violations: Dict) -> str:
        """Determine violation severity"""
        critical_patterns = {'aadhaar', 'pan', 'credit_card', 'ssn'}
        if any(p in violations for p in critical_patterns):
            return 'critical'
        elif len(violations) >= 3:
            return 'high'
        elif len(violations) >= 1:
            return 'medium'
        return 'low'