# app/services/dlp_manager.py
import re
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import PyPDF2
from docx import Document
import pandas as pd

class DLPManager:
    """Data Leakage Prevention manager with Indian pattern detection"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.patterns = self._load_patterns()
        self.sensitive_keywords = self._load_keywords()
        self.config = self._load_config()
    
    def _load_patterns(self) -> Dict:
        """Load DLP patterns including Indian-specific patterns"""
        return {
            'aadhaar': re.compile(r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b'),
            'pan': re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
            'upi_id': re.compile(r'\b[\w\.-]+@(okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl)\b'),
            'indian_mobile': re.compile(r'\b(\+91|0)?[6789]\d{9}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        }
    
    def _load_keywords(self) -> List[str]:
        """Load sensitive keywords"""
        return [
            'confidential', 'secret', 'classified', 'restricted', 'proprietary',
            'internal use only', 'do not distribute', 'password', 'token', 'api key',
            'credentials', 'salary', 'bank account', 'routing number', 'patient',
            'medical record', 'diagnosis', 'social security', 'driver license',
            'passport', 'aadhaar', 'pan card', 'permanent account number',
            'voter id', 'ration card', 'driving license', 'bank statement',
            'salary slip', 'income tax', 'gst', 'gstin'
        ]
    
    def _load_config(self) -> Dict:
        """Load DLP configuration"""
        config_path = "config/dlp_config.json"
        default_config = {
            "actions": {
                "aadhaar": "block",
                "pan": "block",
                "credit_card": "encrypt",
                "ssn": "encrypt",
                "pii_count": 3,
                "keyword_count": 5
            },
            "notify_admin": True,
            "log_violations": True,
            "encryption_enabled": True
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
        except:
            pass
        
        return default_config
    
    def scan_file(self, file_path: str, user_id: int, context: Dict) -> Dict:
        """Scan file for sensitive content with DLP rules"""
        if not os.path.exists(file_path):
            return {'error': 'File not found', 'risk_score': 0}
        
        # Extract text based on file type
        text = self._extract_text(file_path)
        
        # Scan for patterns
        pattern_detections = self._scan_patterns(text)
        
        # Scan for keywords
        keyword_detections = self._scan_keywords(text)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(pattern_detections, keyword_detections)
        
        # Determine DLP action
        dlp_action = self._determine_dlp_action(pattern_detections, keyword_detections, risk_score)
        
        # Create scan result
        scan_result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'pattern_detections': pattern_detections,
            'keyword_detections': keyword_detections,
            'risk_score': risk_score,
            'dlp_action': dlp_action,
            'scan_time': datetime.now().isoformat()
        }
        
        # Log DLP violation if needed
        if dlp_action['action'] != 'allow':
            self._log_dlp_violation(user_id, file_path, scan_result, dlp_action, context)
        
        # Notify admin if configured
        if self.config.get('notify_admin', True) and dlp_action['action'] != 'allow':
            self._notify_admin(user_id, file_path, scan_result, dlp_action)
        
        return scan_result
    
    def _extract_text(self, file_path: str) -> str:
        """Extract text from various file types"""
        text = ""
        ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if ext == '.pdf':
                with open(file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    for page in pdf_reader.pages:
                        text += page.extract_text() + "\n"
            
            elif ext == '.docx':
                doc = Document(file_path)
                for paragraph in doc.paragraphs:
                    text += paragraph.text + "\n"
            
            elif ext == '.csv':
                df = pd.read_csv(file_path)
                text = df.to_string()
            
            elif ext == '.txt' or ext == '.log':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
            
            elif ext in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
                text = df.to_string()
        
        except Exception as e:
            print(f"Error extracting text from {file_path}: {e}")
        
        return text
    
    def _scan_patterns(self, text: str) -> Dict:
        """Scan for sensitive patterns"""
        detections = {}
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                detections[pattern_name] = {
                    'count': len(matches),
                    'samples': list(set(matches))[:3]  # Show unique samples, max 3
                }
        
        return detections
    
    def _scan_keywords(self, text: str) -> Dict:
        """Scan for sensitive keywords"""
        text_lower = text.lower()
        detections = {}
        
        for keyword in self.sensitive_keywords:
            # Use regex for whole word matching
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            matches = pattern.findall(text_lower)
            if matches:
                detections[keyword] = len(matches)
        
        return detections
    
    def _calculate_risk_score(self, pattern_detections: Dict, keyword_detections: Dict) -> float:
        """Calculate risk score based on detections"""
        score = 0
        
        # Pattern weights
        pattern_weights = {
            'aadhaar': 0.8,
            'pan': 0.8,
            'credit_card': 0.6,
            'ssn': 0.6,
            'upi_id': 0.4,
            'indian_mobile': 0.3,
            'email': 0.1,
            'ip_address': 0.1
        }
        
        # Add pattern scores
        for pattern_name, detection in pattern_detections.items():
            weight = pattern_weights.get(pattern_name, 0.1)
            count = detection.get('count', 0)
            score += min(weight * count * 0.2, weight)  # Cap contribution
        
        # Add keyword scores
        keyword_count = sum(keyword_detections.values())
        score += min(keyword_count * 0.05, 0.3)  # Max 0.3 from keywords
        
        return min(score, 1.0)
    
    def _determine_dlp_action(self, pattern_detections: Dict, 
                             keyword_detections: Dict, risk_score: float) -> Dict:
        """Determine DLP action based on detections and risk score"""
        actions_config = self.config.get('actions', {})
        
        # Check for critical patterns
        if 'aadhaar' in pattern_detections or 'pan' in pattern_detections:
            return {
                'action': 'block',
                'reason': 'Contains Aadhaar/PAN numbers',
                'severity': 'critical'
            }
        
        # Check for high-risk patterns
        if 'credit_card' in pattern_detections or 'ssn' in pattern_detections:
            return {
                'action': 'encrypt',
                'reason': 'Contains credit card/SSN numbers',
                'severity': 'high'
            }
        
        # Check PII count threshold
        pii_count = sum(d.get('count', 0) for d in pattern_detections.values())
        pii_threshold = actions_config.get('pii_count', 3)
        if pii_count >= pii_threshold:
            return {
                'action': 'encrypt',
                'reason': f'Contains {pii_count} PII elements',
                'severity': 'medium'
            }
        
        # Check keyword count threshold
        keyword_count = sum(keyword_detections.values())
        keyword_threshold = actions_config.get('keyword_count', 5)
        if keyword_count >= keyword_threshold:
            return {
                'action': 'warn',
                'reason': f'Contains {keyword_count} sensitive keywords',
                'severity': 'low'
            }
        
        # Check risk score
        if risk_score > 0.7:
            return {
                'action': 'encrypt',
                'reason': f'High risk score: {risk_score:.2f}',
                'severity': 'high'
            }
        elif risk_score > 0.4:
            return {
                'action': 'warn',
                'reason': f'Medium risk score: {risk_score:.2f}',
                'severity': 'medium'
            }
        
        return {
            'action': 'allow',
            'reason': 'No significant risks detected',
            'severity': 'low'
        }
    
    def _log_dlp_violation(self, user_id: int, file_path: str, 
                          scan_result: Dict, dlp_action: Dict, context: Dict):
        """Log DLP violation to database"""
        try:
            # Save file record first to get file_id
            file_name = os.path.basename(file_path)
            file_id = self.db.save_file_record(
                user_id=user_id,
                filename=file_name,
                filepath=file_path,
                file_type=os.path.splitext(file_path)[1],
                file_size=scan_result.get('file_size', 0),
                risk_score=scan_result.get('risk_score', 0),
                scan_result=json.dumps(scan_result),
                dlp_action=dlp_action.get('action'),
                dlp_reason=dlp_action.get('reason')
            )
            
            # Log DLP violation
            violation_type = self._get_violation_type(scan_result)
            self.db.log_dlp_violation(
                user_id=user_id,
                violation_type=violation_type,
                action_taken=dlp_action.get('action'),
                severity=dlp_action.get('severity', 'medium'),
                file_id=file_id,
                detected_pattern=self._get_detected_patterns(scan_result),
                matched_content=self._get_matched_content_sample(scan_result)
            )
            
            # Log security event
            self.db.log_security_event(
                user_id=user_id,
                action_type='dlp_violation',
                file_name=file_name,
                file_path=file_path,
                ip_address=context.get('ip_address'),
                user_agent=context.get('user_agent'),
                risk_score=scan_result.get('risk_score', 0),
                dlp_action=dlp_action.get('action'),
                detection_details={
                    'violation_type': violation_type,
                    'patterns_found': list(scan_result.get('pattern_detections', {}).keys())
                }
            )
            
        except Exception as e:
            print(f"Error logging DLP violation: {e}")
    
    def _get_violation_type(self, scan_result: Dict) -> str:
        """Determine violation type from scan results"""
        patterns = scan_result.get('pattern_detections', {})
        
        if 'aadhaar' in patterns:
            return 'aadhaar_leak'
        elif 'pan' in patterns:
            return 'pan_leak'
        elif 'credit_card' in patterns or 'ssn' in patterns:
            return 'pii_leak'
        elif patterns:
            return 'sensitive_data_leak'
        else:
            return 'keyword_violation'
    
    def _get_detected_patterns(self, scan_result: Dict) -> str:
        """Get detected patterns as string"""
        patterns = scan_result.get('pattern_detections', {})
        return ', '.join(patterns.keys())
    
    def _get_matched_content_sample(self, scan_result: Dict) -> str:
        """Get sample of matched content (sanitized)"""
        patterns = scan_result.get('pattern_detections', {})
        samples = []
        
        for pattern_name, detection in patterns.items():
            pattern_samples = detection.get('samples', [])
            if pattern_samples:
                # Sanitize samples (mask sensitive data)
                for sample in pattern_samples[:2]:  # Max 2 samples per pattern
                    if pattern_name in ['aadhaar', 'pan', 'credit_card', 'ssn']:
                        # Mask sensitive data
                        masked = re.sub(r'\d', 'X', sample[-4:])  # Mask last 4 chars
                        samples.append(f"{sample[:-4]}{masked}")
                    else:
                        samples.append(sample[:50])  # Truncate
        
        return ' | '.join(samples[:3])  # Max 3 samples total
    
    def _notify_admin(self, user_id: int, file_path: str, 
                     scan_result: Dict, dlp_action: Dict):
        """Notify admin about DLP violation"""
        try:
            from email_alert import EmailAlertSystem
            
            # Get user info
            user_info = self._get_user_info(user_id)
            
            # Create email alert
            email_system = EmailAlertSystem()
            
            # Prepare email data
            file_info = {
                'filename': os.path.basename(file_path),
                'size': scan_result.get('file_size', 0),
                'risk_score': scan_result.get('risk_score', 0)
            }
            
            email_system.send_dlp_alert(
                user_info=user_info,
                file_info=file_info,
                dlp_action=dlp_action,
                scan_result=scan_result
            )
            
        except Exception as e:
            print(f"Error notifying admin: {e}")
    
    def _get_user_info(self, user_id: int) -> Dict:
        """Get user information"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, role FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else {'username': 'Unknown', 'email': 'Unknown', 'role': 'user'}