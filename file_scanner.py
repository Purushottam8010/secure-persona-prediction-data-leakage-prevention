# file_scanner.py - CORRECTED VERSION
import PyPDF2
import pandas as pd
from docx import Document
import re
import json
import os
from typing import Dict, List, Tuple
import magic
from datetime import datetime

# Define FileScanner class FIRST
class FileScanner:
    """Base file scanner class"""
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.sensitive_keywords = [
            'password', 'secret', 'confidential', 'private',
            'ssn', 'credit card', 'bank account', 'password',
            'token', 'api key', 'credentials', 'login'
        ]
    
    def scan_file(self, file_path: str) -> Dict:
        """Base scanning method"""
        return {
            'safe': True,
            'risk_level': 'low',
            'file_type': self._detect_file_type(file_path)
        }
    
    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type"""
        try:
            mime = magic.from_file(file_path, mime=True)
            return mime
        except:
            return 'unknown'
    
    def _extract_all_text(self, file_path: str) -> str:
        """Extract text from various file types"""
        text = ""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext == '.pdf':
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        text += page.extract_text() + " "
            elif file_ext in ['.docx', '.doc']:
                doc = Document(file_path)
                for para in doc.paragraphs:
                    text += para.text + " "
            elif file_ext in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
                text = df.to_string()
            elif file_ext == '.txt':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
        except Exception as e:
            print(f"Error extracting text: {e}")
        
        return text

# Then define EnhancedFileScanner that inherits from FileScanner
class EnhancedFileScanner(FileScanner):
    """Extended file scanner with Indian-specific patterns and DLP actions"""
    
    def __init__(self, db_manager=None):
        super().__init__(db_manager)
        self.dlp_config = self.load_dlp_config()
        
        # Add Indian-specific patterns
        self.indian_patterns = {
            'aadhaar': r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b',
            'pan': r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
            'upi_id': r'\b[\w\.-]+@(okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl)\b',
            'indian_mobile': r'\b(\+91|0)?[6789]\d{9}\b'
        }
        
        # Sensitive content keywords for Indian context
        self.sensitive_keywords.extend([
            'aadhaar', 'pan card', 'permanent account number',
            'voter id', 'ration card', 'driving license',
            'passport', 'bank statement', 'salary slip',
            'income tax', 'gst', 'gstin', 'company registration',
            'incorporation', 'memorandum', 'articles of association'
        ])
    
    # ... rest of your EnhancedFileScanner methods ...
    
    def load_dlp_config(self) -> Dict:
        """Load DLP configuration from file"""
        config_path = "config/dlp_config.json"
        default_config = {
            "block_sensitive_types": True,
            "encrypt_on_detection": False,
            "notify_admin": True,
            "thresholds": {
                "aadhaar": "block",
                "pan": "block",
                "upi": "warn",
                "pii_count": 5
            },
            "action": "block"  # block, encrypt, or warn
        }
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except:
            return default_config
    
    def scan_with_dlp(self, file_path: str, user_id: int, context: Dict) -> Dict:
        """Enhanced scan with DLP actions"""
        # Perform standard scan
        scan_results = self.scan_file(file_path)
        
        # Check for Indian-specific patterns
        indian_detections = self._scan_indian_patterns(file_path)
        if indian_detections:
            scan_results['indian_detections'] = indian_detections
            scan_results['has_leak'] = True
        
        # Apply DLP rules
        dlp_action = self._apply_dlp_rules(scan_results, indian_detections)
        scan_results['dlp_action'] = dlp_action
        
        # Log DLP event
        self._log_dlp_event(user_id, file_path, scan_results, dlp_action, context)
        
        # Take action if needed
        if dlp_action['action'] == 'block':
            self._handle_block_action(file_path, user_id, dlp_action)
        elif dlp_action['action'] == 'encrypt':
            encrypted_path = self._encrypt_file(file_path, user_id)
            scan_results['encrypted_path'] = encrypted_path
            scan_results['original_path'] = file_path
        
        return scan_results
    
    def _scan_indian_patterns(self, file_path: str) -> Dict:
        """Scan for Indian-specific sensitive patterns"""
        text = self._extract_all_text(file_path)
        detections = {}
        
        for pattern_name, pattern in self.indian_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detections[pattern_name] = {
                    'count': len(matches),
                    'samples': matches[:2]  # Don't expose full data
                }
        
        return detections
    
    def _apply_dlp_rules(self, scan_results: Dict, indian_detections: Dict) -> Dict:
        """Apply DLP rules to determine action"""
        config = self.dlp_config
        
        # Check for critical Indian patterns
        if 'aadhaar' in indian_detections or 'pan' in indian_detections:
            return {
                'action': 'block',
                'reason': 'Contains Aadhaar/PAN numbers',
                'severity': 'critical'
            }
        
        # Check PII count threshold
        pii_count = scan_results.get('pii_count', 0)
        if pii_count >= config['thresholds'].get('pii_count', 5):
            return {
                'action': 'encrypt' if config.get('encrypt_on_detection') else 'block',
                'reason': f'Contains {pii_count} PII elements',
                'severity': 'high'
            }
        
        # Check for sensitive keywords
        keyword_count = scan_results.get('keyword_count', 0)
        if keyword_count >= 3:
            return {
                'action': 'warn',
                'reason': f'Contains {keyword_count} sensitive keywords',
                'severity': 'medium'
            }
        
        return {
            'action': 'allow',
            'reason': 'No DLP violations detected',
            'severity': 'low'
        }
    
    def _log_dlp_event(self, user_id: int, file_path: str, 
                      scan_results: Dict, dlp_action: Dict, context: Dict):
        """Log DLP event to security logs"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO security_logs 
                (user_id, action_type, file_name, file_path, ip_address, 
                 user_agent, risk_score, dlp_action, detection_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                'dlp_scan',
                os.path.basename(file_path),
                file_path,
                context.get('ip_address'),
                context.get('user_agent'),
                scan_results.get('risk_score', 0),
                dlp_action.get('action'),
                json.dumps({
                    'detections': scan_results.get('detections', []),
                    'indian_detections': scan_results.get('indian_detections', {}),
                    'dlp_reason': dlp_action.get('reason')
                })
            ))
            conn.commit()
        except Exception as e:
            print(f"Error logging DLP event: {e}")
            conn.rollback()
    
    def _encrypt_file(self, file_path: str, user_id: int) -> str:
        """Encrypt sensitive file"""
        from cryptography.fernet import Fernet
        import base64
        
        # Generate or retrieve user's encryption key
        key = self._get_user_encryption_key(user_id)
        cipher = Fernet(key)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = cipher.encrypt(file_data)
        
        encrypted_path = file_path + '.encrypted'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Store encryption metadata
        self._store_encryption_metadata(user_id, file_path, encrypted_path)
        
        return encrypted_path