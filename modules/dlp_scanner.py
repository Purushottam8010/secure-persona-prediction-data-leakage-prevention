import re
import json
from typing import List, Dict, Tuple
import pandas as pd

class DLPScanner:
    def __init__(self):
        # Define patterns for sensitive data detection
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
        # Keywords that might indicate sensitive info
        self.sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'confidential',
            'private', 'restricted', 'classified', 'personal'
        ]
        
    def scan_text(self, text: str) -> Dict:
        """Scan text for potential PII leaks"""
        results = {
            'has_leak': False,
            'detections': [],
            'risk_level': 'low'
        }
        
        if not isinstance(text, str):
            return results
        
        # Check for pattern matches
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results['has_leak'] = True
                results['detections'].append({
                    'type': data_type,
                    'matches': matches[:3],  # Show only first 3 matches
                    'count': len(matches)
                })
        
        # Check for sensitive keywords
        text_lower = text.lower()
        found_keywords = []
        for keyword in self.sensitive_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            results['has_leak'] = True
            results['detections'].append({
                'type': 'sensitive_keyword',
                'keywords': found_keywords
            })
        
        # Determine risk level
        if results['has_leak']:
            leak_types = [d['type'] for d in results['detections']]
            if 'ssn' in leak_types or 'credit_card' in leak_types:
                results['risk_level'] = 'high'
            elif 'email' in leak_types or 'phone' in leak_types:
                results['risk_level'] = 'medium'
        
        return results
    
    def scan_dataframe(self, df: pd.DataFrame) -> Dict:
        """Scan entire dataframe for PII leaks"""
        all_results = {
            'total_rows': len(df),
            'leaking_rows': 0,
            'detections_by_column': {},
            'risk_summary': {}
        }
        
        for column in df.columns:
            col_results = []
            for idx, value in df[column].items():
                if pd.isna(value):
                    continue
                    
                result = self.scan_text(str(value))
                if result['has_leak']:
                    all_results['leaking_rows'] += 1
                    col_results.append({
                        'row': idx,
                        'detections': result['detections'],
                        'risk_level': result['risk_level']
                    })
            
            if col_results:
                all_results['detections_by_column'][column] = col_results
        
        # Generate summary
        risk_counts = {'low': 0, 'medium': 0, 'high': 0}
        for col, detections in all_results['detections_by_column'].items():
            for det in detections:
                risk_counts[det['risk_level']] += 1
        
        all_results['risk_summary'] = risk_counts
        
        return all_results
    
    def mask_sensitive_data(self, text: str) -> str:
        """Mask detected sensitive data in text"""
        masked_text = text
        
        # Mask emails
        masked_text = re.sub(
            self.patterns['email'], 
            '[EMAIL_REDACTED]', 
            masked_text
        )
        
        # Mask SSN
        masked_text = re.sub(
            self.patterns['ssn'],
            '[SSN_REDACTED]',
            masked_text
        )
        
        # Mask phone numbers
        masked_text = re.sub(
            self.patterns['phone'],
            '[PHONE_REDACTED]',
            masked_text
        )
        
        return masked_text

if __name__ == "__main__":
    # Test DLP scanner
    scanner = DLPScanner()
    
    test_texts = [
        "My email is john.doe@example.com and phone is 123-456-7890",
        "SSN: 123-45-6789 and credit card 1234-5678-9012-3456",
        "No sensitive data here",
        "password is secret123 and token is abcdef"
    ]
    
    for text in test_texts:
        print(f"\nText: {text}")
        result = scanner.scan_text(text)
        print(f"Has leak: {result['has_leak']}")
        if result['has_leak']:
            print(f"Detections: {result['detections']}")
            print(f"Masked: {scanner.mask_sensitive_data(text)}")