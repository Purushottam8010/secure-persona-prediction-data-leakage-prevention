from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
from database import DatabaseManager
from app.security.persona_detector import PersonaDetector

class ThreatDetector:
    """Real-time threat detection and behavior analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.thresholds = {
            'uploads_per_hour': 10,
            'downloads_per_hour': 20,
            'failed_logins': 5,
            'high_risk_files_per_day': 3,
            'concurrent_sessions': 2
        }
        
        # User behavior tracking
        self.user_activity = {}
    
    def analyze_user_behavior(self, user_id: int, activity_type: str, 
                             details: str = None) -> Optional[Dict]:
        """Analyze user behavior for anomalies"""
        current_time = datetime.now()
        
        # Initialize user tracking
        if user_id not in self.user_activity:
            self.user_activity[user_id] = {
                'uploads': [],
                'downloads': [],
                'logins': [],
                'failed_logins': [],
                'high_risk_actions': []
            }
        
        user_data = self.user_activity[user_id]
        
        # Record activity
        if activity_type == 'file_upload':
            user_data['uploads'].append(current_time)
        elif activity_type == 'file_download':
            user_data['downloads'].append(current_time)
        elif activity_type == 'login':
            user_data['logins'].append(current_time)
        elif activity_type == 'login_failed':
            user_data['failed_logins'].append(current_time)
        elif activity_type in ['high_risk_file', 'pii_leak']:
            user_data['high_risk_actions'].append(current_time)
        
        # Clean old records (keep last 24 hours)
        cutoff_time = current_time - timedelta(hours=24)
        for key in user_data:
            user_data[key] = [t for t in user_data[key] if t > cutoff_time]
        
        # Check for anomalies
        anomalies = self._check_anomalies(user_id, user_data, activity_type, details)
        
        return anomalies
    
    def _check_anomalies(self, user_id: int, user_data: Dict, 
                        activity_type: str, details: str) -> Optional[Dict]:
        """Check for specific anomaly patterns"""
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)
        
        # 1. Excessive uploads
        recent_uploads = [t for t in user_data['uploads'] if t > hour_ago]
        if len(recent_uploads) > self.thresholds['uploads_per_hour']:
            return {
                'type': 'excessive_uploads',
                'severity': 'high',
                'description': f'User uploaded {len(recent_uploads)} files in the last hour',
                'threshold': self.thresholds['uploads_per_hour'],
                'actual': len(recent_uploads)
            }
        
        # 2. Excessive downloads
        recent_downloads = [t for t in user_data['downloads'] if t > hour_ago]
        if len(recent_downloads) > self.thresholds['downloads_per_hour']:
            return {
                'type': 'excessive_downloads',
                'severity': 'high',
                'description': f'User downloaded {len(recent_downloads)} files in the last hour',
                'threshold': self.thresholds['downloads_per_hour'],
                'actual': len(recent_downloads)
            }
        
        # 3. Failed login attempts
        recent_failed = [t for t in user_data['failed_logins'] if t > hour_ago]
        if len(recent_failed) >= self.thresholds['failed_logins']:
            return {
                'type': 'brute_force_attempt',
                'severity': 'critical',
                'description': f'{len(recent_failed)} failed login attempts in the last hour',
                'threshold': self.thresholds['failed_logins'],
                'actual': len(recent_failed)
            }
        
        # 4. High-risk files in short period
        day_ago = current_time - timedelta(hours=24)
        recent_high_risk = [t for t in user_data['high_risk_actions'] if t > day_ago]
        if len(recent_high_risk) >= self.thresholds['high_risk_files_per_day']:
            return {
                'type': 'data_exfiltration_pattern',
                'severity': 'critical',
                'description': f'{len(recent_high_risk)} high-risk actions in 24 hours',
                'threshold': self.thresholds['high_risk_files_per_day'],
                'actual': len(recent_high_risk)
            }
        
        # 5. Unusual access patterns (placeholder for ML-based detection)
        if activity_type == 'login':
            # Check for login at unusual time (e.g., 2 AM - 5 AM)
            if 2 <= current_time.hour <= 5:
                return {
                    'type': 'unusual_access_time',
                    'severity': 'medium',
                    'description': f'Login at unusual hour: {current_time.hour}:00',
                    'threshold': 'Normal business hours',
                    'actual': f'{current_time.hour}:00'
                }
        
        return None
    
def detect_insider_threat(self, user_id: int, user_role: str, 
                         action: str, resource: str, details: str = "") -> Optional[Dict]:
    """Detect potential insider threats based on role and action"""
    # Define normal behavior patterns per role
    role_patterns = {
        'user': {
            'allowed_actions': ['upload', 'download_own', 'view_own'],
            'sensitive_resources': ['admin_panel', 'audit_logs', 'all_users']
        },
        'admin': {
            'allowed_actions': ['upload', 'download_all', 'view_all', 'delete', 'config'],
            'sensitive_resources': ['system_config', 'user_credentials']
        }
    }
    
    user_pattern = role_patterns.get(user_role, role_patterns['user'])
    
    # Check for privilege escalation
    if action in ['delete', 'config'] and user_role == 'user':
        return {
            'type': 'privilege_escalation_attempt',
            'severity': 'critical',
            'description': f'User attempted {action} action requiring admin privileges',
            'role': user_role,
            'action': action
        }
    
    # Check for access to sensitive resources
    if resource in user_pattern['sensitive_resources'] and action not in ['view_own']:
        return {
            'type': 'sensitive_resource_access',
            'severity': 'high',
            'description': f'User accessed sensitive resource: {resource}',
            'role': user_role,
            'resource': resource
        }
    
    # Check for bulk data export - FIXED: Now uses details parameter
    if action == 'download_all' and 'download' in details and 'bulk' in details.lower():
        return {
            'type': 'bulk_data_export',
            'severity': 'high',
            'description': 'User attempting bulk data export',
            'role': user_role,
            'action': action
        }
    
    return None
    
def calculate_persona_risk_score(self, user_id: int, current_context: Dict) -> Dict:
        """Enhanced risk scoring combining persona and threat detection"""
        # Get persona risk
        persona_detector = PersonaDetector(self.db)
        persona_score, persona_factors = persona_detector.calculate_risk_score(
        user_id, current_context
    )
    
    # Get threat-based risk
        threat_report = self.generate_threat_report(user_id, period_hours=24)
        threat_score = threat_report.get('risk_score', 0)
    
    # Combine scores (weighted)
        combined_score = (persona_score * 0.6) + (threat_score * 0.4)
    
    # Determine risk level
        if combined_score >= 0.7:
            risk_level = 'critical'
        elif combined_score >= 0.5:
            risk_level = 'high'
        elif combined_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
    
        return {
        'combined_score': combined_score,
        'persona_score': persona_score,
        'threat_score': threat_score,
        'risk_level': risk_level,
        'persona_factors': persona_factors,
        'threats': threat_report.get('threats', []),
        'recommendations': self._generate_enhanced_recommendations(
            persona_factors, 
            threat_report.get('threats', []),
            combined_score
        )
    }

def _generate_enhanced_recommendations(self, persona_factors: Dict, 
                                      threats: List[Dict], score: float) -> List[str]:
    """Generate recommendations based on combined risk factors"""
    recommendations = []
    
    # Persona-based recommendations
    if persona_factors.get('ip_consistency', 0) > 0.5:
        recommendations.append("🔍 Unusual login location detected")
        recommendations.append("   - Verify user identity")
        recommendations.append("   - Check for VPN usage")
    
    if persona_factors.get('login_time', 0) > 0.5:
        recommendations.append("⏰ Unusual login time detected")
        recommendations.append("   - Require MFA for off-hours access")
    
    # Combine with existing threat recommendations
    existing_recs = self._generate_recommendations(threats, score)
    recommendations.extend(existing_recs)
    
    return recommendations