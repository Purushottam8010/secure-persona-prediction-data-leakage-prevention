# app/security/persona_detector.py
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import statistics
import json
import re


class PersonaDetector:
    """User behavior profiling and anomaly detection for persona detection"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.behavior_weights = {
            'login_time': 0.25,
            'ip_consistency': 0.20,
            'upload_frequency': 0.30,
            'device_consistency': 0.15,
            'session_duration': 0.10
        }
        self.risk_threshold = 0.7  # Above this triggers alerts
        
    def build_persona_profile(self, user_id: int) -> Dict:
        """Build behavioral profile from historical data"""
        activities = self.db.get_user_activities(user_id, limit=1000)
        
        if not activities:
            return self._create_initial_profile(user_id)
        
        # Extract patterns from activities
        login_times = []
        ip_addresses = []
        devices = []
        upload_times = []
        
        for activity in activities:
            timestamp = activity.get('timestamp')
            if timestamp:
                try:
                    login_times.append(datetime.fromisoformat(timestamp))
                except:
                    pass
            
            ip = activity.get('ip_address', '')
            if ip:
                ip_addresses.append(ip)
            
            device = activity.get('user_agent', '')
            if device:
                devices.append(device)
            
            if activity.get('activity_type') == 'file_upload':
                try:
                    upload_times.append(datetime.fromisoformat(timestamp))
                except:
                    pass
        
        profile = {
            'user_id': user_id,
            'login_time_pattern': self._analyze_time_pattern(login_times),
            'common_ips': self._get_common_values(ip_addresses, top_n=3),
            'common_devices': self._get_device_patterns(devices),
            'upload_pattern': self._analyze_upload_pattern(upload_times),
            'avg_session_duration': self._calculate_avg_session_duration(user_id),
            'total_uploads': len(upload_times),
            'profile_built_at': datetime.now().isoformat()
        }
        
        # Save profile to database
        self.db.save_persona_profile(user_id, profile)
        
        return profile
    
    def calculate_risk_score(self, user_id: int, current_activity: Dict) -> Tuple[float, Dict]:
        """Calculate risk score by comparing current behavior with historical profile"""
        profile = self.db.get_persona_profile(user_id)
        if not profile:
            profile_data = self.build_persona_profile(user_id)
            if isinstance(profile_data, dict):
                profile = {'profile_data': profile_data}
        
        if not profile:
            return 0.0, {}
        
        # Get profile data
        if isinstance(profile.get('profile_data'), str):
            try:
                profile_data = json.loads(profile['profile_data'])
            except:
                profile_data = {}
        else:
            profile_data = profile.get('profile_data', {})
        
        risk_factors = {}
        total_score = 0
        
        # 1. Login time anomaly
        current_time = datetime.now()
        login_pattern = profile_data.get('login_time_pattern', {})
        risk_factors['login_time'] = self._check_time_anomaly(current_time, login_pattern)
        total_score += risk_factors['login_time'] * self.behavior_weights['login_time']
        
        # 2. IP address anomaly
        current_ip = current_activity.get('ip_address', '')
        common_ips = profile_data.get('common_ips', [])
        risk_factors['ip_consistency'] = self._check_ip_anomaly(current_ip, common_ips)
        total_score += risk_factors['ip_consistency'] * self.behavior_weights['ip_consistency']
        
        # 3. Device/browser anomaly
        current_device = current_activity.get('user_agent', '')
        common_devices = profile_data.get('common_devices', [])
        risk_factors['device_consistency'] = self._check_device_anomaly(current_device, common_devices)
        total_score += risk_factors['device_consistency'] * self.behavior_weights['device_consistency']
        
        # 4. Upload frequency anomaly
        upload_count = self.db.count_user_files(user_id)
        risk_factors['upload_frequency'] = self._check_upload_anomaly(upload_count, profile_data)
        total_score += risk_factors['upload_frequency'] * self.behavior_weights['upload_frequency']
        
        return min(total_score, 1.0), risk_factors
    
    def _check_time_anomaly(self, current_time: datetime, time_pattern: Dict) -> float:
        """Check if login time is unusual"""
        hour = current_time.hour
        typical_hours = time_pattern.get('typical_hours', [9, 10, 11, 14, 15, 16])  # 9AM-5PM
        
        if hour in typical_hours:
            return 0.0
        elif 0 <= hour < 6:  # Midnight to 6AM
            return 0.8
        elif 18 <= hour <= 23:  # 6PM to 11PM
            return 0.5
        else:
            return 0.3
    
    def _check_ip_anomaly(self, current_ip: str, common_ips: List[str]) -> float:
        """Check if IP address is unusual"""
        if not current_ip or current_ip in common_ips:
            return 0.0
        
        # Check if IP is from same country/region (basic check)
        if common_ips:
            current_prefix = '.'.join(current_ip.split('.')[:2])  # First two octets
            for ip in common_ips:
                if ip and '.' in ip:
                    ip_prefix = '.'.join(ip.split('.')[:2])
                    if ip_prefix == current_prefix:
                        return 0.2
        
        return 0.8  # Completely new IP
    
    def _check_device_anomaly(self, current_device: str, common_devices: List[str]) -> float:
        """Check if device/browser is unusual"""
        if not current_device or not common_devices:
            return 0.3
        
        # Simple device matching
        current_lower = current_device.lower()
        for device in common_devices:
            if device and device.lower() in current_lower:
                return 0.0
        
        return 0.6
    
    def _check_upload_anomaly(self, current_count: int, profile_data: Dict) -> float:
        """Check if upload frequency is unusual"""
        total_uploads = profile_data.get('total_uploads', 0)
        if total_uploads == 0:
            return 0.0
        
        # Calculate average daily uploads
        upload_pattern = profile_data.get('upload_pattern', {})
        avg_daily = upload_pattern.get('avg_per_day', 1)
        
        if current_count > avg_daily * 3:  # 3x more than average
            return 0.7
        elif current_count > avg_daily * 2:  # 2x more than average
            return 0.4
        else:
            return 0.0
    
    def _analyze_time_pattern(self, times: List[datetime]) -> Dict:
        """Analyze typical login times"""
        if not times:
            return {'typical_hours': [9, 10, 11, 14, 15, 16], 'spread': 'unknown'}
        
        hours = [t.hour for t in times]
        hour_counts = {}
        for hour in hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        # Get top 6 most common hours
        typical_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        typical_hours = [h[0] for h in typical_hours]
        
        return {
            'typical_hours': typical_hours,
            'spread': 'wide' if len(set(hours)) > 8 else 'narrow',
            'most_common_hour': max(hour_counts, key=hour_counts.get) if hour_counts else 9
        }
    
    def _get_common_values(self, values: List[str], top_n: int = 3) -> List[str]:
        """Get most common values from list"""
        if not values:
            return []
        
        value_counts = {}
        for value in values:
            if value:
                value_counts[value] = value_counts.get(value, 0) + 1
        
        # Return top N most common values
        sorted_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)
        return [v[0] for v in sorted_values[:top_n]]
    
    def _get_device_patterns(self, devices: List[str]) -> List[str]:
        """Extract device patterns"""
        if not devices:
            return []
        
        patterns = []
        for device in devices:
            if not device:
                continue
            
            # Extract browser/OS info
            device_lower = device.lower()
            if 'chrome' in device_lower:
                patterns.append('chrome')
            elif 'firefox' in device_lower:
                patterns.append('firefox')
            elif 'safari' in device_lower:
                patterns.append('safari')
            elif 'edge' in device_lower:
                patterns.append('edge')
            
            if 'windows' in device_lower:
                patterns.append('windows')
            elif 'mac' in device_lower:
                patterns.append('macos')
            elif 'linux' in device_lower:
                patterns.append('linux')
            elif 'android' in device_lower:
                patterns.append('android')
            elif 'iphone' in device_lower or 'ipad' in device_lower:
                patterns.append('ios')
        
        return list(set(patterns))
    
    def _analyze_upload_pattern(self, upload_times: List[datetime]) -> Dict:
        """Analyze upload patterns"""
        if not upload_times:
            return {'avg_per_day': 1, 'pattern': 'unknown'}
        
        # Group by day
        uploads_by_day = {}
        for time in upload_times:
            day = time.date().isoformat()
            uploads_by_day[day] = uploads_by_day.get(day, 0) + 1
        
        avg_per_day = sum(uploads_by_day.values()) / len(uploads_by_day) if uploads_by_day else 1
        
        return {
            'avg_per_day': avg_per_day,
            'max_per_day': max(uploads_by_day.values()) if uploads_by_day else 1,
            'total_days': len(uploads_by_day),
            'pattern': 'regular' if avg_per_day > 0.5 else 'sporadic'
        }
    
    def _calculate_avg_session_duration(self, user_id: int) -> float:
        """Calculate average session duration (in minutes)"""
        activities = self.db.get_user_activities(user_id, limit=100)
        login_times = []
        logout_times = []
        
        for activity in activities:
            if activity['activity_type'] == 'login_success':
                try:
                    login_times.append(datetime.fromisoformat(activity['timestamp']))
                except:
                    pass
            elif activity['activity_type'] == 'logout':
                try:
                    logout_times.append(datetime.fromisoformat(activity['timestamp']))
                except:
                    pass
        
        if len(login_times) < 2:
            return 30.0  # Default 30 minutes
        
        # Calculate average time between logins (simplified)
        login_times.sort()
        durations = []
        for i in range(1, len(login_times)):
            duration = (login_times[i] - login_times[i-1]).total_seconds() / 60
            if duration < 480:  # Less than 8 hours (reasonable session)
                durations.append(duration)
        
        return statistics.mean(durations) if durations else 30.0
    
    def _create_initial_profile(self, user_id: int) -> Dict:
        """Create initial profile for new user"""
        return {
            'user_id': user_id,
            'login_time_pattern': {'typical_hours': [9, 10, 11, 14, 15, 16], 'spread': 'unknown'},
            'common_ips': [],
            'common_devices': [],
            'upload_pattern': {'avg_per_day': 0, 'pattern': 'new_user'},
            'avg_session_duration': 30.0,
            'total_uploads': 0,
            'profile_built_at': datetime.now().isoformat()
        }
    
    def detect_persona_anomaly(self, user_id: int, context: Dict) -> Optional[Dict]:
        """Detect persona anomalies and trigger alerts if needed"""
        risk_score, risk_factors = self.calculate_risk_score(user_id, context)
        
        if risk_score >= self.risk_threshold:
            # Get user info for alert
            user_info = self._get_user_info(user_id)
            
            anomaly = {
                'user_id': user_id,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'context': context,
                'timestamp': datetime.now().isoformat(),
                'user_info': user_info
            }
            
            # Log security event
            self.db.log_security_event(
                user_id=user_id,
                action_type='persona_anomaly',
                ip_address=context.get('ip_address'),
                user_agent=context.get('user_agent'),
                risk_score=risk_score,
                persona_anomaly_score=risk_score,
                detection_details={'risk_factors': risk_factors}
            )
            
            # Create alert
            self.db.create_alert(
                alert_type='persona_anomaly',
                user_id=user_id,
                severity='high' if risk_score > 0.8 else 'medium',
                title=f'Persona Anomaly Detected - {user_info.get("username", "User")}',
                message=f'User behavior anomaly detected. Risk score: {risk_score:.2%}'
            )
            
            return anomaly
        
        return None
    
    def _get_user_info(self, user_id: int) -> Dict:
        """Get basic user info"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, role FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else {'username': 'Unknown', 'email': 'Unknown', 'role': 'user'}