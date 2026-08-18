import time
import streamlit as st
from datetime import datetime, timedelta
from typing import Optional, Dict

class SessionManager:
    """Manage user sessions with timeout and activity tracking"""
    
    def __init__(self, timeout_minutes: int = 30):
        self.timeout_minutes = timeout_minutes
        self.session_key = "user_session"
        self.last_activity_key = "last_activity"
    
    def start_session(self, user_id: int, username: str, role: str):
        """Start a new user session"""
        st.session_state[self.session_key] = {
            'user_id': user_id,
            'username': username,
            'role': role,
            'login_time': datetime.now().isoformat()
        }
        self.update_activity()
    
    def update_activity(self):
        """Update last activity timestamp"""
        st.session_state[self.last_activity_key] = time.time()
    
    def is_session_valid(self) -> bool:
        """Check if current session is still valid"""
        if self.session_key not in st.session_state:
            return False
        
        if self.last_activity_key not in st.session_state:
            return False
        
        last_activity = st.session_state[self.last_activity_key]
        time_since_activity = time.time() - last_activity
        
        if time_since_activity > (self.timeout_minutes * 60):
            self.end_session()
            return False
        
        return True
    
    def end_session(self):
        """End the current session"""
        if self.session_key in st.session_state:
            del st.session_state[self.session_key]
        if self.last_activity_key in st.session_state:
            del st.session_state[self.last_activity_key]
    
    def get_current_user(self) -> Optional[Dict]:
        """Get current user information"""
        return st.session_state.get(self.session_key, None)
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated and session is valid"""
        return self.session_key in st.session_state and self.is_session_valid()

# Middleware function to check session
def session_middleware():
    """Middleware to check session validity on each page load"""
    session_manager = SessionManager()
    
    if 'session_manager' not in st.session_state:
        st.session_state.session_manager = session_manager
    
    # Update activity on each interaction
    if session_manager.is_authenticated():
        session_manager.update_activity()
    
    return session_manager