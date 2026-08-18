import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
import streamlit as st
import pandas as pd

class NotificationService:
    """Real-time notification system for approvals, DLP alerts, and system events"""
    
    def __init__(self, db_path: str = "data/security.db"):
        self.db_path = db_path
        
    def create_tables(self):
        """Create notification tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                notification_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notification_preferences (
                user_id INTEGER PRIMARY KEY,
                email_notifications BOOLEAN DEFAULT 1,
                in_app_notifications BOOLEAN DEFAULT 1,
                file_approved BOOLEAN DEFAULT 1,
                file_rejected BOOLEAN DEFAULT 1,
                dlp_alert BOOLEAN DEFAULT 1,
                system_alert BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_notification(self, user_id: int, notification_type: str, title: str, 
                        message: str, metadata: Dict = None):
        """Add a new notification for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO notifications (user_id, notification_type, title, message, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, notification_type, title, message, json.dumps(metadata) if metadata else None))
        
        conn.commit()
        conn.close()
        
        # Trigger real-time update in session state
        if 'notifications' in st.session_state:
            st.session_state.notifications = self.get_unread_notifications(user_id)
    
    def get_unread_notifications(self, user_id: int) -> List[Dict]:
        """Get unread notifications for a user"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM notifications 
            WHERE user_id = ? AND is_read = 0 
            ORDER BY created_at DESC
        """, (user_id,))
        
        notifications = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return notifications
    
    def mark_as_read(self, notification_id: int):
        """Mark a notification as read"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
        conn.commit()
        conn.close()
    
    def mark_all_as_read(self, user_id: int):
        """Mark all notifications as read for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
    
    def get_notification_preferences(self, user_id: int) -> Dict:
        """Get user's notification preferences"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM notification_preferences WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return dict(result)
        
        # Return default preferences
        return {
            'user_id': user_id,
            'email_notifications': 1,
            'in_app_notifications': 1,
            'file_approved': 1,
            'file_rejected': 1,
            'dlp_alert': 1,
            'system_alert': 1
        }
    
    def update_preferences(self, user_id: int, preferences: Dict):
        """Update notification preferences"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO notification_preferences 
            (user_id, email_notifications, in_app_notifications, file_approved, 
             file_rejected, dlp_alert, system_alert)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, 
              preferences.get('email_notifications', 1),
              preferences.get('in_app_notifications', 1),
              preferences.get('file_approved', 1),
              preferences.get('file_rejected', 1),
              preferences.get('dlp_alert', 1),
              preferences.get('system_alert', 1)))
        
        conn.commit()
        conn.close()

def render_notification_center(notification_service: NotificationService, user_id: int):
    """Render the notification center UI component"""
    
    # Initialize session state for notifications
    if 'notifications' not in st.session_state:
        st.session_state.notifications = notification_service.get_unread_notifications(user_id)
    
    # CSS for notification bell
    st.markdown("""
        <style>
        .notification-bell {
            position: relative;
            display: inline-block;
            cursor: pointer;
            font-size: 24px;
        }
        .notification-badge {
            position: absolute;
            top: -8px;
            right: -8px;
            background-color: red;
            color: white;
            border-radius: 50%;
            padding: 2px 6px;
            font-size: 12px;
            font-weight: bold;
        }
        .notification-dropdown {
            position: absolute;
            right: 0;
            top: 40px;
            width: 350px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            z-index: 1000;
            max-height: 400px;
            overflow-y: auto;
        }
        .notification-item {
            padding: 12px;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }
        .notification-item:hover {
            background: #f5f5f5;
        }
        .notification-unread {
            background: #e3f2fd;
            border-left: 3px solid #2196f3;
        }
        .notification-title {
            font-weight: bold;
            margin-bottom: 4px;
        }
        .notification-message {
            font-size: 12px;
            color: #666;
        }
        .notification-time {
            font-size: 10px;
            color: #999;
            margin-top: 4px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Notification Bell Icon
    unread_count = len([n for n in st.session_state.notifications if not n.get('is_read', 0)])
    
    col1, col2, col3 = st.columns([10, 1, 1])
    with col2:
        if st.button("🔔", key="notification_bell"):
            st.session_state.show_notifications = not st.session_state.get('show_notifications', False)
            st.rerun()
        
        if unread_count > 0:
            st.markdown(f'<span class="notification-badge">{unread_count}</span>', unsafe_allow_html=True)
    
    # Notification Dropdown
    if st.session_state.get('show_notifications', False):
        with st.container():
            st.markdown('<div class="notification-dropdown">', unsafe_allow_html=True)
            
            # Header with actions
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown("### 📬 Notifications")
            with col2:
                if st.button("Mark all read", key="mark_all_read"):
                    notification_service.mark_all_as_read(user_id)
                    st.session_state.notifications = []
                    st.session_state.show_notifications = False
                    st.rerun()
            
            # Notification list
            notifications = notification_service.get_unread_notifications(user_id)
            
            if not notifications:
                st.info("✨ No new notifications")
            else:
                for notif in notifications:
                    with st.container():
                        st.markdown(f"""
                        <div class="notification-item notification-unread">
                            <div class="notification-title">{notif['title']}</div>
                            <div class="notification-message">{notif['message']}</div>
                            <div class="notification-time">{notif['created_at']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        if st.button("Mark read", key=f"mark_read_{notif['id']}"):
                            notification_service.mark_as_read(notif['id'])
                            st.rerun()
            
            st.markdown('</div>', unsafe_allow_html=True)