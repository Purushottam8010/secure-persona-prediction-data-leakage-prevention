# Create new file: app/services/approval_workflow.py
import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional
import json

class ApprovalWorkflow:
    """Complete file approval workflow"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def get_pending_approvals(self, admin_id: int = None) -> List[Dict]:
        """Get pending approvals for admin"""
        with self.db.connection_lock:
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                query = '''
                    SELECT 
                        fa.id as approval_id,
                        fa.file_id,
                        fa.user_id,
                        fa.requested_at,
                        fa.risk_level,
                        f.filename,
                        f.file_type,
                        f.file_size,
                        f.risk_score,
                        f.scan_result,
                        f.dlp_action_taken,
                        f.dlp_reason,
                        u.username,
                        u.email,
                        u.full_name
                    FROM file_approvals fa
                    JOIN files f ON fa.file_id = f.id
                    JOIN users u ON fa.user_id = u.id
                    WHERE fa.status = 'pending'
                '''
                
                if admin_id:
                    query += ' AND fa.approver_id IS NULL'
                
                query += ' ORDER BY fa.requested_at DESC'
                
                cursor.execute(query)
                approvals = []
                for row in cursor.fetchall():
                    approval = dict(row)
                    
                    # Parse scan result
                    if approval.get('scan_result'):
                        try:
                            approval['scan_result'] = json.loads(approval['scan_result'])
                        except:
                            approval['scan_result'] = {}
                    
                    approvals.append(approval)
                
                return approvals
            except Exception as e:
                print(f"Error getting pending approvals: {e}")
                return []
    
    def approve_file(self, file_id: int, approver_id: int, notes: str = "") -> bool:
        """Approve a file"""
        try:
            # Update approval record
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE file_approvals 
                SET status = 'approved', 
                    approver_id = ?,
                    approval_notes = ?,
                    reviewed_at = datetime('now')
                WHERE file_id = ? AND status = 'pending'
            ''', (approver_id, notes, file_id))
            
            # Update file status
            cursor.execute('''
                UPDATE files 
                SET approval_status = 'approved'
                WHERE id = ?
            ''', (file_id,))
            
            # Get user info for notification
            cursor.execute('''
                SELECT user_id, filename FROM files WHERE id = ?
            ''', (file_id,))
            file_info = cursor.fetchone()
            
            if file_info:
                # Create user alert
                self.db.create_alert(
                    alert_type='approval_update',
                    user_id=file_info['user_id'],
                    file_id=file_id,
                    severity='low',
                    title='File Approved',
                    message=f'Your file "{file_info["filename"]}" has been approved by admin'
                )
            
            conn.commit()
            
            # Send email notification
            self._send_approval_email(file_id, 'approved', notes)
            
            return True
        except Exception as e:
            print(f"Error approving file: {e}")
            if conn:
                conn.rollback()
            return False
    
    def reject_file(self, file_id: int, approver_id: int, reason: str) -> bool:
        """Reject a file"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE file_approvals 
                SET status = 'rejected', 
                    approver_id = ?,
                    approval_notes = ?,
                    reviewed_at = datetime('now')
                WHERE file_id = ? AND status = 'pending'
            ''', (approver_id, reason, file_id))
            
            cursor.execute('''
                UPDATE files 
                SET approval_status = 'rejected'
                WHERE id = ?
            ''', (file_id,))
            
            # Get user info for notification
            cursor.execute('''
                SELECT user_id, filename FROM files WHERE id = ?
            ''', (file_id,))
            file_info = cursor.fetchone()
            
            if file_info:
                self.db.create_alert(
                    alert_type='approval_update',
                    user_id=file_info['user_id'],
                    file_id=file_id,
                    severity='medium',
                    title='File Rejected',
                    message=f'Your file "{file_info["filename"]}" was rejected: {reason}'
                )
            
            conn.commit()
            
            # Send email notification
            self._send_approval_email(file_id, 'rejected', reason)
            
            return True
        except Exception as e:
            print(f"Error rejecting file: {e}")
            if conn:
                conn.rollback()
            return False
    
    def _send_approval_email(self, file_id: int, status: str, notes: str):
        """Send email notification for approval/rejection"""
        try:
            # Get file and user info
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT f.filename, u.email, u.username 
                FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE f.id = ?
            ''', (file_id,))
            
            result = cursor.fetchone()
            if result and hasattr(self, 'email_system') and self.email_system:
                subject = f"File {status.capitalize()}: {result['filename']}"
                body = f"""
                Your file "{result['filename']}" has been {status}.
                
                Status: {status.upper()}
                Notes: {notes}
                Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
                ---
                Secure File Approval System
                """
                
                self.email_system.send_email(
                    to_email=result['email'],
                    subject=subject,
                    body=body
                )
        except Exception as e:
            print(f"Failed to send approval email: {e}")