import json
from datetime import datetime

class ApprovalWorkflow:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def get_pending_approvals(self, admin_id=None):
        """Get pending approvals"""
        try:
            # Use get_connection() instead of connection_lock
            with self.db.get_connection() as conn:
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
    
    def approve_file(self, file_id, approver_id, notes=""):
        """Approve a file"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE file_approvals 
                    SET status = 'approved', 
                        approver_id = ?,
                        approval_notes = ?,
                        reviewed_at = datetime('now')
                    WHERE file_id = ? AND status = 'pending'
                ''', (approver_id, notes, file_id))
                
                cursor.execute('''
                    UPDATE files 
                    SET approval_status = 'approved'
                    WHERE id = ?
                ''', (file_id,))
                
                # Create notification
                cursor.execute('SELECT user_id, filename FROM files WHERE id = ?', (file_id,))
                file_info = cursor.fetchone()
                
                if file_info:
                    self.db.create_notification(
                        user_id=file_info['user_id'],
                        title='File Approved',
                        message=f'Your file "{file_info["filename"]}" has been approved'
                    )
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error approving file: {e}")
            return False
    
    def reject_file(self, file_id, approver_id, reason):
        """Reject a file"""
        try:
            with self.db.get_connection() as conn:
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
                
                # Create notification
                cursor.execute('SELECT user_id, filename FROM files WHERE id = ?', (file_id,))
                file_info = cursor.fetchone()
                
                if file_info:
                    self.db.create_notification(
                        user_id=file_info['user_id'],
                        title='File Rejected',
                        message=f'Your file "{file_info["filename"]}" was rejected: {reason}'
                    )
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error rejecting file: {e}")
            return False
    
    def get_approval_history(self, user_id=None, limit=50):
        """Get approval history"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT 
                        fa.id as approval_id,
                        fa.file_id,
                        fa.user_id,
                        fa.approver_id,
                        fa.status,
                        fa.risk_level,
                        fa.approval_notes,
                        fa.requested_at,
                        fa.reviewed_at,
                        f.filename,
                        f.risk_score,
                        u.username,
                        approver.username as approver_username
                    FROM file_approvals fa
                    JOIN files f ON fa.file_id = f.id
                    JOIN users u ON fa.user_id = u.id
                    LEFT JOIN users approver ON fa.approver_id = approver.id
                '''
                
                params = []
                if user_id:
                    query += ' WHERE fa.user_id = ?'
                    params.append(user_id)
                
                query += ' ORDER BY fa.reviewed_at DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting approval history: {e}")
            return []