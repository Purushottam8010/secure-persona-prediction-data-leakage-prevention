import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional
import streamlit as st
import pandas as pd

class AIAdminAgent:
    """Automated AI Agent that processes ALL pending files automatically"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.db_path = db_manager.db_path if hasattr(db_manager, 'db_path') else "data/security.db"
        
        # AI decision thresholds
        self.thresholds = {
            'auto_approve_max_risk': 30,      # Files with risk <= 30 auto-approved
            'auto_reject_min_risk': 70,        # Files with risk >= 70 auto-rejected
            'manual_review_range': (31, 69)    # Files with risk 31-69 need manual review
        }
        
        # Intelligent decision weights
        self.weights = {
            'dlp_violations_weight': 0.4,
            'file_type_weight': 0.2,
            'user_history_weight': 0.3,
            'file_size_weight': 0.1
        }
        
        # Ensure required columns exist
        self._ensure_columns()
    
    def _ensure_columns(self):
        """Ensure required columns exist in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if updated_at column exists
            cursor.execute("PRAGMA table_info(files)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Add updated_at column if it doesn't exist
            if 'updated_at' not in columns:
                try:
                    cursor.execute("ALTER TABLE files ADD COLUMN updated_at TIMESTAMP")
                    print("Added updated_at column to files table")
                except:
                    pass
            
            # Add reviewed_at column if it doesn't exist
            if 'reviewed_at' not in columns:
                try:
                    cursor.execute("ALTER TABLE files ADD COLUMN reviewed_at TIMESTAMP")
                    print("Added reviewed_at column to files table")
                except:
                    pass
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error ensuring columns: {e}")
    
    def scan_and_process_pending_files(self) -> Dict:
        """
        Automatically scan all pending files and make AI decisions
        Returns summary of actions taken
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all pending files
        cursor.execute("""
            SELECT f.*, u.username, u.email, u.department
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.approval_status = 'pending'
            ORDER BY f.uploaded_at ASC
        """)
        
        pending_files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        results = {
            'auto_approved': [],
            'auto_rejected': [],
            'manual_review': [],
            'errors': []
        }
        
        for file in pending_files:
            try:
                decision = self.make_ai_decision(file)
                
                if decision['action'] == 'approve':
                    self._auto_approve_file(file['id'], decision['reason'])
                    results['auto_approved'].append({
                        'file_id': file['id'],
                        'filename': file['filename'],
                        'user': file['username'],
                        'risk_score': file['risk_score'],
                        'reason': decision['reason']
                    })
                    
                    # Send notification to user
                    self._send_notification(file['user_id'], 'approved', file['filename'])
                    
                elif decision['action'] == 'reject':
                    self._auto_reject_file(file['id'], decision['reason'])
                    results['auto_rejected'].append({
                        'file_id': file['id'],
                        'filename': file['filename'],
                        'user': file['username'],
                        'risk_score': file['risk_score'],
                        'reason': decision['reason']
                    })
                    
                    # Send notification to user
                    self._send_notification(file['user_id'], 'rejected', file['filename'], decision['reason'])
                    
                else:
                    results['manual_review'].append({
                        'file_id': file['id'],
                        'filename': file['filename'],
                        'user': file['username'],
                        'risk_score': file['risk_score'],
                        'reason': decision['reason']
                    })
                    
            except Exception as e:
                results['errors'].append({
                    'file_id': file['id'],
                    'filename': file['filename'],
                    'error': str(e)
                })
        
        return results
    
    def make_ai_decision(self, file: Dict) -> Dict:
        """
        Make intelligent AI decision based on multiple factors
        """
        risk_score = file.get('risk_score', 0)
        scan_result = file.get('scan_result', '')
        dlp_action = file.get('dlp_action_taken', '')
        
        # Handle risk_score if it's a string or percentage
        if isinstance(risk_score, str):
            try:
                risk_score = float(risk_score.replace('%', '')) / 100
            except:
                risk_score = 0.5
        elif isinstance(risk_score, (int, float)):
            if risk_score > 1:
                risk_score = risk_score / 100
        
        # Factor 1: Risk score based decision
        if risk_score <= (self.thresholds['auto_approve_max_risk'] / 100):
            return {
                'action': 'approve',
                'reason': f"Risk score ({risk_score:.1%}) is within safe threshold (≤{self.thresholds['auto_approve_max_risk']}%)"
            }
        
        if risk_score >= (self.thresholds['auto_reject_min_risk'] / 100):
            return {
                'action': 'reject',
                'reason': f"Risk score ({risk_score:.1%}) exceeds maximum allowed threshold (≥{self.thresholds['auto_reject_min_risk']}%)"
            }
        
        # Factor 2: DLP violations
        if dlp_action and 'violation' in dlp_action.lower():
            return {
                'action': 'reject',
                'reason': f"DLP violations detected: {dlp_action}"
            }
        
        # Factor 3: Check scan result for sensitive content
        if scan_result:
            try:
                if isinstance(scan_result, str):
                    scan_data = json.loads(scan_result)
                else:
                    scan_data = scan_result
                    
                if scan_data.get('sensitive_data_found', False):
                    return {
                        'action': 'reject',
                        'reason': "Sensitive data detected during security scan"
                    }
            except:
                pass
        
        # Factor 4: Check user history
        user_risk = self._get_user_risk_profile(file['user_id'])
        if user_risk['risk_level'] == 'high':
            return {
                'action': 'reject',
                'reason': f"User has high risk profile ({user_risk['violation_count']} previous violations)"
            }
        
        if user_risk['risk_level'] == 'low' and risk_score <= 0.5:
            return {
                'action': 'approve',
                'reason': f"Trusted user with good history, risk score {risk_score:.1%} is acceptable"
            }
        
        # Factor 5: File type analysis
        filename = file.get('filename', '')
        file_extension = filename.split('.')[-1].lower() if '.' in filename else ''
        safe_extensions = ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv']
        if file_extension and file_extension not in safe_extensions:
            return {
                'action': 'reject',
                'reason': f"Unsafe file type detected: .{file_extension}"
            }
        
        # Default: Manual review for medium risk files
        return {
            'action': 'manual',
            'reason': f"Risk score {risk_score:.1%} requires manual admin review"
        }
    
    def _get_user_risk_profile(self, user_id: int) -> Dict:
        """Get user's risk profile based on history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) as violation_count, 
                   COUNT(DISTINCT file_id) as affected_files
            FROM dlp_violations
            WHERE user_id = ?
        """, (user_id,))
        
        violations = cursor.fetchone()
        conn.close()
        
        violation_count = violations[0] if violations else 0
        
        if violation_count == 0:
            risk_level = 'low'
        elif violation_count <= 3:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        return {
            'violation_count': violation_count,
            'risk_level': risk_level
        }
    
    def _auto_approve_file(self, file_id: int, reason: str):
        """Automatically approve a file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().isoformat()
        
        cursor.execute("""
            UPDATE files 
            SET approval_status = 'approved',
                dlp_action_taken = ?,
                reviewed_at = ?
            WHERE id = ?
        """, (f"AI Auto-approved: {reason}", current_time, file_id))
        
        conn.commit()
        conn.close()
    
    def _auto_reject_file(self, file_id: int, reason: str):
        """Automatically reject a file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().isoformat()
        
        cursor.execute("""
            UPDATE files 
            SET approval_status = 'rejected',
                dlp_action_taken = ?,
                reviewed_at = ?
            WHERE id = ?
        """, (f"AI Auto-rejected: {reason}", current_time, file_id))
        
        conn.commit()
        conn.close()
    
    def _send_notification(self, user_id: int, status: str, filename: str, reason: str = None):
        """Send notification to user about file status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create notification table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                message TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        if status == 'approved':
            title = "✅ File Approved"
            message = f"Your file '{filename}' has been automatically approved by AI Agent."
        else:
            title = "❌ File Rejected"
            message = f"Your file '{filename}' was rejected. Reason: {reason}"
        
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message)
            VALUES (?, ?, ?)
        """, (user_id, title, message))
        
        conn.commit()
        conn.close()
    
    def get_processing_stats(self) -> Dict:
        """Get statistics about AI agent processing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get total processed files
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN approval_status = 'approved' AND dlp_action_taken LIKE 'AI Auto-approved%' THEN 1 ELSE 0 END) as ai_approved,
                SUM(CASE WHEN approval_status = 'rejected' AND dlp_action_taken LIKE 'AI Auto-rejected%' THEN 1 ELSE 0 END) as ai_rejected,
                SUM(CASE WHEN approval_status = 'pending' THEN 1 ELSE 0 END) as pending
            FROM files
        """)
        
        stats = cursor.fetchone()
        conn.close()
        
        total_files = stats[0] or 0
        ai_approved = stats[1] or 0
        ai_rejected = stats[2] or 0
        pending = stats[3] or 0
        
        auto_processing_rate = ((ai_approved + ai_rejected) / total_files * 100) if total_files > 0 else 0
        
        return {
            'total_files': total_files,
            'ai_approved': ai_approved,
            'ai_rejected': ai_rejected,
            'pending': pending,
            'auto_processing_rate': auto_processing_rate
        }
    
    def get_ai_decision_log(self, limit: int = 50) -> pd.DataFrame:
        """Get log of AI decisions - Handles datetime format issues"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Simple query using only existing columns
            query = f"""
                SELECT 
                    f.id,
                    f.filename,
                    u.username,
                    f.risk_score,
                    f.approval_status,
                    f.dlp_action_taken as ai_decision,
                    f.uploaded_at,
                    f.reviewed_at
                FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE f.dlp_action_taken LIKE 'AI Auto-%'
                ORDER BY f.uploaded_at DESC
                LIMIT {limit}
            """
            
            df = pd.read_sql_query(query, conn)
            conn.close()
            
            if df.empty:
                return df
            
            # Format datetime columns safely
            for col in ['uploaded_at', 'reviewed_at']:
                if col in df.columns:
                    try:
                        # Try different datetime formats
                        df[col] = pd.to_datetime(df[col], errors='coerce')
                        
                        # If still have NaT, try with format='mixed'
                        if df[col].isna().any():
                            df[col] = pd.to_datetime(df[col], format='mixed', errors='coerce')
                        
                        # Format for display
                        df[f'{col}_display'] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception as e:
                        print(f"Error formatting {col}: {e}")
                        df[f'{col}_display'] = df[col]
            
            # Format risk_score for display
            if 'risk_score' in df.columns:
                def format_risk(val):
                    try:
                        if val is None or pd.isna(val):
                            return "N/A"
                        if isinstance(val, str):
                            val = float(val.replace('%', ''))
                        if val > 1:
                            val = val / 100
                        return f"{val:.1%}"
                    except:
                        return "N/A"
                df['risk_score_display'] = df['risk_score'].apply(format_risk)
            
            return df
            
        except Exception as e:
            print(f"Error in get_ai_decision_log: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()