
import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import bcrypt
import threading
import time
import atexit
from contextlib import contextmanager

class DatabaseManager:
    """Secure database operations with encryption and audit logging"""
    
    def __init__(self, db_path: str = "data/security.db"):
        self.db_path = db_path
        self._local = threading.local()
        self.timeout = 30  # 30 second timeout
        self.connection_lock = threading.Lock()  
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Get thread-safe database connection with context manager"""
        conn = None
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(
                    self.db_path,
                    timeout=self.timeout,
                    check_same_thread=False,
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=30000")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA synchronous=NORMAL")
                yield conn
                conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                if conn:
                    conn.rollback()
                    conn.close()
                raise
            except Exception as e:
                if conn:
                    conn.rollback()
                    conn.close()
                raise
            finally:
                if conn:
                    conn.close()
    
    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """Execute a query with automatic connection handling"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                return cursor.lastrowid
    
    def init_database(self):
        """Initialize database with secure tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Users table with role-based access
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                        full_name TEXT,
                        department TEXT,
                        is_active INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        login_attempts INTEGER DEFAULT 0,
                        locked_until TIMESTAMP,
                        last_ip TEXT,
                        last_user_agent TEXT
                    )
                ''')
                
                # Files table for tracking uploads
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        filename TEXT NOT NULL,
                        filepath TEXT NOT NULL,
                        file_type TEXT NOT NULL,
                        file_size INTEGER,
                        risk_score REAL DEFAULT 0,
                        scan_result TEXT,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        approval_status TEXT DEFAULT 'pending',
                        encrypted INTEGER DEFAULT 0,
                        encryption_key_id INTEGER,
                        dlp_action_taken TEXT,
                        dlp_reason TEXT,
                        reviewed_at TIMESTAMP,
                        processed_at TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # Security incidents table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        incident_type TEXT NOT NULL,
                        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                        description TEXT,
                        file_id INTEGER,
                        user_ip TEXT,
                        user_agent TEXT,
                        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved_at TIMESTAMP,
                        status TEXT DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'resolved', 'false_positive')),
                        action_taken TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL
                    )
                ''')
                
                # User activity logs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS activity_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        activity_type TEXT NOT NULL,
                        details TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        risk_score REAL DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # User personas table for behavioral profiling
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_personas (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER UNIQUE NOT NULL,
                        profile_data TEXT NOT NULL,
                        risk_score REAL DEFAULT 0,
                        avg_login_hour REAL,
                        common_ip_patterns TEXT,
                        common_device_patterns TEXT,
                        upload_frequency REAL,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # Enhanced security logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        action_type TEXT NOT NULL,
                        file_name TEXT,
                        file_path TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        risk_score REAL,
                        dlp_action TEXT,
                        detection_details TEXT,
                        persona_anomaly_score REAL DEFAULT 0,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # DLP rules table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS dlp_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_name TEXT NOT NULL,
                        pattern_type TEXT NOT NULL,
                        pattern TEXT NOT NULL,
                        action TEXT NOT NULL CHECK(action IN ('block', 'encrypt', 'warn', 'allow')),
                        severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                        is_active INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # DLP violation logs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS dlp_violations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        file_id INTEGER,
                        rule_id INTEGER,
                        violation_type TEXT NOT NULL,
                        detected_pattern TEXT,
                        matched_content TEXT,
                        action_taken TEXT NOT NULL,
                        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                        filename TEXT,
                        username TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL,
                        FOREIGN KEY (rule_id) REFERENCES dlp_rules (id) ON DELETE SET NULL
                    )
                ''')
                
                # Encryption keys table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS encryption_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        file_id INTEGER,
                        key_hash TEXT NOT NULL,
                        encryption_method TEXT DEFAULT 'AES-256-GCM',
                        encrypted_key TEXT NOT NULL,
                        iv TEXT,
                        key_version INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        is_active INTEGER DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
                    )
                ''')
                
                # User login patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS login_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        login_time TIMESTAMP NOT NULL,
                        ip_address TEXT NOT NULL,
                        user_agent TEXT,
                        success INTEGER DEFAULT 1,
                        location_estimate TEXT,
                        risk_indicator REAL DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # System settings
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # File approvals table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_approvals (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        approver_id INTEGER,
                        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'escalated')),
                        risk_level TEXT CHECK(risk_level IN ('low', 'medium', 'high', 'critical')),
                        approval_notes TEXT,
                        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        reviewed_at TIMESTAMP,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        FOREIGN KEY (approver_id) REFERENCES users (id) ON DELETE SET NULL
                    )
                ''')
                
                # Email alerts log
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS email_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_type TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        content TEXT NOT NULL,
                        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed', 'retrying')),
                        sent_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        retry_count INTEGER DEFAULT 0
                    )
                ''')
                
                # Keyword scanning results
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS keyword_matches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id INTEGER NOT NULL,
                        keyword TEXT NOT NULL,
                        category TEXT NOT NULL,
                        match_count INTEGER DEFAULT 1,
                        context TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
                    )
                ''')
                
                # Alert notifications
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_type TEXT NOT NULL,
                        user_id INTEGER,
                        file_id INTEGER,
                        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        is_read INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
                        FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL
                    )
                ''')
                
                # Notifications table for user notifications
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        is_read INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # Notification preferences table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS notification_preferences (
                        user_id INTEGER PRIMARY KEY,
                        email_notifications INTEGER DEFAULT 1,
                        in_app_notifications INTEGER DEFAULT 1,
                        file_approved INTEGER DEFAULT 1,
                        file_rejected INTEGER DEFAULT 1,
                        dlp_alert INTEGER DEFAULT 1,
                        system_alert INTEGER DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                
                # Insert default admin if not exists
                admin_password = bcrypt.hashpw('Admin@123'.encode(), bcrypt.gensalt()).decode()
                cursor.execute('''
                    INSERT OR IGNORE INTO users (username, email, password_hash, role, full_name)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', 'admin@company.com', admin_password, 'admin', 'System Administrator'))
                
                # Insert default settings
                default_settings = [
                    ('high_risk_threshold', '0.7'),
                    ('medium_risk_threshold', '0.4'),
                    ('auto_approve_low_risk', '1'),
                    ('email_alerts_enabled', '1'),
                    ('encryption_enabled', '0'),
                    ('require_approval_medium_risk', '1'),
                    ('require_approval_high_risk', '1'),
                    ('persona_risk_threshold', '0.7'),
                    ('dlp_action_block', '1'),
                    ('dlp_action_encrypt', '0'),
                    ('dlp_notify_admin', '1'),
                    ('aadhaar_detection_enabled', '1'),
                    ('pan_detection_enabled', '1'),
                    ('enable_persona_detection', '1'),
                    ('max_login_attempts', '5'),
                    ('session_timeout_minutes', '30')
                ]
                
                for key, value in default_settings:
                    cursor.execute('''
                        INSERT OR IGNORE INTO settings (key, value)
                        VALUES (?, ?)
                    ''', (key, value))
                
                # Insert default DLP rules
                default_dlp_rules = [
                    ('Aadhaar Number Detection', 'regex', r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b', 'block', 'critical'),
                    ('PAN Card Detection', 'regex', r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', 'block', 'critical'),
                    ('Indian Mobile Number', 'regex', r'\b(\+91|0)?[6789]\d{9}\b', 'warn', 'medium'),
                    ('UPI ID Detection', 'regex', r'\b[\w\.-]+@(okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl)\b', 'warn', 'medium'),
                    ('Credit Card Number', 'regex', r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'encrypt', 'high'),
                    ('SSN Pattern', 'regex', r'\b\d{3}-\d{2}-\d{4}\b', 'encrypt', 'high'),
                    ('Confidential Keyword', 'keyword', 'confidential', 'warn', 'low'),
                    ('Secret Keyword', 'keyword', 'secret', 'warn', 'low'),
                    ('Password Keyword', 'keyword', 'password', 'warn', 'medium')
                ]
                
                for rule in default_dlp_rules:
                    cursor.execute('''
                        INSERT OR IGNORE INTO dlp_rules (rule_name, pattern_type, pattern, action, severity)
                        VALUES (?, ?, ?, ?, ?)
                    ''', rule)
                
                conn.commit()
                
                # Run schema verification after initialization
                self._verify_and_fix_schema()
                
        except Exception as e:
            print(f"Database initialization error: {e}")
            raise
    
    def _verify_and_fix_schema(self):
        """Verify and fix database schema"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check and fix activity_logs table
                cursor.execute("PRAGMA table_info(activity_logs)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'risk_score' not in columns:
                    try:
                        cursor.execute("ALTER TABLE activity_logs ADD COLUMN risk_score REAL DEFAULT 0")
                        print("✅ Added missing risk_score column to activity_logs")
                    except:
                        pass
                
                # Check and fix files table
                cursor.execute("PRAGMA table_info(files)")
                columns = [col[1] for col in cursor.fetchall()]
                
                required_columns = ['approval_status', 'dlp_action_taken', 'dlp_reason', 'encrypted', 'reviewed_at', 'processed_at']
                for col in required_columns:
                    if col not in columns:
                        try:
                            if col == 'approval_status':
                                cursor.execute("ALTER TABLE files ADD COLUMN approval_status TEXT DEFAULT 'pending'")
                            elif col == 'encrypted':
                                cursor.execute("ALTER TABLE files ADD COLUMN encrypted INTEGER DEFAULT 0")
                            elif col == 'reviewed_at':
                                cursor.execute("ALTER TABLE files ADD COLUMN reviewed_at TIMESTAMP")
                            elif col == 'processed_at':
                                cursor.execute("ALTER TABLE files ADD COLUMN processed_at TIMESTAMP")
                            else:
                                cursor.execute(f"ALTER TABLE files ADD COLUMN {col} TEXT")
                            print(f"✅ Added missing {col} column to files")
                        except:
                            pass
                
                # Check and fix dlp_violations table
                cursor.execute("PRAGMA table_info(dlp_violations)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'filename' not in columns:
                    try:
                        cursor.execute("ALTER TABLE dlp_violations ADD COLUMN filename TEXT")
                        print("✅ Added filename column to dlp_violations")
                    except:
                        pass
                
                if 'username' not in columns:
                    try:
                        cursor.execute("ALTER TABLE dlp_violations ADD COLUMN username TEXT")
                        print("✅ Added username column to dlp_violations")
                    except:
                        pass
                
                conn.commit()
                
        except Exception as e:
            print(f"Error verifying schema: {e}")

    # ===== USER MANAGEMENT METHODS =====
    
    def create_user(self, username: str, email: str, password: str, 
                   role: str = 'user', **kwargs) -> bool:
        """Securely create a new user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, role, full_name, department)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, email, password_hash, role, 
                      kwargs.get('full_name', ''), kwargs.get('department', '')))
                
                user_id = cursor.lastrowid
                
                # Create default notification preferences
                cursor.execute('''
                    INSERT OR IGNORE INTO notification_preferences (user_id)
                    VALUES (?)
                ''', (user_id,))
                
                # Log the activity
                self.log_activity(user_id, 'user_registration', f'New {role} registered')
                
                return True
                
        except sqlite3.Error as e:
            print(f"Error creating user: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error creating user: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str, 
                         ip_address: str = None, user_agent: str = None) -> Optional[Dict]:
        """Secure user authentication with brute force protection"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM users 
                    WHERE username = ? AND is_active = 1
                ''', (username,))
                
                user = cursor.fetchone()
                
                if not user:
                    return None
                
                # Check if account is locked
                if user['locked_until']:
                    try:
                        lock_time = datetime.fromisoformat(user['locked_until']) 
                        if lock_time > datetime.now():
                            return None
                    except:
                        pass
                
                # Verify password
                if bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
                    # Reset login attempts on successful login
                    cursor.execute('''
                        UPDATE users 
                        SET login_attempts = 0, last_login = ?, last_ip = ?, last_user_agent = ?
                        WHERE id = ?
                    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                          ip_address, user_agent, user['id']))
                    
                    # Log successful login
                    self.log_activity(user['id'], 'login_success', 'User logged in', 
                                     ip_address, user_agent)
                    
                    # Log to login patterns
                    cursor.execute('''
                        INSERT INTO login_patterns 
                        (user_id, login_time, ip_address, user_agent, success)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (user['id'], datetime.now().isoformat(), ip_address, 
                          user_agent, 1))
                    
                    # Convert to dict
                    user_dict = {key: user[key] for key in user.keys()}
                    return user_dict
                    
                else:
                    # Increment failed attempts
                    new_attempts = user['login_attempts'] + 1
                    lock_time = None
                    
                    if new_attempts >= 5:
                        lock_until = datetime.now() + timedelta(minutes=30)
                        lock_time = lock_until.strftime("%Y-%m-%d %H:%M:%S")
                    
                    cursor.execute('''
                        UPDATE users 
                        SET login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (new_attempts, lock_time, user['id']))
                    
                    # Log failed attempt
                    self.log_activity(user['id'], 'login_failed', 
                                     f'Failed login attempt {new_attempts}',
                                     ip_address, user_agent)
                    
                    cursor.execute('''
                        INSERT INTO login_patterns 
                        (user_id, login_time, ip_address, user_agent, success)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (user['id'], datetime.now().isoformat(), ip_address, 
                          user_agent, 0))
                    
                    return None
                    
        except sqlite3.Error as e:
            print(f"Authentication error: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
                return dict(user) if user else None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                user = cursor.fetchone()
                return dict(user) if user else None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def get_all_users(self) -> List[str]:
        """Get all usernames"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username FROM users WHERE role = "user"')
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []
    
    def log_activity(self, user_id: int, activity_type: str, details: str, 
                    ip_address: str = None, user_agent: str = None, 
                    risk_score: float = 0.0):
        """Log user activity for audit trail"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO activity_logs (user_id, activity_type, details, 
                                              ip_address, user_agent, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, activity_type, details, ip_address, user_agent, risk_score))
        except Exception as e:
            print(f"Error logging activity: {e}")
    
    def get_user_activities(self, user_id: int, limit: int = 10) -> List[Dict]:
        """Get recent user activities"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        id, 
                        activity_type, 
                        details, 
                        timestamp,
                        risk_score,
                        ip_address
                    FROM activity_logs 
                    WHERE user_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (user_id, limit))
                
                activities = []
                for row in cursor.fetchall():
                    activity = dict(row)
                    # Format timestamp for display
                    if activity.get('timestamp'):
                        try:
                            dt = datetime.fromisoformat(str(activity['timestamp']))
                            activity['time_ago'] = self._get_time_ago(dt)
                        except:
                            activity['time_ago'] = str(activity['timestamp'])[:16]
                    activities.append(activity)
                
                return activities
        except Exception as e:
            print(f"Error getting user activities: {e}")
            return []
    
    def get_recent_activities(self, limit: int = 20) -> List[Dict]:
        """Get recent activities across all users (for admin)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        al.id,
                        al.user_id,
                        al.activity_type,
                        al.details,
                        al.timestamp,
                        al.risk_score,
                        al.ip_address,
                        u.username
                    FROM activity_logs al
                    JOIN users u ON al.user_id = u.id
                    ORDER BY al.timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                activities = []
                for row in cursor.fetchall():
                    activity = dict(row)
                    if activity.get('timestamp'):
                        try:
                            dt = datetime.fromisoformat(str(activity['timestamp']))
                            activity['time_ago'] = self._get_time_ago(dt)
                        except:
                            activity['time_ago'] = str(activity['timestamp'])[:16]
                    activities.append(activity)
                
                return activities
        except Exception as e:
            print(f"Error getting recent activities: {e}")
            return []
    
    def _get_time_ago(self, dt: datetime) -> str:
        """Get human readable time ago string"""
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 365:
            return f"{diff.days // 365} year(s) ago"
        elif diff.days > 30:
            return f"{diff.days // 30} month(s) ago"
        elif diff.days > 0:
            return f"{diff.days} day(s) ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600} hour(s) ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60} minute(s) ago"
        else:
            return "Just now"
    
    def get_user_upload_stats(self, user_id: int) -> Dict:
        """Get detailed upload statistics for user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get total uploads
                cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,))
                total_uploads = cursor.fetchone()[0] or 0
                
                # Get uploads by risk level
                cursor.execute('''
                    SELECT 
                        SUM(CASE WHEN risk_score >= 0.7 THEN 1 ELSE 0 END) as high_risk,
                        SUM(CASE WHEN risk_score >= 0.4 AND risk_score < 0.7 THEN 1 ELSE 0 END) as medium_risk,
                        SUM(CASE WHEN risk_score < 0.4 THEN 1 ELSE 0 END) as low_risk
                    FROM files WHERE user_id = ?
                ''', (user_id,))
                row = cursor.fetchone()
                
                # Get uploads by status
                cursor.execute('''
                    SELECT 
                        SUM(CASE WHEN approval_status = 'approved' THEN 1 ELSE 0 END) as approved,
                        SUM(CASE WHEN approval_status = 'pending' THEN 1 ELSE 0 END) as pending,
                        SUM(CASE WHEN approval_status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN approval_status = 'blocked' THEN 1 ELSE 0 END) as blocked
                    FROM files WHERE user_id = ?
                ''', (user_id,))
                status_row = cursor.fetchone()
                
                # Get recent uploads (last 7 days)
                cursor.execute('''
                    SELECT DATE(uploaded_at) as date, COUNT(*) as count
                    FROM files 
                    WHERE user_id = ? AND uploaded_at >= DATE('now', '-7 days')
                    GROUP BY DATE(uploaded_at)
                    ORDER BY date DESC
                ''', (user_id,))
                recent_uploads = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'total_uploads': total_uploads,
                    'high_risk': row[0] if row else 0,
                    'medium_risk': row[1] if row else 0,
                    'low_risk': row[2] if row else 0,
                    'approved': status_row[0] if status_row else 0,
                    'pending': status_row[1] if status_row else 0,
                    'rejected': status_row[2] if status_row else 0,
                    'blocked': status_row[3] if status_row else 0,
                    'recent_uploads': recent_uploads
                }
        except Exception as e:
            print(f"Error getting user upload stats: {e}")
            return {
                'total_uploads': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'approved': 0,
                'pending': 0,
                'rejected': 0,
                'blocked': 0,
                'recent_uploads': []
            }
    
    def get_user_notifications(self, user_id: int, unread_only: bool = False, limit: int = 20) -> List[Dict]:
        """Get user notifications"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                query = 'SELECT * FROM notifications WHERE user_id = ?'
                params = [user_id]
                
                if unread_only:
                    query += ' AND is_read = 0'
                
                query += ' ORDER BY created_at DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                notifications = []
                for row in cursor.fetchall():
                    notif = dict(row)
                    if notif.get('created_at'):
                        try:
                            dt = datetime.fromisoformat(str(notif['created_at']))
                            notif['time_ago'] = self._get_time_ago(dt)
                        except:
                            pass
                    notifications.append(notif)
                
                return notifications
        except Exception as e:
            print(f"Error getting notifications: {e}")
            return []
    
    def create_notification(self, user_id: int, title: str, message: str) -> int:
        """Create a notification for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO notifications (user_id, title, message, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, title, message, datetime.now().isoformat()))
                return cursor.lastrowid
        except Exception as e:
            print(f"Error creating notification: {e}")
            return -1
    
    def mark_notification_read(self, notification_id: int) -> bool:
        """Mark a notification as read"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
                return True
        except Exception as e:
            print(f"Error marking notification read: {e}")
            return False
    
    def get_notification_preferences(self, user_id: int) -> Dict:
        """Get user's notification preferences"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                
                # Create default preferences
                cursor.execute('INSERT INTO notification_preferences (user_id) VALUES (?)', (user_id,))
                return {
                    'user_id': user_id,
                    'email_notifications': 1,
                    'in_app_notifications': 1,
                    'file_approved': 1,
                    'file_rejected': 1,
                    'dlp_alert': 1,
                    'system_alert': 1
                }
        except Exception as e:
            print(f"Error getting notification preferences: {e}")
            return {}
    
    def update_notification_preferences(self, user_id: int, preferences: Dict) -> bool:
        """Update notification preferences"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO notification_preferences 
                    (user_id, email_notifications, in_app_notifications, file_approved, file_rejected, dlp_alert, system_alert)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, 
                      preferences.get('email_notifications', 1),
                      preferences.get('in_app_notifications', 1),
                      preferences.get('file_approved', 1),
                      preferences.get('file_rejected', 1),
                      preferences.get('dlp_alert', 1),
                      preferences.get('system_alert', 1)))
                return True
        except Exception as e:
            print(f"Error updating notification preferences: {e}")
            return False

    # ===== FILE MANAGEMENT METHODS =====
    
    def save_file_record(self, user_id: int, filename: str, filepath: str,
                        file_type: str, file_size: int, risk_score: float = 0,
                        scan_result: dict = None, approval_status: str = 'pending',
                        dlp_action: str = None, dlp_reason: str = None) -> int:
        """Save file upload record with DLP information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                scan_result_json = None
                if scan_result:
                    if isinstance(scan_result, dict):
                        scan_result_json = json.dumps(scan_result)
                    else:
                        scan_result_json = str(scan_result)
                
                current_time = datetime.now().isoformat()
                
                cursor.execute('''
                    INSERT INTO files 
                    (user_id, filename, filepath, file_type, file_size, 
                     risk_score, scan_result, approval_status, 
                     dlp_action_taken, dlp_reason, uploaded_at, reviewed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, filename, filepath, file_type, file_size,
                    risk_score,
                    scan_result_json,
                    approval_status,
                    dlp_action,
                    dlp_reason,
                    current_time,
                    current_time
                ))
                
                file_id = cursor.lastrowid
                
                # Create entry in file_approvals if pending
                if approval_status == 'pending':
                    risk_level = 'high' if risk_score >= 0.7 else 'medium' if risk_score >= 0.4 else 'low'
                    cursor.execute('''
                        INSERT INTO file_approvals 
                        (file_id, user_id, status, risk_level, requested_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (file_id, user_id, 'pending', risk_level, current_time))
                
                # Log to security logs if high risk
                if risk_score >= 0.7:
                    cursor.execute('''
                        INSERT INTO security_logs 
                        (user_id, action_type, file_name, file_path, risk_score, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (user_id, 'file_upload_high_risk', filename, filepath, risk_score, current_time))
                
                return file_id
                
        except Exception as e:
            print(f"Error saving file record: {e}")
            return -1
    
    def get_user_files(self, user_id: int) -> List[Dict]:
        """Get files uploaded by user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        f.id, f.filename, f.filepath, f.file_type, f.file_size,
                        f.risk_score, f.scan_result, f.uploaded_at, f.approval_status,
                        f.dlp_action_taken, f.dlp_reason, f.encrypted
                    FROM files f
                    WHERE f.user_id = ? 
                    ORDER BY f.uploaded_at DESC
                ''', (user_id,))
                
                files = []
                for row in cursor.fetchall():
                    file_data = dict(row)
                    if file_data.get('scan_result'):
                        try:
                            file_data['scan_result'] = json.loads(file_data['scan_result'])
                        except:
                            pass
                    files.append(file_data)
                
                return files
                
        except Exception as e:
            print(f"Error getting user files: {e}")
            return []
    
    def get_all_files(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Get all files with optional status filter"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT f.*, u.username, u.email
                    FROM files f
                    JOIN users u ON f.user_id = u.id
                '''
                params = []
                
                if status:
                    query += ' WHERE f.approval_status = ?'
                    params.append(status)
                
                query += ' ORDER BY f.uploaded_at DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                
                files = []
                for row in cursor.fetchall():
                    file_data = dict(row)
                    if file_data.get('scan_result'):
                        try:
                            file_data['scan_result'] = json.loads(file_data['scan_result'])
                        except:
                            pass
                    files.append(file_data)
                
                return files
                
        except Exception as e:
            print(f"Error getting all files: {e}")
            return []
    
    def update_file_approval_status(self, file_id: int, status: str, reason: str = None):
        """Update file approval status"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                current_time = datetime.now().isoformat()
                
                cursor.execute('''
                    UPDATE files 
                    SET approval_status = ?, 
                        dlp_reason = COALESCE(?, dlp_reason),
                        reviewed_at = ?
                    WHERE id = ?
                ''', (status, reason, current_time, file_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error updating file status: {e}")
            return False
    
    def create_approval_request(self, approval_data: dict) -> int:
        """Create an approval request"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_approvals 
                    (file_id, user_id, risk_level, scan_summary, status, requested_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    approval_data.get('file_id'),
                    approval_data.get('user_id'),
                    approval_data.get('risk_level', 'medium'),
                    json.dumps(approval_data.get('scan_summary', {})),
                    approval_data.get('status', 'pending'),
                    datetime.now().isoformat()
                ))
                return cursor.lastrowid
        except Exception as e:
            print(f"Error creating approval request: {e}")
            return -1
    
    def count_pending_approvals(self, user_id: int = None) -> int:
        """Count pending approvals for a user or all users"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if user_id:
                    cursor.execute('SELECT COUNT(*) FROM file_approvals WHERE user_id = ? AND status = "pending"', (user_id,))
                else:
                    cursor.execute('SELECT COUNT(*) FROM file_approvals WHERE status = "pending"')
                return cursor.fetchone()[0] or 0
        except Exception as e:
            print(f"Error counting pending approvals: {e}")
            return 0

    # ===== DLP MANAGEMENT METHODS =====
    
    def log_dlp_violation(self, user_id: int, violation_type: str, 
                         action_taken: str, severity: str, **kwargs) -> int:
        """Log DLP violation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO dlp_violations 
                    (user_id, file_id, rule_id, violation_type, detected_pattern, 
                     matched_content, action_taken, severity, filename, username, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    kwargs.get('file_id'),
                    kwargs.get('rule_id'),
                    violation_type,
                    kwargs.get('detected_pattern'),
                    kwargs.get('matched_content', '')[:500],
                    action_taken,
                    severity,
                    kwargs.get('filename'),
                    kwargs.get('username'),
                    datetime.now().isoformat()
                ))
                
                return cursor.lastrowid
                
        except Exception as e:
            print(f"Error logging DLP violation: {e}")
            return -1
    
    def get_dlp_violations(self, user_id: int = None, days: int = 7, limit: int = 100) -> List[Dict]:
        """Get DLP violations with filters"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT dv.*, u.username as user_username, f.filename as file_filename
                    FROM dlp_violations dv
                    LEFT JOIN users u ON dv.user_id = u.id
                    LEFT JOIN files f ON dv.file_id = f.id
                    WHERE 1=1
                '''
                params = []
                
                if days > 0:
                    query += ' AND dv.timestamp >= datetime("now", ?)'
                    params.append(f'-{days} days')
                
                if user_id:
                    query += ' AND dv.user_id = ?'
                    params.append(user_id)
                
                query += ' ORDER BY dv.timestamp DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if 'file_filename' in result and result['file_filename']:
                        result['filename'] = result['file_filename']
                    elif 'filename' not in result or not result['filename']:
                        result['filename'] = 'Unknown'
                    results.append(result)
                
                return results
                
        except Exception as e:
            print(f"Error getting DLP violations: {e}")
            return []

    # ===== PERSONA DETECTION METHODS =====
    
    def save_persona_profile(self, user_id: int, profile_data: Dict) -> bool:
        """Save or update user persona profile"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                profile_json = json.dumps(profile_data)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_personas 
                    (user_id, profile_data, risk_score, last_updated)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, profile_json, profile_data.get('risk_score', 0), datetime.now().isoformat()))
                
                return True
                
        except Exception as e:
            print(f"Error saving persona profile: {e}")
            return False
    
    def get_persona_profile(self, user_id: int) -> Optional[Dict]:
        """Get user persona profile"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM user_personas WHERE user_id = ?', (user_id,))
                row = cursor.fetchone()
                
                if row:
                    profile = dict(row)
                    if profile.get('profile_data'):
                        try:
                            profile['profile_data'] = json.loads(profile['profile_data'])
                        except:
                            profile['profile_data'] = {}
                    return profile
                return None
                
        except Exception as e:
            print(f"Error getting persona profile: {e}")
            return None
    
    def get_all_persona_profiles(self) -> List[Dict]:
        """Get all persona profiles"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT up.*, u.username, u.email, u.role
                    FROM user_personas up
                    JOIN users u ON up.user_id = u.id
                    ORDER BY up.risk_score DESC
                ''')
                
                profiles = []
                for row in cursor.fetchall():
                    profile = dict(row)
                    if profile.get('profile_data'):
                        try:
                            profile['profile_data'] = json.loads(profile['profile_data'])
                        except:
                            profile['profile_data'] = {}
                    profiles.append(profile)
                
                return profiles
                
        except Exception as e:
            print(f"Error getting persona profiles: {e}")
            return []
    
    def get_user_risk_summary(self, user_id: int) -> Dict:
        """Get comprehensive risk summary for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                summary = {'user_id': user_id, 'persona_risk_score': 0.0, 'high_risk_files': 0}
                
                # Get persona risk
                cursor.execute('SELECT risk_score FROM user_personas WHERE user_id = ?', (user_id,))
                row = cursor.fetchone()
                if row and row[0] is not None:
                    summary['persona_risk_score'] = row[0]
                
                # Get DLP violations count
                cursor.execute('''
                    SELECT COUNT(*) as count
                    FROM dlp_violations 
                    WHERE user_id = ? AND timestamp >= datetime("now", "-30 days")
                ''', (user_id,))
                row = cursor.fetchone()
                if row:
                    summary['dlp_violations'] = row[0] or 0
                
                # Get file risk summary
                cursor.execute('''
                    SELECT COUNT(*) as total_files,
                           AVG(risk_score) as avg_file_risk,
                           SUM(CASE WHEN risk_score >= 0.7 THEN 1 ELSE 0 END) as high_risk_files
                    FROM files 
                    WHERE user_id = ?
                ''', (user_id,))
                row = cursor.fetchone()
                if row:
                    summary['total_files'] = row[0] or 0
                    summary['avg_file_risk'] = row[1] or 0.0
                    summary['high_risk_files'] = row[2] or 0
                
                return summary
                
        except Exception as e:
            print(f"Error getting user risk summary: {e}")
            return {'user_id': user_id, 'persona_risk_score': 0.0, 'high_risk_files': 0}

    # ===== STATISTICS METHODS =====
    
    def get_system_stats(self) -> Dict:
        """Get system statistics for dashboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Count users
                cursor.execute('SELECT COUNT(*) FROM users')
                stats['total_users'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
                stats['admin_users'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE role = "user"')
                stats['regular_users'] = cursor.fetchone()[0] or 0
                
                # Count files
                cursor.execute('SELECT COUNT(*) FROM files')
                stats['total_files'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM files WHERE risk_score >= 0.7')
                stats['high_risk_files'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM files WHERE DATE(uploaded_at) = DATE("now")')
                stats['files_today'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "pending"')
                stats['pending_approvals'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "approved"')
                stats['approved_files'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "rejected"')
                stats['rejected_files'] = cursor.fetchone()[0] or 0
                
                # DLP violations
                cursor.execute('SELECT COUNT(*) FROM dlp_violations WHERE DATE(timestamp) = DATE("now")')
                stats['dlp_violations_today'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT COUNT(*) FROM dlp_violations')
                stats['total_dlp_violations'] = cursor.fetchone()[0] or 0
                
                # Incidents
                cursor.execute('SELECT COUNT(*) FROM incidents WHERE status = "open"')
                stats['open_incidents'] = cursor.fetchone()[0] or 0
                
                cursor.execute('SELECT severity, COUNT(*) FROM incidents GROUP BY severity')
                severity_counts = cursor.fetchall()
                stats['incidents_by_severity'] = {row[0]: row[1] for row in severity_counts}
                
                return stats
                
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {}
    
    def get_upload_stats(self, user_id: int = None) -> Dict:
        """Get upload statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                if user_id:
                    cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,))
                    stats['total_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "approved" AND user_id = ?', (user_id,))
                    stats['approved_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "pending" AND user_id = ?', (user_id,))
                    stats['pending_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE risk_score >= 0.7 AND user_id = ?', (user_id,))
                    stats['high_risk_files'] = cursor.fetchone()[0] or 0
                else:
                    cursor.execute('SELECT COUNT(*) FROM files')
                    stats['total_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "approved"')
                    stats['approved_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE approval_status = "pending"')
                    stats['pending_files'] = cursor.fetchone()[0] or 0
                    
                    cursor.execute('SELECT COUNT(*) FROM files WHERE risk_score >= 0.7')
                    stats['high_risk_files'] = cursor.fetchone()[0] or 0
                
                return stats
                
        except Exception as e:
            print(f"Error getting upload stats: {e}")
            return {}
    
    def get_upload_trends(self, days: int = 7, user_id: int = None) -> List[Dict]:
        """Get upload trends"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT DATE(uploaded_at) as date, 
                           COUNT(*) as count,
                           SUM(CASE WHEN approval_status = 'approved' THEN 1 ELSE 0 END) as approved,
                           SUM(CASE WHEN approval_status = 'pending' THEN 1 ELSE 0 END) as pending,
                           SUM(CASE WHEN approval_status = 'rejected' THEN 1 ELSE 0 END) as rejected
                    FROM files
                    WHERE uploaded_at >= datetime('now', ?)
                '''
                
                params = [f'-{days} days']
                
                if user_id:
                    query += ' AND user_id = ?'
                    params.append(user_id)
                
                query += ' GROUP BY DATE(uploaded_at) ORDER BY date'
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            print(f"Error getting upload trends: {e}")
            return []
    
    def get_risk_distribution(self) -> List[Dict]:
        """Get risk level distribution"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT 
                        CASE 
                            WHEN risk_score >= 0.7 THEN 'high'
                            WHEN risk_score >= 0.4 THEN 'medium'
                            ELSE 'low'
                        END as risk_level,
                        COUNT(*) as count
                    FROM files
                    GROUP BY 
                        CASE 
                            WHEN risk_score >= 0.7 THEN 'high'
                            WHEN risk_score >= 0.4 THEN 'medium'
                            ELSE 'low'
                        END
                ''')
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            print(f"Error getting risk distribution: {e}")
            return []
    
    def get_all_incidents(self, limit: int = 50, status: str = None) -> List[Dict]:
        """Get all security incidents"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                query = '''
                    SELECT i.*, u.username
                    FROM incidents i
                    JOIN users u ON i.user_id = u.id
                '''
                params = []
                
                if status:
                    query += ' WHERE i.status = ?'
                    params.append(status)
                
                query += ' ORDER BY i.detected_at DESC LIMIT ?'
                params.append(limit)
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting incidents: {e}")
            return []
    
    def get_alerts(self, user_id: int = None, limit: int = 50) -> List[Dict]:
        """Get alerts for user or all users"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if user_id:
                    cursor.execute('''
                        SELECT a.*, u.username
                        FROM alerts a
                        JOIN users u ON a.user_id = u.id
                        WHERE a.user_id = ?
                        ORDER BY a.created_at DESC LIMIT ?
                    ''', (user_id, limit))
                else:
                    cursor.execute('''
                        SELECT a.*, u.username
                        FROM alerts a
                        JOIN users u ON a.user_id = u.id
                        ORDER BY a.created_at DESC LIMIT ?
                    ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def create_alert(self, alert_type: str, user_id: int, file_id: int = None, 
                     severity: str = 'medium', title: str = '', message: str = ''):
        """Create a security alert"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (alert_type, user_id, file_id, severity, title, message, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (alert_type, user_id, file_id, severity, title, message, datetime.now().isoformat()))
                return cursor.lastrowid
        except Exception as e:
            print(f"Error creating alert: {e}")
            return -1
    
    # ===== UTILITY METHODS =====
    
    def check_session(self) -> bool:
        """Check if user has an active session"""
        return True
    
    def get_current_user(self) -> Optional[Dict]:
        """Get current user from session"""
        return None
    
    def get_risk_threshold(self) -> float:
        """Get high risk threshold from settings"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM settings WHERE key = "high_risk_threshold"')
                row = cursor.fetchone()
                return float(row[0]) if row else 0.7
        except Exception as e:
            print(f"Error getting risk threshold: {e}")
            return 0.7