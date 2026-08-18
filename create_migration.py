import sqlite3
import os
from pathlib import Path

def fix_database_schema():
    """Fix database schema to match the code expectations"""
    
    db_path = "data/security.db"
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    # Create backup
    backup_path = "data/security_backup.db"
    import shutil
    shutil.copy2(db_path, backup_path)
    print(f"✅ Database backup created at {backup_path}")
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # ===== FIX 1: Add risk_score column to activity_logs table =====
        try:
            cursor.execute("SELECT risk_score FROM activity_logs LIMIT 1")
            print("✅ risk_score column already exists in activity_logs")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE activity_logs ADD COLUMN risk_score REAL DEFAULT 0")
            print("✅ Added risk_score column to activity_logs table")
        
        # ===== FIX 2: Add approval_status column to files table if not exists =====
        try:
            cursor.execute("SELECT approval_status FROM files LIMIT 1")
            print("✅ approval_status column already exists in files")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE files ADD COLUMN approval_status TEXT DEFAULT 'pending'")
            print("✅ Added approval_status column to files table")
        
        # ===== FIX 3: Add missing columns to files table =====
        # Check for dlp_action_taken
        try:
            cursor.execute("SELECT dlp_action_taken FROM files LIMIT 1")
            print("✅ dlp_action_taken column already exists in files")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE files ADD COLUMN dlp_action_taken TEXT")
            print("✅ Added dlp_action_taken column to files table")
        
        # Check for dlp_reason
        try:
            cursor.execute("SELECT dlp_reason FROM files LIMIT 1")
            print("✅ dlp_reason column already exists in files")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE files ADD COLUMN dlp_reason TEXT")
            print("✅ Added dlp_reason column to files table")
        
        # Check for encrypted
        try:
            cursor.execute("SELECT encrypted FROM files LIMIT 1")
            print("✅ encrypted column already exists in files")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE files ADD COLUMN encrypted INTEGER DEFAULT 0")
            print("✅ Added encrypted column to files table")
        
        # ===== FIX 4: Add persona_risk_score to user_personas table =====
        try:
            cursor.execute("SELECT persona_risk_score FROM user_personas LIMIT 1")
        except sqlite3.OperationalError:
            try:
                cursor.execute("ALTER TABLE user_personas ADD COLUMN persona_risk_score REAL DEFAULT 0")
                print("✅ Added persona_risk_score column to user_personas table")
            except:
                pass
        
        # ===== FIX 5: Create missing tables if they don't exist =====
        
        # Create user_personas table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_personas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                profile_data TEXT,
                risk_score REAL DEFAULT 0,
                avg_login_hour REAL,
                common_ip_patterns TEXT,
                common_device_patterns TEXT,
                upload_frequency REAL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        print("✅ Ensured user_personas table exists")
        
        # Create dlp_violations table if not exists
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
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                filename TEXT,
                username TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL
            )
        ''')
        print("✅ Ensured dlp_violations table exists")
        
        # Create file_approvals table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                approver_id INTEGER,
                status TEXT DEFAULT 'pending',
                risk_level TEXT,
                approval_notes TEXT,
                scan_summary TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (approver_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        print("✅ Ensured file_approvals table exists")
        
        # Create security_logs table if not exists
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
        print("✅ Ensured security_logs table exists")
        
        # ===== FIX 6: Update existing files with default approval_status =====
        cursor.execute("UPDATE files SET approval_status = 'pending' WHERE approval_status IS NULL")
        print("✅ Updated NULL approval_status to 'pending'")
        
        # ===== FIX 7: Create indexes for better performance =====
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_approval_status ON files(approval_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dlp_violations_user_id ON dlp_violations(user_id)")
        print("✅ Created database indexes")
        
        # Commit changes
        conn.commit()
        print("\n" + "="*50)
        print("✅ DATABASE MIGRATION COMPLETED SUCCESSFULLY!")
        print("="*50)
        
        # Show table schemas for verification
        print("\n📊 Current table schemas:")
        print("-"*50)
        
        tables = ['activity_logs', 'files', 'user_personas', 'dlp_violations', 'file_approvals', 'security_logs']
        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                print(f"\n📁 {table}:")
                for col in columns:
                    print(f"  - {col['name']}: {col['type']}")
            except:
                print(f"\n⚠️  {table}: Table not found")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    print("🔄 Running database migration...")
    fix_database_schema()