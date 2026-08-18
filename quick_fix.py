import sqlite3
import os
from pathlib import Path

def quick_fix():
    """Quick fix for the most urgent database issues"""
    
    db_path = "data/security.db"
    
    if not os.path.exists(db_path):
        print("Database not found. Will be created when app runs.")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Add risk_score to activity_logs if missing
        try:
            cursor.execute("ALTER TABLE activity_logs ADD COLUMN risk_score REAL DEFAULT 0")
            print("✅ Added risk_score column to activity_logs")
        except:
            print("ℹ️ risk_score column already exists or couldn't be added")
        
        # Add approval_status to files if missing
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN approval_status TEXT DEFAULT 'pending'")
            print("✅ Added approval_status column to files")
        except:
            print("ℹ️ approval_status column already exists or couldn't be added")
        
        # Add dlp_action_taken to files if missing
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN dlp_action_taken TEXT")
            print("✅ Added dlp_action_taken column to files")
        except:
            pass
        
        # Add dlp_reason to files if missing
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN dlp_reason TEXT")
            print("✅ Added dlp_reason column to files")
        except:
            pass
        
        # Update existing files with pending status
        try:
            cursor.execute("UPDATE files SET approval_status = 'pending' WHERE approval_status IS NULL")
            print("✅ Updated NULL approval_status to 'pending'")
        except:
            pass
        
        conn.commit()
        print("\n✅ Quick fix completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    quick_fix()