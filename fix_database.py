import sqlite3

def fix_database():
    """Add missing columns to database"""
    conn = sqlite3.connect("data/security.db")
    cursor = conn.cursor()
    
    # Get existing columns
    cursor.execute("PRAGMA table_info(files)")
    columns = [column[1] for column in cursor.fetchall()]
    
    print("Existing columns:", columns)
    
    # Add updated_at column without default first
    if 'updated_at' not in columns:
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN updated_at TIMESTAMP")
            print("✅ Added updated_at column")
            
            # Set default value for existing rows
            cursor.execute("UPDATE files SET updated_at = uploaded_at WHERE updated_at IS NULL")
            print("✅ Set initial values for updated_at")
        except Exception as e:
            print(f"Note: {e}")
    
    # Add reviewed_at column
    if 'reviewed_at' not in columns:
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN reviewed_at TIMESTAMP")
            print("✅ Added reviewed_at column")
        except Exception as e:
            print(f"Note: {e}")
    
    # Add processed_at column as alternative
    if 'processed_at' not in columns:
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN processed_at TIMESTAMP")
            print("✅ Added processed_at column")
        except Exception as e:
            print(f"Note: {e}")
    
    conn.commit()
    
    # Verify columns after changes
    cursor.execute("PRAGMA table_info(files)")
    updated_columns = [column[1] for column in cursor.fetchall()]
    print("\nUpdated columns:", updated_columns)
    
    conn.close()
    
    print("\n✅ Database fix completed!")

if __name__ == "__main__":
    fix_database()