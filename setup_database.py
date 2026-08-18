# setup_database.py
from database import DatabaseManager

def setup_upgraded_database():
    """Setup database with new tables and columns"""
    print("Setting up upgraded database...")
    
    db = DatabaseManager()
    
    # Create new tables
    db.create_tables_v2()
    print("✓ Created new tables")
    
    # Add missing columns to existing tables
    db.add_column_if_not_exists("files", "approval_status", "TEXT DEFAULT 'pending'")
    db.add_column_if_not_exists("files", "encrypted", "INTEGER DEFAULT 0")
    db.add_column_if_not_exists("files", "encryption_key_id", "INTEGER")
    print("✓ Added missing columns")
    
    # Initialize keyword scanner
    from keyword_scanner import Keyword_scanner
    scanner = Keyword_scanner()
    print("✓ Initialized keyword scanner")
    
    print("\n✅ Database upgrade complete!")
    print("Total keywords loaded:", sum(len(v) for v in scanner.keywords.values()))

if __name__ == "__main__":
    setup_upgraded_database()