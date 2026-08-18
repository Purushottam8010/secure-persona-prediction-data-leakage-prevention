import streamlit as st
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import DatabaseManager
from auth import AuthenticationSystem

# Initialize
db = DatabaseManager()
auth = AuthenticationSystem(db)

print("Testing authentication...")

# Test login
success, message = auth.login_user("admin", "Admin@123")
print(f"Login result: {success}, Message: {message}")

if success:
    user = auth.get_current_user()
    print(f"User: {user}")
    
    # Test logout
    auth.logout_user()
    print("Logged out")

print("Test complete!")