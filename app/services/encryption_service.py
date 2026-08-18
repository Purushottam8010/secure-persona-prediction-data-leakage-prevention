import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Corrected import
from pathlib import Path
import streamlit as st

class FileEncryptionService:
    """AES-256 encryption for uploaded files"""
    
    def __init__(self, key_file: str = "data/encryption.key"):
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing encryption key or generate a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            
            # Save key securely
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            # Set permissions (Windows compatibility)
            try:
                # For Windows, this might not work, but we'll try
                os.chmod(self.key_file, 0o600)
            except:
                pass  # Skip permission setting on Windows
            
            return key
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """Encrypt a file using AES-256"""
        if output_path is None:
            output_path = file_path + '.encrypted'
        
        # Read original file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt data
        encrypted_data = self.cipher.encrypt(file_data)
        
        # Save encrypted file
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original file if different path
        if output_path != file_path and os.path.exists(file_path):
            os.remove(file_path)
        
        return output_path
    
    def decrypt_file(self, encrypted_path: str, output_path: str = None) -> str:
        """Decrypt an encrypted file"""
        if output_path is None:
            output_path = encrypted_path.replace('.encrypted', '')
        
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt data
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def get_file_hash(self, file_path: str) -> str:
        """Generate SHA-256 hash of file for integrity checking"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def verify_integrity(self, original_hash: str, file_path: str) -> bool:
        """Verify file integrity by comparing hash"""
        current_hash = self.get_file_hash(file_path)
        return original_hash == current_hash

# Integration with file upload system
def encrypt_uploaded_file(uploaded_file, upload_dir: str = "uploads/user_uploads"):
    """Process and encrypt an uploaded file"""
    # Create encryption service
    encryption_service = FileEncryptionService()
    
    # Ensure upload directory exists
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save temporary file
    temp_path = os.path.join(upload_dir, f"temp_{uploaded_file.name}")
    with open(temp_path, 'wb') as f:
        f.write(uploaded_file.getbuffer())
    
    # Calculate original hash
    original_hash = encryption_service.get_file_hash(temp_path)
    
    # Encrypt file
    encrypted_path = encryption_service.encrypt_file(temp_path)
    
    return {
        'original_filename': uploaded_file.name,
        'encrypted_path': encrypted_path,
        'file_hash': original_hash,
        'file_size': os.path.getsize(encrypted_path),
        'encrypted': True
    }