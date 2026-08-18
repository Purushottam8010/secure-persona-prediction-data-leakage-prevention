import re
import random
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

class SupportChatbot:
    """Enhanced chatbot with conversation memory and context awareness"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.conversation_memory = defaultdict(list)  # user_id -> list of messages
        self.context_window = 5  # Keep last 5 messages for context
        
        # Enhanced intents with more patterns and responses
        self.intents = {
            'greeting': {
                'patterns': [r'hello|hi|hey|good morning|good evening|greetings|sup|yo'],
                'responses': [
                    "Hello! 👋 How can I assist you with file security today?",
                    "Hi there! I'm your AI security assistant. Need help with anything?",
                    "Greetings! 👋 Ready to help with DLP, file uploads, or approvals."
                ]
            },
            'file_upload': {
                'patterns': [r'how to upload|upload file|uploading|upload files|attach file'],
                'responses': [
                    "📤 To upload a file:\n1. Go to 'Upload Files' tab\n2. Choose your file\n3. Click 'Upload & Scan'\n4. Wait for DLP scan results",
                    "Uploading is easy! Just navigate to the Upload Files section, select your document, and our system will automatically scan for sensitive data.",
                    "You can upload files from your dashboard. Supported formats: PDF, DOCX, TXT, XLSX, and images."
                ]
            },
            'approval_status': {
                'patterns': [r'approval|pending|how long|status|approved|rejected|review time'],
                'responses': [
                    "⏳ Files are typically reviewed within 24 hours. Check 'My Files' tab for real-time status updates.",
                    "Approval time depends on DLP risk score:\n- Low risk: Auto-approved instantly\n- Medium risk: Manual review (24h)\n- High risk: Rejected automatically",
                    "You'll receive a notification when your file is approved or rejected."
                ]
            },
            'dlp_scan': {
                'patterns': [r'dlp|data leakage|sensitive data|aadhaar|pan card|credit card|pii'],
                'responses': [
                    "🛡️ Our DLP system scans for:\n• Aadhaar numbers\n• PAN cards\n• Credit card numbers\n• Confidential keywords",
                    "DLP (Data Leakage Prevention) checks every file for sensitive information before approval.",
                    "If DLP detects violations, the file is automatically rejected to prevent data leakage."
                ]
            },
            'risk_score': {
                'patterns': [r'risk score|risk level|how risky|dangerous'],
                'responses': [
                    "Risk scores range from 0-100:\n🟢 0-30: Safe\n🟡 31-60: Medium\n🔴 61-100: High Risk",
                    "The risk score is calculated based on DLP violations, file type, and content analysis."
                ]
            },
            'ai_agent': {
                'patterns': [r'ai agent|automatic approval|auto approval|ai decision'],
                'responses': [
                    "🤖 The AI Admin Agent automatically reviews files based on:\n• Risk score thresholds\n• Historical patterns\n• DLP violation severity",
                    "Our AI can approve low-risk files instantly and flag suspicious ones for manual review."
                ]
            },
            'persona': {
                'patterns': [r'persona|behavior|behavioral|profile|trust score'],
                'responses': [
                    "👤 Your persona is built from:\n• Upload history\n• File types\n• Risk patterns\n• Time of activity",
                    "We analyze behavioral patterns to detect anomalies and prevent insider threats."
                ]
            },
            'security': {
                'patterns': [r'security|encryption|safe|protect|secure'],
                'responses': [
                    "🔒 Security features include:\n• AES-256 encryption\n• DLP scanning\n• Behavioral analysis\n• Audit logging",
                    "All files are encrypted before storage and scanned for malware/viruses."
                ]
            },
            'help': {
                'patterns': [r'help|support|assist|what can you do|features|capabilities'],
                'responses': [
                    "I can help with:\n📤 File uploads & scanning\n✅ Approval tracking\n🛡️ DLP explanations\n👤 \n🤖 AI agent questions\n🔒 Security features",
                    "Just ask me anything about file security, DLP, approvals, or system features!"
                ]
            },
            'complaint': {
                'patterns': [r'complaint|issue|problem|not working|bug|error'],
                'responses': [
                    "Sorry to hear that! 🙁 Please describe the issue and I'll help troubleshoot.\n\nYou can also contact admin at pthombre200@gmail.com",
                    "I apologize for the inconvenience. Let me help you resolve this. What specific problem are you facing?"
                ]
            },
            'thank_you': {
                'patterns': [r'thank|thanks|appreciate|grateful|helpful'],
                'responses': [
                    "You're welcome! 😊 Happy to help!",
                    "Glad I could assist! Feel free to ask if you need anything else.",
                    "My pleasure! Stay secure! 🔒"
                ]
            },
            'goodbye': {
                'patterns': [r'bye|goodbye|see you|exit|quit'],
                'responses': [
                    "Goodbye! 👋 Stay secure!",
                    "See you later! Remember to practice safe file handling!",
                    "Farewell! Feel free to return if you need assistance."
                ]
            },
            'unknown': {
                'patterns': [],
                'responses': [
                    "I'm not sure I understand. Could you rephrase that?\n\nTry asking about:\n• File uploads\n• DLP scanning\n• Approval status\n• Security features",
                    "Hmm, I don't have an answer for that yet. My expertise is in file security, DLP, and approvals. Can you ask something related to these topics?"
                ]
            }
        }
        
        # Context-aware response mapping
        self.context_handlers = {
            'upload': self._handle_upload_context,
            'approval': self._handle_approval_context,
            'dlp': self._handle_dlp_context
        }
    
    def _handle_upload_context(self, user_id: int, question: str) -> Optional[str]:
        """Handle context-aware responses for upload questions"""
        recent_files = self.get_user_recent_files(user_id)
        if recent_files:
            return f"I see you've uploaded {len(recent_files)} files recently. The most recent was '{recent_files[0]['filename']}'. Need help with upload settings?"
        return None
    
    def _handle_approval_context(self, user_id: int, question: str) -> Optional[str]:
        """Handle context-aware responses for approval questions"""
        pending_files = self.get_pending_files(user_id)
        if pending_files:
            return f"You have {len(pending_files)} file(s) pending approval. The oldest is from {pending_files[0]['uploaded_at']}. Need status update?"
        return None
    
    def _handle_dlp_context(self, user_id: int, question: str) -> Optional[str]:
        """Handle context-aware responses for DLP questions"""
        violations = self.get_user_violations(user_id)
        if violations:
            return f"Your last DLP violation was {violations[0]['violation_type']} on {violations[0]['timestamp']}. Need help understanding DLP rules?"
        return None
    
    def get_user_recent_files(self, user_id: int, limit: int = 3) -> List[Dict]:
        """Get user's recent files"""
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filename, uploaded_at, approval_status 
            FROM files WHERE user_id = ? 
            ORDER BY uploaded_at DESC LIMIT ?
        """, (user_id, limit))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return files
    
    def get_pending_files(self, user_id: int) -> List[Dict]:
        """Get user's pending files"""
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filename, uploaded_at 
            FROM files 
            WHERE user_id = ? AND approval_status = 'pending'
            ORDER BY uploaded_at ASC
        """, (user_id,))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return files
    
    def get_user_violations(self, user_id: int, limit: int = 3) -> List[Dict]:
        """Get user's DLP violations"""
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT violation_type, severity, timestamp 
            FROM dlp_violations 
            WHERE user_id = ? 
            ORDER BY timestamp DESC LIMIT ?
        """, (user_id, limit))
        
        violations = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return violations
    
    def add_to_memory(self, user_id: int, role: str, content: str):
        """Add message to conversation memory"""
        self.conversation_memory[user_id].append({
            'role': role,
            'content': content,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only last N messages
        if len(self.conversation_memory[user_id]) > self.context_window * 2:
            self.conversation_memory[user_id] = self.conversation_memory[user_id][-self.context_window * 2:]
    
    def get_conversation_context(self, user_id: int) -> str:
        """Get recent conversation context"""
        messages = self.conversation_memory.get(user_id, [])
        context = "\n".join([f"{m['role']}: {m['content']}" for m in messages[-self.context_window:]])
        return context
    
    def ask(self, question: str, user_id: int = None) -> str:
        """Process user question with context awareness"""
        # Add user message to memory
        if user_id:
            self.add_to_memory(user_id, 'user', question)
        
        # Check for context-aware responses
        if user_id:
            for keyword, handler in self.context_handlers.items():
                if keyword in question.lower():
                    context_response = handler(user_id, question)
                    if context_response:
                        response = context_response
                        break
            else:
                response = self._match_intent(question)
        else:
            response = self._match_intent(question)
        
        # Add assistant response to memory
        if user_id:
            self.add_to_memory(user_id, 'assistant', response)
        
        return response
    
    def _match_intent(self, question: str) -> str:
        """Match question to intent and return response"""
        question_lower = question.lower()
        
        for intent_name, intent_data in self.intents.items():
            if intent_name == 'unknown':
                continue
                
            for pattern in intent_data['patterns']:
                if re.search(pattern, question_lower):
                    return random.choice(intent_data['responses'])
        
        # Return unknown intent response
        return random.choice(self.intents['unknown']['responses'])
    
    def get_conversation_history(self, user_id: int) -> List[Dict]:
        """Get full conversation history for a user"""
        return self.conversation_memory.get(user_id, [])
    
    def clear_conversation_history(self, user_id: int):
        """Clear conversation history for a user"""
        if user_id in self.conversation_memory:
            self.conversation_memory[user_id] = []