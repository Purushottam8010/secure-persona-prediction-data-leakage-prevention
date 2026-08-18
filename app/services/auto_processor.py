import time
import threading
import streamlit as st
from datetime import datetime
from typing import Dict
import pandas as pd

class AutoFileProcessor:
    """Background processor that automatically runs AI Agent on pending files"""
    
    def __init__(self, ai_agent):
        self.ai_agent = ai_agent
        self.is_running = False
        self.last_run = None
        self.processing_thread = None
        
    def start_background_processing(self, interval_seconds: int = 30):
        """Start background thread to process files automatically"""
        if self.processing_thread is None or not self.processing_thread.is_alive():
            self.is_running = True
            self.processing_thread = threading.Thread(
                target=self._process_loop,
                args=(interval_seconds,),
                daemon=True
            )
            self.processing_thread.start()
            return True
        return False
    
    def stop_background_processing(self):
        """Stop background processing"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
    
    def _process_loop(self, interval_seconds: int):
        """Main processing loop"""
        while self.is_running:
            try:
                self.process_pending_files()
                time.sleep(interval_seconds)
            except Exception as e:
                print(f"Error in auto processor: {e}")
                time.sleep(interval_seconds)
    
    def process_pending_files(self) -> Dict:
        """Process all pending files using AI Agent"""
        results = self.ai_agent.scan_and_process_pending_files()
        self.last_run = datetime.now()
        
        # Store results in session state for UI
        if 'ai_processing_results' not in st.session_state:
            st.session_state.ai_processing_results = []
        
        if results['auto_approved'] or results['auto_rejected']:
            st.session_state.ai_processing_results.insert(0, {
                'timestamp': self.last_run,
                'approved': len(results['auto_approved']),
                'rejected': len(results['auto_rejected']),
                'manual': len(results['manual_review']),
                'details': results
            })
            
            # Keep only last 10 results
            st.session_state.ai_processing_results = st.session_state.ai_processing_results[:10]
        
        return results
    
    def get_processing_status(self) -> Dict:
        """Get current processing status"""
        return {
            'is_running': self.is_running,
            'last_run': self.last_run,
            'thread_alive': self.processing_thread.is_alive() if self.processing_thread else False
        }