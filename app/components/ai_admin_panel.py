import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

def render_ai_admin_panel(ai_agent, auto_processor=None):
    """Render AI Admin Panel with auto-processing controls"""
    
    st.markdown("## 🤖 AI Admin Agent Dashboard")
    
    # Auto-processing controls
    st.markdown("### ⚙️ Auto-Processing Settings")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if auto_processor and not auto_processor.is_running:
            if st.button("▶️ Start Auto-Processing", use_container_width=True):
                auto_processor.start_background_processing(30)
                st.success("Auto-processing started! AI will scan files every 30 seconds.")
                st.rerun()
        elif auto_processor and auto_processor.is_running:
            if st.button("⏸️ Stop Auto-Processing", use_container_width=True):
                auto_processor.stop_background_processing()
                st.warning("Auto-processing stopped.")
                st.rerun()
    
    with col2:
        if st.button("🔄 Run Manual Scan Now", use_container_width=True):
            with st.spinner("AI Agent scanning all pending files..."):
                results = ai_agent.scan_and_process_pending_files()
                st.success(f"Scan complete! ✅ {len(results['auto_approved'])} approved, ❌ {len(results['auto_rejected'])} rejected")
                st.rerun()
    
    with col3:
        stats = ai_agent.get_processing_stats()
        st.metric("Auto-Processing Rate", f"{stats['auto_processing_rate']:.1f}%")
    
    # Display auto-processor status
    if auto_processor:
        status = auto_processor.get_processing_status()
        if status['is_running']:
            st.info(f"🟢 Auto-processor is RUNNING | Last run: {status['last_run'].strftime('%Y-%m-%d %H:%M:%S') if status['last_run'] else 'Never'}")
        else:
            st.warning("⚫ Auto-processor is STOPPED")
    
    # Statistics Section
    st.markdown("### 📊 AI Agent Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Files", stats['total_files'])
    with col2:
        st.metric("AI Approved", stats['ai_approved'], delta="Auto")
    with col3:
        st.metric("AI Rejected", stats['ai_rejected'], delta="Auto")
    with col4:
        st.metric("Pending Review", stats['pending'])
    
    # AI Decision Log
    st.markdown("### 📋 AI Decision Log")
    
    try:
        decision_log = ai_agent.get_ai_decision_log(50)
        
        if not decision_log.empty:
            # Prepare display data
            display_data = []
            
            for _, row in decision_log.iterrows():
                # Get display datetime
                uploaded_display = row.get('uploaded_at_display', row.get('uploaded_at', 'N/A'))
                if pd.isna(uploaded_display):
                    uploaded_display = 'N/A'
                
                # Get risk score display
                risk_display = row.get('risk_score_display', 'N/A')
                
                # Truncate long AI decision text
                ai_decision = row.get('ai_decision', 'N/A')
                if isinstance(ai_decision, str) and len(ai_decision) > 100:
                    ai_decision = ai_decision[:100] + "..."
                
                display_data.append({
                    "Filename": row.get('filename', 'N/A'),
                    "User": row.get('username', 'N/A'),
                    "Risk Score": risk_display,
                    "Status": row.get('approval_status', 'N/A').title(),
                    "AI Decision": ai_decision,
                    "Processed At": uploaded_display
                })
            
            if display_data:
                display_df = pd.DataFrame(display_data)
                st.dataframe(display_df, use_container_width=True)
                
                # Download button
                csv = decision_log.to_csv(index=False)
                st.download_button(
                    label="📥 Download AI Decision Log (CSV)",
                    data=csv,
                    file_name=f"ai_decisions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No AI decisions recorded yet. Upload files or run manual scan to see decisions.")
        else:
            st.info("No AI decisions recorded yet. Upload files or run manual scan to see decisions.")
            
    except Exception as e:
        st.error(f"Error loading AI decision log: {str(e)}")
        st.info("Upload some files first to see AI decisions.")
    
    # Recent Processing Results
    if 'ai_processing_results' in st.session_state and st.session_state.ai_processing_results:
        st.markdown("### 🆕 Recent Processing Results")
        
        latest = st.session_state.ai_processing_results[0]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Auto-Approved", latest['approved'], delta="✓")
        with col2:
            st.metric("Auto-Rejected", latest['rejected'], delta="✗")
        with col3:
            st.metric("Manual Review", latest['manual'], delta="👤")
        
        # Show details of latest processing
        if latest['details']['auto_approved']:
            with st.expander(f"✅ Recently Approved Files ({latest['approved']})"):
                for file in latest['details']['auto_approved']:
                    st.write(f"📄 **{file['filename']}** - {file['user']} - Risk: {file['risk_score']}")
                    st.caption(f"Reason: {file['reason']}")
                    st.divider()
        
        if latest['details']['auto_rejected']:
            with st.expander(f"❌ Recently Rejected Files ({latest['rejected']})"):
                for file in latest['details']['auto_rejected']:
                    st.write(f"📄 **{file['filename']}** - {file['user']} - Risk: {file['risk_score']}")
                    st.caption(f"Reason: {file['reason']}")
                    st.divider()
    
    # Configuration Section
    with st.expander("⚙️ AI Agent Configuration"):
        st.markdown("### Decision Thresholds")
        
        col1, col2 = st.columns(2)
        with col1:
            new_approve_threshold = st.slider(
                "Auto-Approve Max Risk Score (%)",
                min_value=0,
                max_value=100,
                value=ai_agent.thresholds['auto_approve_max_risk'],
                step=5
            )
            ai_agent.thresholds['auto_approve_max_risk'] = new_approve_threshold
        
        with col2:
            new_reject_threshold = st.slider(
                "Auto-Reject Min Risk Score (%)",
                min_value=0,
                max_value=100,
                value=ai_agent.thresholds['auto_reject_min_risk'],
                step=5
            )
            ai_agent.thresholds['auto_reject_min_risk'] = new_reject_threshold
        
        st.info(f"Manual Review Range: {ai_agent.thresholds['auto_approve_max_risk']+1}% - {ai_agent.thresholds['auto_reject_min_risk']-1}%")
        
        if st.button("💾 Save Configuration"):
            st.success("Configuration saved successfully!")