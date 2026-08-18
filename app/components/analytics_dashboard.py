import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sqlite3
from typing import Dict, List

class AnalyticsDashboard:
    """Advanced analytics and reporting for admin"""
    
    def __init__(self, db_path: str = "data/security.db"):
        self.db_path = db_path
    
    def get_dlp_statistics(self, days: int = 30) -> Dict:
        """Get DLP violation statistics"""
        conn = sqlite3.connect(self.db_path)
        
        # Calculate date range
        start_date = datetime.now() - timedelta(days=days)
        
        # Query violations
        violations_df = pd.read_sql_query("""
            SELECT 
                violation_type,
                severity,
                DATE(timestamp) as date,
                users.username
            FROM dlp_violations
            JOIN users ON dlp_violations.user_id = users.id
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        """, conn, params=(start_date,))
        
        conn.close()
        
        return {
            'total_violations': len(violations_df),
            'by_type': violations_df['violation_type'].value_counts().to_dict(),
            'by_severity': violations_df['severity'].value_counts().to_dict(),
            'by_user': violations_df['username'].value_counts().head(10).to_dict(),
            'daily_trend': violations_df.groupby('date').size().to_dict()
        }
    
    def get_approval_statistics(self, days: int = 30) -> Dict:
        """Get file approval statistics"""
        conn = sqlite3.connect(self.db_path)
        
        start_date = datetime.now() - timedelta(days=days)
        
        approvals_df = pd.read_sql_query("""
            SELECT 
                approval_status,
                DATE(uploaded_at) as date,
                risk_score,
                users.username
            FROM files
            JOIN users ON files.user_id = users.id
            WHERE uploaded_at >= ?
        """, conn, params=(start_date,))
        
        conn.close()
        
        return {
            'total_files': len(approvals_df),
            'approved': len(approvals_df[approvals_df['approval_status'] == 'approved']),
            'rejected': len(approvals_df[approvals_df['approval_status'] == 'rejected']),
            'pending': len(approvals_df[approvals_df['approval_status'] == 'pending']),
            'avg_risk_score': approvals_df['risk_score'].mean(),
            'risk_distribution': {
                'low': len(approvals_df[approvals_df['risk_score'] < 30]),
                'medium': len(approvals_df[(approvals_df['risk_score'] >= 30) & (approvals_df['risk_score'] < 60)]),
                'high': len(approvals_df[approvals_df['risk_score'] >= 60])
            }
        }
    
    def get_user_activity(self, days: int = 30) -> pd.DataFrame:
        """Get user activity metrics"""
        conn = sqlite3.connect(self.db_path)
        
        start_date = datetime.now() - timedelta(days=days)
        
        activity_df = pd.read_sql_query("""
            SELECT 
                users.username,
                users.department,
                COUNT(DISTINCT files.id) as total_uploads,
                COUNT(DISTINCT dlp_violations.id) as total_violations,
                AVG(files.risk_score) as avg_risk_score,
                MAX(files.uploaded_at) as last_activity
            FROM users
            LEFT JOIN files ON users.id = files.user_id AND files.uploaded_at >= ?
            LEFT JOIN dlp_violations ON users.id = dlp_violations.user_id AND dlp_violations.timestamp >= ?
            WHERE users.role = 'user'
            GROUP BY users.id
            ORDER BY total_uploads DESC
        """, conn, params=(start_date, start_date))
        
        conn.close()
        return activity_df
    
    def render_dashboard(self):
        """Render the complete analytics dashboard"""
        st.markdown("## 📊 Advanced Analytics Dashboard")
        
        # Date range selector
        col1, col2 = st.columns(2)
        with col1:
            days = st.slider("Select time period (days)", 7, 90, 30)
        with col2:
            refresh = st.button("🔄 Refresh Data")
        
        # Get statistics
        dlp_stats = self.get_dlp_statistics(days)
        approval_stats = self.get_approval_statistics(days)
        user_activity = self.get_user_activity(days)
        
        # Key Metrics Row
        st.markdown("### 📈 Key Metrics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Files", approval_stats['total_files'], 
                     delta=f"+{approval_stats['approved']} approved")
        with col2:
            st.metric("DLP Violations", dlp_stats['total_violations'],
                     delta=f"{len(dlp_stats['by_type'])} types")
        with col3:
            approval_rate = (approval_stats['approved'] / approval_stats['total_files'] * 100) if approval_stats['total_files'] > 0 else 0
            st.metric("Approval Rate", f"{approval_rate:.1f}%")
        with col4:
            st.metric("Avg Risk Score", f"{approval_stats['avg_risk_score']:.1f}")
        
        # Charts Row 1
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### DLP Violations by Type")
            if dlp_stats['by_type']:
                fig = px.pie(values=list(dlp_stats['by_type'].values()), 
                            names=list(dlp_stats['by_type'].keys()),
                            title="Violation Distribution")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No DLP violations in selected period")
        
        with col2:
            st.markdown("#### Risk Score Distribution")
            if approval_stats['risk_distribution']:
                fig = px.bar(x=['Low (0-30)', 'Medium (31-60)', 'High (61-100)'],
                           y=[approval_stats['risk_distribution']['low'],
                              approval_stats['risk_distribution']['medium'],
                              approval_stats['risk_distribution']['high']],
                           title="Risk Levels",
                           color=['Low', 'Medium', 'High'],
                           color_discrete_map={'Low': 'green', 'Medium': 'orange', 'High': 'red'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No files uploaded in selected period")
        
        # Charts Row 2
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Daily Violation Trend")
            if dlp_stats['daily_trend']:
                df_trend = pd.DataFrame(list(dlp_stats['daily_trend'].items()), 
                                       columns=['Date', 'Violations'])
                fig = px.line(df_trend, x='Date', y='Violations', 
                            title="DLP Violations Over Time")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No trend data available")
        
        with col2:
            st.markdown("#### Top Users by Violations")
            if dlp_stats['by_user']:
                df_users = pd.DataFrame(list(dlp_stats['by_user'].items()),
                                       columns=['User', 'Violations'])
                fig = px.bar(df_users.head(10), x='User', y='Violations',
                           title="Users with Most DLP Violations")
                st.plotly_chart(fig, use_container_width=True)
        
        # User Activity Table
        st.markdown("### 👥 User Activity Metrics")
        if not user_activity.empty:
            # Format the dataframe
            display_df = user_activity.copy()
            display_df['avg_risk_score'] = display_df['avg_risk_score'].round(2)
            display_df['last_activity'] = pd.to_datetime(display_df['last_activity']).dt.strftime('%Y-%m-%d')
            display_df.columns = ['Username', 'Department', 'Uploads', 'Violations', 'Avg Risk', 'Last Activity']
            
            st.dataframe(display_df, use_container_width=True)
            
            # Download button
            csv = display_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Report (CSV)",
                data=csv,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No user activity data available")
        
        # AI Performance Metrics
        st.markdown("### 🤖 AI Agent Performance")
        self.render_ai_performance_metrics()
    
    def render_ai_performance_metrics(self):
        """Render AI Agent performance metrics"""
        conn = sqlite3.connect(self.db_path)
        
        # Query AI decisions
        ai_decisions = pd.read_sql_query("""
            SELECT 
                approval_status,
                dlp_action_taken,
                DATE(uploaded_at) as date
            FROM files
            WHERE dlp_action_taken IS NOT NULL
            AND uploaded_at >= date('now', '-30 days')
        """, conn)
        
        conn.close()
        
        if not ai_decisions.empty:
            col1, col2, col3 = st.columns(3)
            
            auto_approved = len(ai_decisions[ai_decisions['approval_status'] == 'approved'])
            auto_rejected = len(ai_decisions[ai_decisions['approval_status'] == 'rejected'])
            total_ai_decisions = len(ai_decisions)
            
            with col1:
                st.metric("Auto-Approved", auto_approved,
                         delta=f"{auto_approved/total_ai_decisions*100:.1f}%" if total_ai_decisions > 0 else "0%")
            with col2:
                st.metric("Auto-Rejected", auto_rejected,
                         delta=f"{auto_rejected/total_ai_decisions*100:.1f}%" if total_ai_decisions > 0 else "0%")
            with col3:
                st.metric("Total AI Decisions", total_ai_decisions)
            
            # Decision trend
            daily_decisions = ai_decisions.groupby('date').size().reset_index(name='decisions')
            fig = px.line(daily_decisions, x='date', y='decisions',
                         title="AI Agent Decision Trend")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No AI decisions recorded in the last 30 days")