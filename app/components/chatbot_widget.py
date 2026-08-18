import streamlit as st
from datetime import datetime

def render_chatbot_widget(chatbot_instance):
    """Render the main chatbot widget with improved styling"""
    
    # Custom CSS for chat styling
    st.markdown("""
    <style>
    /* Chat message containers */
    .chat-message {
        display: flex;
        margin-bottom: 10px;
    }
    
    /* User message styling */
    .user-message {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 10px 15px;
        border-radius: 20px;
        border-top-right-radius: 5px;
        max-width: 70%;
        margin-left: auto;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    
    /* Bot message styling */
    .bot-message {
        background: #2c3e50;
        color: #ecf0f1;
        padding: 10px 15px;
        border-radius: 20px;
        border-top-left-radius: 5px;
        max-width: 70%;
        margin-right: auto;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        border-left: 3px solid #27ae60;
    }
    
    /* Bot name indicator */
    .bot-name {
        color: #27ae60;
        font-size: 0.8em;
        font-weight: bold;
        margin-bottom: 5px;
    }
    
    /* Timestamp */
    .timestamp {
        color: #7f8c8d;
        font-size: 0.7em;
        margin-top: 5px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Chat header
    with st.expander("💬 Support Chatbot - Ask me anything!", expanded=False):
        st.markdown("**🤖 AI Assistant** - I can help with:")
        st.markdown("- 📁 File upload issues\n- 🔒 Security questions\n- 📊 Report generation\n- 🆘 General help")
        
        # Initialize chat history in session state
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = [
                {"role": "bot", "message": "Hello! 👋 I'm your support assistant. How can I help you today?", "timestamp": datetime.now()}
            ]
        
        # Display chat messages with styling
        for msg in st.session_state.chat_history:
            if msg["role"] == "user":
                # User message (right aligned)
                st.markdown(f"""
                <div class="chat-message">
                    <div class="user-message">
                        <strong>👤 You</strong><br>
                        {msg["message"]}
                        <div class="timestamp">{msg["timestamp"].strftime("%H:%M")}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                # Bot message (left aligned with distinct color)
                st.markdown(f"""
                <div class="chat-message">
                    <div class="bot-message">
                        <div class="bot-name">🤖 AI Assistant</div>
                        {msg["message"]}
                        <div class="timestamp">{msg["timestamp"].strftime("%H:%M")}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        # Chat input
        st.markdown("---")
        user_question = st.text_input("💭 Type your question here...", key="chat_input", placeholder="e.g., How do I upload a file?")
        
        col1, col2, col3 = st.columns([1,1,4])
        with col1:
            send_button = st.button("📤 Send", type="primary", use_container_width=True)
        with col2:
            if st.button("🗑️ Clear", use_container_width=True):
                st.session_state.chat_history = [
                    {"role": "bot", "message": "Chat cleared! 👋 How can I help you?", "timestamp": datetime.now()}
                ]
                st.rerun()
        
        if send_button and user_question:
            # Add user message
            st.session_state.chat_history.append({
                "role": "user",
                "message": user_question,
                "timestamp": datetime.now()
            })
            
            # Get bot response
            with st.spinner("🤔 Thinking..."):
                response = chatbot_instance.ask(user_question)
            
            # Add bot response
            st.session_state.chat_history.append({
                "role": "bot",
                "message": response,
                "timestamp": datetime.now()
            })
            
            st.rerun()


def render_chatbot_sidebar(chatbot_instance):
    """Render chatbot in sidebar mode"""
    with st.sidebar:
        st.markdown("### 💬 Support Chatbot")
        st.markdown("---")
        
        # Custom sidebar CSS
        st.markdown("""
        <style>
        .sidebar-user-msg {
            background-color: #1e88e5;
            color: white;
            padding: 8px;
            border-radius: 10px;
            margin: 5px 0;
            font-size: 0.9em;
        }
        .sidebar-bot-msg {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 8px;
            border-radius: 10px;
            margin: 5px 0;
            font-size: 0.9em;
            border-left: 2px solid #27ae60;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Initialize chat history for sidebar
        if "sidebar_chat_history" not in st.session_state:
            st.session_state.sidebar_chat_history = [
                {"role": "bot", "message": "Hi! 👋 Need help? Ask me anything!"}
            ]
        
        # Display chat history
        chat_container = st.container()
        with chat_container:
            for msg in st.session_state.sidebar_chat_history:
                if msg["role"] == "user":
                    st.markdown(f'<div class="sidebar-user-msg">👤 {msg["message"]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="sidebar-bot-msg">🤖 {msg["message"]}</div>', unsafe_allow_html=True)
        
        # Chat input
        user_input = st.text_input("Ask a question:", key="sidebar_chat_input", placeholder="Type here...", label_visibility="collapsed")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            if st.button("📤 Send", key="sidebar_send", use_container_width=True):
                if user_input:
                    # Add user message
                    st.session_state.sidebar_chat_history.append({"role": "user", "message": user_input})
                    
                    # Get bot response
                    with st.spinner("🤔"):
                        response = chatbot_instance.ask(user_input)
                    
                    # Add bot response
                    st.session_state.sidebar_chat_history.append({"role": "bot", "message": response})
                    
                    st.rerun()
        with col2:
            if st.button("🗑️ Clear", key="sidebar_clear", use_container_width=True):
                st.session_state.sidebar_chat_history = [
                    {"role": "bot", "message": "Chat cleared! 👋 Ask me anything!"}
                ]
                st.rerun()