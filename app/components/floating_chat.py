import streamlit as st
from datetime import datetime

def render_floating_chat(chatbot_instance, user_id=None):
    """Simple floating chat using Streamlit containers - Guaranteed to work"""
    
    # Custom CSS for floating chat
    st.markdown("""
    <style>
    /* Fixed position container */
    .floating-chat-container {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 999;
        width: 380px;
        max-width: 90vw;
    }
    
    /* Chat button */
    .chat-toggle-btn {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 14px 20px;
        border-radius: 50px;
        cursor: pointer;
        font-weight: bold;
        font-size: 16px;
        margin-bottom: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        transition: all 0.3s ease;
        text-align: center;
    }
    
    .chat-toggle-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.4);
    }
    
    /* Chat window */
    .chat-window-popup {
        background: #1e1e2e;
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.1);
        animation: slideUp 0.3s ease;
    }
    
    @keyframes slideUp {
        from {
            opacity: 0;
            transform: translateY(50px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    /* Chat header */
    .chat-header-popup {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 12px 15px;
        color: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .chat-header-popup h4 {
        margin: 0;
        font-size: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    /* Messages area */
    .chat-messages-popup {
        height: 400px;
        overflow-y: auto;
        padding: 15px;
        background: #2d2d3d;
    }
    
    /* Message bubbles */
    .message-user {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 10px 14px;
        border-radius: 18px;
        margin: 8px 0;
        margin-left: auto;
        max-width: 85%;
        width: fit-content;
        text-align: right;
        word-wrap: break-word;
    }
    
    .message-bot {
        background: #3d3d4d;
        color: #e0e0e0;
        padding: 10px 14px;
        border-radius: 18px;
        margin: 8px 0;
        margin-right: auto;
        max-width: 85%;
        width: fit-content;
        border-left: 3px solid #27ae60;
        word-wrap: break-word;
    }
    
    /* Input area */
    .chat-input-popup {
        display: flex;
        padding: 12px;
        gap: 10px;
        background: #1e1e2e;
        border-top: 1px solid rgba(255,255,255,0.1);
    }
    
    .chat-input-popup input {
        flex: 1;
        padding: 10px 15px;
        border-radius: 25px;
        border: 1px solid #444;
        background: #2d2d3d;
        color: white;
        outline: none;
    }
    
    .chat-input-popup input:focus {
        border-color: #667eea;
    }
    
    .chat-input-popup button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 10px 20px;
        cursor: pointer;
        transition: transform 0.2s;
    }
    
    .chat-input-popup button:hover {
        transform: scale(1.05);
    }
    
    /* Scrollbar */
    .chat-messages-popup::-webkit-scrollbar {
        width: 6px;
    }
    
    .chat-messages-popup::-webkit-scrollbar-track {
        background: #1e1e2e;
    }
    
    .chat-messages-popup::-webkit-scrollbar-thumb {
        background: #667eea;
        border-radius: 10px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if 'show_floating_chat' not in st.session_state:
        st.session_state.show_floating_chat = False
    
    if 'floating_messages' not in st.session_state:
        st.session_state.floating_messages = [
            {"role": "bot", "content": "👋 Hello! I'm your AI assistant. How can I help you today?"}
        ]
    
    # HTML container for floating element
    import streamlit.components.v1 as components
    
    # Create the floating button and chat window
    chat_html = f"""
    <div class="floating-chat-container">
        <button class="chat-toggle-btn" onclick="toggleChat()">
            {'🔴 Close Chat' if st.session_state.show_floating_chat else '💬 Chat with AI Assistant'}
        </button>
        
        <div id="chatPopup" class="chat-window-popup" style="display: {'flex' if st.session_state.show_floating_chat else 'none'}; flex-direction: column;">
            <div class="chat-header-popup">
                <h4>
                    🤖 AI Assistant
                    <span style="font-size: 11px; background: #27ae60; padding: 2px 8px; border-radius: 10px;">Online</span>
                </h4>
                <button onclick="toggleChat()" style="background: none; border: none; color: white; font-size: 20px; cursor: pointer;">✕</button>
            </div>
            
            <div id="chatMessages" class="chat-messages-popup">
    """
    
    # Add existing messages
    for msg in st.session_state.floating_messages:
        if msg["role"] == "user":
            chat_html += f'<div class="message-user">👤 {msg["content"]}</div>'
        else:
            chat_html += f'<div class="message-bot">🤖 {msg["content"]}</div>'
    
    chat_html += """
            </div>
            
            <div class="chat-input-popup">
                <input type="text" id="chatInput" placeholder="Type your message..." onkeypress="if(event.keyCode==13) sendMessage()">
                <button onclick="sendMessage()">Send ➤</button>
            </div>
        </div>
    </div>
    
    <script>
        function toggleChat() {
            var chatWindow = document.getElementById('chatPopup');
            if (chatWindow.style.display === 'none' || chatWindow.style.display === '') {
                chatWindow.style.display = 'flex';
            } else {
                chatWindow.style.display = 'none';
            }
        }
        
        function sendMessage() {
            var input = document.getElementById('chatInput');
            var message = input.value;
            if (message.trim()) {
                // Store message in localStorage
                localStorage.setItem('chat_message', message);
                // Reload page to process message
                window.location.reload();
            }
        }
        
        // Auto-scroll to bottom of messages
        var messagesDiv = document.getElementById('chatMessages');
        if (messagesDiv) {{
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }}
        
        // Check for stored message on load
        var storedMsg = localStorage.getItem('chat_message');
        if (storedMsg) {{
            localStorage.removeItem('chat_message');
            // Send to Streamlit via URL parameter
            var url = new URL(window.location.href);
            url.searchParams.set('chat_msg', storedMsg);
            window.location.href = url.toString();
        }}
    </script>
    """
    
    # Render the HTML component
    components.html(chat_html, height=120)
    
    # Process message from URL parameter
    import streamlit as st
    
    # Check for chat message in query params
    query_params = st.query_params
    if 'chat_msg' in query_params:
        user_message = query_params['chat_msg']
        if user_message and user_message != st.session_state.get('last_processed'):
            st.session_state.last_processed = user_message
            
            # Add user message
            st.session_state.floating_messages.append({"role": "user", "content": user_message})
            
            # Get bot response
            try:
                response = chatbot_instance.ask(user_message, user_id)
            except:
                response = chatbot_instance.ask(user_message)  # Fallback without user_id
            
            # Add bot response
            st.session_state.floating_messages.append({"role": "bot", "content": response})
            
            # Clear the query param
            st.query_params.clear()
            st.rerun()