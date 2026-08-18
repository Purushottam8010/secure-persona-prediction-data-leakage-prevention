from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from typing import Dict, List
from pydantic import BaseModel
import json

from ..services.admin_agent import AIAdminAgent
from ..services.chatbot import SupportChatbot
from ..database import SessionLocal

router = APIRouter(prefix="/agent", tags=["AI Agent & Chatbot"])

# Initialize services
agent = None
chatbot = None

def get_services():
    global agent, chatbot
    from database import DatabaseManager
    db = DatabaseManager()
    if agent is None:
        agent = AIAdminAgent(db)
    if chatbot is None:
        chatbot = SupportChatbot(db)
    return agent, chatbot

class ChatMessage(BaseModel):
    message: str
    user_id: int

class BatchProcessRequest(BaseModel):
    limit: int = 50

@router.post("/process-pending")
async def process_pending_files(request: BatchProcessRequest):
    """AI Agent: Process all pending files"""
    agent, _ = get_services()
    results = agent.process_pending_files(request.limit)
    
    return {
        "processed": len(results),
        "results": [
            {
                "decision": r.decision.value,
                "confidence": r.confidence,
                "reason": r.reason,
                "action": r.action_taken
            }
            for r in results
        ]
    }

@router.post("/analyze-file/{file_id}")
async def analyze_single_file(file_id: int):
    """AI Agent: Analyze and process a single file"""
    agent, _ = get_services()
    result = agent.analyze_file(file_id)
    
    return {
        "file_id": file_id,
        "decision": result.decision.value,
        "confidence": result.confidence,
        "reason": result.reason,
        "action_taken": result.action_taken,
        "notification": result.notification_message
    }

@router.get("/agent-stats")
async def get_agent_stats():
    """Get AI Agent statistics"""
    agent, _ = get_services()
    return agent.get_agent_stats()

@router.post("/chat")
async def chat_with_bot(chat: ChatMessage):
    """Chatbot: Send message to support bot"""
    _, chatbot = get_services()
    response = chatbot.get_response(chat.user_id, chat.message)
    return response

@router.get("/chat-history/{user_id}")
async def get_chat_history(user_id: int, limit: int = 10):
    """Chatbot: Get conversation history"""
    _, chatbot = get_services()
    history = chatbot.get_conversation_history(user_id, limit)
    return {"history": history}

@router.post("/chat/clear/{user_id}")
async def clear_chat_context(user_id: int):
    """Chatbot: Clear conversation context"""
    _, chatbot = get_services()
    chatbot.clear_context(user_id)
    return {"message": "Context cleared"}

@router.websocket("/ws/chat/{user_id}")
async def websocket_chat(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time chat"""
    await websocket.accept()
    _, chatbot = get_services()
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            message = message_data.get('message', '')
            
            # Get bot response
            response = chatbot.get_response(user_id, message)
            
            # Send response
            await websocket.send_json(response)
            
    except WebSocketDisconnect:
        print(f"User {user_id} disconnected from chat")