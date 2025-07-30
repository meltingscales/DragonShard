"""
Session management API endpoints
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import logging
from datetime import datetime, timedelta

from ..models import Session, SessionSummary, BaseResponse
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage
sessions: List[Session] = []

@router.get("/", response_model=List[Session])
async def get_sessions():
    """Get all sessions"""
    try:
        return sessions
    except Exception as e:
        logger.error(f"Error getting sessions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{session_id}", response_model=Session)
async def get_session(session_id: str):
    """Get specific session by ID"""
    try:
        for session in sessions:
            if session.id == session_id:
                return session
        
        raise HTTPException(status_code=404, detail="Session not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/summary/stats", response_model=SessionSummary)
async def get_session_summary():
    """Get session statistics summary"""
    try:
        total_sessions = len(sessions)
        authenticated_sessions = len([s for s in sessions if s.authenticated])
        active_sessions = len([s for s in sessions if s.last_used > datetime.now() - timedelta(hours=1)])
        
        # Group by target
        by_target = {}
        for session in sessions:
            by_target[session.target] = by_target.get(session.target, 0) + 1
        
        return SessionSummary(
            total_sessions=total_sessions,
            authenticated_sessions=authenticated_sessions,
            active_sessions=active_sessions,
            by_target=by_target
        )
    except Exception as e:
        logger.error(f"Error getting session summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/", response_model=Session)
async def create_session(session: Session):
    """Create a new session"""
    try:
        sessions.append(session)
        
        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({
            "type": "session_created",
            "data": session.dict()
        })
        
        logger.info(f"Created session: {session.id}")
        return session
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/{session_id}", response_model=Session)
async def update_session(session_id: str, session: Session):
    """Update a session"""
    try:
        for i, existing_session in enumerate(sessions):
            if existing_session.id == session_id:
                sessions[i] = session
                
                # Broadcast to WebSocket clients
                await websocket_manager.broadcast({
                    "type": "session_updated",
                    "data": session.dict()
                })
                
                logger.info(f"Updated session: {session_id}")
                return session
        
        raise HTTPException(status_code=404, detail="Session not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating session: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/{session_id}", response_model=BaseResponse)
async def delete_session(session_id: str):
    """Delete a session"""
    try:
        for i, session in enumerate(sessions):
            if session.id == session_id:
                deleted_session = sessions.pop(i)
                
                # Broadcast to WebSocket clients
                await websocket_manager.broadcast({
                    "type": "session_deleted",
                    "data": {"session_id": session_id}
                })
                
                logger.info(f"Deleted session: {session_id}")
                return BaseResponse(message=f"Session {session_id} deleted successfully")
        
        raise HTTPException(status_code=404, detail="Session not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting session: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Mock data for testing
def create_mock_sessions():
    """Create mock session data for testing"""
    global sessions
    
    from datetime import timedelta
    
    mock_sessions = [
        Session(
            id="session_001",
            target="http://localhost:8085",
            authenticated=True,
            auth_method="form",
            cookies={"session_id": "abc123", "csrf_token": "xyz789"},
            headers={"User-Agent": "DragonShard/1.0"},
            created_at=datetime.now() - timedelta(minutes=30),
            last_used=datetime.now(),
            requests_count=15
        ),
        Session(
            id="session_002",
            target="192.168.1.100",
            authenticated=False,
            auth_method=None,
            cookies={},
            headers={"User-Agent": "DragonShard/1.0"},
            created_at=datetime.now() - timedelta(minutes=5),
            last_used=datetime.now() - timedelta(minutes=2),
            requests_count=3
        )
    ]
    
    sessions = mock_sessions

# Initialize mock data
create_mock_sessions() 