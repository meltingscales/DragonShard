"""
Fuzzing progress API endpoints
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import logging
from datetime import datetime

from ..models import FuzzingSession, FuzzingProgress, GeneticAlgorithmStats, FuzzingStatus
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage
fuzzing_sessions: List[FuzzingSession] = []
fuzzing_progress: List[FuzzingProgress] = []

@router.get("/sessions", response_model=List[FuzzingSession])
async def get_fuzzing_sessions():
    """Get all fuzzing sessions"""
    try:
        return fuzzing_sessions
    except Exception as e:
        logger.error(f"Error getting fuzzing sessions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/sessions/{session_id}", response_model=FuzzingSession)
async def get_fuzzing_session(session_id: str):
    """Get specific fuzzing session by ID"""
    try:
        for session in fuzzing_sessions:
            if session.id == session_id:
                return session
        
        raise HTTPException(status_code=404, detail="Fuzzing session not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting fuzzing session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/progress/{session_id}", response_model=List[FuzzingProgress])
async def get_fuzzing_progress(session_id: str):
    """Get progress for a specific fuzzing session"""
    try:
        session_progress = [p for p in fuzzing_progress if p.session_id == session_id]
        return session_progress
    except Exception as e:
        logger.error(f"Error getting fuzzing progress: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/stats", response_model=GeneticAlgorithmStats)
async def get_genetic_algorithm_stats():
    """Get genetic algorithm statistics"""
    try:
        total_sessions = len(fuzzing_sessions)
        active_sessions = len([s for s in fuzzing_sessions if s.status == FuzzingStatus.RUNNING])
        total_generations = sum(s.generation for s in fuzzing_sessions)
        total_mutations = sum(s.mutations_count for s in fuzzing_sessions)
        
        if fuzzing_sessions:
            average_fitness = sum(s.average_fitness for s in fuzzing_sessions) / len(fuzzing_sessions)
            best_fitness = max(s.best_fitness for s in fuzzing_sessions)
        else:
            average_fitness = 0.0
            best_fitness = 0.0
        
        return GeneticAlgorithmStats(
            total_sessions=total_sessions,
            active_sessions=active_sessions,
            total_generations=total_generations,
            total_mutations=total_mutations,
            average_fitness=average_fitness,
            best_fitness=best_fitness
        )
    except Exception as e:
        logger.error(f"Error getting genetic algorithm stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/sessions", response_model=FuzzingSession)
async def create_fuzzing_session(session: FuzzingSession):
    """Create a new fuzzing session"""
    try:
        fuzzing_sessions.append(session)
        
        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({
            "type": "fuzzing_session_created",
            "data": session.dict()
        })
        
        logger.info(f"Created fuzzing session: {session.id}")
        return session
    except Exception as e:
        logger.error(f"Error creating fuzzing session: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/progress", response_model=FuzzingProgress)
async def add_fuzzing_progress(progress: FuzzingProgress):
    """Add fuzzing progress update"""
    try:
        fuzzing_progress.append(progress)
        
        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({
            "type": "fuzzing_progress_updated",
            "data": progress.dict()
        })
        
        logger.info(f"Added fuzzing progress for session: {progress.session_id}")
        return progress
    except Exception as e:
        logger.error(f"Error adding fuzzing progress: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Mock data for testing
def create_mock_fuzzing():
    """Create mock fuzzing data for testing"""
    global fuzzing_sessions, fuzzing_progress
    
    # Create mock fuzzing session
    mock_session = FuzzingSession(
        id="fuzz_session_001",
        name="SQL Injection Fuzzing",
        status=FuzzingStatus.RUNNING,
        target="http://localhost:8085/api/sql/complex",
        payload_type="sql_injection",
        generation=15,
        population_size=50,
        best_fitness=0.85,
        average_fitness=0.62,
        mutations_count=1250,
        start_time=datetime.now()
    )
    
    # Create mock progress data
    mock_progress = [
        FuzzingProgress(
            session_id="fuzz_session_001",
            generation=15,
            population_size=50,
            best_fitness=0.85,
            average_fitness=0.62,
            diversity=0.73,
            mutations_count=1250,
            successful_payloads=23,
            timestamp=datetime.now()
        ),
        FuzzingProgress(
            session_id="fuzz_session_001",
            generation=14,
            population_size=50,
            best_fitness=0.82,
            average_fitness=0.58,
            diversity=0.75,
            mutations_count=1200,
            successful_payloads=21,
            timestamp=datetime.now()
        )
    ]
    
    fuzzing_sessions = [mock_session]
    fuzzing_progress = mock_progress

# Initialize mock data
create_mock_fuzzing() 