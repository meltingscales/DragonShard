"""
Fuzzing progress API endpoints
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models import FuzzingProgress, FuzzingSession, FuzzingStatus, GeneticAlgorithmStats
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage
fuzzing_sessions: List[FuzzingSession] = []
fuzzing_progress: List[FuzzingProgress] = []
active_fuzzing_tasks: Dict[str, asyncio.Task] = {}
mutation_tree_nodes: Dict[str, Dict[str, Any]] = {}


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
            average_fitness = sum(s.average_fitness for s in fuzzing_sessions) / len(
                fuzzing_sessions
            )
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
            best_fitness=best_fitness,
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
        await websocket_manager.broadcast(
            {"type": "fuzzing_session_created", "data": session.dict()}
        )

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
        await websocket_manager.broadcast(
            {"type": "fuzzing_progress_updated", "data": progress.dict()}
        )

        logger.info(f"Added fuzzing progress for session: {progress.session_id}")
        return progress
    except Exception as e:
        logger.error(f"Error adding fuzzing progress: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/start")
async def start_fuzzing(request: Dict[str, Any]):
    """Start a new fuzzing session"""
    try:
        session_id = f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"

        # Create new fuzzing session
        session = FuzzingSession(
            id=session_id,
            name=f"Fuzzing Session {session_id}",
            status=FuzzingStatus.RUNNING,
            target=request.get("target_url", "http://localhost:8082"),
            payload_type=request.get("payload_type", "sql_injection"),
            generation=0,
            population_size=request.get("population_size", 50),
            best_fitness=0.0,
            average_fitness=0.0,
            mutations_count=0,
            start_time=datetime.now(),
        )

        fuzzing_sessions.append(session)

        # Start background task to simulate fuzzing
        task = asyncio.create_task(simulate_fuzzing(session_id, request))
        active_fuzzing_tasks[session_id] = task

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {
                "type": "fuzzing_started",
                "data": {
                    "session_id": session_id,
                    "target_url": request.get("target_url"),
                    "payload_type": request.get("payload_type"),
                },
            }
        )

        logger.info(f"Started fuzzing session: {session_id}")
        return {
            "success": True,
            "session_id": session_id,
            "message": "Fuzzing started successfully",
        }
    except Exception as e:
        logger.error(f"Error starting fuzzing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_fuzzing():
    """Stop all running fuzzing sessions"""
    try:
        stopped_sessions = []

        # Cancel all active tasks
        for session_id, task in active_fuzzing_tasks.items():
            if not task.done():
                task.cancel()
                stopped_sessions.append(session_id)

        # Update session status
        for session in fuzzing_sessions:
            if session.status == FuzzingStatus.RUNNING:
                session.status = FuzzingStatus.COMPLETED
                session.end_time = datetime.now()
                if session.start_time:
                    session.duration = (session.end_time - session.start_time).total_seconds()

        # Clear active tasks
        active_fuzzing_tasks.clear()

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {"type": "fuzzing_stopped", "data": {"stopped_sessions": stopped_sessions}}
        )

        logger.info(f"Stopped {len(stopped_sessions)} fuzzing sessions")
        return {
            "success": True,
            "stopped_sessions": stopped_sessions,
            "message": "Fuzzing stopped successfully",
        }
    except Exception as e:
        logger.error(f"Error stopping fuzzing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def simulate_fuzzing(session_id: str, request: Dict[str, Any]):
    """Simulate fuzzing process with real-time updates"""
    try:
        generation = 0
        max_generations = request.get("generations", 100)
        population_size = request.get("population_size", 50)

        while generation < max_generations:
            # Check if task was cancelled
            if session_id not in active_fuzzing_tasks:
                break

            # Simulate generation progress
            generation += 1
            best_fitness = min(1.0, 0.1 + (generation * 0.008) + (generation % 10) * 0.02)
            average_fitness = best_fitness * 0.7
            mutations_count = generation * population_size

            # Update session
            for session in fuzzing_sessions:
                if session.id == session_id:
                    session.generation = generation
                    session.best_fitness = best_fitness
                    session.average_fitness = average_fitness
                    session.mutations_count = mutations_count
                    break

            # Create progress update
            progress = FuzzingProgress(
                session_id=session_id,
                generation=generation,
                population_size=population_size,
                best_fitness=best_fitness,
                average_fitness=average_fitness,
                diversity=0.8 - (generation * 0.01),
                mutations_count=mutations_count,
                successful_payloads=int(best_fitness * population_size * 0.3),
                timestamp=datetime.now(),
            )

            fuzzing_progress.append(progress)

            # Broadcast progress update
            await websocket_manager.broadcast(
                {"type": "fuzzing_progress_updated", "data": progress.dict(exclude_none=True)}
            )

            # Wait between generations
            await asyncio.sleep(2)

        # Mark session as completed
        for session in fuzzing_sessions:
            if session.id == session_id:
                session.status = FuzzingStatus.COMPLETED
                session.end_time = datetime.now()
                if session.start_time:
                    session.duration = (session.end_time - session.start_time).total_seconds()
                break

        # Remove from active tasks
        if session_id in active_fuzzing_tasks:
            del active_fuzzing_tasks[session_id]

        logger.info(f"Completed fuzzing session: {session_id}")

    except asyncio.CancelledError:
        logger.info(f"Fuzzing session cancelled: {session_id}")
    except Exception as e:
        logger.error(f"Error in fuzzing simulation: {e}")


@router.get("/mutation-tree")
async def get_mutation_tree():
    """Get mutation tree data"""
    try:
        return mutation_tree_nodes
    except Exception as e:
        logger.error(f"Error getting mutation tree: {e}")
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
        start_time=datetime.now(),
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
            timestamp=datetime.now(),
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
            timestamp=datetime.now(),
        ),
    ]

    fuzzing_sessions = [mock_session]
    fuzzing_progress = mock_progress


# Initialize mock data
create_mock_fuzzing()
