"""
Genetic Algorithm API Endpoints
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio

from ..models import *
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data for genetic algorithm
genetic_sessions: Dict[str, Dict[str, Any]] = {}
generation_data: List[Dict[str, Any]] = []
mutation_tree: Dict[str, Dict[str, Any]] = {}

@router.post("/start")
async def start_genetic_algorithm(request: Dict[str, Any]):
    """Start a new genetic algorithm session"""
    try:
        session_id = f"genetic_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session_data = {
            "id": session_id,
            "target_url": request.get("target_url"),
            "payload_type": request.get("payload_type"),
            "population_size": request.get("population_size", 50),
            "generations": request.get("generations", 100),
            "mutation_rate": request.get("mutation_rate", 0.1),
            "crossover_rate": request.get("crossover_rate", 0.8),
            "status": "running",
            "start_time": datetime.now().isoformat(),
            "current_generation": 0,
            "best_fitness": 0.0,
            "average_fitness": 0.0,
            "total_mutations": 0
        }
        
        genetic_sessions[session_id] = session_data
        
        # Start background task to simulate genetic algorithm
        asyncio.create_task(simulate_genetic_algorithm(session_id))
        
        return {
            "success": True,
            "session_id": session_id,
            "message": "Genetic algorithm started successfully"
        }
    except Exception as e:
        logger.error(f"Error starting genetic algorithm: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_genetic_algorithm():
    """Stop all running genetic algorithm sessions"""
    try:
        for session_id in genetic_sessions:
            if genetic_sessions[session_id]["status"] == "running":
                genetic_sessions[session_id]["status"] = "stopped"
                genetic_sessions[session_id]["end_time"] = datetime.now().isoformat()
        
        return {
            "success": True,
            "message": "All genetic algorithm sessions stopped"
        }
    except Exception as e:
        logger.error(f"Error stopping genetic algorithm: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_genetic_stats():
    """Get genetic algorithm statistics"""
    try:
        running_sessions = sum(1 for s in genetic_sessions.values() if s["status"] == "running")
        total_sessions = len(genetic_sessions)
        
        best_fitness = 0.0
        total_generations = 0
        total_mutations = 0
        
        for session in genetic_sessions.values():
            if session["best_fitness"] > best_fitness:
                best_fitness = session["best_fitness"]
            total_generations += session["current_generation"]
            total_mutations += session["total_mutations"]
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": running_sessions,
            "total_generations": total_generations,
            "total_mutations": total_mutations,
            "best_fitness": best_fitness,
            "average_fitness": best_fitness / 2 if best_fitness > 0 else 0.0
        }
    except Exception as e:
        logger.error(f"Error getting genetic stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/sessions")
async def get_genetic_sessions():
    """Get all genetic algorithm sessions"""
    try:
        return list(genetic_sessions.values())
    except Exception as e:
        logger.error(f"Error getting genetic sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/generations")
async def get_generation_data():
    """Get generation data for visualization"""
    try:
        return generation_data
    except Exception as e:
        logger.error(f"Error getting generation data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/mutation-tree")
async def get_mutation_tree():
    """Get mutation tree data"""
    try:
        return mutation_tree
    except Exception as e:
        logger.error(f"Error getting mutation tree: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def simulate_genetic_algorithm(session_id: str):
    """Simulate genetic algorithm evolution"""
    try:
        session = genetic_sessions[session_id]
        generation = 0
        
        while session["status"] == "running" and generation < session["generations"]:
            # Simulate generation
            generation += 1
            session["current_generation"] = generation
            
            # Simulate fitness values
            best_fitness = 0.5 + (generation * 0.01) + (generation % 10 * 0.05)
            average_fitness = best_fitness * 0.7
            
            session["best_fitness"] = best_fitness
            session["average_fitness"] = average_fitness
            session["total_mutations"] += 10
            
            # Create generation data
            gen_data = {
                "generation": generation,
                "best_fitness": best_fitness,
                "average_fitness": average_fitness,
                "population_size": session["population_size"],
                "diversity": 0.8 - (generation * 0.005),
                "mutations_count": session["total_mutations"],
                "successful_payloads": generation * 2,
                "timestamp": datetime.now().isoformat()
            }
            
            generation_data.append(gen_data)
            
            # Create mutation tree nodes
            for i in range(5):
                node_id = f"node_{session_id}_{generation}_{i}"
                mutation_tree[node_id] = {
                    "id": node_id,
                    "payload": f"payload_{generation}_{i}",
                    "parent_payload": f"payload_{generation-1}_{i}" if generation > 1 else None,
                    "generation": generation,
                    "fitness": best_fitness * (0.8 + (i * 0.1)),
                    "vulnerability_score": 0.1 + (i * 0.2),
                    "mutation_type": "crossover" if i % 2 == 0 else "mutation",
                    "children": [],
                    "timestamp": datetime.now().isoformat()
                }
            
            # Send WebSocket updates
            await websocket_manager.broadcast({
                "type": "genetic_generation",
                "data": gen_data
            })
            
            await websocket_manager.broadcast({
                "type": "genetic_mutation",
                "data": mutation_tree[node_id]
            })
            
            # Wait between generations
            await asyncio.sleep(2)
        
        # Mark session as completed
        session["status"] = "completed"
        session["end_time"] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Error in genetic algorithm simulation: {e}")
        session["status"] = "error"
        session["error"] = str(e) 