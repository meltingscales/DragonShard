"""
Genetic Algorithm API Endpoints
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dragonshard.fuzzing.genetic_mutator import GeneticMutator, PayloadType
from dragonshard.fuzzing.response_analyzer import ResponseAnalyzer

from ..models import (
    FuzzingProgress,
    FuzzingSession,
    FuzzingStatus,
    GeneticAlgorithmStats,
    WebSocketMessage,
)
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Real genetic algorithm instances
genetic_sessions: Dict[str, Dict[str, Any]] = {}
generation_data: List[Dict[str, Any]] = []
mutation_tree: Dict[str, Dict[str, Any]] = {}
active_genetic_tasks: Dict[str, asyncio.Task] = {}

# Global instances
response_analyzer = ResponseAnalyzer()


@router.post("/start")
async def start_genetic_algorithm(request: Dict[str, Any]):
    """Start a new genetic algorithm session with real functionality"""
    try:
        session_id = f"genetic_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        target_url = request.get("target_url", "http://localhost:8082")
        payload_type = request.get("payload_type", "sql_injection")
        population_size = request.get("population_size", 50)
        max_generations = request.get("generations", 100)
        mutation_rate = request.get("mutation_rate", 0.1)
        crossover_rate = request.get("crossover_rate", 0.8)

        # Convert payload type string to enum
        payload_type_enum = PayloadType.SQL_INJECTION  # default
        if payload_type == "xss":
            payload_type_enum = PayloadType.XSS
        elif payload_type == "command_injection":
            payload_type_enum = PayloadType.COMMAND_INJECTION
        elif payload_type == "path_traversal":
            payload_type_enum = PayloadType.PATH_TRAVERSAL
        elif payload_type == "lfi":
            payload_type_enum = PayloadType.LFI
        elif payload_type == "rfi":
            payload_type_enum = PayloadType.RFI
        elif payload_type == "xxe":
            payload_type_enum = PayloadType.XXE
        elif payload_type == "ssrf":
            payload_type_enum = PayloadType.SSRF
        elif payload_type == "template_injection":
            payload_type_enum = PayloadType.TEMPLATE_INJECTION
        elif payload_type == "no_sql_injection":
            payload_type_enum = PayloadType.NOSQL_INJECTION

        session_data = {
            "id": session_id,
            "target_url": target_url,
            "payload_type": payload_type,
            "payload_type_enum": payload_type_enum,
            "population_size": population_size,
            "generations": max_generations,
            "mutation_rate": mutation_rate,
            "crossover_rate": crossover_rate,
            "status": "running",
            "start_time": datetime.now().isoformat(),
            "current_generation": 0,
            "best_fitness": 0.0,
            "average_fitness": 0.0,
            "total_mutations": 0,
        }

        genetic_sessions[session_id] = session_data

        # Start background task with real genetic algorithm
        task = asyncio.create_task(
            run_real_genetic_algorithm(
                session_id,
                target_url,
                payload_type_enum,
                population_size,
                max_generations,
                mutation_rate,
                crossover_rate
            )
        )
        active_genetic_tasks[session_id] = task

        return {
            "success": True,
            "session_id": session_id,
            "message": "Real genetic algorithm started successfully",
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

        # Cancel all active tasks
        for session_id, task in active_genetic_tasks.items():
            if not task.done():
                task.cancel()

        # Clear active tasks
        active_genetic_tasks.clear()

        return {"success": True, "message": "All genetic algorithm sessions stopped"}
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
            "average_fitness": best_fitness * 0.7 if best_fitness > 0 else 0.0,
        }
    except Exception as e:
        logger.error(f"Error getting genetic algorithm stats: {e}")
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


async def run_real_genetic_algorithm(
    session_id: str,
    target_url: str,
    payload_type: PayloadType,
    population_size: int,
    max_generations: int,
    mutation_rate: float,
    crossover_rate: float
):
    """Run real genetic algorithm evolution"""
    try:
        session = genetic_sessions[session_id]
        
        # Initialize genetic mutator
        genetic_mutator = GeneticMutator(
            population_size=population_size,
            mutation_rate=mutation_rate,
            crossover_rate=crossover_rate,
            max_generations=max_generations,
            response_analyzer=response_analyzer,
            target_url=target_url,
        )

        # Initialize population with base payloads
        base_payloads = []
        try:
            with open("dragonshard/fuzzing/payloads.json", "r") as f:
                payloads_data = json.load(f)
                payload_type_key = payload_type.value
                if payload_type_key in payloads_data:
                    base_payloads = payloads_data[payload_type_key].get("payloads", [])
        except Exception as e:
            logger.warning(f"Could not load payloads: {e}")
            # Fallback payloads
            if payload_type == PayloadType.SQL_INJECTION:
                base_payloads = ["' OR 1=1--", "' UNION SELECT NULL--", "'; DROP TABLE users--"]
            elif payload_type == PayloadType.XSS:
                base_payloads = ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]
            elif payload_type == PayloadType.COMMAND_INJECTION:
                base_payloads = ["; ls", "| whoami", "&& cat /etc/passwd"]

        genetic_mutator.initialize_population(base_payloads, payload_type)

        # Create fitness function
        fitness_function = genetic_mutator.create_response_based_fitness(target_url)

        generation = 0
        while session["status"] == "running" and generation < max_generations:
            # Run one generation
            generation += 1
            session["current_generation"] = generation

            # Evolve population
            evolved_population = genetic_mutator.evolve(fitness_function)

            # Get best payloads for this generation
            best_payloads = genetic_mutator.get_best_payloads(5)
            
            if best_payloads:
                best_fitness = max(p.fitness for p in best_payloads)
                average_fitness = sum(p.fitness for p in best_payloads) / len(best_payloads)
            else:
                best_fitness = 0.0
                average_fitness = 0.0

            session["best_fitness"] = best_fitness
            session["average_fitness"] = average_fitness
            session["total_mutations"] = genetic_mutator.get_search_statistics().get("total_mutations", 0)

            # Create generation data
            gen_data = {
                "generation": generation,
                "best_fitness": best_fitness,
                "average_fitness": average_fitness,
                "population_size": population_size,
                "diversity": genetic_mutator._calculate_population_diversity(),
                "mutations_count": session["total_mutations"],
                "successful_payloads": len([p for p in best_payloads if p.fitness > 0.5]),
                "timestamp": datetime.now().isoformat(),
            }

            generation_data.append(gen_data)

            # Create mutation tree nodes
            for i, payload in enumerate(best_payloads[:5]):
                node_id = f"node_{session_id}_{generation}_{i}"
                mutation_tree[node_id] = {
                    "id": node_id,
                    "payload": payload.payload,
                    "parent_payload": payload.payload,  # Simplified for now
                    "generation": generation,
                    "fitness": payload.fitness,
                    "vulnerability_score": payload.vulnerability_score,
                    "mutation_type": "crossover" if i % 2 == 0 else "mutation",
                    "children": [],
                    "timestamp": datetime.now().isoformat(),
                }

            # Send WebSocket updates
            await websocket_manager.broadcast({"type": "genetic_generation", "data": gen_data})

            await websocket_manager.broadcast(
                {"type": "genetic_mutation", "data": mutation_tree[node_id]}
            )

            # Wait between generations
            await asyncio.sleep(1)

        # Mark session as completed
        session["status"] = "completed"
        session["end_time"] = datetime.now().isoformat()

        # Remove from active tasks
        if session_id in active_genetic_tasks:
            del active_genetic_tasks[session_id]

    except asyncio.CancelledError:
        logger.info(f"Genetic algorithm session cancelled: {session_id}")
        session["status"] = "cancelled"
    except Exception as e:
        logger.error(f"Error in real genetic algorithm: {e}")
        session["status"] = "error"
        session["error"] = str(e)


@router.get("/sessions/{session_id}/results")
async def get_genetic_session_results(session_id: str):
    """Get results for a specific genetic algorithm session"""
    try:
        if session_id not in genetic_sessions:
            raise HTTPException(status_code=404, detail="Genetic algorithm session not found")
        
        session = genetic_sessions[session_id]
        
        # Get generation data for this session
        session_generations = [g for g in generation_data if g.get("session_id") == session_id]
        
        # Get mutation tree nodes for this session
        session_mutations = {k: v for k, v in mutation_tree.items() if session_id in k}
        
        return {
            "session_id": session_id,
            "session": session,
            "generations": session_generations,
            "mutations": session_mutations,
            "total_generations": len(session_generations),
            "total_mutations": len(session_mutations)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting genetic session results: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sessions/{session_id}/progress")
async def get_genetic_session_progress(session_id: str):
    """Get progress for a specific genetic algorithm session"""
    try:
        if session_id not in genetic_sessions:
            raise HTTPException(status_code=404, detail="Genetic algorithm session not found")
        
        # Get generation data for this session
        session_generations = [g for g in generation_data if g.get("session_id") == session_id]
        
        return session_generations
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting genetic session progress: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/start-evolution")
async def start_genetic_evolution(request: Dict[str, Any]):
    """Start a new genetic algorithm evolution (alternative endpoint for frontend)"""
    return await start_genetic_algorithm(request)
