"""
Fuzzing progress API endpoints
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
import json

from fastapi import APIRouter, HTTPException, Query

from dragonshard.fuzzing.fuzzer import Fuzzer, FuzzResult
from dragonshard.fuzzing.genetic_mutator import GeneticMutator, PayloadType
from dragonshard.fuzzing.response_analyzer import ResponseAnalyzer

from ..models import FuzzingProgress, FuzzingSession, FuzzingStatus, GeneticAlgorithmStats
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Real fuzzing instances
fuzzing_sessions: List[FuzzingSession] = []
fuzzing_progress: List[FuzzingProgress] = []
active_fuzzing_tasks: Dict[str, asyncio.Task] = {}
mutation_tree_nodes: Dict[str, Dict[str, Any]] = {}

# Global instances
fuzzer = Fuzzer()
response_analyzer = ResponseAnalyzer()


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
    """Start a new fuzzing session with real fuzzing"""
    try:
        session_id = f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
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

        # Create new fuzzing session
        session = FuzzingSession(
            id=session_id,
            name=f"Fuzzing Session {session_id}",
            status=FuzzingStatus.RUNNING,
            target=target_url,
            payload_type=payload_type,
            generation=0,
            population_size=population_size,
            best_fitness=0.0,
            average_fitness=0.0,
            mutations_count=0,
            start_time=datetime.now(),
        )

        fuzzing_sessions.append(session)

        # Start background task with real fuzzing
        task = asyncio.create_task(
            run_real_fuzzing(
                session_id, 
                target_url, 
                payload_type_enum, 
                population_size, 
                max_generations,
                mutation_rate,
                crossover_rate
            )
        )
        active_fuzzing_tasks[session_id] = task

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {
                "type": "fuzzing_started",
                "data": {
                    "session_id": session_id,
                    "target_url": target_url,
                    "payload_type": payload_type,
                },
            }
        )

        logger.info(f"Started real fuzzing session: {session_id}")
        return {
            "success": True,
            "session_id": session_id,
            "message": "Real fuzzing started successfully",
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


async def run_real_fuzzing(
    session_id: str,
    target_url: str,
    payload_type: PayloadType,
    population_size: int,
    max_generations: int,
    mutation_rate: float,
    crossover_rate: float
):
    """Run real fuzzing with genetic algorithm"""
    try:
        # Initialize genetic mutator
        genetic_mutator = GeneticMutator(
            population_size=population_size,
            mutation_rate=mutation_rate,
            crossover_rate=crossover_rate,
            max_generations=max_generations,
            response_analyzer=response_analyzer,
            target_url=target_url,
        )

        # Get baseline response
        baseline_response = None
        try:
            baseline_result = fuzzer.fuzz_url(target_url, method="GET", payload_types=[])
            if baseline_result:
                baseline_response = response_analyzer.analyze_response(
                    baseline_result[0].response_body,
                    baseline_result[0].response_headers,
                    baseline_result[0].status_code,
                    baseline_result[0].response_time,
                )
        except Exception as e:
            logger.warning(f"Could not get baseline response: {e}")

        # Set baseline for genetic mutator
        if baseline_response:
            genetic_mutator.set_baseline_response(target_url, baseline_response)

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
        fitness_function = genetic_mutator.create_response_based_fitness(target_url, baseline_response)

        generation = 0
        while generation < max_generations:
            # Check if task was cancelled
            if session_id not in active_fuzzing_tasks:
                break

            # Run one generation
            generation += 1
            evolved_population = genetic_mutator.evolve(fitness_function)

            # Get best payloads for this generation
            best_payloads = genetic_mutator.get_best_payloads(5)
            
            if best_payloads:
                best_fitness = max(p.fitness for p in best_payloads)
                average_fitness = sum(p.fitness for p in best_payloads) / len(best_payloads)
            else:
                best_fitness = 0.0
                average_fitness = 0.0

            # Test best payloads against target
            for payload in best_payloads[:3]:  # Test top 3
                try:
                    results = fuzzer.fuzz_url(
                        target_url, 
                        method="GET", 
                        payload_types=[payload_type.value]
                    )
                    
                    # Update payload with response analysis
                    if results:
                        result = results[0]
                        response_analysis = response_analyzer.analyze_response(
                            result.response_body,
                            result.response_headers,
                            result.status_code,
                            result.response_time,
                        )
                        genetic_mutator.update_payload_with_response(
                            payload, response_analysis, baseline_response
                        )
                except Exception as e:
                    logger.warning(f"Error testing payload: {e}")

            # Update session
            for session in fuzzing_sessions:
                if session.id == session_id:
                    session.generation = generation
                    session.best_fitness = best_fitness
                    session.average_fitness = average_fitness
                    session.mutations_count = genetic_mutator.get_search_statistics().get("total_mutations", 0)
                    break

            # Create progress update
            progress = FuzzingProgress(
                session_id=session_id,
                generation=generation,
                population_size=population_size,
                best_fitness=best_fitness,
                average_fitness=average_fitness,
                diversity=genetic_mutator._calculate_population_diversity(),
                mutations_count=genetic_mutator.get_search_statistics().get("total_mutations", 0),
                successful_payloads=len([p for p in best_payloads if p.fitness > 0.5]),
                timestamp=datetime.now(),
            )

            fuzzing_progress.append(progress)

            # Broadcast progress update
            await websocket_manager.broadcast(
                {"type": "fuzzing_progress_updated", "data": progress.dict(exclude_none=True)}
            )

            # Add mutation tree nodes
            for i, payload in enumerate(best_payloads[:5]):
                node_id = f"node_{session_id}_{generation}_{i}"
                mutation_tree_nodes[node_id] = {
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

            # Wait between generations
            await asyncio.sleep(1)

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

        logger.info(f"Completed real fuzzing session: {session_id}")

    except asyncio.CancelledError:
        logger.info(f"Fuzzing session cancelled: {session_id}")
    except Exception as e:
        logger.error(f"Error in real fuzzing: {e}")
        # Mark session as failed
        for session in fuzzing_sessions:
            if session.id == session_id:
                session.status = FuzzingStatus.FAILED
                break


@router.get("/mutation-tree")
async def get_mutation_tree():
    """Get mutation tree data"""
    try:
        return mutation_tree_nodes
    except Exception as e:
        logger.error(f"Error getting mutation tree: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/results/{session_id}")
async def get_fuzzing_results(session_id: str):
    """Get fuzzing results for a session"""
    try:
        # Get vulnerabilities found by the fuzzer
        vulnerabilities = fuzzer.get_vulnerabilities()
        
        # Filter by session if needed (for now return all)
        return {
            "session_id": session_id,
            "vulnerabilities": [v.__dict__ for v in vulnerabilities],
            "total_vulnerabilities": len(vulnerabilities),
            "summary": fuzzer.get_results_summary()
        }
    except Exception as e:
        logger.error(f"Error getting fuzzing results: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/start-fuzzing")
async def start_fuzzing_session(request: Dict[str, Any]):
    """Start a new fuzzing session (alternative endpoint for frontend)"""
    return await start_fuzzing(request)


@router.get("/sessions/{session_id}/results")
async def get_session_results(session_id: str):
    """Get results for a specific fuzzing session"""
    try:
        # Find the session
        session = None
        for s in fuzzing_sessions:
            if s.id == session_id:
                session = s
                break
        
        if not session:
            raise HTTPException(status_code=404, detail="Fuzzing session not found")
        
        # Get vulnerabilities found by the fuzzer
        vulnerabilities = fuzzer.get_vulnerabilities()
        
        return {
            "session_id": session_id,
            "session": session.dict(),
            "vulnerabilities": [v.__dict__ for v in vulnerabilities],
            "total_vulnerabilities": len(vulnerabilities),
            "summary": fuzzer.get_results_summary()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting session results: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sessions/{session_id}/progress")
async def get_session_progress(session_id: str):
    """Get progress for a specific fuzzing session"""
    try:
        session_progress = [p for p in fuzzing_progress if p.session_id == session_id]
        return session_progress
    except Exception as e:
        logger.error(f"Error getting session progress: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
