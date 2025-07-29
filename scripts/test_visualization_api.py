#!/usr/bin/env python3
"""
Test script for DragonShard Visualization API
"""

import asyncio
import httpx
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API configuration
API_BASE = "http://localhost:8000/api/v1"

async def test_api_endpoints():
    """Test all API endpoints"""
    async with httpx.AsyncClient() as client:
        logger.info("🧪 Testing DragonShard Visualization API")
        logger.info("=" * 50)
        
        # Test attacks endpoint
        logger.info("📊 Testing attacks endpoint...")
        try:
            response = await client.get(f"{API_BASE}/attacks/")
            if response.status_code == 200:
                attacks = response.json()
                logger.info(f"✅ Attacks endpoint: {len(attacks)} attacks found")
            else:
                logger.error(f"❌ Attacks endpoint failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Attacks endpoint error: {e}")
        
        # Test attack summary
        try:
            response = await client.get(f"{API_BASE}/attacks/summary/stats")
            if response.status_code == 200:
                stats = response.json()
                logger.info(f"✅ Attack summary: {stats['total_attacks']} total attacks")
            else:
                logger.error(f"❌ Attack summary failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Attack summary error: {e}")
        
        # Test vulnerabilities endpoint
        logger.info("🛡️ Testing vulnerabilities endpoint...")
        try:
            response = await client.get(f"{API_BASE}/vulnerabilities/")
            if response.status_code == 200:
                vulns = response.json()
                logger.info(f"✅ Vulnerabilities endpoint: {len(vulns)} vulnerabilities found")
            else:
                logger.error(f"❌ Vulnerabilities endpoint failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Vulnerabilities endpoint error: {e}")
        
        # Test vulnerability summary
        try:
            response = await client.get(f"{API_BASE}/vulnerabilities/summary")
            if response.status_code == 200:
                stats = response.json()
                logger.info(f"✅ Vulnerability summary: {stats['total_vulnerabilities']} total vulnerabilities")
            else:
                logger.error(f"❌ Vulnerability summary failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Vulnerability summary error: {e}")
        
        # Test network endpoint
        logger.info("🌐 Testing network endpoint...")
        try:
            response = await client.get(f"{API_BASE}/network/topology")
            if response.status_code == 200:
                topology = response.json()
                logger.info(f"✅ Network topology: {topology['total_hosts']} hosts, {topology['total_services']} services")
            else:
                logger.error(f"❌ Network topology failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Network topology error: {e}")
        
        # Test fuzzing endpoint
        logger.info("🧬 Testing fuzzing endpoint...")
        try:
            response = await client.get(f"{API_BASE}/fuzzing/stats")
            if response.status_code == 200:
                stats = response.json()
                logger.info(f"✅ Fuzzing stats: {stats['active_sessions']} active sessions")
            else:
                logger.error(f"❌ Fuzzing stats failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Fuzzing stats error: {e}")
        
        # Test sessions endpoint
        logger.info("🔐 Testing sessions endpoint...")
        try:
            response = await client.get(f"{API_BASE}/sessions/")
            if response.status_code == 200:
                sessions = response.json()
                logger.info(f"✅ Sessions endpoint: {len(sessions)} sessions found")
            else:
                logger.error(f"❌ Sessions endpoint failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Sessions endpoint error: {e}")
        
        # Test export endpoint
        logger.info("📤 Testing export endpoint...")
        try:
            export_data = {
                "data_type": "attacks",
                "format": "json",
                "include_details": True
            }
            response = await client.post(f"{API_BASE}/export/", json=export_data)
            if response.status_code == 200:
                export = response.json()
                logger.info(f"✅ Export created: {export['export_id']}")
            else:
                logger.error(f"❌ Export failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Export error: {e}")

async def test_websocket():
    """Test WebSocket connection"""
    logger.info("🔌 Testing WebSocket connection...")
    try:
        import websockets
        uri = "ws://localhost:8000/ws"
        
        async with websockets.connect(uri) as websocket:
            # Send ping
            await websocket.send(json.dumps({"type": "ping"}))
            
            # Wait for pong
            response = await websocket.recv()
            message = json.loads(response)
            
            if message.get("type") == "pong":
                logger.info("✅ WebSocket connection successful")
            else:
                logger.error(f"❌ Unexpected WebSocket response: {message}")
                
    except ImportError:
        logger.warning("⚠️ websockets library not installed, skipping WebSocket test")
    except Exception as e:
        logger.error(f"❌ WebSocket test failed: {e}")

async def main():
    """Main test function"""
    logger.info("🚀 Starting DragonShard Visualization API Tests")
    logger.info("=" * 60)
    
    # Test API endpoints
    await test_api_endpoints()
    
    # Test WebSocket
    await test_websocket()
    
    logger.info("=" * 60)
    logger.info("✅ DragonShard Visualization API tests completed!")

if __name__ == "__main__":
    asyncio.run(main()) 