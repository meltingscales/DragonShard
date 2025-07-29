#!/usr/bin/env python3
"""
Development server script for DragonShard Visualization

Starts both the FastAPI backend and React frontend development server.
"""

import subprocess
import sys
import os
import signal
import time
from pathlib import Path

def start_backend():
    """Start the FastAPI backend server"""
    print("🚀 Starting FastAPI backend server...")
    backend_process = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "dragonshard.visualizer.api.app:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ], cwd=Path(__file__).parent.parent.parent)
    return backend_process

def start_frontend():
    """Start the React frontend development server"""
    print("🌐 Starting React frontend development server...")
    frontend_dir = Path(__file__).parent / "frontend"
    frontend_process = subprocess.Popen([
        "npm", "run", "dev"
    ], cwd=frontend_dir)
    return frontend_process

def main():
    """Main function to start both servers"""
    print("🐉 DragonShard Visualization Development Server")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not (Path(__file__).parent / "api").exists():
        print("❌ Error: API directory not found. Please run this script from the visualizer directory.")
        sys.exit(1)
    
    if not (Path(__file__).parent / "frontend").exists():
        print("❌ Error: Frontend directory not found. Please run this script from the visualizer directory.")
        sys.exit(1)
    
    # Check if npm is available
    try:
        subprocess.run(["npm", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: npm not found. Please install Node.js and npm.")
        sys.exit(1)
    
    # Check if frontend dependencies are installed
    frontend_dir = Path(__file__).parent / "frontend"
    if not (frontend_dir / "node_modules").exists():
        print("📦 Installing frontend dependencies...")
        subprocess.run(["npm", "install"], cwd=frontend_dir, check=True)
    
    backend_process = None
    frontend_process = None
    
    try:
        # Start backend
        backend_process = start_backend()
        time.sleep(2)  # Give backend time to start
        
        # Start frontend
        frontend_process = start_frontend()
        time.sleep(2)  # Give frontend time to start
        
        print("\n✅ Development servers started successfully!")
        print("📊 Backend API: http://localhost:8000")
        print("📊 API Docs: http://localhost:8000/api/docs")
        print("🌐 Frontend: http://localhost:5173")
        print("\nPress Ctrl+C to stop both servers...")
        
        # Wait for processes
        while True:
            time.sleep(1)
            if backend_process.poll() is not None:
                print("❌ Backend server stopped unexpectedly")
                break
            if frontend_process.poll() is not None:
                print("❌ Frontend server stopped unexpectedly")
                break
                
    except KeyboardInterrupt:
        print("\n🛑 Stopping development servers...")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        # Clean up processes
        if backend_process:
            backend_process.terminate()
            try:
                backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_process.kill()
        
        if frontend_process:
            frontend_process.terminate()
            try:
                frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                frontend_process.kill()
        
        print("✅ Development servers stopped.")

if __name__ == "__main__":
    main() 