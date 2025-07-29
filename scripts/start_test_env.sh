#!/bin/bash

# Start Test Environment for Genetic Fuzzer
echo "🧬 Starting DragonShard Genetic Fuzzer Test Environment"
echo "=================================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose is not installed. Please install docker-compose first."
    exit 1
fi

echo "🐳 Starting vulnerable containers..."
docker-compose -f docker-compose.test.yml up -d

echo "⏳ Waiting for containers to be healthy..."
sleep 30

echo "🔍 Checking container status..."
docker-compose -f docker-compose.test.yml ps

echo "🧪 Testing target availability..."
python3 test_genetic_fuzzer.py --check-only

echo ""
echo "✅ Test environment is ready!"
echo ""
echo "🎯 Available targets:"
echo "  - DVWA: http://localhost:8080"
echo "  - Juice Shop: http://localhost:3000"
echo "  - WebGoat: http://localhost:8081"
echo "  - Vulnerable PHP: http://localhost:8082"
echo "  - Vulnerable Node.js: http://localhost:8083"
echo "  - Vulnerable Python: http://localhost:8084"
echo ""
echo "🧬 Run the genetic fuzzer test:"
echo "  python3 test_genetic_fuzzer.py"
echo ""
echo "🛑 Stop the environment:"
echo "  docker-compose -f docker-compose.test.yml down"