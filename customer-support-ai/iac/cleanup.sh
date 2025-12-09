#!/bin/bash
set -e

echo "🗑️  Customer Support AI - Cleanup Script"
echo "=========================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Install/upgrade pip
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
echo "📦 Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Run cleanup script
echo ""
python3 cleanup.py

# Deactivate virtual environment
deactivate
