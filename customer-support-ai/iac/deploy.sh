#!/bin/bash
set -e

echo "🚀 Customer Support AI - Deployment Script"
echo "=========================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Install/upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip > /dev/null

# Install requirements
echo "📦 Installing dependencies..."
pip install -r requirements.txt > /dev/null

# Run deployment script
echo ""
echo "🚀 Starting deployment..."
echo ""
python3 deploy.py

# Deactivate virtual environment
deactivate
