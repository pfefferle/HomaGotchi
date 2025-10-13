#!/bin/bash
# Home Assistant Development Environment Runner

# Navigate to project directory
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Run Home Assistant pointing to test_env config
echo "🚀 Starting Home Assistant with Homagotchi integration..."
echo "📁 Config directory: test_env/"
echo "🌐 Access at: http://localhost:8123"
echo ""
echo "Press Ctrl+C to stop"
echo ""

hass -c test_env --debug
