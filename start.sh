#!/bin/bash

# Start the Facebook Auto-Post application
echo "Starting Facebook Auto-Post application..."

# Set default environment variables if not set
export FLASK_ENV=${FLASK_ENV:-production}
export PORT=${PORT:-5000}

# Start the application
python app.py 