#!/bin/bash
export PORT="${PORT:-8001}"
echo "Starting server on port $PORT..."
exec python3 -m uvicorn main:app --host 0.0.0.0 --port "$PORT"
