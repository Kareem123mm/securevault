#!/bin/bash
echo "Starting SecureVault Network Demo..."
cd "$(dirname "$0")/.."

# Start server in background
python network/socket_server.py &
SERVER_PID=$!
echo "Server started (PID $SERVER_PID)"

# Wait for server to be ready
sleep 2

# Run client
python network/socket_client.py

# Clean up server
kill $SERVER_PID 2>/dev/null
echo "Network demo complete."
