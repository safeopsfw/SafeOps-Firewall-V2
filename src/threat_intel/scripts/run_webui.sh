#!/bin/bash
# Run threat intelligence web UI

set -e

cd "$(dirname "$0")/.."

echo "Starting Threat Intelligence Web UI..."

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Run web UI
go run cmd/webui/main.go "$@"
