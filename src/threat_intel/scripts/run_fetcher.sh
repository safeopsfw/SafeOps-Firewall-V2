#!/bin/bash
# Run threat intelligence fetcher service

set -e

cd "$(dirname "$0")/.."

echo "Starting Threat Intelligence Fetcher..."

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Run fetcher
go run cmd/fetcher/main.go "$@"
