#!/bin/bash
# Import legacy CSV data into threat intelligence database

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <csv_file>"
    exit 1
fi

CSV_FILE="$1"

echo "Importing legacy CSV data from: $CSV_FILE"

# TODO: Implement CSV import using CLI tool
go run cmd/cli/main.go import --file "$CSV_FILE"

echo "Import complete!"
