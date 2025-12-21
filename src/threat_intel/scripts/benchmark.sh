#!/bin/bash
# Benchmark threat intelligence operations

set -e

echo "Running Threat Intelligence Benchmarks..."

cd "$(dirname "$0")/.."

# Benchmark database inserts
echo "=== Bulk Insert Benchmark ==="
go test -bench=BenchmarkBulkInsert -benchtime=10s ./internal/storage/...

# Benchmark query performance
echo "=== Query Benchmark ==="
go test -bench=BenchmarkQuery -benchtime=10s ./internal/database/repository/...

# Benchmark feed parsing
echo "=== Parser Benchmark ==="
go test -bench=BenchmarkParse -benchtime=10s ./internal/parsers/...

echo "Benchmarks complete!"
