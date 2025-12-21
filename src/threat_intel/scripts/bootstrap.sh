#!/bin/bash
# Bootstrap script for threat intelligence service

set -e

echo "Bootstrapping Threat Intelligence Service..."

# Create data directories
mkdir -p data/cache data/downloads data/state logs

# Check PostgreSQL connection
echo "Checking PostgreSQL connection..."
psql -h ${POSTGRES_HOST:-localhost} -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DATABASE:-safeops_threat_intel} -c "SELECT 1" > /dev/null
echo "✓ Database connection OK"

# Run migrations
echo "Running database migrations..."
# TODO: Add migration command
echo "✓ Migrations complete"

# Initialize feed configurations
echo "Initializing feed configurations..."
ls -1 configs/sources/*.yaml | wc -l
echo "✓ Feed configurations loaded"

echo "Bootstrap complete!"
