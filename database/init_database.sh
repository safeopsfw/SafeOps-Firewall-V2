#!/bin/bash
# ============================================================================
# SafeOps Threat Intelligence Database Initialization
# ============================================================================
# Purpose: Initialize complete threat intelligence database with all schemas
# Usage: ./init_database.sh
# ============================================================================

set -e

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-safeops_threatintel}"
DB_USER="${DB_USER:-safeops}"
ADMIN_USER="${ADMIN_USER:-postgres}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================"
echo "SafeOps Threat Intelligence Database Setup"
echo "============================================"
echo ""
echo "Database: $DB_NAME"
echo "Host: $DB_HOST:$DB_PORT"
echo "User: $DB_USER"
echo ""

# Function to run SQL file with progress
run_sql() {
    local file=$1
    local user=${2:-$DB_USER}
    local db=${3:-$DB_NAME}
    local filename=$(basename "$file")
    
    echo -e "${BLUE}  ▶${NC} Running: $filename"
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$user" -d "$db" -f "$file" -q 2>&1; then
        echo -e "${GREEN}  ✓${NC} Completed: $filename"
    else
        echo -e "${RED}  ✗${NC} Failed: $filename"
        exit 1
    fi
}

# Step 1: Initial Setup (as admin)
echo ""
echo -e "${YELLOW}[1/5]${NC} Creating database, roles, and extensions..."
run_sql "schemas/001_initial_setup.sql" "$ADMIN_USER" "postgres"

# Step 2: Create core schema tables
echo ""
echo -e "${YELLOW}[2/5]${NC} Creating threat intelligence schemas (10 files)..."

# Explicitly run in order for dependencies
echo -e "${BLUE}Creating IP reputation schema...${NC}"
run_sql "schemas/002_ip_reputation.sql"

echo -e "${BLUE}Creating domain reputation schema...${NC}"
run_sql "schemas/003_domain_reputation.sql"

echo -e "${BLUE}Creating hash reputation schema...${NC}"
run_sql "schemas/004_hash_reputation.sql"

echo -e "${BLUE}Creating IOC storage schema...${NC}"
run_sql "schemas/005_ioc_storage.sql"

echo -e "${BLUE}Creating proxy/anonymizer schema...${NC}"
run_sql "schemas/006_proxy_anonymizer.sql"

echo -e "${BLUE}Creating geolocation schema...${NC}"
run_sql "schemas/007_geolocation.sql"

echo -e "${BLUE}Creating threat feeds schema...${NC}"
run_sql "schemas/008_threat_feeds.sql"

echo -e "${BLUE}Creating ASN data schema...${NC}"
run_sql "schemas/009_asn_data.sql"

# Step 3: Create indexes and maintenance functions
echo ""
echo -e "${YELLOW}[3/5]${NC} Creating performance indexes and maintenance functions..."
if [ -f "schemas/999_indexes_and_maintenance.sql" ]; then
    run_sql "schemas/999_indexes_and_maintenance.sql"
else
    echo -e "${RED}  ✗${NC} Warning: 999_indexes_and_maintenance.sql not found"
fi

# Step 4: Create views
echo ""
echo -e "${YELLOW}[4/5]${NC} Creating database views..."
view_count=0
if [ -d "views" ]; then
    for view in views/*.sql; do
        if [ -f "$view" ]; then
            run_sql "$view"
            ((view_count++))
        fi
    done
    echo -e "${GREEN}  Created $view_count views${NC}"
else
    echo -e "${YELLOW}  No views directory found - skipping${NC}"
fi

# Step 5: Seed data (optional)
echo ""
echo -e "${YELLOW}[5/5]${NC} Seed initial data (optional)..."
echo ""
echo "Available seed files:"
seed_count=0
if [ -d "seeds" ]; then
    for seed in seeds/*.sql; do
        if [ -f "$seed" ]; then
            echo "  - $(basename "$seed")"
            ((seed_count++))
        fi
    done
    
    if [ $seed_count -gt 0 ]; then
        echo ""
        read -p "Load all $seed_count seed files? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Loading seed data..."
            for seed in seeds/*.sql; do
                if [ -f "$seed" ]; then
                    run_sql "$seed"
                fi
            done
            echo -e "${GREEN}  ✓ Seed data loaded successfully${NC}"
        else
            echo -e "${YELLOW}  Skipped seed data${NC}"
        fi
    fi
else
    echo -e "${YELLOW}  No seeds directory found - skipping${NC}"
fi

# Final summary
echo ""
echo "============================================"
echo -e "${GREEN}✓ Database setup complete!${NC}"
echo "============================================"
echo ""

# Get database statistics
echo "Database Summary:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
    "SELECT * FROM threat_intel.get_database_stats();" 2>/dev/null || echo "  (Statistics not available yet)"

echo ""
echo "Connection Details:"
echo "  Host: $DB_HOST:$DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""
echo "Connection String:"
echo "  postgresql://$DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo ""
echo "Quick Commands:"
echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME"
echo "  SELECT * FROM threat_intel.threat_summary_stats;"
echo "  SELECT * FROM threat_intel.active_threats LIMIT 10;"
echo ""
echo "Next Steps:"
echo "  1. Configure feed sources (already loaded if you seeded data)"
echo "  2. Start threat feed ingestion service"
echo "  3. Configure backup schedule"
echo "  4. Set up pg_cron for automated maintenance"
echo ""
echo "Documentation: ../docs/README.md"
echo "============================================"

