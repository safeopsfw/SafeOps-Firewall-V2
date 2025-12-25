package main

import (
	"fmt"
	"os"
	"strings"

	"threat_intel/src/storage"
)

// =============================================================================
// Storage Test Command
// Tests database connectivity and displays table headers for each storage module
// Run with: go run ./cmd/storage_test
// =============================================================================

func main() {
	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", 78) + "╗")
	fmt.Println("║" + centerText("STORAGE LAYER - Database Connection Test", 78) + "║")
	fmt.Println("╚" + strings.Repeat("═", 78) + "╝")
	fmt.Println()

	// Get database config from environment or use defaults
	config := storage.DefaultDBConfig()

	// Override from environment if available
	if host := os.Getenv("DB_HOST"); host != "" {
		config.Host = host
	}
	if user := os.Getenv("DB_USER"); user != "" {
		config.User = user
	}
	if pass := os.Getenv("DB_PASSWORD"); pass != "" {
		config.Password = pass
	}
	if dbname := os.Getenv("DB_NAME"); dbname != "" {
		config.Database = dbname
	}

	fmt.Printf("Database Configuration:\n")
	fmt.Printf("  Host:     %s\n", config.Host)
	fmt.Printf("  Port:     %d\n", config.Port)
	fmt.Printf("  Database: %s\n", config.Database)
	fmt.Printf("  User:     %s\n", config.User)
	fmt.Printf("  SSL Mode: %s\n", config.SSLMode)
	fmt.Println()

	// Test connection
	fmt.Print("Testing connection... ")
	db, err := storage.NewDB(config)
	if err != nil {
		fmt.Printf("FAILED!\n")
		fmt.Printf("  Error: %s\n", err)
		fmt.Println()
		fmt.Println("Make sure PostgreSQL is running and the database exists.")
		fmt.Println("Create database with: CREATE DATABASE threat_intel_db;")
		return
	}
	defer db.Close()

	fmt.Println("SUCCESS!")
	fmt.Println()

	// Get connection status
	status := db.GetStatus()
	fmt.Printf("Connection Status:\n")
	fmt.Printf("  Connected:    %t\n", status.Connected)
	fmt.Printf("  Ping Latency: %s\n", status.PingLatency)
	fmt.Printf("  Open Conns:   %d\n", status.OpenConns)
	fmt.Printf("  Idle Conns:   %d\n", status.IdleConns)
	fmt.Println()

	// List all tables
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println("DATABASE TABLES")
	fmt.Println(strings.Repeat("─", 80))

	tables, err := db.GetAllTables()
	if err != nil {
		fmt.Printf("Error listing tables: %s\n", err)
	} else if len(tables) == 0 {
		fmt.Println("No tables found. Run database migrations first.")
	} else {
		fmt.Printf("Found %d tables:\n", len(tables))
		for _, t := range tables {
			fmt.Printf("  • %s\n", t)
		}
	}
	fmt.Println()

	// Test each storage module
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println("STORAGE MODULES")
	fmt.Println(strings.Repeat("═", 80))

	// Domain Storage
	testStorageModule("DOMAINS", storage.DomainTableName, storage.NewDomainStorage(db))

	// Hash Storage
	testStorageModule("HASHES", storage.HashTableName, storage.NewHashStorage(db))

	// IP Blacklist Storage
	testStorageModule("IP BLACKLIST", storage.IPBlacklistTableName, storage.NewIPBlacklistStorage(db))

	// IP Anonymization Storage
	testStorageModule("IP ANONYMIZATION", storage.IPAnonymizationTableName, storage.NewIPAnonymizationStorage(db))

	// IP Geolocation Storage
	testStorageModule("IP GEOLOCATION", storage.IPGeoTableName, storage.NewIPGeoStorage(db))

	// Summary
	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("═", 80))

	// Count tables that exist
	existingTables := 0
	totalRows := int64(0)
	for _, tableName := range []string{
		storage.DomainTableName,
		storage.HashTableName,
		storage.IPBlacklistTableName,
		storage.IPAnonymizationTableName,
		storage.IPGeoTableName,
	} {
		info, err := db.GetTableInfo(tableName)
		if err == nil && info.Exists {
			existingTables++
			totalRows += info.RowCount
		}
	}

	fmt.Printf("Database: %s @ %s:%d\n", config.Database, config.Host, config.Port)
	fmt.Printf("Tables Ready: %d/5\n", existingTables)
	fmt.Printf("Total Records: %d\n", totalRows)
	fmt.Println()

	// Usage examples
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println("USAGE EXAMPLES")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println()
	fmt.Println("// Direct usage in any program:")
	fmt.Println()
	fmt.Println("  // Create database connection")
	fmt.Println("  db, _ := storage.NewDB(storage.DefaultDBConfig())")
	fmt.Println("  defer db.Close()")
	fmt.Println()
	fmt.Println("  // Use Domain Storage")
	fmt.Println("  domainStore := storage.NewDomainStorage(db)")
	fmt.Println("  headers, _ := domainStore.GetHeaders()")
	fmt.Println("  count, _ := domainStore.GetRowCount()")
	fmt.Println("  domainStore.AddColumn(\"custom_field\", \"TEXT\", \"''\")")
	fmt.Println()
	fmt.Println("  // Use IP Blacklist Storage")
	fmt.Println("  ipStore := storage.NewIPBlacklistStorage(db)")
	fmt.Println("  isBlacklisted, score, _ := ipStore.CheckIP(ctx, \"1.2.3.4\")")
	fmt.Println()
	fmt.Println("  // Use Hash Storage")
	fmt.Println("  hashStore := storage.NewHashStorage(db)")
	fmt.Println("  record, _ := hashStore.GetBySHA256(ctx, \"abc123...\")")
	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
}

// StorageModule interface for testing
type StorageModule interface {
	GetTableInfo() (*storage.TableInfo, error)
	GetHeaders() ([]string, error)
}

func testStorageModule(name, tableName string, store StorageModule) {
	fmt.Println()
	fmt.Printf("▶ %s (%s)\n", name, tableName)
	fmt.Println(strings.Repeat("-", 40))

	info, err := store.GetTableInfo()
	if err != nil {
		fmt.Printf("  ❌ Error: %s\n", err)
		return
	}

	if !info.Exists {
		fmt.Printf("  ⚠️  Table does not exist\n")
		return
	}

	fmt.Printf("  ✅ Table exists\n")
	fmt.Printf("  📊 Row count: %d\n", info.RowCount)
	fmt.Printf("  📋 Columns (%d):\n", len(info.Columns))

	for _, col := range info.Columns {
		nullable := ""
		if col.IsNullable {
			nullable = " (nullable)"
		}
		defaultVal := ""
		if col.DefaultValue != "" {
			defaultVal = fmt.Sprintf(" [default: %s]", truncate(col.DefaultValue, 20))
		}
		fmt.Printf("     • %-25s %-15s%s%s\n", col.Name, col.DataType, nullable, defaultVal)
	}
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
