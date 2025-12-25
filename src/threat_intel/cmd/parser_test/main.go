package main

import (
	"fmt"
	"os"

	"threat_intel/src/parser"
)

// =============================================================================
// Parser Test Command
// Demonstrates the parser subsystem capabilities
// Run with: go run ./cmd/parser_test
// =============================================================================

func main() {
	fmt.Println()
	fmt.Println("Starting Parser Subsystem Test...")
	fmt.Println()

	// Change to threat_intel directory if running from project root
	if _, err := os.Stat("data/fetch"); os.IsNotExist(err) {
		if err := os.Chdir("src/threat_intel"); err != nil {
			// Try threat_intel directly
			os.Chdir("threat_intel")
		}
	}

	// Run comprehensive tests
	parser.TestAllParsers()

	fmt.Println()
	fmt.Println("Parser Test Complete!")
	fmt.Println()

	// Quick example of direct usage
	fmt.Println("=" + string(make([]byte, 79, 79)))
	fmt.Println("QUICK PARSE EXAMPLE")
	fmt.Println("=" + string(make([]byte, 79, 79)))

	// Example: Parse a specific file directly
	fmt.Println("\nDirect Usage Examples:")
	fmt.Println("  // Parse any file (auto-detects format)")
	fmt.Println("  result, _ := parser.QuickParse(\"data/fetch/ip/some_file.txt\")")
	fmt.Println("  ips := result.GetAllIPs()")
	fmt.Println()
	fmt.Println("  // Parse directory")
	fmt.Println("  results, _ := parser.QuickParseDir(\"data/fetch/domain/\")")
	fmt.Println()
	fmt.Println("  // Direct TXT reading")
	fmt.Println("  data, _ := parser.ReadTXT(\"file.txt\", nil)")
	fmt.Println("  for _, rec := range data.Records {")
	fmt.Println("      fmt.Printf(\"%s is %s\\n\", rec.Value, rec.ContentType)")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("  // Direct CSV reading")
	fmt.Println("  csvData, _ := parser.ReadCSV(\"file.csv\", nil)")
	fmt.Println("  ips := csvData.GetIPs()")
	fmt.Println("  domains := csvData.GetDomains()")
	fmt.Println()
	fmt.Println("  // Direct JSON reading")
	fmt.Println("  jsonData, _ := parser.ReadJSON(\"file.json\", nil)")
	fmt.Println("  iocs := jsonData.GetIOCs()")
}
