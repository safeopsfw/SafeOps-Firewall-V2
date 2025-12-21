// Package main implements the threat intelligence CLI tool
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "fetch":
		fmt.Println("Fetching threat intelligence feeds...")
		// TODO: Implement feed fetching
	case "query":
		fmt.Println("Querying IOC database...")
		// TODO: Implement IOC query
	case "stats":
		fmt.Println("Database statistics:")
		// TODO: Implement stats display
	case "import":
		fmt.Println("Importing data...")
		// TODO: Implement data import
	case "export":
		fmt.Println("Exporting data...")
		// TODO: Implement data export
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	usage := `Threat Intelligence CLI

Usage:
  threat-intel <command> [options]

Commands:
  fetch       Fetch threat intelligence feeds
  query       Query IOC database
  stats       Show database statistics
  import      Import threat data from file
  export      Export threat data to file

Examples:
  threat-intel fetch --all
  threat-intel query --ip 192.168.1.1
  threat-intel stats
  threat-intel import --file data.csv
`
	fmt.Println(usage)
}
