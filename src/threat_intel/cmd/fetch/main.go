package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"threat_intel/config"
	"threat_intel/src/fetcher"
)

func main() {
	fmt.Println("==========================================================")
	fmt.Println("SafeOps Threat Intelligence - Feed Fetcher Utility")
	fmt.Println("==========================================================")

	// Load configuration (adjust path for running from cmd/fetch/)
	fmt.Println("📋 Loading configuration...")
	configPath := filepath.Join("..", "..", "config", "config.yaml")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
	fmt.Printf("✅ Configuration loaded from: %s\n", configPath)

	// Load threat intelligence sources
	fmt.Println("📂 Loading threat intelligence sources...")
	sourcesPath := filepath.Join("..", "..", "config", "sources.yaml")
	configSources, err := config.LoadSources(sourcesPath)
	if err != nil {
		log.Fatalf("❌ Failed to load sources: %v", err)
	}

	// Convert config.FeedSource to fetcher.Source
	sources := convertSources(configSources)

	// Filter enabled sources
	enabledSources := fetcher.GetEnabledSources(sources)
	fmt.Printf("✅ Loaded %d total sources (%d enabled)\n", len(sources), len(enabledSources))

	// Print enabled sources by category
	printSourcesByCategory(enabledSources)

	// Create fetcher instance
	fmt.Println("\n🚀 Initializing fetcher...")
	fetcherInstance, err := fetcher.NewFetcher(cfg, sources)
	if err != nil {
		log.Fatalf("❌ Failed to create fetcher: %v", err)
	}
	fmt.Println("✅ Fetcher initialized")

	// Print download location
	fmt.Printf("\n📁 Download location: %s\n", cfg.Storage.BasePath)
	fmt.Printf("   Files will be saved to: %s/{category}/{source}_{timestamp}.{ext}\n", cfg.Storage.BasePath)

	// Confirm before proceeding
	fmt.Printf("\n🔄 About to download %d feeds. This may take several minutes.\n", len(enabledSources))
	fmt.Print("   Press ENTER to continue or Ctrl+C to cancel... ")
	fmt.Scanln()

	// Start fetching
	fmt.Println("\n⏬ Starting download of all feeds...")
	startTime := time.Now()

	stats, err := fetcherInstance.FetchAll()
	if err != nil {
		log.Printf("⚠️  Fetch completed with errors: %v", err)
	}

	duration := time.Since(startTime)

	// Print results
	fmt.Println("\n==========================================================")
	fmt.Println("📊 FETCH RESULTS")
	fmt.Println("==========================================================")
	fmt.Printf("Total Jobs:        %d\n", stats.TotalJobs)
	fmt.Printf("Successful:        %d ✅\n", stats.SuccessfulJobs)
	fmt.Printf("Failed:            %d ❌\n", stats.FailedJobs)
	fmt.Printf("Total Downloaded:  %s\n", formatBytes(stats.TotalBytesDownloaded))
	fmt.Printf("Average Duration:  %v\n", stats.AverageDuration)
	fmt.Printf("Total Time:        %v\n", duration)
	fmt.Println("==========================================================")

	// Print download location again
	fmt.Printf("\n📂 Downloaded files are in: %s\n", cfg.Storage.BasePath)
	fmt.Println("   Next step: Run parser to process these files into database")

	// Exit with appropriate code
	if stats.FailedJobs > 0 {
		os.Exit(1)
	}
}

// printSourcesByCategory prints enabled sources grouped by category
func printSourcesByCategory(sources []fetcher.Source) {
	categories := map[string][]string{
		fetcher.CategoryIPGeo:           {},
		fetcher.CategoryIPBlacklist:     {},
		fetcher.CategoryIPAnonymization: {},
		fetcher.CategoryDomain:          {},
		fetcher.CategoryHash:            {},
		fetcher.CategoryIOC:             {},
		fetcher.CategoryASN:             {},
	}

	// Group sources by category
	for _, source := range sources {
		if source.Enabled {
			categories[source.Category] = append(categories[source.Category], source.Name)
		}
	}

	// Print each category
	fmt.Println("📋 Enabled Sources by Category:")
	for category, sourceNames := range categories {
		if len(sourceNames) > 0 {
			fmt.Printf("\n   %s (%d feeds):\n", fetcher.GetCategoryDisplayName(category), len(sourceNames))
			for _, name := range sourceNames {
				fmt.Printf("      • %s\n", name)
			}
		}
	}
}

// convertSources converts config.FeedSource to fetcher.Source
func convertSources(configSources []config.FeedSource) []fetcher.Source {
	sources := make([]fetcher.Source, len(configSources))
	for i, cs := range configSources {
		sources[i] = fetcher.Source{
			Name:            cs.Name,
			Category:        cs.Category,
			URL:             cs.URL,
			Format:          cs.Format,
			Enabled:         cs.Enabled,
			UpdateFrequency: cs.UpdateFrequency,
			Description:     cs.Description,
			AuthRequired:    cs.AuthRequired,
			AuthType:        cs.AuthType,
			ParserConfig:    cs.ParserConfig,
			Priority:        0, // Default priority
		}
	}
	return sources
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
