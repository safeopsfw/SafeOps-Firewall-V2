package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// ResolveConfigDir finds the configs directory relative to the running binary.
// Search order:
//  1. <exeDir>/configs/firewall.toml    (deployed: bin/firewall-engine/configs/)
//  2. <exeDir>/../configs/firewall.toml  (fallback)
//  3. ./configs/firewall.toml            (dev: running from src/firewall_engine/)
//
// Returns the absolute path to the directory containing firewall.toml,
// or an error if not found in any location.
func ResolveConfigDir() (string, error) {
	exeDir, err := executableDir()
	if err != nil {
		exeDir = "." // fallback to cwd
	}

	candidates := []string{
		filepath.Join(exeDir, "configs"),
		filepath.Join(exeDir, "..", "configs"),
		filepath.Join(".", "configs"),
	}

	for _, dir := range candidates {
		probe := filepath.Join(dir, "firewall.toml")
		if _, err := os.Stat(probe); err == nil {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return dir, nil
			}
			return abs, nil
		}
	}

	return "", fmt.Errorf("configs directory not found (searched relative to %s and cwd)", exeDir)
}

// ResolveDataDir returns the data directory relative to the running binary.
// Layout: <exeDir>/data/ — creates the directory tree if it doesn't exist.
func ResolveDataDir() (string, error) {
	exeDir, err := executableDir()
	if err != nil {
		exeDir = "."
	}

	dataDir := filepath.Join(exeDir, "data")
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}

	if err := os.MkdirAll(abs, 0755); err != nil {
		return "", fmt.Errorf("failed to create data dir %s: %w", abs, err)
	}

	return abs, nil
}

// ResolveAlertDir returns the alert log directory, creating it if needed.
// If alertLogDir from config is relative, it's resolved against dataDir.
func ResolveAlertDir(alertLogDir string, dataDir string) (string, error) {
	dir := alertLogDir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(dataDir, dir)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}

	if err := os.MkdirAll(abs, 0755); err != nil {
		return "", fmt.Errorf("failed to create alert dir %s: %w", abs, err)
	}

	return abs, nil
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}
