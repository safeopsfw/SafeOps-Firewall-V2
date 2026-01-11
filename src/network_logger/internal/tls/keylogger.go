package tls

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"
)

// KeyLogger monitors SSLKEYLOGFILE for TLS keys
type KeyLogger struct {
	keylogPath string
	keys       map[string]*TLSKey
	mu         sync.RWMutex
	lastSize   int64
}

// TLSKey represents a TLS session key
type TLSKey struct {
	Label     string
	Secret    string
	Timestamp time.Time
}

// NewKeyLogger creates a new TLS key logger
func NewKeyLogger(path string) *KeyLogger {
	return &KeyLogger{
		keylogPath: path,
		keys:       make(map[string]*TLSKey),
	}
}

// Start begins monitoring the key log file
func (k *KeyLogger) Start(ctx context.Context) {
	go k.monitorFile(ctx)
}

// monitorFile watches for changes to the key log file
func (k *KeyLogger) monitorFile(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.checkForUpdates()
		}
	}
}

// checkForUpdates checks if the file has new content
func (k *KeyLogger) checkForUpdates() {
	stat, err := os.Stat(k.keylogPath)
	if err != nil {
		// File doesn't exist yet
		return
	}

	if stat.Size() > k.lastSize {
		k.readNewKeys()
		k.lastSize = stat.Size()
	}
}

// readNewKeys reads new keys from the file
func (k *KeyLogger) readNewKeys() {
	file, err := os.Open(k.keylogPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Seek to last read position
	if k.lastSize > 0 {
		file.Seek(k.lastSize, 0)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		k.parseLine(line)
	}
}

// parseLine parses a key log line
func (k *KeyLogger) parseLine(line string) {
	line = strings.TrimSpace(line)

	// Skip comments and empty lines
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	// Format: LABEL <space> <client_random> <space> <secret>
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return
	}

	label := parts[0]
	clientRandom := parts[1]
	secret := strings.Join(parts[2:], " ")

	k.mu.Lock()
	defer k.mu.Unlock()

	k.keys[clientRandom] = &TLSKey{
		Label:     label,
		Secret:    secret,
		Timestamp: time.Now(),
	}
}

// GetKey retrieves a TLS key by client random
func (k *KeyLogger) GetKey(clientRandom string) *TLSKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return k.keys[clientRandom]
}

// GetStats returns key logger statistics
func (k *KeyLogger) GetStats() KeyLogStats {
	k.mu.RLock()
	defer k.mu.RUnlock()

	recentCount := 0
	now := time.Now()

	for _, key := range k.keys {
		if now.Sub(key.Timestamp) < 5*time.Minute {
			recentCount++
		}
	}

	return KeyLogStats{
		TotalKeys:  len(k.keys),
		RecentKeys: recentCount,
	}
}

// KeyLogStats represents key logger statistics
type KeyLogStats struct {
	TotalKeys  int
	RecentKeys int
}

// Decryptor provides TLS decryption capabilities
type Decryptor struct {
	keyLogger *KeyLogger
}

// NewDecryptor creates a new TLS decryptor
func NewDecryptor(keyLogger *KeyLogger) *Decryptor {
	return &Decryptor{
		keyLogger: keyLogger,
	}
}

// TryDecrypt attempts to decrypt TLS data
func (d *Decryptor) TryDecrypt(clientRandom string, encryptedData []byte) *DecryptionResult {
	result := &DecryptionResult{
		Decrypted:    false,
		KeyAvailable: false,
	}

	// Check if key is available
	key := d.keyLogger.GetKey(clientRandom)
	if key != nil {
		result.KeyAvailable = true
		result.Note = "Keys available - decryption not yet implemented"
		// TODO: Implement actual decryption in Phase 2
	} else {
		result.Note = "No key available for this session"
	}

	return result
}

// DecryptionResult represents the result of a decryption attempt
type DecryptionResult struct {
	Decrypted        bool
	KeyAvailable     bool
	Cipher           string
	DecryptedLength  int
	DecryptedHex     string
	DecryptedBase64  string
	DecryptedPreview string
	HTTPParsed       bool
	Note             string
}
