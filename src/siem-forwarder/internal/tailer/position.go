package tailer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FilePosition tracks the read position for a single file
type FilePosition struct {
	Offset    int64  `json:"offset"`
	Inode     uint64 `json:"inode"`
	UpdatedAt int64  `json:"updated_at"`
}

// PositionDB manages file positions across restarts
type PositionDB struct {
	path      string
	positions map[string]FilePosition
	mu        sync.RWMutex
	dirty     bool
}

// NewPositionDB creates a new position database
func NewPositionDB(path string) (*PositionDB, error) {
	db := &PositionDB{
		path:      path,
		positions: make(map[string]FilePosition),
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	// Load existing positions if file exists
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &db.positions); err != nil {
			// Ignore invalid JSON, start fresh
			db.positions = make(map[string]FilePosition)
		}
	}

	return db, nil
}

// Get returns the stored position for a file
func (db *PositionDB) Get(filePath string) (FilePosition, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	pos, ok := db.positions[filePath]
	return pos, ok
}

// Set updates the position for a file
func (db *PositionDB) Set(filePath string, offset int64, inode uint64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.positions[filePath] = FilePosition{
		Offset:    offset,
		Inode:     inode,
		UpdatedAt: time.Now().Unix(),
	}
	db.dirty = true
}

// Save persists positions to disk
func (db *PositionDB) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.dirty {
		return nil
	}

	data, err := json.MarshalIndent(db.positions, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file and rename for atomic update
	tmpPath := db.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, db.path); err != nil {
		return err
	}

	db.dirty = false
	return nil
}

// StartAutoSave begins periodic position saving
func (db *PositionDB) StartAutoSave(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				_ = db.Save()
			case <-stop:
				ticker.Stop()
				_ = db.Save()
				return
			}
		}
	}()
}
