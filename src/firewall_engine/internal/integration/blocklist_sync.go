package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"firewall_engine/internal/logging"
)

// BlocklistSync pushes domain blocking decisions from the firewall engine
// to the SafeOps engine via its HTTP control API (127.0.0.1:50052).
//
// The firewall engine runs as a separate process from SafeOps. Communication
// uses the control API rather than in-process function calls.
type BlocklistSync struct {
	logger      logging.Logger
	apiBase     string // e.g. "http://127.0.0.1:50052"
	client      *http.Client
	syncedCount atomic.Int64
}

// NewBlocklistSync creates a new HTTP-based blocklist sync.
// apiAddr is the SafeOps control API address (e.g. "127.0.0.1:50052").
func NewBlocklistSync(logger logging.Logger, apiAddr string) *BlocklistSync {
	return &BlocklistSync{
		logger:  logger,
		apiBase: "http://" + apiAddr,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// syncDomainsRequest matches SafeOps control API format.
type syncDomainsRequest struct {
	Domains []string `json:"domains"`
}

type blockDomainReq struct {
	Domain string `json:"domain"`
}

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SyncDomains pushes a full domain list to SafeOps Engine via bulk sync API.
// Clears existing domains and replaces with the new list.
// Returns the number of domains synced.
func (s *BlocklistSync) SyncDomains(domains []string) int {
	body, err := json.Marshal(syncDomainsRequest{Domains: domains})
	if err != nil {
		s.logger.Error().Err(err).Msg("BlocklistSync: failed to marshal domain list")
		return 0
	}

	resp, err := s.client.Post(s.apiBase+"/api/v1/sync/domains", "application/json", bytes.NewReader(body))
	if err != nil {
		s.logger.Warn().Err(err).Msg("BlocklistSync: SafeOps control API not reachable")
		return 0
	}
	defer resp.Body.Close()

	var result apiResponse
	json.NewDecoder(resp.Body).Decode(&result)

	if !result.Success {
		s.logger.Error().Str("message", result.Message).Msg("BlocklistSync: sync failed")
		return 0
	}

	count := len(domains)
	s.syncedCount.Store(int64(count))

	s.logger.Info().
		Int("synced", count).
		Msg("BlocklistSync: domains synced to SafeOps Engine")

	return count
}

// SyncDomain pushes a single domain block to SafeOps Engine.
func (s *BlocklistSync) SyncDomain(domain string) {
	body, err := json.Marshal(blockDomainReq{Domain: domain})
	if err != nil {
		return
	}

	resp, err := s.client.Post(s.apiBase+"/api/v1/block/domain", "application/json", bytes.NewReader(body))
	if err != nil {
		s.logger.Warn().Err(err).Str("domain", domain).Msg("BlocklistSync: failed to sync domain")
		return
	}
	resp.Body.Close()
	s.syncedCount.Add(1)
}

// UnsyncDomain removes a domain from SafeOps Engine.
func (s *BlocklistSync) UnsyncDomain(domain string) {
	body, err := json.Marshal(blockDomainReq{Domain: domain})
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodDelete, s.apiBase+"/api/v1/block/domain", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn().Err(err).Str("domain", domain).Msg("BlocklistSync: failed to unsync domain")
		return
	}
	resp.Body.Close()
	s.syncedCount.Add(-1)
}

// SyncedCount returns the number of domains currently synced.
func (s *BlocklistSync) SyncedCount() int64 {
	return s.syncedCount.Load()
}

// WaitForAPI waits up to maxWait for the SafeOps control API to become available.
// Returns nil on success, error on timeout.
func (s *BlocklistSync) WaitForAPI(maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		resp, err := s.client.Get(s.apiBase + "/api/v1/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("SafeOps control API not available after %v", maxWait)
}
