// Package processor implements the central packet processing pipeline.
package processor

import (
	"context"
	"sync"
	"time"

	"tls_proxy/internal/buffer"
	"tls_proxy/internal/config"
	"tls_proxy/internal/dns"
	"tls_proxy/internal/models"
	"tls_proxy/internal/tls"
)

// =============================================================================
// STATISTICS
// =============================================================================

// ProcessorStats tracks packet processing metrics.
type ProcessorStats struct {
	// TotalPacketsProcessed is the count of all Process() invocations
	TotalPacketsProcessed uint64

	// HTTPSPacketsDetected is packets with DestinationPort 443
	HTTPSPacketsDetected uint64

	// SNIExtractionsAttempted is the count of SNI extraction calls
	SNIExtractionsAttempted uint64

	// SNIExtractionsSucceeded is the count of successful extractions
	SNIExtractionsSucceeded uint64

	// DNSQueriesPerformed is the count of resolver.Resolve() calls
	DNSQueriesPerformed uint64

	// DNSQueriesSucceeded is the count of successful DNS resolutions
	DNSQueriesSucceeded uint64

	// BufferStoreOperations is the count of buffer.Store() calls
	BufferStoreOperations uint64

	// ProcessingErrors is the count of any errors encountered
	ProcessingErrors uint64

	// TotalProcessingTime is cumulative processing duration
	TotalProcessingTime time.Duration

	// LastProcessedTime is timestamp of last processed packet
	LastProcessedTime time.Time
}

// AverageProcessingTime returns the mean duration of Process() calls.
func (s *ProcessorStats) AverageProcessingTime() time.Duration {
	if s.TotalPacketsProcessed == 0 {
		return 0
	}
	return s.TotalProcessingTime / time.Duration(s.TotalPacketsProcessed)
}

// SNISuccessRate returns the percentage of successful SNI extractions.
func (s *ProcessorStats) SNISuccessRate() float64 {
	if s.SNIExtractionsAttempted == 0 {
		return 0
	}
	return float64(s.SNIExtractionsSucceeded) / float64(s.SNIExtractionsAttempted) * 100
}

// DNSSuccessRate returns the percentage of successful DNS resolutions.
func (s *ProcessorStats) DNSSuccessRate() float64 {
	if s.DNSQueriesPerformed == 0 {
		return 0
	}
	return float64(s.DNSQueriesSucceeded) / float64(s.DNSQueriesPerformed) * 100
}

// =============================================================================
// PACKET PROCESSOR
// =============================================================================

// PacketProcessor orchestrates the complete packet processing pipeline.
type PacketProcessor struct {
	// config contains timeout and limit configuration
	config *config.Config

	// resolver performs DNS queries for SNI domains
	resolver *dns.SNIResolver

	// buffer stores packets with metadata during processing
	buffer *buffer.PacketBuffer

	// connectionCache caches SNI results per connection (optional optimization)
	connectionCache map[string]string
	cacheMutex      sync.RWMutex

	// stats tracks processing metrics
	stats      ProcessorStats
	statsMutex sync.RWMutex
}

// =============================================================================
// CONSTRUCTOR
// =============================================================================

// NewPacketProcessor creates a new processor with all dependencies.
func NewPacketProcessor(
	cfg *config.Config,
	resolver *dns.SNIResolver,
	buf *buffer.PacketBuffer,
) *PacketProcessor {
	return &PacketProcessor{
		config:          cfg,
		resolver:        resolver,
		buffer:          buf,
		connectionCache: make(map[string]string),
		stats:           ProcessorStats{},
	}
}

// =============================================================================
// MAIN PROCESSING FUNCTION
// =============================================================================

// Process executes the complete packet processing pipeline.
// Returns a ProcessingResult indicating the forwarding action.
// Phase 1: Always returns FORWARD_UNCHANGED (pass-through mode).
func (p *PacketProcessor) Process(packet *models.Packet) (*models.ProcessingResult, error) {
	startTime := time.Now()

	// Apply overall processing timeout
	ctx, cancel := context.WithTimeout(context.Background(), p.config.GRPCRequestTimeout)
	defer cancel()

	// Create result channel for timeout handling
	resultChan := make(chan *models.ProcessingResult, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := p.processInternal(packet, startTime)
		if err != nil {
			errChan <- err
		} else {
			resultChan <- result
		}
	}()

	// Wait for result or timeout
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return p.createPassThroughResult(time.Since(startTime)), err
	case <-ctx.Done():
		p.incrementErrors()
		return p.createPassThroughResult(time.Since(startTime)), ctx.Err()
	}
}

// processInternal implements the actual processing pipeline.
func (p *PacketProcessor) processInternal(packet *models.Packet, startTime time.Time) (*models.ProcessingResult, error) {
	// Step 1: Initial Validation
	if packet == nil {
		p.incrementErrors()
		return p.createPassThroughResult(time.Since(startTime)), nil
	}

	if len(packet.RawData) == 0 {
		p.incrementErrors()
		return p.createPassThroughResult(time.Since(startTime)), nil
	}

	// Increment total processed count
	p.incrementProcessed()

	var sni string
	var resolvedIP string

	// Step 2: HTTPS Detection
	if packet.IsHTTPS() {
		p.incrementHTTPS()

		// Check connection cache first
		if cachedSNI := p.getCachedSNI(packet.ConnectionID); cachedSNI != "" {
			sni = cachedSNI
		} else {
			// Step 3: SNI Extraction
			sni = p.extractSNI(packet)
			if sni != "" {
				p.cacheSNI(packet.ConnectionID, sni)
			}
		}

		// Step 4: DNS Resolution (only if SNI extracted)
		if sni != "" {
			resolvedIP = p.resolveDNS(sni)
		}
	}

	// Step 5: Buffer Storage
	p.storeInBuffer(packet, sni, resolvedIP)

	// Step 6: Return Processing Result
	result := p.createPassThroughResult(time.Since(startTime))
	result.SNIHostname = sni
	result.ResolvedIP = resolvedIP

	return result, nil
}

// =============================================================================
// SNI EXTRACTION
// =============================================================================

// extractSNI attempts to extract SNI from a TLS ClientHello packet.
func (p *PacketProcessor) extractSNI(packet *models.Packet) string {
	p.statsMutex.Lock()
	p.stats.SNIExtractionsAttempted++
	p.statsMutex.Unlock()

	sni, err := tls.ExtractSNI(packet)
	if err != nil {
		// SNI extraction failed - this is normal for non-ClientHello packets
		return ""
	}

	p.statsMutex.Lock()
	p.stats.SNIExtractionsSucceeded++
	p.statsMutex.Unlock()

	return sni
}

// =============================================================================
// DNS RESOLUTION
// =============================================================================

// resolveDNS queries the DNS Server for the given SNI domain.
func (p *PacketProcessor) resolveDNS(sni string) string {
	p.statsMutex.Lock()
	p.stats.DNSQueriesPerformed++
	p.statsMutex.Unlock()

	ip, err := p.resolver.Resolve(sni)
	if err != nil {
		// DNS resolution failed - continue with empty IP
		return ""
	}

	p.statsMutex.Lock()
	p.stats.DNSQueriesSucceeded++
	p.statsMutex.Unlock()

	return ip
}

// =============================================================================
// BUFFER OPERATIONS
// =============================================================================

// storeInBuffer saves the packet with metadata to the buffer.
func (p *PacketProcessor) storeInBuffer(packet *models.Packet, sni, resolvedIP string) {
	entry := models.NewBufferEntry(*packet, p.config.BufferTTL)
	entry.SNI = sni
	entry.ResolvedIP = resolvedIP
	entry.SetCompleted()

	p.buffer.Store(entry)

	p.statsMutex.Lock()
	p.stats.BufferStoreOperations++
	p.statsMutex.Unlock()
}

// =============================================================================
// CONNECTION CACHE
// =============================================================================

// getCachedSNI retrieves cached SNI for a connection.
func (p *PacketProcessor) getCachedSNI(connectionID string) string {
	p.cacheMutex.RLock()
	defer p.cacheMutex.RUnlock()
	return p.connectionCache[connectionID]
}

// cacheSNI stores SNI for a connection.
func (p *PacketProcessor) cacheSNI(connectionID, sni string) {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()
	p.connectionCache[connectionID] = sni
}

// ClearConnectionCache removes all cached SNI entries.
func (p *PacketProcessor) ClearConnectionCache() {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()
	p.connectionCache = make(map[string]string)
}

// =============================================================================
// RESULT CREATION
// =============================================================================

// createPassThroughResult creates a Phase 1 pass-through result.
func (p *PacketProcessor) createPassThroughResult(duration time.Duration) *models.ProcessingResult {
	return &models.ProcessingResult{
		Action:             models.ActionForwardUnchanged,
		ModifiedPacket:     nil, // No modification in Phase 1
		DropReason:         "",  // No dropping in Phase 1
		ProcessingDuration: duration,
	}
}

// =============================================================================
// STATISTICS
// =============================================================================

// incrementProcessed safely increments total packet count.
func (p *PacketProcessor) incrementProcessed() {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	p.stats.TotalPacketsProcessed++
	p.stats.LastProcessedTime = time.Now()
}

// incrementHTTPS safely increments HTTPS packet count.
func (p *PacketProcessor) incrementHTTPS() {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	p.stats.HTTPSPacketsDetected++
}

// incrementErrors safely increments error count.
func (p *PacketProcessor) incrementErrors() {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	p.stats.ProcessingErrors++
}

// GetStats returns a copy of processor statistics.
func (p *PacketProcessor) GetStats() ProcessorStats {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()

	return ProcessorStats{
		TotalPacketsProcessed:   p.stats.TotalPacketsProcessed,
		HTTPSPacketsDetected:    p.stats.HTTPSPacketsDetected,
		SNIExtractionsAttempted: p.stats.SNIExtractionsAttempted,
		SNIExtractionsSucceeded: p.stats.SNIExtractionsSucceeded,
		DNSQueriesPerformed:     p.stats.DNSQueriesPerformed,
		DNSQueriesSucceeded:     p.stats.DNSQueriesSucceeded,
		BufferStoreOperations:   p.stats.BufferStoreOperations,
		ProcessingErrors:        p.stats.ProcessingErrors,
		TotalProcessingTime:     p.stats.TotalProcessingTime,
		LastProcessedTime:       p.stats.LastProcessedTime,
	}
}

// GetBufferStats returns current buffer statistics.
func (p *PacketProcessor) GetBufferStats() buffer.BufferStats {
	return p.buffer.GetStats()
}

// GetResolverStats returns current resolver statistics.
func (p *PacketProcessor) GetResolverStats() dns.ResolverStats {
	return p.resolver.GetStats()
}
