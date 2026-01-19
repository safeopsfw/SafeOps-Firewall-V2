package parser

import (
	"bufio"
	"bytes"
	"strings"
)

// HTTPParser extracts Host header from HTTP requests
type HTTPParser struct{}

// NewHTTPParser creates a new HTTP parser
func NewHTTPParser() *HTTPParser {
	return &HTTPParser{}
}

// ExtractHost extracts the Host header from an HTTP request
// Returns empty string if not a valid HTTP request
func (p *HTTPParser) ExtractHost(payload []byte) string {
	if len(payload) < 16 {
		return ""
	}

	// Check if it looks like an HTTP request
	if !p.isHTTPRequest(payload) {
		return ""
	}

	// Parse headers
	scanner := bufio.NewScanner(bytes.NewReader(payload))

	for scanner.Scan() {
		line := scanner.Text()

		// Look for Host header
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			// Extract host value
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[1])

				// Remove port if present
				if idx := strings.Index(host, ":"); idx > 0 {
					host = host[:idx]
				}

				return host
			}
		}
	}

	return ""
}

// IsHTTPRequest checks if the payload looks like an HTTP request (public)
func (p *HTTPParser) IsHTTPRequest(payload []byte) bool {
	return p.isHTTPRequest(payload)
}

// isHTTPRequest checks if the payload looks like an HTTP request
func (p *HTTPParser) isHTTPRequest(payload []byte) bool {
	// Check for HTTP methods
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}

	for _, method := range methods {
		if bytes.HasPrefix(payload, []byte(method)) {
			return true
		}
	}

	return false
}
