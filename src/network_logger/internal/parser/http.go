package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/safeops/network_logger/pkg/models"
)

// HTTPParser parses HTTP traffic
type HTTPParser struct{}

// NewHTTPParser creates a new HTTP parser
func NewHTTPParser() *HTTPParser {
	return &HTTPParser{}
}

// Parse attempts to parse HTTP from payload
func (p *HTTPParser) Parse(payload []byte) *models.HTTPData {
	if len(payload) < 10 {
		return nil
	}

	// Try parsing as HTTP request
	if httpData := p.parseRequest(payload); httpData != nil {
		return httpData
	}

	// Try parsing as HTTP response
	if httpData := p.parseResponse(payload); httpData != nil {
		return httpData
	}

	return nil
}

// parseRequest parses HTTP request
func (p *HTTPParser) parseRequest(payload []byte) *models.HTTPData {
	reader := bufio.NewReader(bytes.NewReader(payload))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil
	}

	httpData := &models.HTTPData{
		Type:    "request",
		Method:  req.Method,
		URI:     req.RequestURI,
		Version: fmt.Sprintf("HTTP/%d.%d", req.ProtoMajor, req.ProtoMinor),
		Host:    req.Host,
		Headers: make(map[string]string),
	}

	// Extract headers
	for key, values := range req.Header {
		httpData.Headers[key] = strings.Join(values, "; ")

		// Extract special headers
		switch strings.ToLower(key) {
		case "user-agent":
			httpData.UserAgent = values[0]
		case "cookie":
			httpData.Cookies = values[0]
		case "referer":
			httpData.Referer = values[0]
		}
	}

	// Try to read body preview
	if req.Body != nil {
		bodyBytes := make([]byte, 256)
		n, _ := req.Body.Read(bodyBytes)
		if n > 0 {
			httpData.BodyPreview = string(bodyBytes[:n])
			httpData.BodyLength = n
		}
	}

	return httpData
}

// parseResponse parses HTTP response
func (p *HTTPParser) parseResponse(payload []byte) *models.HTTPData {
	reader := bufio.NewReader(bytes.NewReader(payload))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil
	}

	httpData := &models.HTTPData{
		Type:          "response",
		StatusCode:    resp.StatusCode,
		StatusMessage: resp.Status,
		Version:       fmt.Sprintf("HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor),
		Headers:       make(map[string]string),
	}

	// Extract headers
	for key, values := range resp.Header {
		httpData.Headers[key] = strings.Join(values, "; ")
	}

	// Try to read body preview
	if resp.Body != nil {
		bodyBytes := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, bodyBytes)
		if n > 0 {
			httpData.BodyPreview = string(bodyBytes[:n])
			httpData.BodyLength = n
		}
	}

	return httpData
}

// IsHTTPPort checks if port is commonly used for HTTP
func IsHTTPPort(port uint16) bool {
	httpPorts := []uint16{80, 8080, 8000, 8888, 3000, 5000, 8081, 8082}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// IsHTTPSPort checks if port is commonly used for HTTPS
func IsHTTPSPort(port uint16) bool {
	httpsPorts := []uint16{443, 8443, 9443}
	for _, p := range httpsPorts {
		if port == p {
			return true
		}
	}
	return false
}
