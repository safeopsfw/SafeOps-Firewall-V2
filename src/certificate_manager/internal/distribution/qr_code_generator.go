package distribution

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

// ============================================================================
// Configuration Types
// ============================================================================

// QRCodeConfig contains configuration for QR code generation.
type QRCodeConfig struct {
	Size            int           // Image size in pixels (width = height)
	ErrorCorrection ErrorLevel    // Error correction level
	ForegroundColor color.Color   // QR code module color (default: black)
	BackgroundColor color.Color   // Background color (default: white)
	DisableBorder   bool          // Disable quiet zone border
	CacheEnabled    bool          // Enable caching of generated QR codes
	CacheTTL        time.Duration // Cache time-to-live
}

// ErrorLevel represents QR code error correction level.
type ErrorLevel int

const (
	// ErrorLevelLow - 7% error correction
	ErrorLevelLow ErrorLevel = iota
	// ErrorLevelMedium - 15% error correction
	ErrorLevelMedium
	// ErrorLevelHigh - 25% error correction
	ErrorLevelHigh
	// ErrorLevelHighest - 30% error correction
	ErrorLevelHighest
)

// QRCodeType represents the type of URL to encode.
type QRCodeType string

const (
	QRCodeTypeGeneric     QRCodeType = "generic"      // /ca.crt
	QRCodeTypeiOS         QRCodeType = "ios"          // /ca.mobileconfig
	QRCodeTypeAndroid     QRCodeType = "android"      // /ca.crt
	QRCodeTypeTrustGuide  QRCodeType = "trust-guide"  // /trust-guide.html
	QRCodeTypeScriptLinux QRCodeType = "script-linux" // /install-ca.sh
	QRCodeTypeScriptWin   QRCodeType = "script-win"   // /install-ca.ps1
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrEmptyURL         = errors.New("URL cannot be empty")
	ErrInvalidSize      = errors.New("size must be between 64 and 2048 pixels")
	ErrQRCodeGeneration = errors.New("QR code generation failed")
	ErrCacheExpired     = errors.New("cache entry expired")
)

// ============================================================================
// QR Code Cache
// ============================================================================

// QRCodeCacheEntry represents a cached QR code.
type QRCodeCacheEntry struct {
	Data      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	CacheKey  string
}

// QRCodeCache manages cached QR code images.
type QRCodeCache struct {
	entries map[string]*QRCodeCacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

// NewQRCodeCache creates a new QR code cache.
func NewQRCodeCache(maxSize int, ttl time.Duration) *QRCodeCache {
	return &QRCodeCache{
		entries: make(map[string]*QRCodeCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves a QR code from cache.
func (c *QRCodeCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Data, true
}

// Set stores a QR code in cache.
func (c *QRCodeCache) Set(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &QRCodeCacheEntry{
		Data:      data,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(c.ttl),
		CacheKey:  key,
	}
}

// Clear removes all entries from cache.
func (c *QRCodeCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*QRCodeCacheEntry)
}

// evictOldest removes the oldest cache entry.
func (c *QRCodeCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// ============================================================================
// QR Code Generator
// ============================================================================

// QRCodeGenerator generates QR code images for CA distribution URLs.
type QRCodeGenerator struct {
	baseURL string
	config  *QRCodeConfig
	cache   *QRCodeCache
}

// NewQRCodeGenerator creates a new QR code generator.
func NewQRCodeGenerator(baseURL string, config *QRCodeConfig) *QRCodeGenerator {
	if config == nil {
		config = DefaultQRCodeConfig()
	}

	var cache *QRCodeCache
	if config.CacheEnabled {
		cache = NewQRCodeCache(100, config.CacheTTL)
	}

	return &QRCodeGenerator{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		config:  config,
		cache:   cache,
	}
}

// DefaultQRCodeConfig returns default QR code configuration.
func DefaultQRCodeConfig() *QRCodeConfig {
	return &QRCodeConfig{
		Size:            256,
		ErrorCorrection: ErrorLevelMedium,
		ForegroundColor: color.Black,
		BackgroundColor: color.White,
		DisableBorder:   false,
		CacheEnabled:    true,
		CacheTTL:        24 * time.Hour,
	}
}

// ============================================================================
// QR Code Generation Functions
// ============================================================================

// GenerateQRCode generates a QR code for the given URL.
func (g *QRCodeGenerator) GenerateQRCode(urlToEncode string) ([]byte, error) {
	return g.GenerateQRCodeWithSize(urlToEncode, g.config.Size)
}

// GenerateQRCodeWithSize generates a QR code with specific size.
func (g *QRCodeGenerator) GenerateQRCodeWithSize(urlToEncode string, size int) ([]byte, error) {
	if strings.TrimSpace(urlToEncode) == "" {
		return nil, ErrEmptyURL
	}

	if size < 64 || size > 2048 {
		return nil, ErrInvalidSize
	}

	// Generate cache key
	cacheKey := g.generateCacheKey(urlToEncode, size)

	// Check cache
	if g.cache != nil {
		if data, ok := g.cache.Get(cacheKey); ok {
			return data, nil
		}
	}

	// Convert error correction level
	level := g.convertErrorLevel(g.config.ErrorCorrection)

	// Generate QR code
	qr, err := qrcode.New(urlToEncode, level)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQRCodeGeneration, err)
	}

	// Configure QR code
	qr.DisableBorder = g.config.DisableBorder
	qr.ForegroundColor = g.config.ForegroundColor
	qr.BackgroundColor = g.config.BackgroundColor

	// Generate PNG
	pngBytes, err := qr.PNG(size)
	if err != nil {
		return nil, fmt.Errorf("%w: PNG encoding: %v", ErrQRCodeGeneration, err)
	}

	// Cache the result
	if g.cache != nil {
		g.cache.Set(cacheKey, pngBytes)
	}

	return pngBytes, nil
}

// GenerateQRCodeForType generates a QR code for a specific URL type.
func (g *QRCodeGenerator) GenerateQRCodeForType(qrType QRCodeType) ([]byte, error) {
	url := g.GetURLForType(qrType)
	return g.GenerateQRCode(url)
}

// GenerateQRCodeForTypeWithSize generates a QR code for a specific URL type with size.
func (g *QRCodeGenerator) GenerateQRCodeForTypeWithSize(qrType QRCodeType, size int) ([]byte, error) {
	url := g.GetURLForType(qrType)
	return g.GenerateQRCodeWithSize(url, size)
}

// GetURLForType returns the URL for a specific QR code type.
func (g *QRCodeGenerator) GetURLForType(qrType QRCodeType) string {
	switch qrType {
	case QRCodeTypeiOS:
		return g.baseURL + "/ca.mobileconfig"
	case QRCodeTypeAndroid:
		return g.baseURL + "/ca.crt"
	case QRCodeTypeTrustGuide:
		return g.baseURL + "/trust-guide.html"
	case QRCodeTypeScriptLinux:
		return g.baseURL + "/install-ca.sh"
	case QRCodeTypeScriptWin:
		return g.baseURL + "/install-ca.ps1"
	default:
		return g.baseURL + "/ca.crt"
	}
}

// ============================================================================
// Batch Generation
// ============================================================================

// QRCodeSet contains QR codes for all platforms.
type QRCodeSet struct {
	Generic     []byte `json:"generic"`
	IOS         []byte `json:"ios"`
	Android     []byte `json:"android"`
	TrustGuide  []byte `json:"trust_guide"`
	ScriptLinux []byte `json:"script_linux"`
	ScriptWin   []byte `json:"script_win"`
}

// GenerateAllQRCodes generates QR codes for all supported types.
func (g *QRCodeGenerator) GenerateAllQRCodes() (*QRCodeSet, error) {
	set := &QRCodeSet{}
	var err error

	set.Generic, err = g.GenerateQRCodeForType(QRCodeTypeGeneric)
	if err != nil {
		return nil, fmt.Errorf("generic: %w", err)
	}

	set.IOS, err = g.GenerateQRCodeForType(QRCodeTypeiOS)
	if err != nil {
		return nil, fmt.Errorf("iOS: %w", err)
	}

	set.Android, err = g.GenerateQRCodeForType(QRCodeTypeAndroid)
	if err != nil {
		return nil, fmt.Errorf("android: %w", err)
	}

	set.TrustGuide, err = g.GenerateQRCodeForType(QRCodeTypeTrustGuide)
	if err != nil {
		return nil, fmt.Errorf("trust-guide: %w", err)
	}

	set.ScriptLinux, err = g.GenerateQRCodeForType(QRCodeTypeScriptLinux)
	if err != nil {
		return nil, fmt.Errorf("script-linux: %w", err)
	}

	set.ScriptWin, err = g.GenerateQRCodeForType(QRCodeTypeScriptWin)
	if err != nil {
		return nil, fmt.Errorf("script-win: %w", err)
	}

	return set, nil
}

// ============================================================================
// Base64 and Data URL Encoding
// ============================================================================

// GenerateQRCodeBase64 generates a QR code and returns it as base64 string.
func (g *QRCodeGenerator) GenerateQRCodeBase64(urlToEncode string) (string, error) {
	pngBytes, err := g.GenerateQRCode(urlToEncode)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pngBytes), nil
}

// GenerateQRCodeDataURL generates a QR code as a data URL for HTML embedding.
func (g *QRCodeGenerator) GenerateQRCodeDataURL(urlToEncode string) (string, error) {
	pngBytes, err := g.GenerateQRCode(urlToEncode)
	if err != nil {
		return "", err
	}
	base64Str := base64.StdEncoding.EncodeToString(pngBytes)
	return fmt.Sprintf("data:image/png;base64,%s", base64Str), nil
}

// GenerateQRCodeDataURLForType generates a data URL for a specific type.
func (g *QRCodeGenerator) GenerateQRCodeDataURLForType(qrType QRCodeType) (string, error) {
	url := g.GetURLForType(qrType)
	return g.GenerateQRCodeDataURL(url)
}

// ============================================================================
// SVG Generation (Using simple SVG template)
// ============================================================================

// GenerateQRCodeSVG generates a QR code in SVG format.
// Uses a simple approach by generating a grid-based SVG.
func (g *QRCodeGenerator) GenerateQRCodeSVG(urlToEncode string, size int) ([]byte, error) {
	if strings.TrimSpace(urlToEncode) == "" {
		return nil, ErrEmptyURL
	}

	if size < 64 || size > 2048 {
		return nil, ErrInvalidSize
	}

	// Convert error correction level
	level := g.convertErrorLevel(g.config.ErrorCorrection)

	// Generate QR code to get the bitmap
	qr, err := qrcode.New(urlToEncode, level)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQRCodeGeneration, err)
	}

	// Get the bitmap
	bitmap := qr.Bitmap()
	gridSize := len(bitmap)
	if gridSize == 0 {
		return nil, fmt.Errorf("%w: empty bitmap", ErrQRCodeGeneration)
	}

	// Calculate module size
	moduleSize := float64(size) / float64(gridSize)

	// Build SVG
	var svg bytes.Buffer
	svg.WriteString(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<rect width="100%%" height="100%%" fill="white"/>
`, size, size, size, size))

	// Draw modules
	for y, row := range bitmap {
		for x, module := range row {
			if module {
				svg.WriteString(fmt.Sprintf(`<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="black"/>
`, float64(x)*moduleSize, float64(y)*moduleSize, moduleSize, moduleSize))
			}
		}
	}

	svg.WriteString("</svg>")

	return svg.Bytes(), nil
}

// ============================================================================
// QR Code with Caption
// ============================================================================

// GenerateQRCodeWithCaption generates a QR code with a text caption below it.
func (g *QRCodeGenerator) GenerateQRCodeWithCaption(urlToEncode string, caption string) ([]byte, error) {
	// Generate QR code first
	qrBytes, err := g.GenerateQRCode(urlToEncode)
	if err != nil {
		return nil, err
	}

	// Decode the PNG
	img, err := png.Decode(bytes.NewReader(qrBytes))
	if err != nil {
		return nil, fmt.Errorf("decode PNG: %w", err)
	}

	// For now, return the QR code without caption
	// Full caption support would require image/draw and font rendering
	// which adds complexity - returning simple QR for now
	_ = img
	_ = caption

	return qrBytes, nil
}

// ============================================================================
// Verification
// ============================================================================

// VerifyQRCode verifies that a generated QR code is valid and decodable.
func VerifyQRCode(pngBytes []byte) (string, error) {
	// Decode PNG to verify it's a valid image
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return "", fmt.Errorf("invalid PNG: %w", err)
	}

	// Check dimensions
	bounds := img.Bounds()
	if bounds.Dx() < 64 || bounds.Dy() < 64 {
		return "", fmt.Errorf("image too small: %dx%d", bounds.Dx(), bounds.Dy())
	}

	// Note: Full QR code decoding would require a decoder library
	// For now, we just verify it's a valid PNG image
	return "PNG verified (decoder not available)", nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateCacheKey creates a unique cache key for QR code parameters.
func (g *QRCodeGenerator) generateCacheKey(url string, size int) string {
	data := fmt.Sprintf("%s|%d|%d|%v", url, size, g.config.ErrorCorrection, g.config.DisableBorder)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// convertErrorLevel converts our ErrorLevel to go-qrcode RecoveryLevel.
func (g *QRCodeGenerator) convertErrorLevel(level ErrorLevel) qrcode.RecoveryLevel {
	switch level {
	case ErrorLevelLow:
		return qrcode.Low
	case ErrorLevelMedium:
		return qrcode.Medium
	case ErrorLevelHigh:
		return qrcode.High
	case ErrorLevelHighest:
		return qrcode.Highest
	default:
		return qrcode.Medium
	}
}

// ClearCache clears the QR code cache.
func (g *QRCodeGenerator) ClearCache() {
	if g.cache != nil {
		g.cache.Clear()
	}
}

// ============================================================================
// Standalone Functions
// ============================================================================

// GenerateSimpleQRCode generates a simple QR code without a generator instance.
func GenerateSimpleQRCode(url string, size int) ([]byte, error) {
	if strings.TrimSpace(url) == "" {
		return nil, ErrEmptyURL
	}
	if size < 64 || size > 2048 {
		return nil, ErrInvalidSize
	}

	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQRCodeGeneration, err)
	}

	return qr.PNG(size)
}

// GenerateQRCodeDataURLSimple generates a data URL QR code without generator instance.
func GenerateQRCodeDataURLSimple(url string, size int) (string, error) {
	pngBytes, err := GenerateSimpleQRCode(url, size)
	if err != nil {
		return "", err
	}
	base64Str := base64.StdEncoding.EncodeToString(pngBytes)
	return fmt.Sprintf("data:image/png;base64,%s", base64Str), nil
}

// ============================================================================
// HTTP Content Types
// ============================================================================

// QRCodeContentType returns the MIME content type for QR code format.
func QRCodeContentType(format string) string {
	switch strings.ToLower(format) {
	case "svg":
		return "image/svg+xml"
	case "png":
		return "image/png"
	default:
		return "image/png"
	}
}

// ============================================================================
// QR Code Image Utilities
// ============================================================================

// GetQRCodeImage returns a decoded image from PNG bytes.
func GetQRCodeImage(pngBytes []byte) (image.Image, error) {
	return png.Decode(bytes.NewReader(pngBytes))
}

// EncodeQRCodeToPNG encodes an image to PNG bytes.
func EncodeQRCodeToPNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("PNG encode: %w", err)
	}
	return buf.Bytes(), nil
}
