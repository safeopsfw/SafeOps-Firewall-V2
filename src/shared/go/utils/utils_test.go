// Package utils provides comprehensive test suite for all utility functions.
// This file validates retry logic, rate limiting, byte operations, string manipulation,
// and input validation to ensure correctness, security, and performance.
package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

// createTestContext creates a context with the specified timeout
func createTestContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// mockFailingOperation returns a function that fails n times before succeeding
func mockFailingOperation(failCount int) func() error {
	attempts := 0
	return func() error {
		attempts++
		if attempts <= failCount {
			return fmt.Errorf("temporary failure (attempt %d)", attempts)
		}
		return nil
	}
}

// mockFailingOperationWithResult returns a function with typed result
func mockFailingOperationWithResult[T any](failCount int, successValue T) func() (T, error) {
	attempts := 0
	return func() (T, error) {
		var zero T
		attempts++
		if attempts <= failCount {
			return zero, fmt.Errorf("temporary failure (attempt %d)", attempts)
		}
		return successValue, nil
	}
}

// assertWithinRange validates timing is within expected range
func assertWithinRange(t *testing.T, actual, min, max time.Duration) {
	t.Helper()
	if actual < min || actual > max {
		t.Errorf("Duration %v not within range [%v, %v]", actual, min, max)
	}
}

// ============================================================================
// Retry Logic Test Suite
// ============================================================================

func TestRetrySuccessFirstAttempt(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	err := Retry(ctx, func() error {
		callCount++
		return nil // Success immediately
	}, DefaultRetryConfig())

	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got: %d", callCount)
	}
}

func TestRetryEventualSuccess(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRetryConfig().WithMaxAttempts(5).WithInitialDelay(10 * time.Millisecond)

	fn := mockFailingOperation(2) // Fails twice, succeeds on 3rd attempt

	start := time.Now()
	err := Retry(ctx, fn, cfg)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Expected nil error after eventual success, got: %v", err)
	}

	// Should have waited for at least 2 backoff delays
	expectedMinDelay := 20 * time.Millisecond // 10ms + ~20ms (with jitter)
	if elapsed < expectedMinDelay {
		t.Errorf("Expected at least %v delay, got: %v", expectedMinDelay, elapsed)
	}
}

func TestRetryMaxAttemptsExhausted(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRetryConfig().WithMaxAttempts(3).WithInitialDelay(10 * time.Millisecond).WithCustomRetryable(func(e error) bool { return true })
	callCount := 0

	err := Retry(ctx, func() error {
		callCount++
		return fmt.Errorf("persistent error")
	}, cfg)

	if err == nil {
		t.Error("Expected error after max attempts exhausted")
	}
	if callCount != 3 {
		t.Errorf("Expected 3 attempts, got: %d", callCount)
	}
	if !strings.Contains(err.Error(), "exhausted") || !strings.Contains(err.Error(), "3") {
		t.Errorf("Error message should contain 'exhausted' and attempt count, got: %v", err)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	ctx, cancel := createTestContext(50 * time.Millisecond)
	defer cancel()

	cfg := DefaultRetryConfig().WithMaxAttempts(10).WithInitialDelay(100 * time.Millisecond).WithCustomRetryable(func(e error) bool { return true })

	start := time.Now()
	err := Retry(ctx, func() error {
		return fmt.Errorf("keep failing")
	}, cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded in error chain, got: %v", err)
	}
	// Should exit quickly due to context timeout
	if elapsed > 200*time.Millisecond {
		t.Errorf("Should have exited quickly due to context timeout, took: %v", elapsed)
	}
}

func TestRetryContextDeadlineExceeded(t *testing.T) {
	ctx, cancel := createTestContext(30 * time.Millisecond)
	defer cancel()

	cfg := DefaultRetryConfig().WithMaxAttempts(10).WithInitialDelay(50 * time.Millisecond)

	err := Retry(ctx, func() error {
		return fmt.Errorf("temporary failure")
	}, cfg)

	if err == nil {
		t.Error("Expected error due to deadline exceeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected DeadlineExceeded, got: %v", err)
	}
}

func TestExponentialBackoffCalculation(t *testing.T) {
	cfg := RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0, // Disable jitter for predictable testing
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},  // First delay
		{2, 200 * time.Millisecond},  // 100 * 2^1
		{3, 400 * time.Millisecond},  // 100 * 2^2
		{4, 800 * time.Millisecond},  // 100 * 2^3
		{5, 1600 * time.Millisecond}, // 100 * 2^4
	}

	for _, tt := range tests {
		delay := CalculateBackoff(tt.attempt, cfg)
		if delay != tt.expected {
			t.Errorf("Attempt %d: expected %v, got %v", tt.attempt, tt.expected, delay)
		}
	}
}

func TestExponentialBackoffMaxDelayCap(t *testing.T) {
	cfg := RetryConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     5 * time.Second,
		Multiplier:   3.0,
		Jitter:       0,
	}

	// Attempt 4 would be 1s * 3^3 = 27s, but should cap at 5s
	delay := CalculateBackoff(4, cfg)
	if delay != 5*time.Second {
		t.Errorf("Expected delay capped at 5s, got: %v", delay)
	}
}

func TestJitterApplied(t *testing.T) {
	cfg := RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.2, // ±20% jitter
	}

	// Run multiple times to verify jitter variation
	delays := make([]time.Duration, 20)
	for i := 0; i < 20; i++ {
		delays[i] = CalculateBackoff(1, cfg)
	}

	// Check that we have variation (not all same)
	allSame := true
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("All delays are identical - jitter not working")
	}

	// All delays should be within expected range (100ms ± 20%)
	for _, d := range delays {
		if d < 80*time.Millisecond || d > 120*time.Millisecond {
			t.Errorf("Delay %v outside expected jitter range [80ms, 120ms]", d)
		}
	}
}

func TestRetryableHTTPStatus(t *testing.T) {
	retryableCodes := []int{408, 429, 500, 502, 503, 504}
	for _, code := range retryableCodes {
		if !IsRetryableHTTPStatus(code) {
			t.Errorf("Expected HTTP %d to be retryable", code)
		}
	}

	nonRetryableCodes := []int{400, 401, 403, 404, 405, 409, 410, 422}
	for _, code := range nonRetryableCodes {
		if IsRetryableHTTPStatus(code) {
			t.Errorf("Expected HTTP %d to be non-retryable", code)
		}
	}
}

func TestRetryWithResultGeneric(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRetryConfig().WithMaxAttempts(5).WithInitialDelay(10 * time.Millisecond)

	fn := mockFailingOperationWithResult(2, "success value")

	result, err := RetryWithResult(ctx, fn, cfg)

	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if result != "success value" {
		t.Errorf("Expected 'success value', got: %s", result)
	}
}

func TestRetryWithResultExhausted(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultRetryConfig().WithMaxAttempts(3).WithInitialDelay(10 * time.Millisecond)

	fn := mockFailingOperationWithResult(10, "success value") // Will never succeed in 3 attempts

	result, err := RetryWithResult(ctx, fn, cfg)

	if err == nil {
		t.Error("Expected error after exhaustion")
	}
	if result != "" { // Zero value for string
		t.Errorf("Expected zero value, got: %s", result)
	}
}

func TestSimpleRetry(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	err := SimpleRetry(ctx, func() error {
		callCount++
		if callCount < 2 {
			return fmt.Errorf("fail once")
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if callCount != 2 {
		t.Errorf("Expected 2 calls, got: %d", callCount)
	}
}

func TestRetryN(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	err := RetryN(ctx, 5, func() error {
		callCount++
		return fmt.Errorf("always fail")
	})

	if err == nil {
		t.Error("Expected error after n retries")
	}
	if callCount != 5 {
		t.Errorf("Expected 5 calls, got: %d", callCount)
	}
}

// ============================================================================
// Rate Limiting Test Suite
// ============================================================================

func TestTokenBucketAllowWithinRate(t *testing.T) {
	tb := NewTokenBucket(10, 20) // 10 req/s, burst 20

	// First 20 requests should be allowed immediately (burst)
	for i := 0; i < 20; i++ {
		if !tb.Allow() {
			t.Errorf("Request %d should be allowed (within burst)", i+1)
		}
	}

	// 21st request should be rejected (tokens exhausted)
	if tb.Allow() {
		t.Error("21st request should be rejected (tokens exhausted)")
	}
}

func TestTokenBucketRejectOverRate(t *testing.T) {
	tb := NewTokenBucket(10, 10) // 10 req/s, burst 10

	// Exhaust tokens
	allowed := 0
	for i := 0; i < 15; i++ {
		if tb.Allow() {
			allowed++
		}
	}

	if allowed != 10 {
		t.Errorf("Expected 10 allowed (burst limit), got: %d", allowed)
	}
}

func TestTokenBucketTokenRefill(t *testing.T) {
	tb := NewTokenBucket(100, 10) // 100 req/s, burst 10

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		tb.Allow()
	}

	// Wait for refill (100ms = 10 tokens)
	time.Sleep(110 * time.Millisecond)

	// Should have ~10 tokens refilled
	allowed := 0
	for i := 0; i < 15; i++ {
		if tb.Allow() {
			allowed++
		}
	}

	if allowed < 8 || allowed > 12 {
		t.Errorf("Expected ~10 tokens refilled, got: %d", allowed)
	}
}

func TestTokenBucketWaitBlocking(t *testing.T) {
	tb := NewTokenBucket(100, 5) // 100 req/s, burst 5

	// Exhaust tokens
	for i := 0; i < 5; i++ {
		tb.Allow()
	}

	ctx, cancel := createTestContext(200 * time.Millisecond)
	defer cancel()

	start := time.Now()
	err := tb.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Expected nil error after wait, got: %v", err)
	}

	// Should have waited some time for token refill
	if elapsed < 5*time.Millisecond {
		t.Error("Expected to wait for token refill")
	}
}

func TestTokenBucketWaitContextCancellation(t *testing.T) {
	tb := NewTokenBucket(0.1, 1) // Very slow rate

	// Exhaust token
	tb.Allow()

	ctx, cancel := createTestContext(50 * time.Millisecond)
	defer cancel()

	start := time.Now()
	err := tb.WaitN(ctx, 1)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
	}

	// Should exit around the context deadline
	if elapsed > 100*time.Millisecond {
		t.Errorf("Should have exited near deadline, took: %v", elapsed)
	}
}

func TestTokenBucketAvailable(t *testing.T) {
	tb := NewTokenBucket(10, 10) // 10 req/s, burst 10

	available := tb.Available()
	if available != 10 {
		t.Errorf("Expected 10 available tokens, got: %d", available)
	}

	tb.Allow()
	available = tb.Available()
	if available != 9 {
		t.Errorf("Expected 9 available tokens after consume, got: %d", available)
	}
}

func TestSlidingWindowAllow(t *testing.T) {
	sw := NewSlidingWindow(5, 100*time.Millisecond) // 5 requests per 100ms

	// First 5 should be allowed
	for i := 0; i < 5; i++ {
		if !sw.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th should be rejected
	if sw.Allow() {
		t.Error("6th request should be rejected")
	}

	// Wait for window to slide
	time.Sleep(110 * time.Millisecond)

	// Should be allowed again
	if !sw.Allow() {
		t.Error("Request after window should be allowed")
	}
}

func TestFixedWindowAllow(t *testing.T) {
	fw := NewFixedWindow(5, 100*time.Millisecond) // 5 requests per 100ms window

	// First 5 should be allowed
	for i := 0; i < 5; i++ {
		if !fw.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th should be rejected
	if fw.Allow() {
		t.Error("6th request should be rejected within window")
	}

	// Check remaining
	remaining := fw.Remaining()
	if remaining != 0 {
		t.Errorf("Expected 0 remaining, got: %d", remaining)
	}

	// Wait for window reset
	time.Sleep(110 * time.Millisecond)

	// Should be allowed again
	if !fw.Allow() {
		t.Error("Request after window reset should be allowed")
	}
}

func TestLeakyBucketAllow(t *testing.T) {
	lb := NewLeakyBucket(100, 5) // 100 req/s leak rate, capacity 5

	// First 5 should be allowed (queue)
	for i := 0; i < 5; i++ {
		if !lb.Allow() {
			t.Errorf("Request %d should be allowed (within capacity)", i+1)
		}
	}

	// 6th should be rejected (queue full)
	if lb.Allow() {
		t.Error("6th request should be rejected (queue full)")
	}
}

func TestConcurrentTokenBucket(t *testing.T) {
	tb := NewTokenBucket(1000, 100) // High rate for concurrent test

	var wg sync.WaitGroup
	allowed := int32(0)
	var mu sync.Mutex

	// Launch 200 goroutines
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tb.Allow() {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should have allowed ~100 (burst limit)
	if allowed > 105 {
		t.Errorf("Expected ~100 allowed with burst, got: %d", allowed)
	}
}

// ============================================================================
// Byte Manipulation Test Suite
// ============================================================================

func TestBytesToHexConversion(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x00, 0xFF, 0xAB}, "00ffab"},
		{[]byte{}, ""},
		{[]byte{0x12, 0x34, 0x56, 0x78}, "12345678"},
	}

	for _, tt := range tests {
		result := BytesToHex(tt.input)
		if result != tt.expected {
			t.Errorf("BytesToHex(%v) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestHexToBytesConversion(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
		hasError bool
	}{
		{"00ffab", []byte{0x00, 0xFF, 0xAB}, false},
		{"00FFAB", []byte{0x00, 0xFF, 0xAB}, false},   // Uppercase
		{"0x00ffab", []byte{0x00, 0xFF, 0xAB}, false}, // With prefix
		{"ggffab", nil, true},                         // Invalid hex
		{"00ffa", nil, true},                          // Odd length
		{"", []byte{}, false},
	}

	for _, tt := range tests {
		result, err := HexToBytes(tt.input)
		if tt.hasError && err == nil {
			t.Errorf("HexToBytes(%s) expected error", tt.input)
		}
		if !tt.hasError {
			if err != nil {
				t.Errorf("HexToBytes(%s) unexpected error: %v", tt.input, err)
			}
			if len(result) != len(tt.expected) {
				t.Errorf("HexToBytes(%s) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	}
}

func TestHexRoundTrip(t *testing.T) {
	original := []byte{0x00, 0xFF, 0xAB, 0x12, 0x34}
	hexStr := BytesToHex(original)
	restored, err := HexToBytes(hexStr)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !Equal(original, restored) {
		t.Errorf("Round trip failed: %v != %v", original, restored)
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	tests := []struct {
		input []byte
	}{
		{[]byte("Hello, World!")},
		{[]byte{0x00, 0xFF, 0x00}}, // Binary with null bytes
		{[]byte{}},
	}

	for _, tt := range tests {
		encoded := BytesToBase64(tt.input)
		decoded, err := Base64ToBytes(encoded)

		if err != nil {
			t.Errorf("Unexpected error decoding base64: %v", err)
			continue
		}
		if !Equal(decoded, tt.input) {
			t.Errorf("Base64 round trip failed: %v != %v", decoded, tt.input)
		}
	}
}

func TestFormatBytesHumanReadable(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{523, "523 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1610612736, "1.5 GiB"},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestFormatBytesDecimal(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{1000, "1.0 KB"},
		{1500, "1.5 KB"},
		{1000000, "1.0 MB"},
		{1500000, "1.5 MB"},
	}

	for _, tt := range tests {
		result := FormatBytesDecimal(tt.bytes, 1)
		if result != tt.expected {
			t.Errorf("FormatBytesDecimal(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestParseBytesFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasError bool
	}{
		{"1.5 KB", 1500, false},
		{"10 MB", 10000000, false},
		{"10MB", 10000000, false}, // No space
		{"1024 B", 1024, false},
		{"1 KiB", 1024, false}, // Binary
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		result, err := ParseBytes(tt.input)
		if tt.hasError && err == nil {
			t.Errorf("ParseBytes(%s) expected error", tt.input)
			continue
		}
		if !tt.hasError {
			if err != nil {
				t.Errorf("ParseBytes(%s) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("ParseBytes(%s) = %d, want %d", tt.input, result, tt.expected)
			}
		}
	}
}

func TestSafeSliceNoPanic(t *testing.T) {
	data := []byte("hello")

	tests := []struct {
		start    int
		end      int
		expected string
	}{
		{0, 5, "hello"},
		{0, 10, "hello"}, // End beyond length
		{10, 20, ""},     // Start beyond length
		{-1, 5, "hello"}, // Negative start
		{3, 2, ""},       // Start > end
		{0, 0, ""},       // Empty range
	}

	for _, tt := range tests {
		result := SafeSlice(data, tt.start, tt.end)
		if string(result) != tt.expected {
			t.Errorf("SafeSlice(data, %d, %d) = %q, want %q", tt.start, tt.end, result, tt.expected)
		}
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("secret password")
	b := []byte("secret password")
	c := []byte("different")

	if !Equal(a, b) {
		t.Error("Equal slices should return true")
	}
	if Equal(a, c) {
		t.Error("Different slices should return false")
	}
}

func TestBitManipulation(t *testing.T) {
	data := []byte{0x00} // 00000000

	// Set bit 5
	SetBit(data, 5)
	if !GetBit(data, 5) {
		t.Error("Bit 5 should be set")
	}
	if data[0] != 0x20 { // 00100000
		t.Errorf("Expected 0x20, got 0x%02x", data[0])
	}

	// Clear bit 5
	ClearBit(data, 5)
	if GetBit(data, 5) {
		t.Error("Bit 5 should be cleared")
	}

	// Count set bits
	data[0] = 0xFF // All bits set
	count := CountSetBits(data)
	if count != 8 {
		t.Errorf("Expected 8 set bits, got %d", count)
	}
}

func TestUintConversions(t *testing.T) {
	// Test uint32 round trip
	var u32 uint32 = 0x12345678
	bytes32 := Uint32ToBytes(u32)
	restored32 := BytesToUint32(bytes32)
	if restored32 != u32 {
		t.Errorf("Uint32 round trip failed: %x != %x", restored32, u32)
	}

	// Test uint64 round trip
	var u64 uint64 = 0x123456789ABCDEF0
	bytes64 := Uint64ToBytes(u64)
	restored64 := BytesToUint64(bytes64)
	if restored64 != u64 {
		t.Errorf("Uint64 round trip failed: %x != %x", restored64, u64)
	}

	// Test short slice handling
	if BytesToUint32([]byte{1, 2}) != 0 {
		t.Error("Short slice should return 0")
	}
}

func TestBufferPool(t *testing.T) {
	// Get buffer
	buf := GetBuffer()
	if len(buf) != 4096 {
		t.Errorf("Expected 4096 byte buffer, got %d", len(buf))
	}

	// Return buffer
	PutBuffer(buf)

	// Get another buffer (should be recycled)
	buf2 := GetBuffer()
	if len(buf2) != 4096 {
		t.Errorf("Expected 4096 byte buffer, got %d", len(buf2))
	}

	// Test small buffer
	smallBuf := GetSmallBuffer()
	if len(smallBuf) != 512 {
		t.Errorf("Expected 512 byte buffer, got %d", len(smallBuf))
	}

	// Test large buffer
	largeBuf := GetLargeBuffer()
	if len(largeBuf) != 65536 {
		t.Errorf("Expected 65536 byte buffer, got %d", len(largeBuf))
	}
}

func TestXOR(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA}
	b := []byte{0x0F, 0xF0, 0x55}
	expected := []byte{0xF0, 0xF0, 0xFF}

	result := XOR(a, b)
	if !Equal(result, expected) {
		t.Errorf("XOR = %v, want %v", result, expected)
	}

	// Different lengths
	if XOR([]byte{1}, []byte{1, 2}) != nil {
		t.Error("XOR of different lengths should return nil")
	}
}

func TestReverse(t *testing.T) {
	input := []byte{1, 2, 3, 4, 5}
	expected := []byte{5, 4, 3, 2, 1}

	result := Reverse(input)
	if !Equal(result, expected) {
		t.Errorf("Reverse = %v, want %v", result, expected)
	}
}

// ============================================================================
// String Utilities Test Suite
// ============================================================================

func TestParseIntWithDefault(t *testing.T) {
	tests := []struct {
		input    string
		defVal   int
		expected int
	}{
		{"123", 0, 123},
		{"invalid", 42, 42},
		{"", 42, 42},
		{" 456 ", 0, 456}, // With spaces
		{"-789", 0, -789},
	}

	for _, tt := range tests {
		result := ParseInt(tt.input, tt.defVal)
		if result != tt.expected {
			t.Errorf("ParseInt(%q, %d) = %d, want %d", tt.input, tt.defVal, result, tt.expected)
		}
	}
}

func TestParseFloatWithDefault(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"123.45", 123.45},
		{"invalid", 0.0},
		{"1.23e5", 123000.0},
	}

	for _, tt := range tests {
		result := ParseFloat(tt.input, 0.0)
		if result != tt.expected {
			t.Errorf("ParseFloat(%q) = %f, want %f", tt.input, result, tt.expected)
		}
	}
}

func TestParseBoolWithDefault(t *testing.T) {
	trueCases := []string{"true", "TRUE", "1", "yes", "YES", "on", "ON"}
	for _, s := range trueCases {
		if !ParseBool(s, false) {
			t.Errorf("ParseBool(%q) should return true", s)
		}
	}

	falseCases := []string{"false", "FALSE", "0", "no", "NO", "off", "OFF"}
	for _, s := range falseCases {
		if ParseBool(s, true) {
			t.Errorf("ParseBool(%q) should return false", s)
		}
	}

	// Invalid returns default
	if ParseBool("invalid", true) != true {
		t.Error("Invalid input should return default")
	}
}

func TestParseDurationWithDefault(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"10s", 10 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"invalid", 0},
	}

	for _, tt := range tests {
		result := ParseDuration(tt.input, 0)
		if result != tt.expected {
			t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestSanitizeForLogInjection(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{"user\nINFO: admin logged in", "user INFO: admin logged in"},
		{"test\r\nmalicious", "test malicious"},
		{"test\x00null", "testnull"},
	}

	for _, tt := range tests {
		result := SanitizeForLog(tt.input)
		if result != tt.expected {
			t.Errorf("SanitizeForLog(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTruncateWithEllipsis(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"long string", 10, "long st..."},
		{"short", 10, "short"},
		{"", 10, ""},
		{"test", 3, "tes"},
		{"hello", 0, ""},
	}

	for _, tt := range tests {
		result := TruncateWithEllipsis(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("TruncateWithEllipsis(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestRemoveNullBytes(t *testing.T) {
	input := "test\x00null\x00bytes"
	expected := "testnullbytes"
	result := RemoveNullBytes(input)
	if result != expected {
		t.Errorf("RemoveNullBytes = %q, want %q", result, expected)
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test    multiple   spaces", "test multiple spaces"},
		{"  leading", "leading"},
		{"trailing  ", "trailing"},
		{"tabs\t\tand\nnewlines", "tabs and newlines"},
	}

	for _, tt := range tests {
		result := NormalizeWhitespace(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeWhitespace(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestEqualFoldCaseInsensitive(t *testing.T) {
	if !EqualFold("Example", "example") {
		t.Error("Should be equal (case insensitive)")
	}
	if !EqualFold("EXAMPLE", "example") {
		t.Error("Should be equal (case insensitive)")
	}
	if EqualFold("Example", "different") {
		t.Error("Should not be equal")
	}
}

func TestCaseConversions(t *testing.T) {
	tests := []struct {
		input string
		snake string
		camel string
		kebab string
	}{
		{"CamelCase", "camel_case", "CamelCase", "camel-case"},
		{"HTTPServer", "http_server", "Httpserver", "http-server"},
		{"simple", "simple", "Simple", "simple"},
	}

	for _, tt := range tests {
		snake := ToSnakeCase(tt.input)
		if snake != tt.snake {
			t.Errorf("ToSnakeCase(%q) = %q, want %q", tt.input, snake, tt.snake)
		}

		kebab := ToKebabCase(tt.input)
		if kebab != tt.kebab {
			t.Errorf("ToKebabCase(%q) = %q, want %q", tt.input, kebab, tt.kebab)
		}
	}

	// Test ToCamelCase from snake
	if result := ToCamelCase("snake_case"); result != "SnakeCase" {
		t.Errorf("ToCamelCase(snake_case) = %q, want SnakeCase", result)
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World!", "hello-world"},
		{"Hello  World", "hello-world"},
		{"--hello--", "hello"},
		{"Special @#$ Chars", "special-chars"},
	}

	for _, tt := range tests {
		result := Slugify(tt.input)
		if result != tt.expected {
			t.Errorf("Slugify(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSafeSubstring(t *testing.T) {
	tests := []struct {
		input    string
		start    int
		end      int
		expected string
	}{
		{"test", 0, 2, "te"},
		{"test", 10, 20, ""},    // Out of bounds
		{"test", -1, 5, "test"}, // Negative start
		{"日本語", 0, 2, "日本"},     // Unicode
	}

	for _, tt := range tests {
		result := SafeSubstring(tt.input, tt.start, tt.end)
		if result != tt.expected {
			t.Errorf("SafeSubstring(%q, %d, %d) = %q, want %q", tt.input, tt.start, tt.end, result, tt.expected)
		}
	}
}

func TestTrimQuotes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"quoted"`, "quoted"},
		{`'single'`, "single"},
		{"`backtick`", "backtick"},
		{"no quotes", "no quotes"},
		{`"mismatched'`, `"mismatched'`},
	}

	for _, tt := range tests {
		result := TrimQuotes(tt.input)
		if result != tt.expected {
			t.Errorf("TrimQuotes(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMask(t *testing.T) {
	result := Mask("password123", 2, 2, '*')
	expected := "pa*******23"
	if result != expected {
		t.Errorf("Mask = %q, want %q", result, expected)
	}
}

func TestMaskEmail(t *testing.T) {
	result := MaskEmail("test@example.com")
	if !strings.Contains(result, "@example.com") {
		t.Errorf("MaskEmail should preserve domain, got: %s", result)
	}
	if !strings.Contains(result, "*") {
		t.Errorf("MaskEmail should contain masked chars, got: %s", result)
	}
}

// ============================================================================
// Input Validation Test Suite
// ============================================================================

func TestIPv4Validation(t *testing.T) {
	validIPs := []string{"192.168.1.1", "10.0.0.1", "255.255.255.255", "0.0.0.0", "127.0.0.1"}
	for _, ip := range validIPs {
		if !IsValidIPv4(ip) {
			t.Errorf("%s should be valid IPv4", ip)
		}
	}

	invalidIPs := []string{"256.1.1.1", "192.168.1", "192.168.1.1.1", "", "abc.def.ghi.jkl"}
	for _, ip := range invalidIPs {
		if IsValidIPv4(ip) {
			t.Errorf("%s should be invalid IPv4", ip)
		}
	}
}

func TestIPv6Validation(t *testing.T) {
	validIPs := []string{"2001:db8::1", "::1", "fe80::1", "2001:0db8:0000:0000:0000:0000:0000:0001"}
	for _, ip := range validIPs {
		if !IsValidIPv6(ip) {
			t.Errorf("%s should be valid IPv6", ip)
		}
	}

	invalidIPs := []string{"2001:gggg::1", "::1::2", "", "192.168.1.1"}
	for _, ip := range invalidIPs {
		if IsValidIPv6(ip) {
			t.Errorf("%s should be invalid IPv6", ip)
		}
	}
}

func TestCombinedIPValidation(t *testing.T) {
	validIPs := []string{"192.168.1.1", "2001:db8::1", "127.0.0.1", "::1"}
	for _, ip := range validIPs {
		if !IsValidIP(ip) {
			t.Errorf("%s should be valid IP", ip)
		}
	}
}

func TestPortValidation(t *testing.T) {
	validPorts := []int{1, 80, 443, 22, 3306, 5432, 65535}
	for _, port := range validPorts {
		if !IsValidPort(port) {
			t.Errorf("Port %d should be valid", port)
		}
	}

	invalidPorts := []int{0, -1, 65536, 100000}
	for _, port := range invalidPorts {
		if IsValidPort(port) {
			t.Errorf("Port %d should be invalid", port)
		}
	}
}

func TestCIDRValidation(t *testing.T) {
	validCIDRs := []string{"192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0"}
	for _, cidr := range validCIDRs {
		if !IsValidCIDR(cidr) {
			t.Errorf("%s should be valid CIDR", cidr)
		}
	}

	invalidCIDRs := []string{"192.168.1.0/33", "192.168.1.0", "invalid"}
	for _, cidr := range invalidCIDRs {
		if IsValidCIDR(cidr) {
			t.Errorf("%s should be invalid CIDR", cidr)
		}
	}
}

func TestMACAddressValidation(t *testing.T) {
	validMACs := []string{
		"00:1A:2B:3C:4D:5E", // Colon separated
		"00-1A-2B-3C-4D-5E", // Hyphen separated
		"001A.2B3C.4D5E",    // Dot separated (Cisco)
	}
	for _, mac := range validMACs {
		if !IsValidMACAddress(mac) {
			t.Errorf("%s should be valid MAC address", mac)
		}
	}

	invalidMACs := []string{"00:1A:2B", "invalid", "", "GG:1A:2B:3C:4D:5E"}
	for _, mac := range invalidMACs {
		if IsValidMACAddress(mac) {
			t.Errorf("%s should be invalid MAC address", mac)
		}
	}
}

func TestPrivateIPDetection(t *testing.T) {
	privateIPs := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.0.1"}
	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		if !IsPrivateIP(ip) {
			t.Errorf("%s should be detected as private", ipStr)
		}
	}

	publicIPs := []string{"8.8.8.8", "1.1.1.1", "208.67.222.222"}
	for _, ipStr := range publicIPs {
		ip := net.ParseIP(ipStr)
		if IsPrivateIP(ip) {
			t.Errorf("%s should be detected as public", ipStr)
		}
	}
}

func TestDomainValidation(t *testing.T) {
	validDomains := []string{"example.com", "sub.example.com", "my-domain.com", "123.com"}
	for _, domain := range validDomains {
		if !IsValidDomain(domain) {
			t.Errorf("%s should be valid domain", domain)
		}
	}

	invalidDomains := []string{"-domain.com", "domain..com", "", strings.Repeat("a", 64) + ".com"}
	for _, domain := range invalidDomains {
		if IsValidDomain(domain) {
			t.Errorf("%s should be invalid domain", domain)
		}
	}
}

func TestHostnameValidation(t *testing.T) {
	validHostnames := []string{"localhost", "router", "web-server", "server01"}
	for _, hostname := range validHostnames {
		if !IsValidHostname(hostname) {
			t.Errorf("%s should be valid hostname", hostname)
		}
	}
}

func TestFQDNValidation(t *testing.T) {
	validFQDNs := []string{"example.com", "example.com."}
	for _, fqdn := range validFQDNs {
		if !IsValidFQDN(fqdn) {
			t.Errorf("%s should be valid FQDN", fqdn)
		}
	}

	if IsValidFQDN("localhost") {
		t.Error("localhost should not be valid FQDN (no TLD)")
	}
}

func TestEmailValidation(t *testing.T) {
	validEmails := []string{"user@example.com", "first.last@example.com", "user+tag@example.com"}
	for _, email := range validEmails {
		if !IsValidEmail(email) {
			t.Errorf("%s should be valid email", email)
		}
	}

	invalidEmails := []string{"user", "user@", "@example.com", "user..name@example.com", ".user@example.com"}
	for _, email := range invalidEmails {
		if IsValidEmail(email) {
			t.Errorf("%s should be invalid email", email)
		}
	}
}

func TestURLValidation(t *testing.T) {
	validURLs := []string{
		"https://example.com/path?query=value",
		"http://user:pass@example.com",
		"https://example.com:8080",
	}
	for _, url := range validURLs {
		if !IsValidURL(url) {
			t.Errorf("%s should be valid URL", url)
		}
	}

	invalidURLs := []string{"javascript:alert(1)", "http://", "not-a-url", ""}
	for _, url := range invalidURLs {
		if IsValidURL(url) {
			t.Errorf("%s should be invalid URL", url)
		}
	}
}

func TestFilePathValidation(t *testing.T) {
	validPaths := []string{"/etc/config", "relative/path/file.txt", "C:\\Windows\\System32"}
	for _, path := range validPaths {
		if !IsValidFilePath(path) {
			t.Errorf("%s should be valid file path", path)
		}
	}

	invalidPaths := []string{"", "path\x00null", "..", "."}
	for _, path := range invalidPaths {
		if IsValidFilePath(path) {
			t.Errorf("%s should be invalid file path", path)
		}
	}
}

func TestSafePathValidation(t *testing.T) {
	baseDir := "/app/uploads"

	safePaths := []string{"file.txt", "subdir/file.txt"}
	for _, path := range safePaths {
		if !IsSafePath(path, baseDir) {
			t.Errorf("%s should be safe under %s", path, baseDir)
		}
	}

	unsafePaths := []string{"../../../etc/passwd", "/etc/passwd"}
	for _, path := range unsafePaths {
		if IsSafePath(path, baseDir) {
			t.Errorf("%s should be unsafe under %s", path, baseDir)
		}
	}
}

func TestFileNameValidation(t *testing.T) {
	validNames := []string{"file.txt", "my-file_2025.pdf", "document.doc"}
	for _, name := range validNames {
		if !IsValidFileName(name) {
			t.Errorf("%s should be valid file name", name)
		}
	}

	invalidNames := []string{"file/name.txt", "file\x00.txt", "", ".", "..", "CON", "PRN", "AUX"}
	for _, name := range invalidNames {
		if IsValidFileName(name) {
			t.Errorf("%s should be invalid file name", name)
		}
	}
}

func TestStringLengthValidation(t *testing.T) {
	// ValidateLength
	if err := ValidateLength("hello", 1, 10); err != nil {
		t.Errorf("'hello' should validate for length 1-10: %v", err)
	}
	if err := ValidateLength("hello", 10, 20); err == nil {
		t.Error("'hello' should fail for length 10-20")
	}

	// ValidateMinLength
	if err := ValidateMinLength("hello", 5); err != nil {
		t.Errorf("'hello' should meet min 5: %v", err)
	}
	if err := ValidateMinLength("hi", 5); err == nil {
		t.Error("'hi' should fail min 5")
	}

	// ValidateMaxLength
	if err := ValidateMaxLength("hello", 10); err != nil {
		t.Errorf("'hello' should meet max 10: %v", err)
	}
	if err := ValidateMaxLength("hello", 3); err == nil {
		t.Error("'hello' should fail max 3")
	}
}

func TestPatternMatching(t *testing.T) {
	// IsAlphanumeric
	if !IsAlphanumeric("abc123") {
		t.Error("abc123 should be alphanumeric")
	}
	if IsAlphanumeric("abc-123") {
		t.Error("abc-123 should not be alphanumeric")
	}

	// IsNumeric
	if !IsNumeric("12345") {
		t.Error("12345 should be numeric")
	}
	if IsNumeric("123.45") {
		t.Error("123.45 should not be numeric (contains dot)")
	}

	// IsHexadecimal
	if !IsHexadecimal("1234abcdef") {
		t.Error("1234abcdef should be hexadecimal")
	}
	if IsHexadecimal("ghijk") {
		t.Error("ghijk should not be hexadecimal")
	}
}

// ============================================================================
// Integration Test Suite
// ============================================================================

func TestRetryWithRateLimiting(t *testing.T) {
	ctx := context.Background()
	tb := NewTokenBucket(10, 5) // 10 req/s, burst 5
	cfg := DefaultRetryConfig().WithMaxAttempts(5).WithInitialDelay(10 * time.Millisecond)

	attempt := 0
	err := Retry(ctx, func() error {
		attempt++
		if !tb.Allow() {
			return fmt.Errorf("rate limited (attempt %d)", attempt)
		}
		if attempt < 3 {
			return fmt.Errorf("temporary failure")
		}
		return nil
	}, cfg)

	if err != nil {
		t.Errorf("Expected eventual success, got: %v", err)
	}
}

func TestValidateAndSanitizeUserInput(t *testing.T) {
	// Simulating user input pipeline
	userInput := "test@example.com\nmalicious line"

	// Step 1: Validate email format
	if !IsValidEmail("test@example.com") {
		t.Error("Email validation failed")
	}

	// Step 2: Sanitize for logging
	sanitized := SanitizeForLog(userInput)
	if strings.Contains(sanitized, "\n") {
		t.Error("Sanitization should remove newlines")
	}

	// Step 3: Truncate if needed
	truncated := TruncateWithEllipsis(sanitized, 20)
	if len(truncated) > 20 {
		t.Error("Truncation failed")
	}
}

func TestNetworkConfigValidation(t *testing.T) {
	// Validate a complete firewall rule
	ip := "192.168.1.100"
	port := 443
	domain := "example.com"

	if err := ValidateIP(ip); err != nil {
		t.Errorf("IP validation failed: %v", err)
	}
	if err := ValidatePort(port); err != nil {
		t.Errorf("Port validation failed: %v", err)
	}
	if err := ValidateDomain(domain); err != nil {
		t.Errorf("Domain validation failed: %v", err)
	}
}

func TestBulkDataValidation(t *testing.T) {
	// Validate 1000 IPs
	ips := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		ips[i] = fmt.Sprintf("192.168.%d.%d", i/256, i%256)
	}

	start := time.Now()
	validCount := 0
	for _, ip := range ips {
		if IsValidIP(ip) {
			validCount++
		}
	}
	elapsed := time.Since(start)

	if validCount != 1000 {
		t.Errorf("Expected 1000 valid IPs, got %d", validCount)
	}
	t.Logf("Validated %d IPs in %v (%.2f µs/ip)", validCount, elapsed, float64(elapsed.Microseconds())/1000)
}

// ============================================================================
// Benchmark Test Suite
// ============================================================================

func BenchmarkRateLimiterAllow(b *testing.B) {
	tb := NewTokenBucket(1000000, 1000000) // Very high rate for benchmark

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Allow()
	}
}

func BenchmarkRetryBackoffCalculation(b *testing.B) {
	cfg := DefaultRetryConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateBackoff(i%5+1, cfg)
	}
}

func BenchmarkBytesToHex(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BytesToHex(data)
	}
}

func BenchmarkBufferPoolVsAllocation(b *testing.B) {
	b.Run("Pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := GetBuffer()
			PutBuffer(buf)
		}
	})

	b.Run("Allocation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 4096)
		}
	})
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	a := make([]byte, 64)
	bc := make([]byte, 64)
	for i := range a {
		a[i] = byte(i)
		bc[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Equal(a, bc)
	}
}

func BenchmarkIPValidation(b *testing.B) {
	ip := "192.168.1.100"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidIP(ip)
	}
}

func BenchmarkDomainValidation(b *testing.B) {
	domain := "sub.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidDomain(domain)
	}
}

func BenchmarkEmailValidation(b *testing.B) {
	email := "user@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidEmail(email)
	}
}

func BenchmarkSanitizeForLog(b *testing.B) {
	input := "test\nwith\r\nnewlines\x00and\x01control"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeForLog(input)
	}
}

func BenchmarkToSnakeCase(b *testing.B) {
	input := "CamelCaseStringExample"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ToSnakeCase(input)
	}
}
