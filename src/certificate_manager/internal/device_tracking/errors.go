package device_tracking

import "errors"

// Package-level errors
var (
	// ErrDeviceNotFound indicates the device was not found
	ErrDeviceNotFound = errors.New("device not found")

	// ErrInvalidMAC indicates an invalid MAC address format
	ErrInvalidMAC = errors.New("invalid MAC address format")

	// ErrInvalidIP indicates an invalid IP address
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrDetectionFailed indicates CA detection failed
	ErrDetectionFailed = errors.New("CA installation detection failed")

	// ErrConnectionFailed indicates connection to device failed
	ErrConnectionFailed = errors.New("connection to device failed")

	// ErrTLSHandshakeFailed indicates TLS handshake failed
	ErrTLSHandshakeFailed = errors.New("TLS handshake failed")

	// ErrRepositoryError indicates a database/storage error
	ErrRepositoryError = errors.New("repository error")
)
