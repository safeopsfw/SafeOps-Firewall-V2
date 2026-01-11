// Package headwind provides integration with Headwind MDM for Android device management.
package headwind

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client connects to Headwind MDM API
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Config holds Headwind client configuration
type Config struct {
	BaseURL string // e.g., "http://mdm.example.com:8080/hmdm"
	APIKey  string // API key from Headwind admin
	Timeout time.Duration
}

// NewClient creates a new Headwind MDM client
func NewClient(cfg *Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ============================================================================
// Device Management
// ============================================================================

// Device represents an enrolled Android device
type Device struct {
	ID            int    `json:"id"`
	Number        string `json:"number"`
	Description   string `json:"description"`
	IMEI          string `json:"imei"`
	Phone         string `json:"phone"`
	Model         string `json:"model"`
	Manufacturer  string `json:"manufacturer"`
	OSVersion     string `json:"osVersion"`
	LastOnline    int64  `json:"lastOnline"`
	Configuration string `json:"configuration"`
	Enrolled      bool   `json:"enrolled"`
}

// ListDevices returns all enrolled devices
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	resp, err := c.get(ctx, "/rest/public/devices")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status  string   `json:"status"`
		Devices []Device `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Devices, nil
}

// GetDevice returns a single device by ID
func (c *Client) GetDevice(ctx context.Context, deviceID int) (*Device, error) {
	resp, err := c.get(ctx, fmt.Sprintf("/rest/public/device/%d", deviceID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var device Device
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		return nil, fmt.Errorf("failed to decode device: %w", err)
	}

	return &device, nil
}

// ============================================================================
// Certificate Management
// ============================================================================

// Certificate represents a CA certificate in Headwind
type Certificate struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Data        string `json:"data"` // Base64 encoded
	InstallType string `json:"installType"`
}

// UploadCertificate uploads a CA certificate to Headwind
func (c *Client) UploadCertificate(ctx context.Context, name string, certData []byte) error {
	payload := map[string]interface{}{
		"name":        name,
		"type":        "ca",
		"data":        certData, // Will be base64 encoded by JSON
		"installType": "system",
	}

	resp, err := c.post(ctx, "/rest/public/certificates", payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to upload certificate: %s", string(body))
	}

	return nil
}

// ============================================================================
// Configuration Management
// ============================================================================

// Configuration represents a device configuration profile
type Configuration struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	CertificateIDs []int  `json:"certificates"`
}

// CreateConfiguration creates a new device configuration
func (c *Client) CreateConfiguration(ctx context.Context, name string, certIDs []int) (int, error) {
	payload := map[string]interface{}{
		"name":         name,
		"certificates": certIDs,
	}

	resp, err := c.post(ctx, "/rest/public/configurations", payload)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	return result.ID, nil
}

// ============================================================================
// SafeOps Integration
// ============================================================================

// SyncDevicesWithSafeOps syncs enrolled devices with SafeOps DNS server
func (c *Client) SyncDevicesWithSafeOps(ctx context.Context, safeopsURL string) error {
	devices, err := c.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	for _, device := range devices {
		if !device.Enrolled {
			continue
		}

		// Notify SafeOps about enrolled device
		payload := map[string]string{
			"device_id": device.Number,
			"os":        "Android",
			"model":     device.Model,
			"method":    "headwind-mdm",
		}

		body, _ := json.Marshal(payload)
		resp, err := http.Post(safeopsURL+"/api/enroll", "application/json", bytes.NewReader(body))
		if err != nil {
			continue // Skip failed devices
		}
		resp.Body.Close()
	}

	return nil
}

// ============================================================================
// HTTP Helpers
// ============================================================================

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	return c.httpClient.Do(req)
}

func (c *Client) post(ctx context.Context, path string, payload interface{}) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}
