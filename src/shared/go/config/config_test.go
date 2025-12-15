package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Create temp config file
	content := `
app:
  name: test-service
  version: "1.0.0"
  environment: development
  debug: true

logging:
  level: debug
  format: json
  output: stdout

server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
`

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.App.Name != "test-service" {
		t.Errorf("expected app.name = test-service, got %s", cfg.App.Name)
	}

	if cfg.App.Version != "1.0.0" {
		t.Errorf("expected app.version = 1.0.0, got %s", cfg.App.Version)
	}

	if !cfg.App.Debug {
		t.Error("expected app.debug = true")
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("expected server.port = 8080, got %d", cfg.Server.Port)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("expected logging.level = debug, got %s", cfg.Logging.Level)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.App.Name == "" {
		t.Error("expected default app.name to be set")
	}

	if cfg.Server.Port == 0 {
		t.Error("expected default server.port to be set")
	}

	if cfg.Database.MaxOpenConns == 0 {
		t.Error("expected default database.max_open_conns to be set")
	}
}

func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.Set("custom_key", "custom_value")

	clone := original.Clone()

	if clone.App.Name != original.App.Name {
		t.Error("clone should have same values")
	}

	// Modify clone shouldn't affect original
	clone.App.Name = "modified"
	if original.App.Name == "modified" {
		t.Error("modifying clone should not affect original")
	}
}

func TestConfigGetSet(t *testing.T) {
	cfg := DefaultConfig()

	cfg.Set("test_key", "test_value")

	if cfg.GetString("test_key") != "test_value" {
		t.Error("expected to get set value")
	}

	cfg.Set("test_int", 42)
	if cfg.GetInt("test_int") != 42 {
		t.Error("expected to get int value")
	}

	cfg.Set("test_bool", true)
	if !cfg.GetBool("test_bool") {
		t.Error("expected to get bool value")
	}
}

func TestValidate(t *testing.T) {
	cfg := DefaultConfig()

	// Valid config
	if err := Validate(cfg); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}

	// Invalid config
	cfg.App.Name = ""
	if err := Validate(cfg); err == nil {
		t.Error("expected validation error for empty app.name")
	}
}

func TestValidator(t *testing.T) {
	v := NewValidator()

	// Test Required
	if v.Required("field", "") {
		t.Error("expected Required to return false for empty string")
	}

	if !v.Required("field", "value") {
		t.Error("expected Required to return true for non-empty string")
	}

	// Test Port
	if v.Port("port", 0) {
		t.Error("expected Port to return false for 0")
	}

	if v.Port("port", 70000) {
		t.Error("expected Port to return false for > 65535")
	}

	if !v.Port("port", 8080) {
		t.Error("expected Port to return true for valid port")
	}

	// Test OneOf
	if v.OneOf("env", "invalid", []string{"dev", "prod"}) {
		t.Error("expected OneOf to return false for invalid value")
	}

	if !v.OneOf("env", "dev", []string{"dev", "prod"}) {
		t.Error("expected OneOf to return true for valid value")
	}
}

func TestValidationErrors(t *testing.T) {
	v := NewValidator()

	v.Required("field1", "")
	v.Port("field2", 0)

	errors := v.Errors()

	if len(errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errors))
	}

	if !errors.HasErrors() {
		t.Error("expected HasErrors to return true")
	}

	errStr := errors.Error()
	if errStr == "" {
		t.Error("expected error string to be non-empty")
	}
}

func TestEnvLoader(t *testing.T) {
	// Set test env vars
	os.Setenv("TEST_APP_NAME", "env-test-app")
	os.Setenv("TEST_APP_DEBUG", "true")
	os.Setenv("TEST_SERVER_PORT", "9090")
	defer func() {
		os.Unsetenv("TEST_APP_NAME")
		os.Unsetenv("TEST_APP_DEBUG")
		os.Unsetenv("TEST_SERVER_PORT")
	}()

	cfg := DefaultConfig()
	loader := NewEnvLoader("TEST")
	loader.Apply(cfg)

	if cfg.App.Name != "env-test-app" {
		t.Errorf("expected app.name = env-test-app, got %s", cfg.App.Name)
	}

	if !cfg.App.Debug {
		t.Error("expected app.debug = true from env")
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected server.port = 9090, got %d", cfg.Server.Port)
	}
}

func TestGetEnvHelpers(t *testing.T) {
	os.Setenv("TEST_STRING", "hello")
	os.Setenv("TEST_INT", "42")
	os.Setenv("TEST_BOOL", "true")
	os.Setenv("TEST_DURATION", "5s")
	os.Setenv("TEST_SLICE", "a,b,c")
	defer func() {
		os.Unsetenv("TEST_STRING")
		os.Unsetenv("TEST_INT")
		os.Unsetenv("TEST_BOOL")
		os.Unsetenv("TEST_DURATION")
		os.Unsetenv("TEST_SLICE")
	}()

	if GetEnv("TEST_STRING", "") != "hello" {
		t.Error("GetEnv failed")
	}

	if GetEnv("NONEXISTENT", "default") != "default" {
		t.Error("GetEnv default failed")
	}

	if GetEnvInt("TEST_INT", 0) != 42 {
		t.Error("GetEnvInt failed")
	}

	if !GetEnvBool("TEST_BOOL", false) {
		t.Error("GetEnvBool failed")
	}

	if GetEnvDuration("TEST_DURATION", 0) != 5*time.Second {
		t.Error("GetEnvDuration failed")
	}

	slice := GetEnvSlice("TEST_SLICE", nil)
	if len(slice) != 3 || slice[0] != "a" {
		t.Error("GetEnvSlice failed")
	}
}

func TestExpandEnv(t *testing.T) {
	os.Setenv("MY_HOST", "localhost")
	defer os.Unsetenv("MY_HOST")

	result := ExpandEnv("http://${MY_HOST}:8080")
	if result != "http://localhost:8080" {
		t.Errorf("expected http://localhost:8080, got %s", result)
	}
}

func TestRequireEnv(t *testing.T) {
	os.Setenv("REQUIRED_VAR", "value")
	defer os.Unsetenv("REQUIRED_VAR")

	if err := RequireEnv("REQUIRED_VAR"); err != nil {
		t.Error("expected no error for existing env var")
	}

	if err := RequireEnv("NONEXISTENT_VAR"); err == nil {
		t.Error("expected error for missing env var")
	}
}

func TestDatabaseDSN(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Database.Password = "secret"

	dsn := cfg.Database.DSN()

	if dsn == "" {
		t.Error("expected non-empty DSN")
	}

	if !contains(dsn, "host=localhost") {
		t.Error("DSN should contain host")
	}
}

func TestServerAddress(t *testing.T) {
	cfg := DefaultConfig()

	addr := cfg.Server.Address()
	if addr != "0.0.0.0:8080" {
		t.Errorf("expected 0.0.0.0:8080, got %s", addr)
	}
}

func TestEnvironmentChecks(t *testing.T) {
	cfg := DefaultConfig()

	cfg.App.Environment = "production"
	if !cfg.IsProduction() {
		t.Error("expected IsProduction to return true")
	}

	cfg.App.Environment = "development"
	if !cfg.IsDevelopment() {
		t.Error("expected IsDevelopment to return true")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
