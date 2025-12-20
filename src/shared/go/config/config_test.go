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

// ==============================================================================
// Additional Loader Tests
// ==============================================================================

func TestLoaderLoadFromBytes(t *testing.T) {
	yamlContent := `
app:
  name: bytes-test
  version: "2.0.0"
  environment: staging
`
	loader := NewLoader()
	cfg, err := loader.LoadFromBytes([]byte(yamlContent), "yaml")
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	if cfg.App.Name != "bytes-test" {
		t.Errorf("expected app.name = bytes-test, got %s", cfg.App.Name)
	}
	if cfg.App.Version != "2.0.0" {
		t.Errorf("expected app.version = 2.0.0, got %s", cfg.App.Version)
	}
}

func TestLoadInvalidFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(tmpFile, []byte("invalid: [yaml: syntax"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := Load(tmpFile)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadWithDefaults(t *testing.T) {
	content := `
app:
  name: override-name
`
	tmpFile := filepath.Join(t.TempDir(), "partial.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	defaults := DefaultConfig()
	defaults.App.Version = "default-version"

	cfg, err := LoadWithDefaults(tmpFile, defaults)
	if err != nil {
		t.Fatalf("LoadWithDefaults failed: %v", err)
	}

	if cfg.App.Name != "override-name" {
		t.Error("expected app.name to be overridden")
	}
}

func TestMustLoadPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustLoad should panic for invalid path")
		}
	}()

	MustLoad("/nonexistent/config.yaml")
}

func TestConfigFilePath(t *testing.T) {
	content := `app:
  name: test
  version: "1.0"
  environment: dev
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(tmpFile, []byte(content), 0644)

	cfg, _ := Load(tmpFile)
	if cfg.FilePath() != tmpFile {
		t.Errorf("FilePath() = %s, want %s", cfg.FilePath(), tmpFile)
	}
}

func TestConfigReload(t *testing.T) {
	content := `app:
  name: initial
  version: "1.0"
  environment: dev
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(tmpFile, []byte(content), 0644)

	cfg, _ := Load(tmpFile)
	if cfg.App.Name != "initial" {
		t.Fatal("initial load failed")
	}

	// Update file
	newContent := `app:
  name: updated
  version: "2.0"
  environment: dev
`
	os.WriteFile(tmpFile, []byte(newContent), 0644)

	// Reload
	if err := cfg.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if cfg.App.Name != "updated" {
		t.Errorf("expected app.name = updated after reload, got %s", cfg.App.Name)
	}
}

func TestConfigReloadNoPath(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Reload(); err == nil {
		t.Error("expected error when reloading config with no file path")
	}
}

func TestGRPCAddress(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.GRPC.Address() != "0.0.0.0:9090" {
		t.Errorf("expected 0.0.0.0:9090, got %s", cfg.GRPC.Address())
	}
}

// ==============================================================================
// Additional Validator Tests
// ==============================================================================

func TestValidatorPositive(t *testing.T) {
	v := NewValidator()

	if v.Positive("field", 0) {
		t.Error("Positive should return false for 0")
	}
	if v.Positive("field", -1) {
		t.Error("Positive should return false for negative")
	}
	if !v.Positive("field", 1) {
		t.Error("Positive should return true for 1")
	}
}

func TestValidatorPositiveOrZero(t *testing.T) {
	v := NewValidator()

	if v.PositiveOrZero("field", -1) {
		t.Error("PositiveOrZero should return false for negative")
	}
	if !v.PositiveOrZero("field", 0) {
		t.Error("PositiveOrZero should return true for 0")
	}
	if !v.PositiveOrZero("field", 1) {
		t.Error("PositiveOrZero should return true for positive")
	}
}

func TestValidatorRange(t *testing.T) {
	v := NewValidator()

	if v.Range("field", 0, 1, 10) {
		t.Error("Range should return false for value below min")
	}
	if v.Range("field", 11, 1, 10) {
		t.Error("Range should return false for value above max")
	}
	if !v.Range("field", 5, 1, 10) {
		t.Error("Range should return true for value in range")
	}
}

func TestValidatorHostPort(t *testing.T) {
	v := NewValidator()

	if v.HostPort("field", "invalid") {
		t.Error("HostPort should return false for invalid")
	}
	if !v.HostPort("field", "localhost:8080") {
		t.Error("HostPort should return true for valid host:port")
	}
}

func TestValidatorURL(t *testing.T) {
	v := NewValidator()

	// Note: url.Parse is very lenient
	if !v.URL("field", "http://example.com") {
		t.Error("URL should return true for valid URL")
	}
}

func TestValidatorEmail(t *testing.T) {
	v := NewValidator()

	if v.Email("field", "invalid") {
		t.Error("Email should return false for invalid")
	}
	if v.Email("field", "no-at-sign.com") {
		t.Error("Email should return false for no @ sign")
	}
	if !v.Email("field", "user@example.com") {
		t.Error("Email should return true for valid email")
	}
}

func TestValidatorRegex(t *testing.T) {
	v := NewValidator()

	if !v.Regex("field", "abc123", `^[a-z]+[0-9]+$`) {
		t.Error("Regex should return true for matching pattern")
	}
	if v.Regex("field", "123abc", `^[a-z]+[0-9]+$`) {
		t.Error("Regex should return false for non-matching pattern")
	}
}

func TestValidatorMinMaxLength(t *testing.T) {
	v := NewValidator()

	if v.MinLength("field", "ab", 3) {
		t.Error("MinLength should return false for short string")
	}
	if !v.MinLength("field", "abc", 3) {
		t.Error("MinLength should return true for string >= min")
	}

	if v.MaxLength("field", "abcd", 3) {
		t.Error("MaxLength should return false for long string")
	}
	if !v.MaxLength("field", "abc", 3) {
		t.Error("MaxLength should return true for string <= max")
	}
}

func TestValidatorCustom(t *testing.T) {
	v := NewValidator()

	if v.Custom("field", false, "custom error", "value") {
		t.Error("Custom should return false when valid=false")
	}
	if !v.Custom("field", true, "custom error", "value") {
		t.Error("Custom should return true when valid=true")
	}
}

func TestValidatorFileExists(t *testing.T) {
	v := NewValidator()

	if v.FileExists("field", "/nonexistent/file.txt") {
		t.Error("FileExists should return false for nonexistent file")
	}
	if v.FileExists("field", "") {
		t.Error("FileExists should return false for empty path")
	}

	// Create temp file
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmpFile, []byte("test"), 0644)

	if !v.FileExists("field", tmpFile) {
		t.Error("FileExists should return true for existing file")
	}
}

func TestValidationErrorString(t *testing.T) {
	err := &ValidationError{
		Field:   "test.field",
		Message: "is required",
		Value:   "",
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("ValidationError.Error() should not be empty")
	}
	if !contains(errStr, "test.field") {
		t.Error("error string should contain field name")
	}
}

func TestValidationErrorsEmpty(t *testing.T) {
	var errs ValidationErrors

	if errs.HasErrors() {
		t.Error("empty ValidationErrors should return false for HasErrors")
	}
	if errs.Error() != "" {
		t.Error("empty ValidationErrors.Error() should be empty string")
	}
}

// ==============================================================================
// Environment Loader Tests
// ==============================================================================

func TestLoadEnv(t *testing.T) {
	os.Setenv("SAFEOPS_APP_NAME", "env-loaded-app")
	defer os.Unsetenv("SAFEOPS_APP_NAME")

	cfg, err := LoadEnv("SAFEOPS")
	if err != nil {
		t.Fatalf("LoadEnv failed: %v", err)
	}

	if cfg.App.Name != "env-loaded-app" {
		t.Errorf("expected app.name = env-loaded-app, got %s", cfg.App.Name)
	}
}

func TestMustGetEnv(t *testing.T) {
	os.Setenv("MUST_GET_TEST", "value")
	defer os.Unsetenv("MUST_GET_TEST")

	result := MustGetEnv("MUST_GET_TEST")
	if result != "value" {
		t.Error("MustGetEnv should return env value")
	}
}

func TestMustGetEnvPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGetEnv should panic for missing env var")
		}
	}()

	MustGetEnv("NONEXISTENT_VAR_12345")
}

func TestEnvError(t *testing.T) {
	err := &EnvError{Missing: []string{"VAR1", "VAR2"}}
	errStr := err.Error()

	if !contains(errStr, "VAR1") || !contains(errStr, "VAR2") {
		t.Error("EnvError should list missing vars")
	}
}

func TestEnvStruct(t *testing.T) {
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	env := NewEnv()
	env.LoadFromOS()

	if env.Get("TEST_VAR") != "test_value" {
		t.Error("Env.Get should return env value")
	}

	env.Set("CUSTOM", "custom_value")
	if env.Get("CUSTOM") != "custom_value" {
		t.Error("Env.Set should set value")
	}

	if !env.Has("CUSTOM") {
		t.Error("Env.Has should return true for set value")
	}
	if env.Has("NONEXISTENT") {
		t.Error("Env.Has should return false for unset value")
	}
}

func TestEnvWithPrefix(t *testing.T) {
	os.Setenv("PREFIX_A", "value_a")
	os.Setenv("PREFIX_B", "value_b")
	os.Setenv("OTHER_C", "value_c")
	defer func() {
		os.Unsetenv("PREFIX_A")
		os.Unsetenv("PREFIX_B")
		os.Unsetenv("OTHER_C")
	}()

	env := NewEnv()
	env.LoadFromOS()

	withPrefix := env.WithPrefix("PREFIX_")
	if len(withPrefix) != 2 {
		t.Errorf("expected 2 vars with prefix, got %d", len(withPrefix))
	}
}

func TestExpandEnvConfig(t *testing.T) {
	os.Setenv("EXPAND_HOST", "expanded-host")
	defer os.Unsetenv("EXPAND_HOST")

	cfg := DefaultConfig()
	cfg.Database.Host = "${EXPAND_HOST}"

	ExpandEnvConfig(cfg)

	if cfg.Database.Host != "expanded-host" {
		t.Errorf("expected expanded host, got %s", cfg.Database.Host)
	}
}

// ==============================================================================
// Watcher Tests
// ==============================================================================

func TestNewWatcher(t *testing.T) {
	callback := func(cfg *Config, err error) {}
	watcher := NewWatcher("/tmp/config.yaml", callback)

	if watcher == nil {
		t.Fatal("NewWatcher returned nil")
	}
	if watcher.path != "/tmp/config.yaml" {
		t.Error("watcher path not set correctly")
	}
	if watcher.interval != 5*time.Second {
		t.Error("default interval should be 5s")
	}
}

func TestWatcherOptions(t *testing.T) {
	callback := func(cfg *Config, err error) {}
	watcher := NewWatcher("/tmp/config.yaml", callback,
		WithInterval(10*time.Second),
		WithDebounce(1*time.Second),
	)

	if watcher.interval != 10*time.Second {
		t.Error("WithInterval did not set interval")
	}
	if watcher.debounce != 1*time.Second {
		t.Error("WithDebounce did not set debounce")
	}
}

func TestWatcherStartStop(t *testing.T) {
	content := `app:
  name: watch-test
  version: "1.0"
  environment: dev
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(tmpFile, []byte(content), 0644)

	callback := func(cfg *Config, err error) {}
	watcher := NewWatcher(tmpFile, callback)

	// Start
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !watcher.IsRunning() {
		t.Error("watcher should be running after Start")
	}

	// Start again (should be no-op)
	if err := watcher.Start(); err != nil {
		t.Error("second Start should not error")
	}

	// Stop
	watcher.Stop()

	if watcher.IsRunning() {
		t.Error("watcher should not be running after Stop")
	}

	// Stop again (should be no-op)
	watcher.Stop()
}

func TestWatcherStartNonexistentFile(t *testing.T) {
	callback := func(cfg *Config, err error) {}
	watcher := NewWatcher("/nonexistent/config.yaml", callback)

	if err := watcher.Start(); err == nil {
		t.Error("Start should fail for nonexistent file")
	}
}

func TestWatchFunction(t *testing.T) {
	content := `app:
  name: watch-func-test
  version: "1.0"
  environment: dev
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(tmpFile, []byte(content), 0644)

	callback := func(cfg *Config, err error) {}
	watcher, err := Watch(tmpFile, callback)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	defer watcher.Stop()

	if !watcher.IsRunning() {
		t.Error("watcher should be running")
	}
}

func TestMultiWatcher(t *testing.T) {
	content := `app:
  name: multi-test
  version: "1.0"
  environment: dev
`
	tmpFile1 := filepath.Join(t.TempDir(), "config1.yaml")
	tmpFile2 := filepath.Join(t.TempDir(), "config2.yaml")
	os.WriteFile(tmpFile1, []byte(content), 0644)
	os.WriteFile(tmpFile2, []byte(content), 0644)

	multi := NewMultiWatcher()
	callback := func(cfg *Config, err error) {}

	if err := multi.Add(tmpFile1, callback); err != nil {
		t.Fatalf("Add file1 failed: %v", err)
	}
	if err := multi.Add(tmpFile2, callback); err != nil {
		t.Fatalf("Add file2 failed: %v", err)
	}

	multi.Stop()
}

func TestMultiWatcherAddFail(t *testing.T) {
	multi := NewMultiWatcher()
	callback := func(cfg *Config, err error) {}

	if err := multi.Add("/nonexistent/config.yaml", callback); err == nil {
		t.Error("Add should fail for nonexistent file")
	}
}

// ==============================================================================
// Config Get Methods Edge Cases
// ==============================================================================

func TestConfigGetNil(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Custom = nil

	if cfg.Get("anykey") != nil {
		t.Error("Get should return nil when Custom is nil")
	}
}

func TestConfigGetIntTypes(t *testing.T) {
	cfg := DefaultConfig()

	cfg.Set("int64_val", int64(42))
	if cfg.GetInt("int64_val") != 42 {
		t.Error("GetInt should handle int64")
	}

	cfg.Set("float64_val", float64(42.0))
	if cfg.GetInt("float64_val") != 42 {
		t.Error("GetInt should handle float64")
	}

	cfg.Set("string_val", "not a number")
	if cfg.GetInt("string_val") != 0 {
		t.Error("GetInt should return 0 for non-numeric")
	}
}

func TestConfigGetBoolFalse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Set("not_bool", "string")

	if cfg.GetBool("not_bool") {
		t.Error("GetBool should return false for non-bool")
	}
	if cfg.GetBool("nonexistent") {
		t.Error("GetBool should return false for nonexistent key")
	}
}

// ==============================================================================
// Benchmark Tests
// ==============================================================================

func BenchmarkLoad(b *testing.B) {
	content := `app:
  name: bench-test
  version: "1.0"
  environment: dev
`
	tmpFile := filepath.Join(b.TempDir(), "config.yaml")
	os.WriteFile(tmpFile, []byte(content), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Load(tmpFile)
	}
}

func BenchmarkValidate(b *testing.B) {
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Validate(cfg)
	}
}

func BenchmarkConfigClone(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Set("custom1", "value1")
	cfg.Set("custom2", "value2")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.Clone()
	}
}
