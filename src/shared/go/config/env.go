// Package config provides environment variable handling functionality.
package config

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// EnvLoader loads configuration from environment variables
type EnvLoader struct {
	prefix    string
	separator string
}

// NewEnvLoader creates a new environment variable loader
func NewEnvLoader(prefix string) *EnvLoader {
	return &EnvLoader{
		prefix:    prefix,
		separator: "_",
	}
}

// LoadEnv loads configuration from environment variables
func LoadEnv(prefix string) (*Config, error) {
	loader := NewEnvLoader(prefix)
	cfg := DefaultConfig()
	loader.Apply(cfg)
	return cfg, nil
}

// Apply applies environment variables to a config
func (e *EnvLoader) Apply(cfg *Config) {
	e.applyToStruct(reflect.ValueOf(cfg).Elem(), e.prefix)
}

// applyToStruct recursively applies env vars to a struct
func (e *EnvLoader) applyToStruct(v reflect.Value, prefix string) {
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !fieldValue.CanSet() {
			continue
		}

		// Get field name from tag or use field name
		envName := field.Tag.Get("env")
		if envName == "" {
			envName = field.Tag.Get("mapstructure")
		}
		if envName == "" {
			envName = strings.ToLower(field.Name)
		}
		if envName == "-" {
			continue
		}

		// Build full env key
		var envKey string
		if prefix != "" {
			envKey = prefix + e.separator + strings.ToUpper(envName)
		} else {
			envKey = strings.ToUpper(envName)
		}

		// Handle nested structs
		if fieldValue.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Duration(0)) {
			e.applyToStruct(fieldValue, envKey)
			continue
		}

		// Get env value
		envValue := os.Getenv(envKey)
		if envValue == "" {
			continue
		}

		// Set value based on type
		e.setFieldValue(fieldValue, envValue)
	}
}

// setFieldValue sets a field value from a string
func (e *EnvLoader) setFieldValue(field reflect.Value, value string) {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Special handling for time.Duration
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			if d, err := time.ParseDuration(value); err == nil {
				field.SetInt(int64(d))
			}
		} else {
			if i, err := strconv.ParseInt(value, 10, 64); err == nil {
				field.SetInt(i)
			}
		}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if u, err := strconv.ParseUint(value, 10, 64); err == nil {
			field.SetUint(u)
		}

	case reflect.Float32, reflect.Float64:
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			field.SetFloat(f)
		}

	case reflect.Bool:
		if b, err := strconv.ParseBool(value); err == nil {
			field.SetBool(b)
		}

	case reflect.Slice:
		// Handle string slices (comma-separated)
		if field.Type().Elem().Kind() == reflect.String {
			parts := strings.Split(value, ",")
			for i, p := range parts {
				parts[i] = strings.TrimSpace(p)
			}
			field.Set(reflect.ValueOf(parts))
		}
	}
}

// GetEnv gets an environment variable with a default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvInt gets an int environment variable with a default value
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetEnvBool gets a bool environment variable with a default value
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

// GetEnvDuration gets a duration environment variable with a default value
func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

// GetEnvSlice gets a string slice environment variable (comma-separated)
func GetEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		return parts
	}
	return defaultValue
}

// MustGetEnv gets an environment variable or panics if not set
func MustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("required environment variable not set: " + key)
	}
	return value
}

// RequireEnv checks that all required environment variables are set
func RequireEnv(keys ...string) error {
	var missing []string
	for _, key := range keys {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return &EnvError{Missing: missing}
	}
	return nil
}

// EnvError represents missing environment variables
type EnvError struct {
	Missing []string
}

func (e *EnvError) Error() string {
	return "missing required environment variables: " + strings.Join(e.Missing, ", ")
}

// ExpandEnv expands environment variables in a config value
func ExpandEnv(value string) string {
	return os.ExpandEnv(value)
}

// ExpandEnvConfig expands environment variables in all config string fields
func ExpandEnvConfig(cfg *Config) {
	expandEnvStruct(reflect.ValueOf(cfg).Elem())
}

// expandEnvStruct recursively expands env vars in string fields
func expandEnvStruct(v reflect.Value) {
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)

		if !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(os.ExpandEnv(field.String()))

		case reflect.Struct:
			if t.Field(i).Type != reflect.TypeOf(time.Duration(0)) {
				expandEnvStruct(field)
			}

		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				for j := 0; j < field.Len(); j++ {
					elem := field.Index(j)
					elem.SetString(os.ExpandEnv(elem.String()))
				}
			}
		}
	}
}

// Env represents environment settings
type Env struct {
	vars map[string]string
}

// NewEnv creates a new Env from current environment
func NewEnv() *Env {
	return &Env{
		vars: make(map[string]string),
	}
}

// LoadFromOS loads all environment variables
func (e *Env) LoadFromOS() {
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			e.vars[pair[0]] = pair[1]
		}
	}
}

// Get gets an environment variable
func (e *Env) Get(key string) string {
	return e.vars[key]
}

// Set sets an environment variable
func (e *Env) Set(key, value string) {
	e.vars[key] = value
}

// Has checks if an environment variable exists
func (e *Env) Has(key string) bool {
	_, ok := e.vars[key]
	return ok
}

// WithPrefix returns vars with a specific prefix
func (e *Env) WithPrefix(prefix string) map[string]string {
	result := make(map[string]string)
	for k, v := range e.vars {
		if strings.HasPrefix(k, prefix) {
			result[k] = v
		}
	}
	return result
}
