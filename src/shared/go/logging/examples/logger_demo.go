package main

import (
	"context"
	"errors"

	"github.com/safeops/shared/go/logging"
)

func main() {
	println("=============================================================")
	println("JSON FORMATTER (Production)")
	println("=============================================================\n")

	// JSON Logger
	jsonLogger := logging.New()
	jsonLogger.SetFormatter(logging.NewJSONFormatter())
	jsonLogger.SetLevelString("debug")

	// Basic logs
	jsonLogger.Info("Service started successfully")
	jsonLogger.Debug("Debugging information")
	jsonLogger.Warn("This is a warning")
	jsonLogger.Error("An error occurred")

	// With fields
	jsonLogger.WithFields(logging.Fields{
		"user_id":    "user123",
		"request_id": "req-abc-456",
		"ip_address": "192.168.1.100",
	}).Info("User login successful")

	// With error
	err := errors.New("database connection timeout")
	jsonLogger.WithError(err).Error("Database operation failed")

	// With context
	ctx := context.Background()
	ctx = logging.WithRequestID(ctx, "req-xyz-789")
	ctx = logging.WithUserID(ctx, "admin")
	jsonLogger.WithContext(ctx).Info("Admin action performed")

	// Chained fields
	jsonLogger.WithField("service", "dns-server").
		WithField("query", "example.com").
		WithField("response_time_ms", 45).
		WithField("cache_hit", true).
		Info("DNS query processed")

	println("\n=============================================================")
	println("TEXT FORMATTER (Development/Console)")
	println("=============================================================\n")

	// Text Logger
	textLogger := logging.New()
	textLogger.SetFormatter(&logging.SafeOpsTextFormatter{
		ColorEnabled:  true,
		FullTimestamp: true,
	})
	textLogger.SetLevelString("debug")

	// Same logs in text format
	textLogger.Debug("Debugging information")
	textLogger.Info("Service started successfully")
	textLogger.Warn("This is a warning")
	textLogger.Error("An error occurred")

	textLogger.WithFields(logging.Fields{
		"user_id":    "user123",
		"request_id": "req-abc-456",
		"ip_address": "192.168.1.100",
	}).Info("User login successful")

	textLogger.WithError(errors.New("database connection timeout")).
		Error("Database operation failed")

	ctx2 := context.Background()
	ctx2 = logging.WithRequestID(ctx2, "req-xyz-789")
	ctx2 = logging.WithUserID(ctx2, "admin")
	textLogger.WithContext(ctx2).Info("Admin action performed")

	textLogger.WithField("service", "dns-server").
		WithField("query", "example.com").
		WithField("response_time_ms", 45).
		WithField("cache_hit", true).
		Info("DNS query processed")

	println("\n=============================================================")
	println("DIFFERENT LOG LEVELS")
	println("=============================================================\n")

	levelLogger := logging.New()
	levelLogger.SetFormatter(&logging.SafeOpsTextFormatter{ColorEnabled: true})

	levelLogger.SetLevelString("trace")
	levelLogger.Trace("TRACE: Most verbose")
	levelLogger.Debug("DEBUG: Detailed troubleshooting")
	levelLogger.Info("INFO: Normal operations")
	levelLogger.Warn("WARN: Potential issues")
	levelLogger.Error("ERROR: Failures requiring attention")

	println("\n=============================================================")
	println("PERMANENT FIELDS (Service Context)")
	println("=============================================================\n")

	serviceLogger := logging.NewWithFields(logging.Fields{
		"service":     "dns-server",
		"version":     "2.0.0",
		"environment": "production",
		"host":        "safeops-01",
	})
	serviceLogger.SetFormatter(logging.NewJSONFormatter())

	serviceLogger.Info("Service initialized")
	serviceLogger.WithField("uptime_seconds", 3600).Info("Health check")

	println("\n=============================================================")
	println("RUNTIME LEVEL CHANGE")
	println("=============================================================\n")

	dynLogger := logging.New()
	dynLogger.SetFormatter(&logging.SafeOpsTextFormatter{ColorEnabled: true})

	dynLogger.SetLevelString("info")
	dynLogger.Debug("This won't appear (level=INFO)")
	dynLogger.Info("This appears (level=INFO)")

	println("\nChanging level to DEBUG...\n")
	dynLogger.SetLevelString("debug")
	dynLogger.Debug("Now this appears! (level=DEBUG)")
	dynLogger.Info("This still appears (level=DEBUG)")

	println("\n=============================================================")
	println("Demo Complete!")
	println("=============================================================")
}
