package logging

import (
	"context"
	"log/slog"
	"time"
)

// AuditAction represents the type of action being performed.
type AuditAction string

const (
	ActionStartup       AuditAction = "STARTUP"
	ActionShutdown      AuditAction = "SHUTDOWN"
	ActionConfigReload  AuditAction = "CONFIG_RELOAD"
	ActionRuleUpdate    AuditAction = "RULE_UPDATE"
	ActionObjectUpdate  AuditAction = "OBJECT_UPDATE"
	ActionSecurityEvent AuditAction = "SECURITY_EVENT"
	ActionLogin         AuditAction = "LOGIN"
)

// AuditStatus represents the outcome of the action.
type AuditStatus string

const (
	StatusSuccess AuditStatus = "SUCCESS"
	StatusFailure AuditStatus = "FAILURE"
)

// Audit logs a security-relevant event.
// It uses the global logger but ensures a consistent structure.
// In a future phase, this could write to a separate audit.log or SIEM.
func Audit(ctx context.Context, action AuditAction, status AuditStatus, msg string, args ...any) {
	// Standard fields for all audit logs
	baseArgs := []any{
		slog.String("event_type", "AUDIT"),
		slog.String("action", string(action)),
		slog.String("status", string(status)),
		slog.Time("timestamp", time.Now().UTC()),
	}

	// Merge baseArgs with user args
	finalArgs := append(baseArgs, args...)

	// We log audit events at INFO level by default, or specific level?
	// If it's a FAILURE, maybe ERROR?
	// Let's stick to INFO for audit trail, unless it's a system error.

	logger := Get()

	if status == StatusFailure {
		logger.ErrorContext(ctx, msg, finalArgs...)
	} else {
		logger.InfoContext(ctx, msg, finalArgs...)
	}
}

// AuditWithActor logs an action performed by a specific user/actor.
func AuditWithActor(ctx context.Context, action AuditAction, actor string, status AuditStatus, msg string, args ...any) {
	Audit(ctx, action, status, msg, append(args, slog.String("actor", actor))...)
}
