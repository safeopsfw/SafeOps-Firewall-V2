package alerting

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatJSON serializes an alert to a compact JSON string for file logging
func FormatJSON(alert *Alert) ([]byte, error) {
	return json.Marshal(alert)
}

// FormatJSONPretty serializes an alert to indented JSON for human reading
func FormatJSONPretty(alert *Alert) ([]byte, error) {
	return json.MarshalIndent(alert, "", "  ")
}

// FormatOneLine produces a compact single-line log entry
func FormatOneLine(alert *Alert) string {
	var sb strings.Builder
	sb.Grow(256)

	// [TIMESTAMP] SEVERITY TYPE src_ip -> dst_ip:port PROTO action "details"
	fmt.Fprintf(&sb, "[%s] %s %s %s",
		alert.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		alert.Severity.String(),
		string(alert.Type),
		alert.SrcIP,
	)

	if alert.DstIP != "" {
		if alert.DstPort > 0 {
			fmt.Fprintf(&sb, " -> %s:%d", alert.DstIP, alert.DstPort)
		} else {
			fmt.Fprintf(&sb, " -> %s", alert.DstIP)
		}
	}

	if alert.Protocol != "" {
		fmt.Fprintf(&sb, " %s", alert.Protocol)
	}

	if alert.Domain != "" {
		fmt.Fprintf(&sb, " domain=%s", alert.Domain)
	}

	fmt.Fprintf(&sb, " action=%s", string(alert.ActionTaken))

	if alert.Count > 1 {
		fmt.Fprintf(&sb, " count=%d", alert.Count)
	}

	if alert.ThreatScore > 0 {
		fmt.Fprintf(&sb, " score=%.1f", alert.ThreatScore)
	}

	if alert.GeoInfo != nil && alert.GeoInfo.CountryCode != "" {
		fmt.Fprintf(&sb, " geo=%s", alert.GeoInfo.CountryCode)
	}

	fmt.Fprintf(&sb, " \"%s\"", alert.Details)

	return sb.String()
}

// FormatCSV produces a CSV line (no header) for bulk export
func FormatCSV(alert *Alert) string {
	geo := ""
	if alert.GeoInfo != nil {
		geo = alert.GeoInfo.CountryCode
	}
	return fmt.Sprintf("%s,%s,%s,%s,%s,%d,%s,%s,%s,%.1f,%s",
		alert.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		alert.Severity.String(),
		string(alert.Type),
		alert.SrcIP,
		alert.DstIP,
		alert.DstPort,
		alert.Protocol,
		alert.Domain,
		string(alert.ActionTaken),
		alert.ThreatScore,
		geo,
	)
}

// CSVHeader returns the CSV header line
func CSVHeader() string {
	return "timestamp,severity,type,src_ip,dst_ip,dst_port,protocol,domain,action,threat_score,geo"
}
