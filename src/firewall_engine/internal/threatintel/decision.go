package threatintel

import (
	"fmt"

	"firewall_engine/internal/alerting"
)

// ThreatResult is the outcome of a threat intel check
type ThreatResult struct {
	IsBlocked    bool
	ThreatScore  int
	Reason       string
	AlertType    alerting.AlertType
	AbuseType    string
	Category     string
	IsAnonymizer bool
	VPNInfo      *VPNInfo
}

// Decision is the unified threat intel check entry point.
// It queries the in-memory caches (never the database) and fires alerts.
type Decision struct {
	ipCache     *IPCache
	domainCache *DomainCache
	alertMgr    *alerting.Manager
}

// NewDecision creates a new threat decision engine
func NewDecision(ipCache *IPCache, domainCache *DomainCache, alertMgr *alerting.Manager) *Decision {
	return &Decision{
		ipCache:     ipCache,
		domainCache: domainCache,
		alertMgr:    alertMgr,
	}
}

// CheckIP checks source and destination IPs against threat intel.
// Returns a non-nil result if either IP is malicious.
func (d *Decision) CheckIP(srcIP, dstIP string) *ThreatResult {
	// Check source IP (inbound threat)
	if threat, ok := d.ipCache.CheckIP(srcIP); ok {
		result := &ThreatResult{
			IsBlocked:   true,
			ThreatScore: threat.ThreatScore,
			AbuseType:   threat.AbuseType,
			AlertType:   alerting.AlertThreatIntel,
			Reason:      fmt.Sprintf("Source IP %s in threat intel blacklist (abuse=%s, score=%d)", srcIP, threat.AbuseType, threat.ThreatScore),
		}

		d.fireIPAlert(srcIP, dstIP, threat, "src")
		return result
	}

	// Check destination IP (outbound to C2/malware)
	if threat, ok := d.ipCache.CheckIP(dstIP); ok {
		result := &ThreatResult{
			IsBlocked:   true,
			ThreatScore: threat.ThreatScore,
			AbuseType:   threat.AbuseType,
			AlertType:   alerting.AlertThreatIntel,
			Reason:      fmt.Sprintf("Destination IP %s in threat intel blacklist (abuse=%s, score=%d)", dstIP, threat.AbuseType, threat.ThreatScore),
		}

		d.fireIPAlert(dstIP, srcIP, threat, "dst")
		return result
	}

	// Check VPN/anonymizer (informational, not blocking by default)
	if vpn, ok := d.ipCache.CheckVPN(srcIP); ok {
		return &ThreatResult{
			IsBlocked:    false, // VPN detection is informational
			IsAnonymizer: true,
			VPNInfo:      vpn,
			ThreatScore:  vpn.RiskScore,
			Reason:       fmt.Sprintf("Source IP %s is %s (%s)", srcIP, vpn.ServiceType, vpn.Provider),
		}
	}

	return nil
}

// CheckDomain checks a domain against the malicious domains cache.
func (d *Decision) CheckDomain(domain string) *ThreatResult {
	if domain == "" {
		return nil
	}

	threat, ok := d.domainCache.CheckDomain(domain)
	if !ok {
		return nil
	}

	result := &ThreatResult{
		IsBlocked:   true,
		ThreatScore: threat.ThreatScore,
		Category:    threat.Category,
		AlertType:   alerting.AlertDomainBlock,
		Reason:      fmt.Sprintf("Domain %s in threat intel (category=%s, score=%d)", domain, threat.Category, threat.ThreatScore),
	}

	d.fireDomainAlert(domain, threat)
	return result
}

// Check performs a combined IP + domain threat intel lookup.
// Returns the first blocking result found, or nil if clean.
func (d *Decision) Check(srcIP, dstIP, domain string) *ThreatResult {
	// IP check first (faster, more certain)
	if result := d.CheckIP(srcIP, dstIP); result != nil && result.IsBlocked {
		return result
	}

	// Domain check
	if result := d.CheckDomain(domain); result != nil {
		return result
	}

	// Non-blocking VPN check (returns anonymizer info)
	if result := d.CheckIP(srcIP, dstIP); result != nil {
		return result
	}

	return nil
}

func (d *Decision) fireIPAlert(threatIP, otherIP string, threat *IPThreat, direction string) {
	if d.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	if threat.ThreatScore >= 80 {
		severity = alerting.SeverityHigh
	}
	if threat.ThreatScore >= 95 {
		severity = alerting.SeverityCritical
	}

	alert := alerting.NewAlert(alerting.AlertThreatIntel, severity).
		WithDetails(fmt.Sprintf("Threat intel match: %s IP %s (abuse=%s, confidence=%d%%)",
			direction, threatIP, threat.AbuseType, threat.Confidence)).
		WithThreatScore(float64(threat.ThreatScore)).
		WithAction(alerting.ActionBlocked).
		WithMeta("abuse_type", threat.AbuseType).
		WithMeta("direction", direction)

	if direction == "src" {
		alert.WithSource(threatIP, 0).WithDestination(otherIP, 0)
	} else {
		alert.WithSource(otherIP, 0).WithDestination(threatIP, 0)
	}

	d.alertMgr.Alert(alert.Build())
}

func (d *Decision) fireDomainAlert(domain string, threat *DomainThreat) {
	if d.alertMgr == nil {
		return
	}

	severity := alerting.SeverityMedium
	if threat.ThreatScore >= 80 {
		severity = alerting.SeverityHigh
	}
	if threat.ThreatScore >= 95 {
		severity = alerting.SeverityCritical
	}

	// Alert only — domain is NOT auto-blocked. Security team reviews.
	alert := alerting.NewAlert(alerting.AlertDomainBlock, severity).
		WithDomain(domain).
		WithDetails(fmt.Sprintf("Threat intel domain detected: %s (category=%s, confidence=%d%%) — NOT auto-blocked, review required",
			domain, threat.Category, threat.Confidence)).
		WithThreatScore(float64(threat.ThreatScore)).
		WithAction(alerting.ActionLogged).
		WithMeta("category", threat.Category).
		WithMeta("auto_blocked", "false")

	d.alertMgr.Alert(alert.Build())
}
