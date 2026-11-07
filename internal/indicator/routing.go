package indicator

import (
	"regexp"
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// RoutingResult holds email routing analysis.
type RoutingResult struct {
	HopCount       int      `json:"hop_count"`
	SuspiciousHops []string `json:"suspicious_hops,omitempty"`
	XMailer        string   `json:"x_mailer,omitempty"`
	XMailerSuspicious bool  `json:"x_mailer_suspicious,omitempty"`
	Details        string   `json:"details,omitempty"`
}

// Known mass-mailing / phishing tool signatures in X-Mailer.
var suspiciousMailers = []string{
	"phpmailer",
	"swiftmailer",
	"php/",
	"mass mail",
	"bulk mail",
	"mail bomber",
	"turbo mailer",
	"atomic mail",
	"group mail",
	"sendy",
	"mailwizz",
	"acelle",
	"interspire",
	"postfix-",
}

// Patterns that suggest suspicious Received headers.
var (
	localhostPattern = regexp.MustCompile(`(?i)\bfrom\s+(localhost|127\.0\.0\.1|\[127\.0\.0\.1\]|unknown)\b`)
	localDomainPattern = regexp.MustCompile(`(?i)\.(local|localdomain|internal|home|lan)\b`)
	ipOnlyPattern = regexp.MustCompile(`\bfrom\s+\[?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?\s`)
)

func analyzeRouting(email *parser.Email) RoutingResult {
	result := RoutingResult{
		HopCount: len(email.Received),
		XMailer:  email.XMailer,
	}

	var details []string

	// X-Mailer analysis
	if email.XMailer != "" {
		mailerLower := strings.ToLower(email.XMailer)
		for _, sig := range suspiciousMailers {
			if strings.Contains(mailerLower, sig) {
				result.XMailerSuspicious = true
				details = append(details, "Suspicious X-Mailer: "+email.XMailer)
				break
			}
		}
	}

	// Received header analysis
	for _, hop := range email.Received {
		hopLower := strings.ToLower(hop)

		// Check for localhost/unknown origin
		if localhostPattern.MatchString(hop) {
			result.SuspiciousHops = append(result.SuspiciousHops, "localhost/unknown origin: "+truncate(hop, 120))
		}

		// Check for local domain names (.local, .localdomain, etc.)
		// Note: Marketing platforms like ExactTarget use .local internally;
		// this is flagged but not heavily weighted in the composite judgment.
		if localDomainPattern.MatchString(hop) && !strings.Contains(hopLower, "google.com") {
			result.SuspiciousHops = append(result.SuspiciousHops, "local domain in routing: "+truncate(hop, 120))
		}

		// Check for IP-only helo (no reverse DNS) — often seen in compromised hosts
		if ipOnlyPattern.MatchString(hop) && !strings.Contains(hop, "by ") {
			result.SuspiciousHops = append(result.SuspiciousHops, "IP-only helo (no rDNS): "+truncate(hop, 120))
		}
	}

	if len(details) > 0 || len(result.SuspiciousHops) > 0 {
		all := append(details, result.SuspiciousHops...)
		result.Details = strings.Join(all, "; ")
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
