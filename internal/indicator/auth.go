package indicator

import (
	"strings"
)

// AuthResult holds SPF/DKIM/DMARC results parsed from Authentication-Results header.
type AuthResult struct {
	SPF    string `json:"spf"`    // pass, fail, softfail, neutral, none, temperror, permerror
	DKIM   string `json:"dkim"`   // pass, fail, none
	DMARC  string `json:"dmarc"`  // pass, fail, none
}

func analyzeAuth(authResults string) AuthResult {
	result := AuthResult{SPF: "none", DKIM: "none", DMARC: "none"}
	if authResults == "" {
		return result
	}

	lower := strings.ToLower(authResults)

	result.SPF = extractAuthVerdict(lower, "spf=")
	result.DKIM = extractAuthVerdict(lower, "dkim=")
	result.DMARC = extractAuthVerdict(lower, "dmarc=")

	return result
}

func extractAuthVerdict(header, prefix string) string {
	idx := strings.Index(header, prefix)
	if idx < 0 {
		return "none"
	}
	rest := header[idx+len(prefix):]
	// Extract the verdict word (e.g., "pass", "fail")
	end := strings.IndexAny(rest, " \t;()\r\n")
	if end < 0 {
		return sanitizeVerdict(rest)
	}
	return sanitizeVerdict(rest[:end])
}

func sanitizeVerdict(v string) string {
	v = strings.TrimSpace(v)
	switch v {
	case "pass", "fail", "softfail", "neutral", "temperror", "permerror", "none":
		return v
	default:
		if strings.HasPrefix(v, "pass") {
			return "pass"
		}
		if strings.HasPrefix(v, "fail") {
			return "fail"
		}
		return v
	}
}
