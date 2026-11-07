package indicator

import (
	"strings"
)

// AuthResult holds SPF/DKIM/DMARC results read from the Authentication-Results fields.
type AuthResult struct {
	SPF   string `json:"spf"`   // pass, fail, softfail, neutral, none, temperror, permerror
	DKIM  string `json:"dkim"`  // pass, fail, none
	DMARC string `json:"dmarc"` // pass, fail, none
	// Conflicting is true when a lower Authentication-Results field gives a
	// mechanism a different result than the top one. Forwarding does this
	// honestly (the first receiver passes SPF, the next one fails it); a
	// forged field added by the sender does it too. It is information only:
	// the verdicts above come from the top field either way.
	Conflicting bool     `json:"conflicting,omitempty"`
	Raw         []string `json:"raw,omitempty"` // every Authentication-Results field, top first
}

// analyzeAuth takes the verdicts from the top Authentication-Results field.
// Each receiving server adds its field above the ones already there, so the
// top field is the recipient's own server's, and a field the sender forged
// sits below it. Within the field the first result of each mechanism counts.
func analyzeAuth(fields []string) AuthResult {
	result := AuthResult{SPF: "none", DKIM: "none", DMARC: "none", Raw: fields}
	if len(fields) == 0 {
		return result
	}
	verdicts := map[string]*string{"spf=": &result.SPF, "dkim=": &result.DKIM, "dmarc=": &result.DMARC}
	for prefix, v := range verdicts {
		top := extractAuthVerdict(strings.ToLower(fields[0]), prefix)
		if top != "" {
			*v = top
		}
		for _, f := range fields[1:] {
			if other := extractAuthVerdict(strings.ToLower(f), prefix); top != "" && other != "" && other != top {
				result.Conflicting = true
			}
		}
	}
	return result
}

// extractAuthVerdict returns the first result for prefix in one field, or ""
// when the field does not mention the mechanism.
func extractAuthVerdict(header, prefix string) string {
	idx := strings.Index(header, prefix)
	if idx < 0 {
		return ""
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
