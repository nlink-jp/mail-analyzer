package indicator

import (
	"strings"
)

// AuthResult holds SPF/DKIM/DMARC results parsed from Authentication-Results headers.
type AuthResult struct {
	SPF   string `json:"spf"`   // pass, fail, softfail, neutral, none, temperror, permerror
	DKIM  string `json:"dkim"`  // pass, fail, none
	DMARC string `json:"dmarc"` // pass, fail, none
	// PerHeader holds each Authentication-Results field's verdicts, top
	// first, when there is more than one. Forwarded mail carries one per
	// receiving hop, and they often disagree.
	PerHeader []AuthVerdicts `json:"per_header,omitempty"`
	// Conflicting is true when the fields gave different verdicts for one
	// method; SPF, DKIM and DMARC then hold the most severe of them.
	Conflicting bool `json:"conflicting,omitempty"`
}

// AuthVerdicts are the verdicts of one Authentication-Results field.
type AuthVerdicts struct {
	SPF   string `json:"spf"`
	DKIM  string `json:"dkim"`
	DMARC string `json:"dmarc"`
}

// analyzeAuthAll reads every Authentication-Results field. A forged "pass"
// placed on top must not hide a "fail" after it, so each method takes the most
// severe verdict any field gave.
func analyzeAuthAll(fields []string) AuthResult {
	result := AuthResult{SPF: "none", DKIM: "none", DMARC: "none"}
	var per []AuthVerdicts
	for _, f := range fields {
		if strings.TrimSpace(f) == "" {
			continue
		}
		one := analyzeAuth(f)
		per = append(per, AuthVerdicts{SPF: one.SPF, DKIM: one.DKIM, DMARC: one.DMARC})
		result.SPF = mergeVerdict(result.SPF, one.SPF, &result.Conflicting)
		result.DKIM = mergeVerdict(result.DKIM, one.DKIM, &result.Conflicting)
		result.DMARC = mergeVerdict(result.DMARC, one.DMARC, &result.Conflicting)
	}
	if len(per) > 1 {
		result.PerHeader = per
	}
	return result
}

// mergeVerdict keeps the more severe of two verdicts for one method; "none"
// (the method absent from a field) neither wins nor conflicts.
func mergeVerdict(cur, next string, conflicting *bool) string {
	if next == "none" {
		return cur
	}
	if cur == "none" {
		return next
	}
	if cur != next {
		*conflicting = true
	}
	if verdictSeverity(next) > verdictSeverity(cur) {
		return next
	}
	return cur
}

func verdictSeverity(v string) int {
	switch v {
	case "fail":
		return 6
	case "softfail":
		return 5
	case "permerror":
		return 4
	case "temperror":
		return 3
	case "neutral":
		return 2
	case "pass":
		return 0
	default: // policy, bestguesspass and other words
		return 1
	}
}

// analyzeAuth reads one Authentication-Results field.
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
