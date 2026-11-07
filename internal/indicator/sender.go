package indicator

import (
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// SenderResult holds sender integrity analysis.
type SenderResult struct {
	FromReturnPathMismatch bool   `json:"from_return_path_mismatch"`
	DisplayNameSpoofing    bool   `json:"display_name_spoofing"`
	ReplyToDivergence      bool   `json:"reply_to_divergence"`
	Details                string `json:"details,omitempty"`
}

func analyzeSender(email *parser.Email) SenderResult {
	result := SenderResult{}
	var details []string

	fromDomain := extractDomain(email.From)
	returnPathDomain := extractDomain(email.ReturnPath)
	replyToDomain := extractDomain(email.ReplyTo)

	// From vs Return-Path domain mismatch.
	// Allow subdomain relationships (e.g., bounce.mag.subaru.jp matches mag.subaru.jp)
	// since legitimate senders often use subdomains for bounce handling.
	if fromDomain != "" && returnPathDomain != "" && !domainsRelated(fromDomain, returnPathDomain) {
		result.FromReturnPathMismatch = true
		details = append(details, "From domain ("+fromDomain+") differs from Return-Path domain ("+returnPathDomain+")")
	}

	// Reply-To divergence
	if replyToDomain != "" && fromDomain != "" && !strings.EqualFold(fromDomain, replyToDomain) {
		result.ReplyToDivergence = true
		details = append(details, "Reply-To domain ("+replyToDomain+") differs from From domain ("+fromDomain+")")
	}

	// Display name spoofing: display name contains an email-like pattern
	displayName := extractDisplayName(email.From)
	if displayName != "" && strings.Contains(displayName, "@") {
		result.DisplayNameSpoofing = true
		details = append(details, "Display name contains email address: "+displayName)
	}

	if len(details) > 0 {
		result.Details = strings.Join(details, "; ")
	}

	return result
}

func extractDomain(addr string) string {
	// Handle "Name <user@domain>" format
	if idx := strings.LastIndex(addr, "<"); idx >= 0 {
		addr = addr[idx+1:]
		addr = strings.TrimRight(addr, ">")
	}
	addr = strings.TrimSpace(addr)
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return strings.ToLower(addr[at+1:])
	}
	return ""
}

func extractDisplayName(from string) string {
	if idx := strings.Index(from, "<"); idx > 0 {
		return strings.TrimSpace(from[:idx])
	}
	return ""
}

// domainsRelated returns true if two domains are the same or one is a
// subdomain of the other. This handles legitimate cases like
// bounce.mag.subaru.jp (Return-Path) matching mag.subaru.jp (From).
func domainsRelated(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	if a == b {
		return true
	}
	// a is subdomain of b, or b is subdomain of a
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}
