package indicator

import (
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
	"github.com/nlink-jp/mailparse"
)

// SenderResult holds sender integrity analysis.
type SenderResult struct {
	FromReturnPathMismatch bool   `json:"from_return_path_mismatch"`
	DisplayNameSpoofing    bool   `json:"display_name_spoofing"`
	ReplyToDivergence      bool   `json:"reply_to_divergence"`
	Details                string `json:"details,omitempty"`
}

// analyzeSender compares every From, Return-Path and Reply-To mailbox. Each
// check fires when any one combination fires, so adding a mailbox can raise a
// flag but never clear one: a second From cannot hide the first.
func analyzeSender(email *parser.Email) SenderResult {
	result := SenderResult{}
	var details []string

	fromDomains := domains(email.FromMailboxes)
	returnPathDomains := domains(email.ReturnPathMailboxes)
	replyToDomains := domains(email.ReplyToMailboxes)

	// From vs Return-Path domain mismatch.
	// Allow subdomain relationships (e.g., bounce.mag.subaru.jp matches mag.subaru.jp)
	// since legitimate senders often use subdomains for bounce handling.
mismatch:
	for _, f := range fromDomains {
		for _, r := range returnPathDomains {
			if !domainsRelated(f, r) {
				result.FromReturnPathMismatch = true
				details = append(details, "From domain ("+f+") differs from Return-Path domain ("+r+")")
				break mismatch
			}
		}
	}

	// Reply-To divergence: a Reply-To domain that is no From domain.
	if len(fromDomains) > 0 {
		for _, r := range replyToDomains {
			if !containsFold(fromDomains, r) {
				result.ReplyToDivergence = true
				details = append(details, "Reply-To domain ("+r+") differs from From domain ("+strings.Join(fromDomains, ", ")+")")
				break
			}
		}
	}

	// Display name spoofing: a display name that contains an email-like pattern.
	for _, mb := range email.FromMailboxes {
		if strings.Contains(mb.Name, "@") {
			result.DisplayNameSpoofing = true
			details = append(details, "Display name contains email address: "+mb.Name)
			break
		}
	}

	if len(details) > 0 {
		result.Details = strings.Join(details, "; ")
	}

	return result
}

// domains returns the lower-cased domain of every mailbox that has an address.
func domains(mbs []mailparse.Mailbox) []string {
	var out []string
	for _, mb := range mbs {
		if d := extractDomain(mb.Address); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func extractDomain(addr string) string {
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return strings.ToLower(strings.TrimSpace(addr[at+1:]))
	}
	return ""
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
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
