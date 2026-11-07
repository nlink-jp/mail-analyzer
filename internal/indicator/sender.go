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

// analyzeSender compares every From mailbox (of every From field) with every
// Return-Path and Reply-To address, and looks for an address in each display
// name. With one From, one Return-Path and one Reply-To this is the original
// one-to-one comparison.
func analyzeSender(email *parser.Email) SenderResult {
	result := SenderResult{}
	var details []string

	froms := fromMailboxes(email)
	fromDomains := domainsOf(froms)
	returnPathDomains := returnPathDomains(email)
	replyToDomains := domainsOf(replyToMailboxes(email))

	// From vs Return-Path domain mismatch.
	// Allow subdomain relationships (e.g., bounce.mag.subaru.jp matches mag.subaru.jp)
	// since legitimate senders often use subdomains for bounce handling.
mismatch:
	for _, fd := range fromDomains {
		for _, rd := range returnPathDomains {
			if !domainsRelated(fd, rd) {
				result.FromReturnPathMismatch = true
				details = append(details, "From domain ("+fd+") differs from Return-Path domain ("+rd+")")
				break mismatch
			}
		}
	}

	// Reply-To divergence: a Reply-To domain that is none of the From domains.
	if len(fromDomains) > 0 {
		for _, rd := range replyToDomains {
			if !containsFold(fromDomains, rd) {
				result.ReplyToDivergence = true
				details = append(details, "Reply-To domain ("+rd+") differs from From domain ("+fromDomains[0]+")")
				break
			}
		}
	}

	// Display name spoofing: a display name contains an email-like pattern.
	for _, mb := range froms {
		if mb.Name != "" && strings.Contains(mb.Name, "@") {
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

// fromMailboxes returns every From mailbox the parser read, or, for an Email
// built by hand with only the From string, one mailbox read from it.
func fromMailboxes(email *parser.Email) []parser.Mailbox {
	if len(email.FromFields) > 0 {
		var out []parser.Mailbox
		for _, f := range email.FromFields {
			out = append(out, f...)
		}
		return out
	}
	if email.From == "" {
		return nil
	}
	return []parser.Mailbox{{Name: extractDisplayName(email.From), Address: extractAddress(email.From)}}
}

func replyToMailboxes(email *parser.Email) []parser.Mailbox {
	if len(email.ReplyToMailboxes) > 0 {
		return email.ReplyToMailboxes
	}
	if email.ReplyTo == "" {
		return nil
	}
	return []parser.Mailbox{{Address: extractAddress(email.ReplyTo)}}
}

func returnPathDomains(email *parser.Email) []string {
	addrs := email.ReturnPaths
	if len(addrs) == 0 && email.ReturnPath != "" {
		addrs = []string{extractAddress(email.ReturnPath)}
	}
	var out []string
	for _, a := range addrs {
		if d := extractDomain(a); d != "" && !containsFold(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func domainsOf(mbs []parser.Mailbox) []string {
	var out []string
	for _, mb := range mbs {
		if d := extractDomain(mb.Address); d != "" && !containsFold(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// extractAddress reads the address out of "Name <user@domain>" or a bare
// address.
func extractAddress(addr string) string {
	if idx := strings.LastIndex(addr, "<"); idx >= 0 {
		addr = addr[idx+1:]
		addr = strings.TrimRight(addr, ">")
	}
	return strings.TrimSpace(addr)
}

func extractDomain(addr string) string {
	addr = extractAddress(addr)
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
