package indicator

import (
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
	"github.com/nlink-jp/mailparse"
	"golang.org/x/net/publicsuffix"
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

	// Display name spoofing: a display name that contains an email-like
	// pattern, or that is a domain of another organization than the address.
	for _, mb := range email.FromMailboxes {
		if strings.Contains(mb.Name, "@") {
			result.DisplayNameSpoofing = true
			details = append(details, "Display name contains email address: "+mb.Name)
			break
		}
		if shown := domainInDisplayName(mb.Name); shown != "" {
			if actual := extractDomain(mb.Address); actual != "" && registrableDomain(shown) != registrableDomain(actual) {
				result.DisplayNameSpoofing = true
				details = append(details, "Display name is a domain ("+shown+") of another organization than the address domain ("+actual+")")
				break
			}
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

// domainInDisplayName returns the lower-cased domain when the whole display
// name is one, and "" otherwise. What counts as a domain is decided by the
// Public Suffix List, so a name that merely has a dot in it (Node.js,
// Taro.Yamada) is not one, and neither is a bare suffix (co.jp, github.io).
func domainInDisplayName(name string) string {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !isHostname(d) {
		return ""
	}
	suffix, icann := publicsuffix.PublicSuffix(d)
	// Neither ICANN-managed nor a dotted private suffix: the list's default
	// rule answered, so the suffix is not a known one.
	if !icann && !strings.Contains(suffix, ".") {
		return ""
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(d); err != nil {
		return ""
	}
	return d
}

// isHostname reports whether s is at least two labels of ASCII letters, digits
// and hyphens, within the length limits of RFC 1035.
func isHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// registrableDomain returns the part of d that one organization registers
// (mail.example.co.jp → example.co.jp), or d itself when it has none.
func registrableDomain(d string) string {
	if r, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return r
	}
	return d
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
