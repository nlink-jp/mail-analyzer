// Package indicator provides rule-based email analysis.
// These checks are deterministic and do not require LLM.
package indicator

import (
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// Indicators holds all rule-based analysis results.
type Indicators struct {
	Authentication AuthResult     `json:"authentication"`
	Sender         SenderResult   `json:"sender"`
	URLs           []URLResult    `json:"urls"`
	Attachments    []AttachResult `json:"attachments"`
	Routing        RoutingResult  `json:"routing"`
}

// Analyze runs all rule-based indicators on the parsed email.
func Analyze(email *parser.Email) *Indicators {
	return &Indicators{
		Authentication: analyzeAuthAll(authFields(email)),
		Sender:         analyzeSender(email),
		URLs:           analyzeURLs(email),
		Attachments:    analyzeAttachments(email),
		Routing:        analyzeRouting(email),
	}
}

// authFields returns every Authentication-Results field the parser read, or the
// single AuthResults string of an Email built by hand.
func authFields(email *parser.Email) []string {
	if len(email.AllAuthResults) > 0 {
		return email.AllAuthResults
	}
	return []string{email.AuthResults}
}

// walkMessages calls fn for email and every message nested in it, with the
// path of the attachment that held it ("" for the top message, "2>1" for a
// message inside the message attached as part 2).
func walkMessages(email *parser.Email, fn func(m *parser.Email, in string)) {
	var walk func(m *parser.Email, in string)
	walk = func(m *parser.Email, in string) {
		fn(m, in)
		for _, n := range m.Nested {
			p := n.Part
			if in != "" {
				p = in + ">" + p
			}
			walk(n, p)
		}
	}
	walk(email, "")
}
