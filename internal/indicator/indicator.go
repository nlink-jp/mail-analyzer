// Package indicator provides rule-based email analysis.
// These checks are deterministic and do not require LLM.
package indicator

import (
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// Indicators holds all rule-based analysis results.
type Indicators struct {
	Authentication AuthResult    `json:"authentication"`
	Sender         SenderResult  `json:"sender"`
	URLs           []URLResult   `json:"urls"`
	Attachments    []AttachResult `json:"attachments"`
	Routing        RoutingResult `json:"routing"`
}

// Analyze runs all rule-based indicators on the parsed email.
func Analyze(email *parser.Email) *Indicators {
	return &Indicators{
		Authentication: analyzeAuth(email.AuthResults),
		Sender:         analyzeSender(email),
		URLs:           analyzeURLs(email),
		Attachments:    analyzeAttachments(email),
		Routing:        analyzeRouting(email),
	}
}
