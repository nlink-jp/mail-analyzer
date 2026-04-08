// Package analyzer provides composite email analysis combining
// rule-based indicators and LLM judgment.
package analyzer

import (
	"context"
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/config"
	"github.com/nlink-jp/mail-analyzer/internal/indicator"
	"github.com/nlink-jp/mail-analyzer/internal/llm"
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// Result is the complete analysis output.
type Result struct {
	SourceFile string                `json:"source_file"`
	Hash       string                `json:"hash"`
	MessageID  string                `json:"message_id,omitempty"`
	Subject    string                `json:"subject"`
	From       string                `json:"from"`
	To         []string              `json:"to"`
	Date       string                `json:"date"`
	Indicators *indicator.Indicators `json:"indicators"`
	Judgment   *llm.Judgment         `json:"judgment"`
}

// Analyze performs complete email analysis: parse → indicators → LLM → result.
func Analyze(ctx context.Context, email *parser.Email, cfg *config.Config) (*Result, error) {
	// 1. Rule-based indicators
	indicators := indicator.Analyze(email)

	// 2. Build prompts
	systemPrompt := llm.BuildSystemPrompt(cfg.Lang)
	userPrompt := llm.BuildUserPrompt(email, indicators)

	// 3. LLM analysis
	judgment, err := llm.Analyze(ctx, cfg, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	// 4. Assemble result
	return &Result{
		SourceFile: email.Source,
		Hash:       email.Hash,
		MessageID:  email.MessageID,
		Subject:    email.Subject,
		From:       email.From,
		To:         email.To,
		Date:       email.Date,
		Indicators: indicators,
		Judgment:   judgment,
	}, nil
}

// AnalyzeOffline performs analysis without LLM (indicators only).
func AnalyzeOffline(email *parser.Email) *Result {
	indicators := indicator.Analyze(email)

	// Heuristic judgment based on indicators alone.
	//
	// SPF/DMARC fail alone is NOT a strong signal — email forwarding and
	// mailing list relays commonly break SPF alignment. These are only
	// counted as supporting evidence when combined with other indicators
	// (e.g., From/Return-Path mismatch, suspicious URLs, dangerous attachments).
	var strongReasons []string
	var weakReasons []string
	category := "safe"

	// Strong signals (each sufficient to flag)
	if indicators.Sender.FromReturnPathMismatch {
		strongReasons = append(strongReasons, "From/Return-Path domain mismatch")
	}
	if indicators.Sender.DisplayNameSpoofing {
		strongReasons = append(strongReasons, "Display name spoofing detected")
	}
	if indicators.Sender.ReplyToDivergence {
		strongReasons = append(strongReasons, "Reply-To domain differs from From domain")
	}
	for _, a := range indicators.Attachments {
		if a.Suspicious {
			strongReasons = append(strongReasons, "Suspicious attachment: "+a.Filename)
		}
	}
	for _, u := range indicators.URLs {
		if u.Suspicious {
			strongReasons = append(strongReasons, "Suspicious URL: "+u.URL)
		}
	}
	if indicators.Routing.XMailerSuspicious {
		strongReasons = append(strongReasons, "Suspicious X-Mailer: "+indicators.Routing.XMailer)
	}
	for _, hop := range indicators.Routing.SuspiciousHops {
		weakReasons = append(weakReasons, "Suspicious routing: "+hop)
	}

	// Weak signals (only count when combined with strong signals)
	if indicators.Authentication.SPF == "fail" {
		weakReasons = append(weakReasons, "SPF authentication failed")
	}
	if indicators.Authentication.DMARC == "fail" {
		weakReasons = append(weakReasons, "DMARC authentication failed")
	}

	// Combine: suspicious only if at least one strong signal exists
	suspicious := len(strongReasons) > 0
	var reasons []string
	reasons = append(reasons, strongReasons...)
	if suspicious {
		// Weak signals are supporting evidence only when strong signals exist
		reasons = append(reasons, weakReasons...)
	}

	if suspicious {
		category = "phishing"
		for _, a := range indicators.Attachments {
			if a.Suspicious {
				category = "malware-delivery"
				break
			}
		}
	}

	confidence := 0.0
	if suspicious {
		confidence = float64(len(strongReasons)) * 0.25
		if len(weakReasons) > 0 {
			confidence += 0.1 // Small boost for supporting evidence
		}
		if confidence > 0.8 {
			confidence = 0.8 // Cap without LLM confirmation
		}
	}

	return &Result{
		SourceFile: email.Source,
		Hash:       email.Hash,
		MessageID:  email.MessageID,
		Subject:    email.Subject,
		From:       email.From,
		To:         email.To,
		Date:       email.Date,
		Indicators: indicators,
		Judgment: &llm.Judgment{
			IsSuspicious: suspicious,
			Category:     category,
			Confidence:   confidence,
			Summary:      "Offline analysis (indicators only, no LLM): " + strings.Join(reasons, "; "),
			Reasons:      reasons,
		},
	}
}
