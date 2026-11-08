package analyzer

import (
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestAnalyzeOfflineSafe(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/simple.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	if result.Judgment.IsSuspicious {
		t.Error("simple email should not be suspicious")
	}
	if result.Judgment.Category != "safe" {
		t.Errorf("Category = %q, want 'safe'", result.Judgment.Category)
	}
	if result.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

func TestAnalyzeOfflineSuspicious(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/suspicious.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	if !result.Judgment.IsSuspicious {
		t.Error("suspicious email should be detected")
	}
	if len(result.Judgment.Reasons) == 0 {
		t.Error("should have at least one reason")
	}
	if result.Indicators == nil {
		t.Error("Indicators should not be nil")
	}
	if result.Indicators.Authentication.SPF != "fail" {
		t.Errorf("SPF = %q, want 'fail'", result.Indicators.Authentication.SPF)
	}
}

// A display name that is another organization's domain is flagged even when
// the sender's own domain passes every authentication check.
func TestAnalyzeOfflineDomainInDisplayName(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/display-name-domain.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	if a := result.Indicators.Authentication; a.SPF != "pass" || a.DKIM != "pass" || a.DMARC != "pass" {
		t.Fatalf("authentication = %+v, want all pass", a)
	}
	if !result.Indicators.Sender.DisplayNameSpoofing {
		t.Errorf("DisplayNameSpoofing = false, details %q", result.Indicators.Sender.Details)
	}
	if !result.Judgment.IsSuspicious || result.Judgment.Category != "phishing" || result.Judgment.Confidence != 0.25 {
		t.Errorf("Judgment = %+v, want suspicious phishing at 0.25", result.Judgment)
	}
}

func TestAnalyzeOfflineWithAttachment(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/attachment.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	// Clean PDF attachment should not be suspicious
	if result.Judgment.IsSuspicious {
		t.Error("email with clean PDF should not be suspicious")
	}
}

// The verdicts come from the top Authentication-Results (the receiving
// server's own); a forged one below only raises the conflicting flag, and the
// parser's warnings reach the result.
func TestAnalyzeOfflineForgedAuthResults(t *testing.T) {
	raw := "Authentication-Results: mx.example.com; spf=fail dkim=none dmarc=fail\r\n" +
		"Return-Path: <x@evil.example>\r\n" +
		"Authentication-Results: forged.example; spf=pass dkim=pass dmarc=pass\r\n" +
		"From: CEO <ceo@example.com>\r\nFrom: x@evil.example\r\nTo: a@example.com\r\nSubject: pay\r\nMessage-ID: <1@evil.example>\r\n\r\nwire money\r\n"
	email, err := parser.ParseBytes([]byte(raw), "t.eml")
	if err != nil {
		t.Fatal(err)
	}
	result := AnalyzeOffline(email)
	auth := result.Indicators.Authentication
	if !auth.Conflicting || auth.SPF != "fail" || auth.DMARC != "fail" || len(auth.Raw) != 2 {
		t.Fatalf("auth = %+v", auth)
	}
	if !result.Indicators.Sender.FromReturnPathMismatch || !result.Judgment.IsSuspicious {
		t.Fatalf("result = %+v", result.Judgment)
	}
	if len(result.Warnings) == 0 || result.Warnings[0].Code != "duplicate_field" {
		t.Fatalf("warnings = %+v", result.Warnings)
	}
}

// warnings is always an array in the JSON, never null.
func TestWarningsAlwaysArray(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	if AnalyzeOffline(email).Warnings == nil {
		t.Fatal("Warnings is nil")
	}
}
