package indicator

import (
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestAnalyzeAuth(t *testing.T) {
	tests := []struct {
		name        string
		authResults string
		wantSPF     string
		wantDKIM    string
		wantDMARC   string
	}{
		{"all pass", "spf=pass dkim=pass dmarc=pass", "pass", "pass", "pass"},
		{"all fail", "spf=fail dkim=fail dmarc=fail", "fail", "fail", "fail"},
		{"empty", "", "none", "none", "none"},
		{"mixed", "spf=softfail dkim=pass dmarc=none", "softfail", "pass", "none"},
		{"with details", "mx.google.com; spf=pass (sender ok); dkim=pass", "pass", "pass", "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzeAuth(tt.authResults)
			if result.SPF != tt.wantSPF {
				t.Errorf("SPF = %q, want %q", result.SPF, tt.wantSPF)
			}
			if result.DKIM != tt.wantDKIM {
				t.Errorf("DKIM = %q, want %q", result.DKIM, tt.wantDKIM)
			}
			if result.DMARC != tt.wantDMARC {
				t.Errorf("DMARC = %q, want %q", result.DMARC, tt.wantDMARC)
			}
		})
	}
}

func TestAnalyzeSender(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		returnPath     string
		replyTo        string
		wantMismatch   bool
		wantSpoofing   bool
		wantDivergence bool
	}{
		{"clean", "alice@example.com", "<alice@example.com>", "", false, false, false},
		{"mismatch", "alice@example.com", "<bounce@other.com>", "", true, false, false},
		{"spoofing", "admin@bank.com <hacker@evil.com>", "", "", false, true, false},
		{"reply-to divergence", "alice@example.com", "", "hacker@evil.com", false, false, true},
		{"subdomain bounce OK", "news@mag.subaru.jp", "<bounce@bounce.mag.subaru.jp>", "", false, false, false},
		{"subdomain unrelated", "info@sbisec.co.jp", "<bounce@zh-net-jingjibao.com>", "", true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &parser.Email{
				From:       tt.from,
				ReturnPath: tt.returnPath,
				ReplyTo:    tt.replyTo,
			}
			result := analyzeSender(email)
			if result.FromReturnPathMismatch != tt.wantMismatch {
				t.Errorf("FromReturnPathMismatch = %v, want %v", result.FromReturnPathMismatch, tt.wantMismatch)
			}
			if result.DisplayNameSpoofing != tt.wantSpoofing {
				t.Errorf("DisplayNameSpoofing = %v, want %v", result.DisplayNameSpoofing, tt.wantSpoofing)
			}
			if result.ReplyToDivergence != tt.wantDivergence {
				t.Errorf("ReplyToDivergence = %v, want %v", result.ReplyToDivergence, tt.wantDivergence)
			}
		})
	}
}

func TestAnalyzeURLs(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{
			{Type: "text/html", Content: `<a href="https://bit.ly/fake">Click</a> Visit https://example.com for info`},
		},
	}

	results := analyzeURLs(email)
	if len(results) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(results))
	}

	// bit.ly should be flagged
	var bitlyFound bool
	for _, r := range results {
		if r.Suspicious && r.Reason == "URL shortener" {
			bitlyFound = true
		}
		// URLs should be defanged
		if r.URL == "https://bit.ly/fake" {
			t.Error("URL should be defanged")
		}
	}
	if !bitlyFound {
		t.Error("bit.ly URL should be flagged as suspicious")
	}
}

func TestAnalyzeURLsAzureBlob(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{
			{Type: "text/html", Content: `<a href="https://fofolalod.z43.web.core.windows.net/">Click</a>`},
		},
	}
	results := analyzeURLs(email)
	if len(results) != 1 {
		t.Fatalf("expected 1 URL, got %d", len(results))
	}
	if !results[0].Suspicious {
		t.Error("Azure Blob Storage URL should be suspicious")
	}
}

func TestAnalyzeURLsSuspiciousTLD(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{
			{Type: "text/html", Content: `<a href="https://www.osteoinduction.cfd/path">Click</a>`},
		},
	}
	results := analyzeURLs(email)
	if len(results) != 1 {
		t.Fatalf("expected 1 URL, got %d", len(results))
	}
	if !results[0].Suspicious {
		t.Error(".cfd TLD should be suspicious")
	}
	if results[0].Reason != "suspicious TLD" {
		t.Errorf("Reason = %q, want 'suspicious TLD'", results[0].Reason)
	}
}

func TestAnalyzeURLsSkipsSchemaRefs(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{
			{Type: "text/html", Content: `xmlns="http://schemas.microsoft.com/office/2004/12/omml"`},
		},
	}
	results := analyzeURLs(email)
	if len(results) != 0 {
		t.Errorf("schema references should be skipped, got %d URLs", len(results))
	}
}

func TestDefangURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"https://evil.com/path", "hxxps://evil[.]com/path"},
		{"http://test.example.com", "hxxp://test[.]example[.]com"},
		{"https://safe.org", "hxxps://safe[.]org"},
	}

	for _, tt := range tests {
		got := defangURL(tt.input)
		if got != tt.want {
			t.Errorf("defangURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAnalyzeAttachments(t *testing.T) {
	email := &parser.Email{
		Attachments: []parser.Attachment{
			{Filename: "report.pdf", MIMEType: "application/pdf", Size: 1024},
			{Filename: "update.exe", MIMEType: "application/octet-stream", Size: 2048},
			{Filename: "budget.xlsm", MIMEType: "application/vnd.ms-excel", Size: 4096},
			{Filename: "invoice.pdf.exe", MIMEType: "application/octet-stream", Size: 2048},
		},
	}

	results := analyzeAttachments(email)
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// PDF should be clean
	if results[0].Suspicious {
		t.Error("PDF should not be suspicious")
	}
	// EXE should be flagged
	if !results[1].Suspicious {
		t.Error("EXE should be suspicious")
	}
	// XLSM should be flagged (macro)
	if !results[2].Suspicious {
		t.Error("XLSM should be suspicious")
	}
	// Double extension should be flagged
	if !results[3].Suspicious {
		t.Error("double extension should be suspicious")
	}
}

func TestAnalyzeRouting(t *testing.T) {
	email := &parser.Email{
		Received: []string{"from a", "from b", "from c"},
	}
	result := analyzeRouting(email)
	if result.HopCount != 3 {
		t.Errorf("HopCount = %d, want 3", result.HopCount)
	}
}

func TestAnalyzeRoutingXMailer(t *testing.T) {
	tests := []struct {
		name       string
		xmailer    string
		suspicious bool
	}{
		{"PHPMailer", "PHPMailer 6.8.0", true},
		{"Outlook", "Microsoft Outlook 16.0", false},
		{"empty", "", false},
		{"SwiftMailer", "SwiftMailer 5.0", true},
		{"Thunderbird", "Mozilla Thunderbird 102.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &parser.Email{XMailer: tt.xmailer}
			result := analyzeRouting(email)
			if result.XMailerSuspicious != tt.suspicious {
				t.Errorf("XMailerSuspicious = %v, want %v", result.XMailerSuspicious, tt.suspicious)
			}
		})
	}
}

func TestAnalyzeRoutingSuspiciousHops(t *testing.T) {
	email := &parser.Email{
		Received: []string{
			"from localhost (localhost [127.0.0.1]) by mail.example.com",
			"from mx.google.com by another.example.com",
			"from unknown (HELO [10.0.0.1]) by relay.example.com",
		},
	}
	result := analyzeRouting(email)
	if len(result.SuspiciousHops) == 0 {
		t.Error("expected suspicious hops for localhost/unknown origin")
	}
}

func TestFullIndicatorAnalysis(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/suspicious.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	indicators := Analyze(email)

	if indicators.Authentication.SPF != "fail" {
		t.Errorf("SPF = %q, want 'fail'", indicators.Authentication.SPF)
	}
	if !indicators.Sender.FromReturnPathMismatch {
		t.Error("expected From/Return-Path mismatch")
	}
	if !indicators.Sender.ReplyToDivergence {
		t.Error("expected Reply-To divergence")
	}

	// Should have suspicious URL (bit.ly)
	var hasSuspiciousURL bool
	for _, u := range indicators.URLs {
		if u.Suspicious {
			hasSuspiciousURL = true
		}
	}
	if !hasSuspiciousURL {
		t.Error("expected suspicious URL in indicators")
	}
}
