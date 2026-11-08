package indicator

import (
	"strings"
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
	"github.com/nlink-jp/mailparse"
)

func TestAnalyzeAuth(t *testing.T) {
	tests := []struct {
		name            string
		fields          []string
		wantSPF         string
		wantDKIM        string
		wantDMARC       string
		wantConflicting bool
	}{
		{"all pass", []string{"spf=pass dkim=pass dmarc=pass"}, "pass", "pass", "pass", false},
		{"all fail", []string{"spf=fail dkim=fail dmarc=fail"}, "fail", "fail", "fail", false},
		{"empty", nil, "none", "none", "none", false},
		{"mixed", []string{"spf=softfail dkim=pass dmarc=none"}, "softfail", "pass", "none", false},
		{"with details", []string{"mx.google.com; spf=pass (sender ok); dkim=pass"}, "pass", "pass", "none", false},
		// The top field (the receiving server's own) decides; a lower field
		// that disagrees, as after forwarding or a forged field, only raises
		// the flag.
		{"forwarded", []string{"mx.example.com; spf=fail dkim=pass dmarc=pass", "first.example.net; spf=pass dkim=pass dmarc=pass"}, "fail", "pass", "pass", true},
		{"forged below", []string{"mx.example.com; spf=fail dkim=none dmarc=fail", "forged.example; spf=pass dkim=pass dmarc=pass"}, "fail", "none", "fail", true},
		// Fields that agree, or that speak of mechanisms the other does not, do not conflict.
		{"agree", []string{"a.example; spf=pass", "b.example; spf=pass dkim=pass"}, "pass", "none", "none", false},
		{"lower speaks of more", []string{"a.example; arc=none", "b.example; spf=pass"}, "none", "none", "none", false},
		// Within one field the first result counts, as before.
		{"two signatures in one field", []string{"mx.example.com; dkim=pass header.d=a.example; dkim=fail header.d=b.example"}, "none", "pass", "none", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzeAuth(tt.fields)
			if result.SPF != tt.wantSPF || result.DKIM != tt.wantDKIM || result.DMARC != tt.wantDMARC || result.Conflicting != tt.wantConflicting {
				t.Errorf("got %+v, want spf=%s dkim=%s dmarc=%s conflicting=%v", result, tt.wantSPF, tt.wantDKIM, tt.wantDMARC, tt.wantConflicting)
			}
			if len(result.Raw) != len(tt.fields) {
				t.Errorf("Raw = %q", result.Raw)
			}
		})
	}
}

func mbs(list ...string) []mailparse.Mailbox {
	var out []mailparse.Mailbox
	for _, s := range list {
		name, addr := "", s
		if i := strings.LastIndex(s, "|"); i >= 0 {
			name, addr = s[:i], s[i+1:]
		}
		out = append(out, mailparse.Mailbox{Name: name, Address: addr})
	}
	return out
}

func TestAnalyzeSender(t *testing.T) {
	tests := []struct {
		name           string
		from           []string // "name|address" or "address"
		returnPath     []string
		replyTo        []string
		wantMismatch   bool
		wantSpoofing   bool
		wantDivergence bool
	}{
		{"clean", []string{"alice@example.com"}, []string{"alice@example.com"}, nil, false, false, false},
		{"mismatch", []string{"alice@example.com"}, []string{"bounce@other.example"}, nil, true, false, false},
		{"spoofing", []string{"admin@bank.example|hacker@evil.example"}, nil, nil, false, true, false},
		{"reply-to divergence", []string{"alice@example.com"}, nil, []string{"hacker@evil.example"}, false, false, true},
		{"subdomain bounce OK", []string{"news@mag.example.jp"}, []string{"bounce@bounce.mag.example.jp"}, nil, false, false, false},
		{"subdomain unrelated", []string{"info@example.co.jp"}, []string{"bounce@unrelated.example"}, nil, true, false, false},
		// A second From that matches the Return-Path cannot hide the first.
		{"second from cannot hide", []string{"ceo@example.com", "x@evil.example"}, []string{"x@evil.example"}, nil, true, false, false},
		// A second Reply-To that matches From cannot hide the first.
		{"second reply-to cannot hide", []string{"alice@example.com"}, nil, []string{"alice@example.com", "x@evil.example"}, false, false, true},
		// A name-only mailbox has no domain to compare.
		{"name only", []string{"Someone|"}, []string{"bounce@other.example"}, nil, false, false, false},

		// A display name that is a domain of another organization.
		{"domain name, other address", []string{"shop.example.jp|random@unrelated.example"}, nil, nil, false, true, false},
		{"domain name, case and trailing dot", []string{" Shop.Example.JP. |random@unrelated.example"}, nil, nil, false, true, false},
		{"second from cannot hide domain name", []string{"a@example.jp", "shop.example.jp|x@unrelated.example"}, nil, nil, false, true, false},
		{"private suffix, other tenant", []string{"a.github.io|x@b.github.io"}, nil, nil, false, true, false},
		// The same organization, whichever side has the subdomain.
		{"domain name, same domain", []string{"example.jp|info@example.jp"}, nil, nil, false, false, false},
		{"domain name, address below", []string{"example.jp|info@mail.example.jp"}, nil, nil, false, false, false},
		{"domain name, address above", []string{"shop.example.jp|info@example.jp"}, nil, nil, false, false, false},
		{"domain name, sibling subdomain", []string{"shop.example.jp|info@mail.example.jp"}, nil, nil, false, false, false},
		{"second-level suffix, same domain", []string{"Amazon.co.jp|x@mail.amazon.co.jp"}, nil, nil, false, false, false},
		// Not a domain: no known suffix, a bare suffix, or more than a domain.
		{"unknown suffix", []string{"Node.js|x@unrelated.example"}, nil, nil, false, false, false},
		{"person name with dot", []string{"Taro.Yamada|x@unrelated.example"}, nil, nil, false, false, false},
		{"version number", []string{"1.2.3|x@unrelated.example"}, nil, nil, false, false, false},
		{"bare ICANN suffix", []string{"co.jp|x@unrelated.example"}, nil, nil, false, false, false},
		{"bare private suffix", []string{"github.io|x@unrelated.example"}, nil, nil, false, false, false},
		{"domain among words", []string{"shop.example.jp support|x@unrelated.example"}, nil, nil, false, false, false},
		{"single label", []string{"Shop|x@unrelated.example"}, nil, nil, false, false, false},
		{"empty label", []string{"shop..example.jp|x@unrelated.example"}, nil, nil, false, false, false},
		{"leading hyphen", []string{"-shop.example.jp|x@unrelated.example"}, nil, nil, false, false, false},
		{"space inside a label", []string{"Example Shop.jp|x@unrelated.example"}, nil, nil, false, false, false},
		// Without an address there is nothing to compare the name to.
		{"domain name, no address", []string{"shop.example.jp|"}, nil, nil, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &parser.Email{
				FromMailboxes:       mbs(tt.from...),
				ReturnPathMailboxes: mbs(tt.returnPath...),
				ReplyToMailboxes:    mbs(tt.replyTo...),
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

// URLs in nested messages and text/* attachments are found and labelled; a
// URL already found in the outer body keeps the outer label.
func TestAnalyzeURLsLayers(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{{Type: "text/plain", Content: "see https://shared.example.com/a"}},
		Texts: []parser.Text{
			{Layer: "3", Content: "https://shared.example.com/a and https://bit.ly/x"},
			{Attachment: "invite.ics", Content: "URL:https://join.example.net/m"},
		},
	}
	results := analyzeURLs(email)
	if len(results) != 3 {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Layer != "" || results[1].Layer != "3" || !results[1].Suspicious || results[2].Attachment != "invite.ics" {
		t.Fatalf("results = %+v", results)
	}
}

func TestAnalyzeAttachmentsLayer(t *testing.T) {
	email := &parser.Email{Attachments: []parser.Attachment{{Filename: "payload.exe", Layer: "2>1"}}}
	results := analyzeAttachments(email)
	if len(results) != 1 || !results[0].Suspicious || results[0].Layer != "2>1" {
		t.Fatalf("results = %+v", results)
	}
}

func TestWarningCodes(t *testing.T) {
	email := &parser.Email{Warnings: []mailparse.Warning{
		{Code: "duplicate_field"}, {Code: "invalid_address"}, {Code: "duplicate_field"},
	}}
	codes := Analyze(email).WarningCodes
	if strings.Join(codes, ",") != "duplicate_field,invalid_address" {
		t.Fatalf("codes = %q", codes)
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

func TestWhere(t *testing.T) {
	if (URLResult{}).Where() != "" || (URLResult{Layer: "2>1", Attachment: "a.ics"}).Where() != `in attached message 2>1, in text attachment "a.ics"` || (AttachResult{Layer: "2"}).Where() != "in attached message 2" {
		t.Fatal("Where")
	}
}

func TestPromptAuthResults(t *testing.T) {
	raw := make([]string, 12)
	for i := range raw {
		raw[i] = "spf=pass"
	}
	raw[0] = strings.Repeat("あ", 400)
	got := PromptAuthResults(raw)
	if len(got) != 11 || got[10] != "(2 more not shown)" || got[0] != strings.Repeat("あ", 300)+"..." {
		t.Fatalf("got %d %q", len(got), got[10])
	}
}
