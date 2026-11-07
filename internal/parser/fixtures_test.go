package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The fixtures pin defects of the in-house parser (v0.4.0 and earlier) that
// reading through mailparse fixed; testdata/fixtures/README.md lists them.

const fixtures = "../../testdata/fixtures/"

func parseFixture(t *testing.T, name string) *Email {
	t.Helper()
	e, err := ParseFile(fixtures + name)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", name, err)
	}
	return e
}

func hasWarning(e *Email, code string) bool {
	for _, w := range e.AllWarnings() {
		if w.Code == code {
			return true
		}
	}
	return false
}

func TestForwardedRFC822IsOpened(t *testing.T) {
	e := parseFixture(t, "04-forwarded-rfc822.eml")
	if len(e.Nested) != 1 {
		t.Fatalf("Nested = %d, want 1", len(e.Nested))
	}
	n := e.Nested[0]
	if n.Subject != "Account verification" {
		t.Errorf("nested Subject = %q", n.Subject)
	}
	if n.Part == "" {
		t.Error("nested Part should name the attachment that held it")
	}
	if !strings.Contains(n.HTMLBody(), "login.phish.example") {
		t.Error("nested HTML body should be read")
	}
	if len(n.Attachments) != 1 || n.Attachments[0].Filename != "invoice.zip" {
		t.Errorf("nested attachments = %+v", n.Attachments)
	}
	// The forwarded message itself is still an attachment of the outer one.
	if len(e.Attachments) != 1 || e.Attachments[0].Hash == "" {
		t.Errorf("outer attachments = %+v", e.Attachments)
	}
}

func TestForwardedOctetStreamIsRecognized(t *testing.T) {
	e := parseFixture(t, "05-forwarded-octet-stream.eml")
	if len(e.Nested) != 1 {
		t.Fatalf("Nested = %d, want 1 (a message attached as application/octet-stream)", len(e.Nested))
	}
	if !strings.Contains(e.Nested[0].From, "support@phish.example") {
		t.Errorf("nested From = %q", e.Nested[0].From)
	}
}

func TestUnclosedBoundaryKeepsSecondPart(t *testing.T) {
	e := parseFixture(t, "06-unclosed-boundary.eml")
	body := e.PlainTextBody()
	if !strings.Contains(body, "first part") || !strings.Contains(body, "second part") {
		t.Errorf("body = %q, want both parts", body)
	}
	if !hasWarning(e, "unclosed_boundary") {
		t.Error("expected an unclosed_boundary warning")
	}
}

func TestDuplicateHeadersAreAllRead(t *testing.T) {
	e := parseFixture(t, "07-duplicate-headers.eml")
	if len(e.FromFields) != 2 {
		t.Fatalf("FromFields = %d, want 2", len(e.FromFields))
	}
	if len(e.FromFields[1]) != 2 || e.FromFields[1][1].Address != "attacker@phish.example" {
		t.Errorf("second From = %+v", e.FromFields[1])
	}
	// From (the display string) stays the first field, as before.
	if e.From != "ceo@example.org" {
		t.Errorf("From = %q", e.From)
	}
	if len(e.AllAuthResults) != 2 || !strings.Contains(e.AllAuthResults[1], "spf=fail") {
		t.Errorf("AllAuthResults = %q", e.AllAuthResults)
	}
	if !strings.Contains(e.AuthResults, "spf=pass") {
		t.Errorf("AuthResults (first field) = %q", e.AuthResults)
	}
	if len(e.Received) != 2 {
		t.Errorf("Received = %d, want 2", len(e.Received))
	}
	if !hasWarning(e, "duplicate_field") {
		t.Error("expected a duplicate_field warning")
	}
}

func TestEncodedDisplayNameCannotInjectAddress(t *testing.T) {
	e := parseFixture(t, "08-rfc2047-address-spoof.eml")
	mb := e.FromFields[0][0]
	if mb.Address != "attacker@phish.example" {
		t.Errorf("Address = %q, want the real address", mb.Address)
	}
	if mb.Name != "Bank Security <security@bank.example>" {
		t.Errorf("Name = %q", mb.Name)
	}
	// The name is quoted in the display form, so it reads as a name.
	want := `"Bank Security <security@bank.example>" <attacker@phish.example>`
	if e.From != want {
		t.Errorf("From = %q, want %q", e.From, want)
	}
}

func TestMetaCharsetDecodesHTML(t *testing.T) {
	e := parseFixture(t, "09-meta-charset.eml")
	if !strings.Contains(e.HTMLBody(), "パスワードの再設定") {
		t.Errorf("HTML body = %q, want Shift_JIS decoded by <meta charset>", e.HTMLBody())
	}
}

func TestMalformedHeaderLineDoesNotFailParse(t *testing.T) {
	e := parseFixture(t, "10-malformed-header-line.eml")
	if e.Subject == "" || e.From == "" {
		t.Errorf("Subject = %q, From = %q; the rest of the header should be read", e.Subject, e.From)
	}
	if !hasWarning(e, "malformed_header_line") {
		t.Error("expected a malformed_header_line warning")
	}
}

func TestBadBase64AttachmentKeepsDecodedBytes(t *testing.T) {
	e := parseFixture(t, "11-bad-base64-attachment.eml")
	if len(e.Attachments) != 1 {
		t.Fatalf("Attachments = %d, want 1", len(e.Attachments))
	}
	a := e.Attachments[0]
	empty := sha256.Sum256(nil)
	if a.Size == 0 || a.Hash == hex.EncodeToString(empty[:]) {
		t.Errorf("attachment hashed as empty data: %+v", a)
	}
	if !hasWarning(e, "invalid_base64") {
		t.Error("expected an invalid_base64 warning")
	}
}

func TestMSGWithTransportHeaders(t *testing.T) {
	e := parseFixture(t, "outlook.msg")
	if e.From != "Bank Support <support@bank.example>" {
		t.Errorf("From = %q, want it from the internet headers", e.From)
	}
	if e.Date == "" {
		t.Error("Date should be read")
	}
	if len(e.AllAuthResults) == 0 {
		t.Error("Authentication-Results should be read from the transport headers")
	}
	if len(e.Received) == 0 {
		t.Error("Received should be read from the transport headers")
	}
	if len(e.Nested) != 1 || e.Nested[0].Subject != "Your mailbox is full" {
		t.Fatalf("embedded message not opened: %+v", e.Nested)
	}
	var pdf *Attachment
	for i := range e.Attachments {
		if e.Attachments[i].Filename == "invoice.pdf" {
			pdf = &e.Attachments[i]
		}
	}
	if pdf == nil || pdf.Hash == "" || pdf.Size == 0 {
		t.Errorf("invoice.pdf = %+v", pdf)
	}
}

func TestMSGWithoutTransportHeaders(t *testing.T) {
	e := parseFixture(t, "sent-items.msg")
	if len(e.To) != 1 || !strings.Contains(e.To[0], "contact@partner.example") {
		t.Errorf("To = %q", e.To)
	}
	if len(e.BCC) != 1 || !strings.Contains(e.BCC[0], "boss@corp.example") {
		t.Errorf("BCC = %q, want the Bcc recipient there, not in To", e.BCC)
	}
	if e.Date == "" {
		t.Error("Date should come from the MAPI submit time")
	}
	// An Exchange DN has no SMTP address; it stays visible in the display form.
	if !strings.Contains(e.From, "/O=CORP") {
		t.Errorf("From = %q, want the Exchange DN kept", e.From)
	}
	if !hasWarning(e, "no_transport_headers") {
		t.Error("expected a no_transport_headers warning")
	}
}

func TestWinmailDatIsOpened(t *testing.T) {
	e := parseFixture(t, "winmail.eml")
	if len(e.Nested) != 1 {
		t.Fatalf("Nested = %d, want winmail.dat opened", len(e.Nested))
	}
	n := e.Nested[0]
	found := false
	for _, a := range n.Attachments {
		if a.Filename == "overdue.docm" && a.Hash != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("TNEF attachments = %+v", n.Attachments)
	}
	if !strings.Contains(n.HTMLBody()+n.PlainTextBody(), "rtf.evil.example") {
		t.Error("the RTF body's link should be read")
	}
}

func TestMailboxString(t *testing.T) {
	tests := []struct {
		mb   Mailbox
		want string
	}{
		{Mailbox{Address: "a@example.com"}, "a@example.com"},
		{Mailbox{Name: "Alice", Address: "a@example.com"}, "Alice <a@example.com>"},
		{Mailbox{Name: "Smith, J.", Address: "j@example.com"}, `"Smith, J." <j@example.com>`},
		{Mailbox{Name: `a "b"`, Address: "x@example.com"}, `"a \"b\"" <x@example.com>`},
		{Mailbox{Name: "J. Smith", Address: "j@example.com"}, "J. Smith <j@example.com>"},
		{Mailbox{Name: "Taro"}, "Taro"},
	}
	for _, tt := range tests {
		if got := tt.mb.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.mb, got, tt.want)
		}
	}
}

func TestAllWarningsPrefixesNestedParts(t *testing.T) {
	e := &Email{
		Warnings: []Warning{{Code: "a", Part: ""}},
		Nested: []*Email{{
			Part:     "2",
			Warnings: []Warning{{Code: "b", Part: "1"}},
			Nested:   []*Email{{Part: "3", Warnings: []Warning{{Code: "c", Part: ""}}}},
		}},
	}
	got := e.AllWarnings()
	want := []Warning{{Code: "a"}, {Code: "b", Part: "2>1"}, {Code: "c", Part: "2>3"}}
	if len(got) != len(want) {
		t.Fatalf("AllWarnings = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllWarnings[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseBytesRejectsOversizedInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	if _, err := ParseBytes(big, "big.eml"); err == nil {
		t.Error("expected an error for input over the size limit")
	}
}

const compatEML = "Received: from relay.example.net (relay.example.net [192.0.2.1])\r\n" +
	"\tby\r\n" +
	"\tmx.example.org; Fri, 6 Nov 2026 10:00:00 +0900\r\n" +
	"From: a@example.net\r\n" +
	"To: b@example.org\r\n" +
	"Subject: invite\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"c\"\r\n" +
	"\r\n" +
	"--c\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"line one\r\nline two\r\n" +
	"--c\r\n" +
	"Content-Type: text/calendar; method=REQUEST\r\n" +
	"\r\n" +
	"BEGIN:VCALENDAR\r\nURL:https://meet.evil.example/join\r\nEND:VCALENDAR\r\n" +
	"--c\r\n" +
	"Content-Type: application/octet-stream\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"QUJD\r\n" +
	"--c--\r\n"

func TestCompatWithInHouseParser(t *testing.T) {
	e, err := ParseBytes([]byte(compatEML), "compat.eml")
	if err != nil {
		t.Fatal(err)
	}
	// Folding whitespace joins into one space, as net/textproto did.
	if len(e.Received) != 1 || !strings.Contains(e.Received[0], "by mx.example.org") {
		t.Errorf("Received = %q", e.Received)
	}
	// Bodies have LF line ends (the last CRLF belongs to the delimiter).
	if got := e.PlainTextBody(); got != "line one\nline two" {
		t.Errorf("PlainTextBody = %q", got)
	}
	// An unnamed inline text/calendar part stays a body, so its links are checked.
	var cal *BodyPart
	for i := range e.Body {
		if e.Body[i].Type == "text/calendar" {
			cal = &e.Body[i]
		}
	}
	if cal == nil || !strings.Contains(cal.Content, "https://meet.evil.example/join") {
		t.Errorf("text/calendar body = %+v", e.Body)
	}
	// An unnamed attachment keeps the old placeholder name.
	if len(e.Attachments) != 1 || e.Attachments[0].Filename != "attachment" {
		t.Errorf("Attachments = %+v", e.Attachments)
	}
}

func TestRTFCopyLeftOutOfLLMBodyWhenAnotherExists(t *testing.T) {
	e := &Email{Body: []BodyPart{
		{Type: "text/plain", Content: "body", Part: "msg/body"},
		{Type: "text/plain", Content: "body again", Part: "msg/rtf"},
		{Type: "text/html", Content: "<p>only rtf</p>", Part: "msg/rtf"},
	}}
	if got := e.PlainTextBody(); got != "body" {
		t.Errorf("PlainTextBody = %q, want the RTF copy left out", got)
	}
	if got := e.HTMLBody(); got != "<p>only rtf</p>" {
		t.Errorf("HTMLBody = %q, want the RTF body when it is the only one", got)
	}
}
