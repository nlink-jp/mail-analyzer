# AGENTS.md — mail-analyzer

## Summary

mail-analyzer is a suspicious email analysis CLI that combines rule-based
indicators (SPF/DKIM/DMARC, sender integrity, URL classification, attachment
risk, routing analysis) with Gemini LLM content analysis to produce a
structured JSON judgment. Mail is read by github.com/nlink-jp/mailparse.

## Build & test commands

```bash
make build       # Build → dist/mail-analyzer
make build-all   # Cross-compile all platforms
make test        # Run tests
make lint        # gofmt + golangci-lint
make clean       # Remove dist/
make verify-release  # gate: notarized, fresh, runs at this version, clean linux archives (run before upload)
```

## Key directory structure

```
mail-analyzer/
├── main.go                      # CLI entry point
├── internal/
│   ├── parser/                  # mailparse.Message → Email, SHA-256
│   │   └── email.go             # Model, dispatch by extension, FromMessage
│   ├── indicator/               # Rule-based analysis
│   │   ├── auth.go              # SPF/DKIM/DMARC
│   │   ├── sender.go            # From/Return-Path, spoofing
│   │   ├── url.go               # URL extraction, defang, classification
│   │   ├── attachment.go        # Extension risk assessment
│   │   └── routing.go           # X-Mailer, Received headers
│   ├── llm/                     # Gemini LLM integration
│   │   ├── client.go            # Vertex AI client, retry
│   │   └── prompt.go            # Prompt construction, injection defense
│   ├── analyzer/analyzer.go     # Composite judgment
│   └── config/config.go         # Environment config
├── testdata/                    # Test EML files
│   └── fixtures/                # Fictional regression fixtures (README lists them)
└── Makefile
```

## Module path

`github.com/nlink-jp/mail-analyzer`

## Environment variables

| Variable | Description |
|----------|-------------|
| `MAIL_ANALYZER_PROJECT` | GCP project ID (required for LLM mode) |
| `MAIL_ANALYZER_LOCATION` | Vertex AI location (default: global) |
| `MAIL_ANALYZER_MODEL` | Gemini model (default: gemini-3.7-flash) |
| `MAIL_ANALYZER_LANG` | Force output language (optional) |

## Gotchas

- Uses google.golang.org/genai SDK (NOT the deprecated vertexai SDK)
- Gemini 3 models are global-endpoint only — a regional location 404s them;
  the client appends a hint to that NOT_FOUND error
- SPF/DMARC fail alone does NOT trigger suspicious — needs other signals
- Subdomain matching: bounce.mag.subaru.jp is considered related to mag.subaru.jp
- testdata/samples/ is gitignored (real email samples, not committed)
- Parsing belongs to mailparse: do not re-add header, charset or MIME code here.
  A mailparse defect is reported to lib-series/mailparse, not patched around.
- Read structured fields (FromFields, ReplyToMailboxes, ReturnPaths,
  AllAuthResults), never addresses out of display strings; the string fields
  remain for output and for Emails built by hand in tests.
- Authentication-Results: every field is read and the most severe verdict wins.
  Real forwarded mail disagrees across hops most of the time, so the prompt
  states it neutrally — do not turn `conflicting` into an alert.
- Rules walk nested messages (walkMessages); a new URL/attachment rule must too.
- An attachment with no extracted bytes has Hash "" (never the empty-data hash).
- Kept for compatibility with the old parser (and with mail-analyzer-local):
  an unnamed inline text/* part other than plain/html (text/calendar) is a
  body so its links are checked (converted with Attachment.Text); an unnamed
  attachment is "attachment"; Received is Field.Collapsed ("by " matching);
  bodies are LF.
- Since mailparse v0.2.0 the helpers it took over are not re-implemented here:
  Mailbox.String, Message.AllWarnings, Body.Origin ("rtf" marks the RTF copy),
  DefaultMaxSize (64 MiB). Only an address field whose mailbox has no address
  (an Exchange DN) falls back to the field's Raw, as before.
- Codesigning needs Apple's timestamp server; in a sandbox without it use
  `make build CODESIGN_IDENTITY=none` for local runs.
