# AGENTS.md — mail-analyzer

## Summary

mail-analyzer is a suspicious email analysis CLI that combines rule-based
indicators (SPF/DKIM/DMARC, sender integrity, URL classification, attachment
risk, routing analysis) with Gemini LLM content analysis to produce a
structured JSON judgment.

## Build & test commands

```bash
make build       # Build → dist/mail-analyzer
make build-all   # Cross-compile all platforms
make test        # Run tests
make clean       # Remove dist/
make verify-release  # gate: notarized, fresh, runs at this version, clean linux archives (run before upload)
```

## Key directory structure

```
mail-analyzer/
├── main.go                      # CLI entry point
├── internal/
│   ├── parser/                  # mailparse.Message → Email (no parsing of its own)
│   │   └── email.go             # Email model, ParseFile/ParseBytes, FromMessage, SHA-256
│   ├── indicator/               # Rule-based analysis
│   │   ├── auth.go              # SPF/DKIM/DMARC (top Authentication-Results), conflicting flag
│   │   ├── sender.go            # From/Return-Path, display name spoofing (Public Suffix List), Reply-To (every mailbox)
│   │   ├── url.go               # URL extraction, defang, classification (all layers, text attachments)
│   │   ├── attachment.go        # Extension risk assessment
│   │   ├── routing.go           # X-Mailer, Received headers
│   │   └── prompt.go            # Helpers both twins' prompts use (Where, PromptAuthResults)
│   ├── llm/                     # Gemini LLM integration
│   │   ├── client.go            # Vertex AI client, retry
│   │   └── prompt.go            # Prompt construction, injection defense
│   ├── analyzer/analyzer.go     # Composite judgment
│   └── config/config.go         # Environment config
├── testdata/                    # Test EML files
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
- **Twin of mail-analyzer-local**: `internal/parser`, `internal/indicator` and `internal/analyzer`
  are the same code in both, differing only in import paths (and, in analyzer.go, the LLM call).
  Change them in both repositories together and compare with the import paths normalized.
- **All parsing is mailparse** (`github.com/nlink-jp/mailparse`). A parsing defect is fixed and
  released in mailparse first, never worked around here. Addresses become text only through
  `Mailbox.String()`; the indicators read the typed mailboxes, never the display strings.
- **Authentication-Results: the top field decides** (the recipient's server adds it; forged fields sit
  below). `conflicting` is information only — honest forwarding produces it in most real mail.
- .msg / TNEF fixtures are built with `mailparse/msgtest`; fixtures are fictional.
