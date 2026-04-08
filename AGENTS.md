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
```

## Key directory structure

```
mail-analyzer/
├── main.go                      # CLI entry point
├── internal/
│   ├── parser/                  # EML/MSG parsers with SHA-256
│   │   ├── email.go             # Unified model, dispatch
│   │   ├── eml.go               # RFC 2822 parser
│   │   ├── msg.go               # OLE2/MAPI parser
│   │   └── charset.go           # Charset conversion, RFC 2047
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
└── Makefile
```

## Module path

`github.com/nlink-jp/mail-analyzer`

## Environment variables

| Variable | Description |
|----------|-------------|
| `MAIL_ANALYZER_PROJECT` | GCP project ID (required for LLM mode) |
| `MAIL_ANALYZER_LOCATION` | Vertex AI location (default: us-central1) |
| `MAIL_ANALYZER_MODEL` | Gemini model (default: gemini-2.5-flash) |
| `MAIL_ANALYZER_LANG` | Force output language (optional) |

## Gotchas

- Uses google.golang.org/genai SDK (NOT the deprecated vertexai SDK)
- SPF/DMARC fail alone does NOT trigger suspicious — needs other signals
- Subdomain matching: bounce.mag.subaru.jp is considered related to mag.subaru.jp
- testdata/samples/ is gitignored (real email samples, not committed)
