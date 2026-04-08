# CLAUDE.md — mail-analyzer

## Project overview

Suspicious email analyzer combining rule-based indicators and Gemini LLM.
Parses .eml/.msg, outputs structured JSON with hashes, indicators, and judgment.

## Build & test

```bash
make build       # Build → dist/mail-analyzer
make test        # Run tests
go test ./...    # Same without Makefile
```

## Architecture

```
internal/
├── parser/      # EML/MSG parsing (from eml-to-jsonl + msg-to-jsonl)
├── indicator/   # Rule-based analysis (auth, sender, url, attachment, routing)
├── llm/         # Gemini LLM (google.golang.org/genai, prompt injection defense)
├── analyzer/    # Composite analysis (indicators + LLM → judgment)
└── config/      # Environment variable config
```

## Key conventions

- google.golang.org/genai SDK (NOT deprecated cloud.google.com/go/vertexai/genai)
- Prompt injection defense at TOP of system prompt (nonce-tagged XML)
- SPF/DMARC fail alone does NOT trigger suspicious judgment
- Subdomain-aware sender comparison
- SHA-256 hashes for file and each attachment
