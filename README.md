# mail-analyzer

Suspicious email analyzer combining rule-based indicators and Gemini LLM.
Parses `.eml` and `.msg` files and outputs structured JSON with SHA-256 hashes,
authentication results, sender integrity checks, URL/attachment risk assessment,
and LLM-powered content analysis.

## Features

- **Dual analysis engine**: deterministic rule-based indicators + Gemini LLM content analysis
- **EML and MSG support**: full charset handling (ISO-2022-JP, Shift_JIS, EUC-JP, etc.)
- **SHA-256 hashes**: file hash and per-attachment hashes for IoC correlation
- **Authentication analysis**: SPF, DKIM, DMARC result parsing
- **Sender integrity**: From/Return-Path mismatch, display name spoofing, Reply-To divergence
- **URL analysis**: extraction, defanging, free hosting / shortener / suspicious TLD detection
- **Attachment analysis**: dangerous extensions, macro-enabled Office, double extensions
- **Routing analysis**: X-Mailer classification, suspicious Received header detection
- **Offline mode**: rule-based analysis without LLM (no API calls)
- **Prompt injection defense**: nonce-tagged XML boundaries with defense instructions at prompt top

## Installation

```bash
git clone https://github.com/nlink-jp/mail-analyzer.git
cd mail-analyzer
make build    # → dist/mail-analyzer
```

## Usage

```bash
# With Gemini LLM (requires GCP project with Vertex AI)
export MAIL_ANALYZER_PROJECT=your-project-id
mail-analyzer email.eml

# Offline mode (rule-based only, no API calls)
mail-analyzer --offline email.eml

# MSG format
mail-analyzer message.msg

# Pipe-friendly
mail-analyzer email.eml | jq '.judgment'
mail-analyzer email.eml | jq '.indicators.urls[] | select(.suspicious)'
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MAIL_ANALYZER_PROJECT` | (required) | GCP project ID for Vertex AI |
| `MAIL_ANALYZER_LOCATION` | `us-central1` | Vertex AI location |
| `MAIL_ANALYZER_MODEL` | `gemini-2.5-flash` | Gemini model name |
| `MAIL_ANALYZER_LANG` | (auto) | Force output language |

## Output Schema

```json
{
  "source_file": "alert.eml",
  "hash": "sha256...",
  "message_id": "<...>",
  "subject": "...",
  "from": "...",
  "to": ["..."],
  "date": "...",
  "indicators": {
    "authentication": { "spf": "fail", "dkim": "pass", "dmarc": "fail" },
    "sender": { "from_return_path_mismatch": true, ... },
    "urls": [{ "url": "hxxps://evil[.]com/path", "suspicious": true, "reason": "..." }],
    "attachments": [{ "filename": "...", "hash": "sha256...", "suspicious": false }],
    "routing": { "hop_count": 7, "x_mailer": "...", "x_mailer_suspicious": false }
  },
  "judgment": {
    "is_suspicious": true,
    "category": "phishing",
    "confidence": 0.95,
    "summary": "...",
    "reasons": ["...", "..."],
    "tags": ["...", "..."]
  }
}
```

## Building

```bash
make build      # Build for current platform → dist/
make build-all  # Cross-compile all platforms
make test       # Run tests
make clean      # Remove dist/
```

## Documentation

- [Architecture](docs/architecture.md) — Design decisions, analysis methodology, rationale
- [README.md](README.md) (English)
- [README.ja.md](README.ja.md) (Japanese)
- [CHANGELOG.md](CHANGELOG.md)
