# mail-analyzer

Suspicious email analyzer combining rule-based indicators and Gemini LLM.
Parses `.eml` and `.msg` files and outputs structured JSON with SHA-256 hashes,
authentication results, sender integrity checks, URL/attachment risk assessment,
and LLM-powered content analysis.

## Features

- **Dual analysis engine**: deterministic rule-based indicators + Gemini LLM content analysis
- **EML and MSG support**: read by [mailparse](https://github.com/nlink-jp/mailparse), written for
  attacker-composed mail — every header field in order with duplicates kept, addresses parsed before display
  names are decoded, full charset handling (ISO-2022-JP, Shift_JIS, EUC-JP, HTML `<meta charset>`), Outlook
  compressed RTF bodies and winmail.dat (TNEF)
- **Attached messages are opened**: a forwarded `.eml`/`.msg` (message/rfc822 or recognized by content), an
  embedded `.msg` and winmail.dat — their URLs and attachments are checked too (`in_message`)
- **Parse warnings**: a malformed header line, a duplicated From, damaged Base64, an unclosed boundary... are
  reported (`parse_warnings`) instead of being dropped silently
- **SHA-256 hashes**: file hash and per-attachment hashes for IoC correlation
- **Authentication analysis**: SPF, DKIM, DMARC from every `Authentication-Results` field; the most severe
  verdict wins, so a forged `pass` placed on top cannot hide a `fail`
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

Configuration is loaded with the following priority:

1. **Environment variables** (`MAIL_ANALYZER_*` or `GOOGLE_CLOUD_*`)
2. **TOML config file** (`~/.config/mail-analyzer/config.toml`)
3. **Defaults**

A key the config file does not know — a typo, say — is an error that names
it, not a setting silently ignored.

```bash
# Setup config file (optional)
mkdir -p ~/.config/mail-analyzer
cp config.example.toml ~/.config/mail-analyzer/config.toml
# Edit project ID
```

| Variable | Default | Description |
|----------|---------|-------------|
| `MAIL_ANALYZER_PROJECT` | (required) | GCP project ID for Vertex AI |
| `MAIL_ANALYZER_LOCATION` | `global` | Vertex AI location (Gemini 3 models require `global`) |
| `MAIL_ANALYZER_MODEL` | `gemini-3.7-flash` | Gemini model name |
| `MAIL_ANALYZER_LANG` | (auto) | Force output language |
| `--config <path>` | | Override config file path |

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
    "authentication": {
      "spf": "fail", "dkim": "pass", "dmarc": "fail",
      "per_header": [{ "spf": "pass", "dkim": "pass", "dmarc": "pass" }, { "spf": "fail", "dkim": "pass", "dmarc": "fail" }],
      "conflicting": true
    },
    "sender": { "from_return_path_mismatch": true, ... },
    "urls": [{ "url": "hxxps://evil[.]com/path", "suspicious": true, "reason": "...", "in_message": "2" }],
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
  },
  "parse_warnings": [{ "code": "duplicate_field", "detail": "...", "part": "" }]
}
```

Notes on the fields:

- `from` is the first From field; every From field (a duplicate is a warning) is read by the rules and shown
  to the LLM. Mailboxes are rendered `Name <address>`, a bare address without brackets; a display name holding
  `<`, `>`, `@`, `,`, `"` or `\` is quoted so it reads as a name. An Exchange `/O=...` sender is shown as written.
- `authentication` takes the most severe verdict per method across all `Authentication-Results` fields;
  `per_header` (topmost first) and `conflicting` appear when there is more than one. Forwarded mail carries one
  field per receiving hop, and they often disagree.
- `in_message` marks a URL or attachment found in an attached message: the part path of that attachment
  (`2`, `msg/attach/1`; `2>1` for a message inside a message).
- An attachment whose bytes could not be extracted (an embedded `.msg`, an OLE object) has no `hash`.
- `parse_warnings` lists mailparse's warning codes; `part` is where in the message (`2>1` inside an attached
  message). Inputs over 64 MiB are refused.

## Building

```bash
make build      # Build for current platform → dist/
make build-all  # Cross-compile all platforms
make test       # Run tests
make lint       # gofmt + golangci-lint
make clean      # Remove dist/
```

## Documentation

- [Architecture](docs/en/architecture.md) — Design decisions, analysis methodology, rationale
- [README.md](README.md) (English)
- [README.ja.md](README.ja.md) (Japanese)
- [CHANGELOG.md](CHANGELOG.md)
