# mail-analyzer

Suspicious email analyzer combining rule-based indicators and Gemini LLM.
Parses `.eml` and `.msg` files and outputs structured JSON with SHA-256 hashes,
authentication results, sender integrity checks, URL/attachment risk assessment,
and LLM-powered content analysis.

## Features

- **Dual analysis engine**: deterministic rule-based indicators + Gemini LLM content analysis
- **EML, MSG and winmail.dat**: read by [mailparse](https://github.com/nlink-jp/mailparse), the
  organization's mail parser written for attacker-composed mail; the format is recognized by
  content; full charset handling (ISO-2022-JP, Shift_JIS, EUC-JP, etc.)
- **SHA-256 hashes**: file hash and per-attachment hashes for IoC correlation
- **Authentication analysis**: SPF, DKIM, DMARC from the top Authentication-Results (the
  recipient's server's); every field kept raw, and a disagreeing lower field flagged as `conflicting`
- **Sender integrity**: From/Return-Path mismatch, display name spoofing, Reply-To divergence —
  checked over every mailbox, so a second From cannot hide the first
- **URL analysis**: extraction, defanging, free hosting / shortener / suspicious TLD detection, in
  the bodies, in attached (forwarded) messages and in text attachments such as calendar invitations
- **Attachment analysis**: dangerous extensions, macro-enabled Office, double extensions, in
  attached messages too
- **Parser warnings**: what the parser met and handled (duplicated headers, malformed addresses,
  broken encodings) in `warnings`; the LLM sees the warning codes
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
    "authentication": { "spf": "fail", "dkim": "pass", "dmarc": "fail",
                        "conflicting": true, "raw": ["mx.example.com; spf=fail ...", "..."] },
    "sender": { "from_return_path_mismatch": true, ... },
    "urls": [{ "url": "hxxps://evil[.]com/path", "suspicious": true, "reason": "...", "layer": "2" }],
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
  "warnings": [{ "code": "duplicate_field", "detail": "..." }]
}
```

- `from` lists every From mailbox (joined by `, `); display names that are not plain atoms are
  quoted, so a name that decodes to an address stays a name.
- `layer` (on a URL or attachment) names the attached message it was found in, as a mailparse
  `Message.Walk` path (`2`, `2>1`); absent for the outer message. `attachment` (on a URL) names the
  text attachment it was found in.
- `authentication.conflicting` is information only: forwarding produces it honestly.
- `warnings` holds mailparse's warnings for the message and every attached message (stable codes,
  see the mailparse README); always an array.
- Files larger than 64 MiB are refused.

## Building

```bash
make build      # Build for current platform → dist/
make build-all  # Cross-compile all platforms
make test       # Run tests
make clean      # Remove dist/
```

## Documentation

- [Architecture](docs/en/architecture.md) — Design decisions, analysis methodology, rationale
- [README.md](README.md) (English)
- [README.ja.md](README.ja.md) (Japanese)
- [CHANGELOG.md](CHANGELOG.md)
