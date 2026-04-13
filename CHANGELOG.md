# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-04-14

### Added

- TOML config file support (`~/.config/mail-analyzer/config.toml`)
- `--config` flag to override config file path
- `GOOGLE_CLOUD_PROJECT` / `GOOGLE_CLOUD_LOCATION` env var fallback

## [0.1.0] - 2026-04-09

### Added

- EML parser with full charset support (adapted from eml-to-jsonl)
- MSG parser with OLE2/MAPI support (adapted from msg-to-jsonl)
- SHA-256 hashing for email files and individual attachments
- Authentication indicator: SPF/DKIM/DMARC result parsing
- Sender indicator: From/Return-Path mismatch, display name spoofing, Reply-To divergence
- URL indicator: extraction, deduplication, defanging, classification (free hosting, shortener, suspicious TLD, Azure Blob)
- Attachment indicator: dangerous extensions, macro-enabled Office, double extension detection
- Routing indicator: X-Mailer classification, suspicious Received header detection (localhost, local domains, IP-only HELO)
- Gemini LLM analysis via google.golang.org/genai SDK (Vertex AI)
- Prompt injection defense with nonce-tagged XML boundaries (defense at prompt top)
- Structured JSON output with composite judgment (is_suspicious, category, confidence, reasons, tags)
- Offline mode (--offline) for rule-based analysis without LLM
- Exponential backoff with jitter for LLM API retries
- SPF/DMARC failure handling: not flagged alone (reduces false positives from forwarded emails)
- Subdomain-aware sender comparison (bounce.mag.subaru.jp matches mag.subaru.jp)
- Broken RFC 2047 encoded-word repair (spaces in Base64 payload from line folding)
- Schema/namespace URL filtering (Microsoft Office XML schemas excluded from analysis)
