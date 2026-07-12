# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-12

### Removed

- **darwin/amd64 (Intel) pre-built binary.** macOS releases now ship
  **arm64 only**, per the org-wide policy (darwin is Apple-Silicon only; no
  universal binaries). Intel Mac users can build from source.

### Changed

- **Linux release archives are now `.tar.gz`** (darwin/windows remain `.zip`),
  per `nlink-jp/.github` CONVENTIONS.md §Release Archive Standard. Archives
  still bundle `LICENSE` + `README.md` alongside the canonical binary.
- **darwin code-signature identifier** is now the canonical `mail-analyzer`
  (was `mail-analyzer-darwin-arm64`), set via `codesign -i` so it stays
  stable after the archived binary is renamed to its canonical name.

No change to the binary's behaviour — a packaging / build-config release.

## [0.1.2] - 2026-05-23

### Added

- **`package` Makefile target.** Builds all 5 platforms, signs darwin
  binaries with Developer ID, zips each with LICENSE + README.md
  using versioned naming
  (`mail-analyzer-vX.Y.Z-<os>-<arch>.zip`), and notarizes the
  darwin zips. Replaces the previous manual zip step that produced
  the v0.1.1 release.

### Changed

- **Darwin releases are now Developer ID signed and Apple-notarized.**
  `mail-analyzer-v0.1.2-darwin-{amd64,arm64}.zip` carry full Apple
  Developer ID Application signatures and notarization tickets from
  Apple. End users on macOS no longer need to bypass Gatekeeper
  with right-click → Open or `xattr -d com.apple.quarantine` on
  first launch; local users who place `mail-analyzer` under
  Dropbox-synced (or any other FileProvider-managed) paths are no
  longer killed by macOS's ad-hoc + provenance distrust policy.
  Pipeline: `scripts/codesign-darwin.sh` +
  `scripts/notarize-darwin.sh`, driven by `make package`. Adopts
  the org-wide convention in `nlink-jp/.github` CONVENTIONS.md
  §Code Signing.

No behaviour change to the binary itself — feature-wise this is
identical to v0.1.1.

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
