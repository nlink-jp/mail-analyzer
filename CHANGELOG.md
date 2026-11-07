# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-11-07

### Changed

- **Mail is read by [mailparse](https://github.com/nlink-jp/mailparse) v0.1.0** instead of the in-house
  `.eml`/`.msg` parser. The community modules `richardlehane/mscfb` and `msoleps` are gone; mailparse reads
  the Outlook container in-house.
- **Every `Authentication-Results` field is read**, and each of SPF, DKIM and DMARC takes the most severe
  verdict any of them gave. Only the first field was read before (and only its first line in a `.msg`), so a
  forged `pass` on top hid a `fail` below. `authentication` gains `per_header` and `conflicting` when there is
  more than one field. On 12 real messages this changed the verdicts of 3 and raised the offline confidence of
  2 by 0.1 (a weak reason added); no judgment changed.
- **The sender rules read every From mailbox** (every From field, every mailbox in it), every Reply-To mailbox
  and every Return-Path, instead of the first From string.
- **Display form of addresses**: mailboxes are rendered from the parsed address — `Name <address>`, a bare
  address without angle brackets (it was `<address>` when the header wrote it so), quotes of the header gone,
  and a display name holding `<`, `>`, `@`, `,`, `"` or `\` quoted. `to`/`cc`/`bcc` split on real address
  boundaries, not on every comma.
- **`.msg` identity comes from the internet headers** when Outlook kept them (From, To, Cc, Subject, Date), and
  from the MAPI properties otherwise; an Exchange `/O=...` sender is shown as written instead of dropped.
- **Bodies have LF line ends** (the LLM excerpt mixed CRLF and LF before), and in a `.msg` the copy of the
  body taken from the compressed RTF is left out of the LLM excerpt when another body of that type exists; its
  links are still checked.
- **Inputs over 64 MiB are refused**; a part over 25 MiB used to be cut silently (and hashed cut).

### Added

- **`parse_warnings`** in the output: mailparse's warning codes for what it met and handled (a malformed header
  line, a duplicated From, damaged Base64, an unclosed boundary, a `.msg` without internet headers...), those
  of attached messages included. The LLM is given the codes.
- **Attached messages are opened**: message/rfc822, a message attached under another type, an embedded `.msg`
  and winmail.dat (TNEF). Their URLs and attachments are checked like the outer ones and marked `in_message`.
- **The LLM sees every From field** (one `From:` line each) and the per-field Authentication-Results verdicts.
- `make lint` (gofmt + golangci-lint).

### Fixed

- **An encoded display name can no longer inject an address**: RFC 2047 was decoded before addresses were
  split, so `=?UTF-8?B?...?= <attacker@...>` became `Bank <security@bank.example> <attacker@...>` and the
  display-name spoofing rule missed it. Addresses are parsed first; the rule now fires.
- **A header line without a colon no longer fails the whole message.**
- **The part after an unclosed multipart boundary is no longer dropped.**
- **An attachment with damaged Base64 is hashed from the bytes that decode**, not as empty data.
- **HTML that declares Shift_JIS only in `<meta charset>` is no longer garbled.**
- **`.msg`: the date is read** (it was always empty), **Bcc recipients are no longer listed as To**, and
  folded header values are read whole.
- **Outlook compressed-RTF bodies and winmail.dat contents are analysed** — their links and attachments were
  not seen.

## [0.4.0] - 2026-11-04

### Changed

- **An unknown key in `config.toml` is now an error** that names the key,
  where it used to be skipped without a word. A typo such as `locaton`
  no longer leaves a setting that seems to do nothing. Remove or correct
  the key the message names.
- **The config file is read by nlink-jp/toml** (v0.1.1) instead of the
  third-party `BurntSushi/toml`, so the tool carries no TOML code from
  outside the organization.

### Fixed

- **`config.example.toml` puts `lang` where it is read.** It sat under
  `[model]`, so uncommenting it set `model.lang`, which the old decoder
  ignored and strict decoding refuses. It is a top-level key and now comes
  before `[gcp]`.
- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).
- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

## [0.3.0] - 2026-08-28

### Changed

- **Default model is now `gemini-3.7-flash`** (was `gemini-2.5-flash`), ahead
  of the Vertex AI Gemini 2.5 retirement. Gemini 2.5 models still work when
  set explicitly via config or `MAIL_ANALYZER_MODEL`.
- **Default location is now `global`** (was `us-central1`): Vertex AI serves
  the Gemini 3 family only from the global endpoint — regional endpoints
  return 404 for them. Gemini 2.5 users should set a regional location
  explicitly.
- Updated google.golang.org/genai SDK.

### Added

- Actionable error hint: requesting a Gemini 3 model from a regional endpoint
  used to fail with a bare `404 NOT_FOUND`; the error now explains that
  Gemini 3 models require `location = "global"`.

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
