# Parser fixtures

Fictional messages only: RFC 2606 domains (`example.com`, `example.net`, `example.org`, `*.example`) and
RFC 5737 addresses. They pin the defects of the in-house parser that mailparse fixed, so a regression shows up
in `go test`.

| File | Source | What it holds | Before mailparse (v0.4.0) |
|---|---|---|---|
| `04-forwarded-rfc822.eml` | mailparse `testdata/eml/` | Original forwarded as message/rfc822, itself with an attachment | inner message not opened |
| `05-forwarded-octet-stream.eml` | mailparse | Original forwarded as `application/octet-stream` | inner message not opened |
| `06-unclosed-boundary.eml` | mailparse | Multipart whose closing boundary never comes | second part silently dropped |
| `07-duplicate-headers.eml` | mailparse | Two From, Sender, a forged `pass` Authentication-Results above a `fail` | only the first From and Authentication-Results read |
| `08-rfc2047-address-spoof.eml` | mailparse | Display name that decodes to an address form | the fake address surfaced as part of From |
| `09-meta-charset.eml` | mailparse | HTML without a charset parameter; Shift_JIS declared only by `<meta>` | garbled |
| `10-malformed-header-line.eml` | mailparse | A header line with no colon | the whole message failed to parse |
| `11-bad-base64-attachment.eml` | mailparse | Base64 attachment with invalid characters | hashed as empty data, no warning |
| `outlook.msg` | mail-dissect `testdata/gen` | .msg with internet headers, an attachment and an embedded message | From, Date and Authentication-Results empty; embedded message not opened |
| `sent-items.msg` | mail-dissect | .msg with no internet headers, a Bcc, an Exchange DN sender | Bcc listed as To; Date empty |
| `winmail.eml` | mail-dissect | winmail.dat (TNEF) with an RTF body link and a `.docm` | winmail.dat hashed as one opaque attachment |

The mailparse files are byte-exact copies (ISO-2022-JP and Shift_JIS bytes on purpose). The `.msg` and TNEF
files were generated from the MS-CFB / MS-OXMSG / MS-OXTNEF specifications.
