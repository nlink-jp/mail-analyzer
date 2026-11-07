package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/richardlehane/mscfb"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

const maxStreamSize = 50 * 1024 * 1024 // 50 MiB

// MAPI property IDs.
const (
	propSubject          uint16 = 0x0037
	propSenderName       uint16 = 0x0C1A
	propSenderEmail      uint16 = 0x0C1F
	propSenderSMTP       uint16 = 0x5D01
	propDisplayTo        uint16 = 0x0E04
	propDisplayCC        uint16 = 0x0E03
	propDisplayBCC       uint16 = 0x0E02
	propBody             uint16 = 0x1000
	propHTMLBody         uint16 = 0x1013
	propDeliveryTime     uint16 = 0x0E06
	propClientSubmitTime uint16 = 0x0039
	propMessageID        uint16 = 0x1035
	propInReplyTo        uint16 = 0x1042
	propTransportHeaders uint16 = 0x007D
	propInternetCPID     uint16 = 0x3FDE
	propRecipType        uint16 = 0x0C15
	propEmailAddr        uint16 = 0x3003
	propDisplayName      uint16 = 0x3001
	propSMTPAddr         uint16 = 0x39FE
	propAttachFilename   uint16 = 0x3704
	propAttachLongName   uint16 = 0x3707
	propAttachMIMETag    uint16 = 0x370E
	propAttachDataBin    uint16 = 0x3701
	propAttachSize       uint16 = 0x0E20

	typeUnicode uint16 = 0x001F
	typeString8 uint16 = 0x001E
	typeBinary  uint16 = 0x0102
	typeSystime uint16 = 0x0040
	typeLong    uint16 = 0x0003
)

type mapiStream struct {
	propID, propType uint16
	data             []byte
}

type mapiProps map[uint16]mapiStream

type msgDocument struct {
	root        mapiProps
	recipients  []mapiProps
	attachments []mapiProps
}

func parseMSG(data []byte, source string) (*Email, error) {
	doc, err := loadMSGDocument(data)
	if err != nil {
		return nil, fmt.Errorf("parsing MSG: %w", err)
	}
	return buildMSGEmail(doc, source), nil
}

func loadMSGDocument(data []byte) (*msgDocument, error) {
	r, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	d := &msgDocument{root: make(mapiProps)}
	recipIdx := map[string]int{}
	attachIdx := map[string]int{}

	for {
		entry, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		if !strings.HasPrefix(entry.Name, "__substg1.0_") {
			continue
		}

		raw, err := io.ReadAll(io.LimitReader(entry, maxStreamSize))
		if err != nil {
			continue
		}

		stream, ok := parseMSGStreamName(entry.Name, raw)
		if !ok {
			continue
		}

		scope := ""
		if len(entry.Path) > 0 {
			scope = entry.Path[len(entry.Path)-1]
		}

		switch {
		case scope == "":
			d.root[stream.propID] = stream
		case strings.HasPrefix(scope, "__recip_version1.0_"):
			idx, exists := recipIdx[scope]
			if !exists {
				idx = len(d.recipients)
				d.recipients = append(d.recipients, make(mapiProps))
				recipIdx[scope] = idx
			}
			d.recipients[idx][stream.propID] = stream
		case strings.HasPrefix(scope, "__attach_version1.0_"):
			idx, exists := attachIdx[scope]
			if !exists {
				idx = len(d.attachments)
				d.attachments = append(d.attachments, make(mapiProps))
				attachIdx[scope] = idx
			}
			d.attachments[idx][stream.propID] = stream
		}
	}

	return d, nil
}

func parseMSGStreamName(name string, data []byte) (mapiStream, bool) {
	const prefix = "__substg1.0_"
	if !strings.HasPrefix(name, prefix) {
		return mapiStream{}, false
	}
	suffix := name[len(prefix):]
	if len(suffix) != 8 {
		return mapiStream{}, false
	}
	b, err := hex.DecodeString(suffix)
	if err != nil || len(b) != 4 {
		return mapiStream{}, false
	}
	propID := uint16(b[0])<<8 | uint16(b[1])
	propType := uint16(b[2])<<8 | uint16(b[3])
	return mapiStream{propID: propID, propType: propType, data: data}, true
}

func buildMSGEmail(doc *msgDocument, source string) *Email {
	m := doc.root
	cpid := m.cpid()

	email := &Email{
		Source:      source,
		Body:        []BodyPart{},
		Attachments: []Attachment{},
	}

	email.MessageID = strings.TrimSpace(m.getString(propMessageID, cpid))
	email.InReplyTo = strings.TrimSpace(m.getString(propInReplyTo, cpid))
	email.Subject = m.getString(propSubject, cpid)

	senderName := m.getString(propSenderName, cpid)
	senderEmail := m.getString(propSenderSMTP, cpid)
	if senderEmail == "" {
		senderEmail = m.getString(propSenderEmail, cpid)
	}
	if strings.HasPrefix(senderEmail, "/O=") || strings.HasPrefix(senderEmail, "/o=") {
		senderEmail = ""
	}
	email.From = formatMSGName(senderName, senderEmail)

	if t, ok := m.getTime(propDeliveryTime); ok {
		email.Date = t.Format(time.RFC3339)
	} else if t, ok := m.getTime(propClientSubmitTime); ok {
		email.Date = t.Format(time.RFC3339)
	}

	if raw := m.getString(propTransportHeaders, cpid); raw != "" {
		email.XMailer = parseMSGTransportXMailer(raw)
		email.Received = parseMSGReceivedHeaders(raw)
		email.ReturnPath = parseMSGHeaderValue(raw, "return-path")
		email.ReplyTo = parseMSGHeaderValue(raw, "reply-to")
		email.AuthResults = parseMSGHeaderValue(raw, "authentication-results")
	}

	// Recipients
	if len(doc.recipients) > 0 {
		for _, r := range doc.recipients {
			rcpid := r.cpid()
			if rcpid == 0 {
				rcpid = cpid
			}
			addr := r.formatMSGAddress(rcpid)
			if addr == "" {
				continue
			}
			rtype, _ := r.getInt(propRecipType)
			switch rtype {
			case 2:
				email.CC = append(email.CC, addr)
			case 3:
				email.BCC = append(email.BCC, addr)
			default:
				email.To = append(email.To, addr)
			}
		}
	} else {
		email.To = splitSemicolon(m.getString(propDisplayTo, cpid))
		email.CC = splitSemicolon(m.getString(propDisplayCC, cpid))
		email.BCC = splitSemicolon(m.getString(propDisplayBCC, cpid))
	}

	if plain := m.getString(propBody, cpid); plain != "" {
		email.Body = append(email.Body, BodyPart{Type: "text/plain", Content: plain})
	}
	if htmlBytes := m.getBinary(propHTMLBody); len(htmlBytes) > 0 {
		email.Body = append(email.Body, BodyPart{Type: "text/html", Content: decodeMSGHTMLBody(htmlBytes, cpid)})
	}

	for _, a := range doc.attachments {
		att := buildMSGAttachment(a, cpid)
		if att != nil {
			email.Attachments = append(email.Attachments, *att)
		}
	}

	return email
}

func buildMSGAttachment(a mapiProps, parentCPID int32) *Attachment {
	cpid := a.cpid()
	if cpid == 0 {
		cpid = parentCPID
	}

	filename := a.getString(propAttachLongName, cpid)
	if filename == "" {
		filename = a.getString(propAttachFilename, cpid)
	}

	mimeType := a.getString(propAttachMIMETag, cpid)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	var size int
	var hash string
	if b := a.getBinary(propAttachDataBin); b != nil {
		size = len(b)
		hash = sha256sum(b)
	} else if v, ok := a.getInt(propAttachSize); ok && v > 0 {
		size = int(v)
	}

	if filename == "" && size == 0 {
		return nil
	}

	return &Attachment{
		Filename: filename,
		MIMEType: mimeType,
		Size:     size,
		Hash:     hash,
	}
}

// MAPI property accessors

func (m mapiProps) getString(propID uint16, cpid int32) string {
	s, ok := m[propID]
	if !ok {
		return ""
	}
	switch s.propType {
	case typeUnicode:
		return decodeMSGUTF16LE(s.data)
	case typeString8:
		return decodeMSGString8(s.data, cpid)
	}
	return ""
}

func (m mapiProps) getInt(propID uint16) (int32, bool) {
	s, ok := m[propID]
	if !ok || s.propType != typeLong || len(s.data) < 4 {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(s.data[:4])), true
}

func (m mapiProps) getTime(propID uint16) (time.Time, bool) {
	s, ok := m[propID]
	if !ok || s.propType != typeSystime || len(s.data) < 8 {
		return time.Time{}, false
	}
	ft := binary.LittleEndian.Uint64(s.data[:8])
	if ft == 0 {
		return time.Time{}, false
	}
	const filetimeEpoch int64 = 116444736000000000
	unixNano := (int64(ft) - filetimeEpoch) * 100
	return time.Unix(0, unixNano).UTC(), true
}

func (m mapiProps) getBinary(propID uint16) []byte {
	s, ok := m[propID]
	if !ok || s.propType != typeBinary {
		return nil
	}
	return s.data
}

func (m mapiProps) cpid() int32 {
	v, _ := m.getInt(propInternetCPID)
	return v
}

func (m mapiProps) formatMSGAddress(cpid int32) string {
	name := m.getString(propDisplayName, cpid)
	email := m.getString(propSMTPAddr, cpid)
	if email == "" {
		email = m.getString(propEmailAddr, cpid)
	}
	if strings.HasPrefix(email, "/O=") || strings.HasPrefix(email, "/o=") {
		email = ""
	}
	return formatMSGName(name, email)
}

func decodeMSGUTF16LE(b []byte) string {
	for len(b) >= 2 && b[len(b)-2] == 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-2]
	}
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func decodeMSGString8(b []byte, cpid int32) string {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return ""
	}
	charset := cpidToCharset(cpid)
	if charset == "" {
		return string(b)
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return string(b)
	}
	result, _, err := transform.Bytes(enc.NewDecoder(), b)
	if err != nil {
		return string(b)
	}
	return string(result)
}

func cpidToCharset(cpid int32) string {
	switch cpid {
	case 932:
		return "windows-31j"
	case 936:
		return "gbk"
	case 949:
		return "euc-kr"
	case 950:
		return "big5"
	case 1250, 1251, 1252, 1253, 1254, 1255, 1256:
		return fmt.Sprintf("windows-%d", cpid)
	case 65001:
		return "utf-8"
	default:
		return ""
	}
}

func decodeMSGHTMLBody(b []byte, cpid int32) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return decodeMSGUTF16LE(b[2:])
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return string(b[3:])
	}
	if cpid != 0 && cpid != 65001 {
		charset := cpidToCharset(cpid)
		if charset != "" {
			return decodeMSGString8(b, cpid)
		}
	}
	return string(b)
}

func formatMSGName(name, email string) string {
	if name != "" && email != "" {
		return name + " <" + email + ">"
	}
	if email != "" {
		return email
	}
	return name
}

func splitSemicolon(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseMSGTransportXMailer(raw string) string {
	return parseMSGHeaderValue(raw, "x-mailer")
}

func parseMSGReceivedHeaders(raw string) []string {
	var received []string
	var current string
	inReceived := false
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(trimmed), "received:") {
			if inReceived && current != "" {
				received = append(received, strings.TrimSpace(current))
			}
			current = strings.TrimSpace(trimmed[len("received:"):])
			inReceived = true
		} else if inReceived && len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
			current += " " + strings.TrimSpace(trimmed)
		} else {
			if inReceived && current != "" {
				received = append(received, strings.TrimSpace(current))
				current = ""
			}
			inReceived = false
		}
	}
	if inReceived && current != "" {
		received = append(received, strings.TrimSpace(current))
	}
	return received
}

func parseMSGHeaderValue(raw, headerName string) string {
	prefix := strings.ToLower(headerName) + ":"
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}
