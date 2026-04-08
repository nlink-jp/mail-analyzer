package parser

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxMIMEDepth = 10
	maxPartSize  = 25 * 1024 * 1024 // 25 MiB
)

type emlResult struct {
	bodyParts   []BodyPart
	attachments []Attachment
	encoding    string
}

func parseEML(data []byte, source string) (*Email, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	email := &Email{
		Source:      source,
		Body:        []BodyPart{},
		Attachments: []Attachment{},
	}

	extractEMLHeaders(msg, email)

	result, err := parseEMLBody(
		msg.Header.Get("Content-Type"),
		msg.Header.Get("Content-Transfer-Encoding"),
		msg.Body,
	)
	if err != nil {
		return nil, err
	}
	email.Body = result.bodyParts
	email.Attachments = result.attachments
	if result.encoding != "" {
		email.Encoding = result.encoding
	}

	return email, nil
}

func extractEMLHeaders(msg *mail.Message, email *Email) {
	h := msg.Header
	email.MessageID = strings.TrimSpace(h.Get("Message-Id"))
	email.InReplyTo = strings.TrimSpace(h.Get("In-Reply-To"))
	email.XMailer = strings.TrimSpace(h.Get("X-Mailer"))
	email.ReturnPath = strings.TrimSpace(h.Get("Return-Path"))
	email.ReplyTo = decodeAddress(h.Get("Reply-To"))
	email.AuthResults = strings.TrimSpace(h.Get("Authentication-Results"))

	if received := msg.Header["Received"]; len(received) > 0 {
		email.Received = make([]string, len(received))
		for i, v := range received {
			email.Received[i] = strings.TrimSpace(v)
		}
	}

	email.Subject = decodeMIMEHeader(h.Get("Subject"))
	email.From = decodeAddress(h.Get("From"))
	email.To = decodeAddressList(h.Get("To"))
	email.CC = decodeAddressList(h.Get("Cc"))
	email.BCC = decodeAddressList(h.Get("Bcc"))

	if dateStr := h.Get("Date"); dateStr != "" {
		if t, err := mail.ParseDate(dateStr); err == nil {
			email.Date = t.Format(time.RFC3339)
		} else {
			email.Date = strings.TrimSpace(dateStr)
		}
	}
}

func parseEMLBody(ct, cte string, body io.Reader) (*emlResult, error) {
	return parseEMLBodyDepth(ct, cte, body, 0)
}

func parseEMLBodyDepth(ct, cte string, body io.Reader, depth int) (*emlResult, error) {
	if ct == "" {
		ct = "text/plain"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		data, _ := io.ReadAll(io.LimitReader(body, maxPartSize))
		return &emlResult{bodyParts: []BodyPart{{Type: "text/plain", Content: string(data)}}}, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		if depth >= maxMIMEDepth {
			return &emlResult{}, nil
		}
		return parseEMLMultipart(params["boundary"], body, depth)
	}

	return parseEMLSinglePart(mediaType, params["charset"], cte, body)
}

func parseEMLMultipart(boundary string, body io.Reader, depth int) (*emlResult, error) {
	result := &emlResult{}
	mr := multipart.NewReader(body, boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		sub, err := processEMLPart(part.Header, part, depth+1)
		part.Close()
		if err != nil {
			continue
		}

		result.bodyParts = append(result.bodyParts, sub.bodyParts...)
		result.attachments = append(result.attachments, sub.attachments...)
		if result.encoding == "" && sub.encoding != "" {
			result.encoding = sub.encoding
		}
	}
	return result, nil
}

func processEMLPart(h textproto.MIMEHeader, body io.Reader, depth int) (*emlResult, error) {
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = "application/octet-stream"
		params = map[string]string{}
	}

	cte := h.Get("Content-Transfer-Encoding")
	cd := h.Get("Content-Disposition")

	if strings.HasPrefix(mediaType, "multipart/") {
		if depth >= maxMIMEDepth {
			return &emlResult{}, nil
		}
		return parseEMLMultipart(params["boundary"], body, depth)
	}

	if isEMLAttachment(mediaType, cd, params) {
		return processEMLAttachment(mediaType, cd, params, cte, body)
	}

	return parseEMLSinglePart(mediaType, params["charset"], cte, body)
}

func isEMLAttachment(mediaType, cd string, params map[string]string) bool {
	cdLower := strings.ToLower(cd)
	if strings.HasPrefix(cdLower, "attachment") {
		return true
	}
	if strings.HasPrefix(cdLower, "inline") {
		if fname := emlAttachmentFilename(cd, params); fname != "" {
			return true
		}
	}
	if !strings.HasPrefix(mediaType, "text/") {
		return true
	}
	return false
}

func processEMLAttachment(mediaType, cd string, params map[string]string, cte string, body io.Reader) (*emlResult, error) {
	decoded, err := decodeTransfer(cte, body)
	if err != nil {
		decoded = []byte{}
	}

	filename := emlAttachmentFilename(cd, params)

	return &emlResult{
		attachments: []Attachment{
			{
				Filename: filename,
				MIMEType: mediaType,
				Size:     len(decoded),
				Hash:     sha256sum(decoded),
			},
		},
	}, nil
}

func parseEMLSinglePart(mediaType, charset, cte string, body io.Reader) (*emlResult, error) {
	decoded, err := decodeTransfer(cte, body)
	if err != nil {
		return &emlResult{}, nil
	}

	content := decodeToUTF8(charset, decoded)

	var originalEncoding string
	if charset != "" && !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "us-ascii") {
		originalEncoding = strings.ToUpper(charset)
	}

	return &emlResult{
		bodyParts: []BodyPart{{Type: mediaType, Content: content}},
		encoding:  originalEncoding,
	}, nil
}

func decodeTransfer(cte string, r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxPartSize)
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, newBase64Cleaner(limited)))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(limited))
	default:
		return io.ReadAll(limited)
	}
}

type base64Cleaner struct{ r io.Reader }

func newBase64Cleaner(r io.Reader) io.Reader { return &base64Cleaner{r: r} }

func (c *base64Cleaner) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	j := 0
	for i := 0; i < n; i++ {
		if p[i] != '\n' && p[i] != '\r' && p[i] != ' ' && p[i] != '\t' {
			p[j] = p[i]
			j++
		}
	}
	return j, err
}

func emlAttachmentFilename(cd string, params map[string]string) string {
	if cd != "" {
		_, cdParams, err := mime.ParseMediaType(cd)
		if err == nil {
			if name := cdParams["filename"]; name != "" {
				return decodeMIMEHeader(name)
			}
		}
	}
	if name := params["name"]; name != "" {
		return decodeMIMEHeader(name)
	}
	return filepath.Base("attachment")
}
