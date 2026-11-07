package indicator

import (
	"path/filepath"
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// AttachResult holds analysis of a single attachment.
type AttachResult struct {
	Filename   string `json:"filename"`
	MIMEType   string `json:"mime_type"`
	Size       int    `json:"size"`
	Hash       string `json:"hash,omitempty"`
	Suspicious bool   `json:"suspicious"`
	Reason     string `json:"reason,omitempty"`
	// InMessage is set for an attachment of an attached message: the path of
	// the attachment that held that message.
	InMessage string `json:"in_message,omitempty"`
}

// Dangerous file extensions commonly used in malware delivery.
var dangerousExtensions = map[string]bool{
	".exe": true, ".scr": true, ".bat": true, ".cmd": true,
	".com": true, ".pif": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".wsh": true,
	".ps1": true, ".msi": true, ".msp": true, ".hta": true,
	".cpl": true, ".reg": true, ".inf": true, ".lnk": true,
	".iso": true, ".img": true, ".vhd": true, ".vhdx": true,
}

// Macro-enabled Office extensions.
var macroExtensions = map[string]bool{
	".xlsm": true, ".docm": true, ".pptm": true,
	".xlam": true, ".dotm": true, ".ppam": true,
	".xltm": true, ".potm": true, ".sldm": true,
}

// analyzeAttachments checks the attachments of the message and of every
// message attached to it (a forwarded mail, an embedded .msg, winmail.dat).
func analyzeAttachments(email *parser.Email) []AttachResult {
	var results []AttachResult
	walkMessages(email, func(m *parser.Email, in string) {
		results = append(results, checkAttachments(m.Attachments, in)...)
	})
	return results
}

func checkAttachments(atts []parser.Attachment, in string) []AttachResult {
	var results []AttachResult
	for _, a := range atts {
		result := AttachResult{
			Filename:  a.Filename,
			MIMEType:  a.MIMEType,
			Size:      a.Size,
			Hash:      a.Hash,
			InMessage: in,
		}

		ext := strings.ToLower(filepath.Ext(a.Filename))

		if dangerousExtensions[ext] {
			result.Suspicious = true
			result.Reason = "dangerous file extension: " + ext
		} else if macroExtensions[ext] {
			result.Suspicious = true
			result.Reason = "macro-enabled Office document: " + ext
		} else if hasDoubleExtension(a.Filename) {
			result.Suspicious = true
			result.Reason = "double extension"
		}

		results = append(results, result)
	}
	return results
}

func hasDoubleExtension(filename string) bool {
	// Remove the last extension and check if what remains also has an extension
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	secondExt := filepath.Ext(base)
	return secondExt != "" && len(secondExt) <= 5
}
