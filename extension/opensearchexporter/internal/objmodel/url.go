package objmodel

import (
	"net/url"
	"strings"
)

// URL removes control characters from the URL parameter. This addresses CWE-117:
// https://cwe.mitre.org/data/definitions/117.html
func URL(unsanitized *url.URL) string {
	escaped := strings.ReplaceAll(unsanitized.String(), "\n", "")
	return strings.ReplaceAll(escaped, "\r", "")
}

// String removes control characters from String parameter. This addresses CWE-117:
// https://cwe.mitre.org/data/definitions/117.html
func String(unsanitized string) string {
	escaped := strings.ReplaceAll(unsanitized, "\n", "")
	return strings.ReplaceAll(escaped, "\r", "")
}
