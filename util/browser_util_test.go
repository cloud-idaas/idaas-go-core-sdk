package util

import (
	"strings"
	"testing"
)

// TestOpenBrowser_RejectsUnsafeScheme verifies that file://, javascript://,
// data: and other non-http(s) schemes are rejected before any OS exec, so a
// tampered verification_uri_complete from a compromised IdP cannot reach
// xdg-open/open/rundll32.
func TestOpenBrowser_RejectsUnsafeScheme(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"javascript:alert(document.cookie)",
		"data:text/html,<script>alert(1)</script>",
		"ftp://evil.example.com/payload",
		"ws://evil.example.com/",
		"vbscript:msgbox(1)",
		"",
	}
	for _, raw := range cases {
		err := OpenBrowser(raw)
		if err == nil {
			t.Errorf("OpenBrowser(%q) should have rejected the scheme, got nil error", raw)
			continue
		}
		// Empty url returns an "empty url" error; others return "unsupported scheme".
		if raw == "" {
			if !strings.Contains(err.Error(), "empty url") {
				t.Errorf("OpenBrowser(\"\") error should mention empty url, got: %v", err)
			}
			continue
		}
		if !strings.Contains(err.Error(), "unsupported scheme") {
			t.Errorf("OpenBrowser(%q) error should mention unsupported scheme, got: %v", raw, err)
		}
	}
}

// TestOpenBrowser_AcceptsHttpHttps verifies the allowlist lets valid targets
// through to the platform opener (we only assert no scheme-rejection error; the
// actual exec is skipped on unsupported platforms).
func TestOpenBrowser_AcceptsHttpHttps(t *testing.T) {
	for _, raw := range []string{"https://idaas.example.com/device", "http://localhost:8080/cb"} {
		// On CI/linux without a DE the exec may fail to start, but the failure
		// must NOT be a scheme rejection — it must be an exec-level error.
		err := OpenBrowser(raw)
		if err != nil && strings.Contains(err.Error(), "unsupported scheme") {
			t.Errorf("OpenBrowser(%q) should not reject scheme, got: %v", raw, err)
		}
	}
}

// TestOpenBrowser_RejectsUnparseable verifies malformed URLs are rejected.
func TestOpenBrowser_RejectsUnparseable(t *testing.T) {
	// Control characters make url.Parse fail.
	err := OpenBrowser("ht\x00tp://example.com")
	if err == nil {
		t.Fatal("OpenBrowser should reject unparseable url")
	}
	if !strings.Contains(err.Error(), "invalid url") {
		t.Errorf("OpenBrowser unparseable error should mention invalid url, got: %v", err)
	}
}
