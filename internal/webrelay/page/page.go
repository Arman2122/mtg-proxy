// Package page generates the bridge document: one dynamically built, no-store
// HTML response carrying a single inline nonce-bearing script and nothing else.
//
// The document is served for exactly one request -- a GET / whose bridge
// parameter resolves to a configured profile -- and it is the only place the
// bootstrap token ever appears. A reload has no query, so it gets the cover
// site instead, which is the intended one-shot lifecycle rather than a defect.
//
// # Why the headers are part of this package
//
// The script and the policy that lets it run are one artefact. A page served
// with a stale Content-Security-Policy is not a degraded page, it is a blank
// one: the client's WebView also injects its own document-start policy, the two
// intersect, and anything this response fails to permit is removed from the
// intersection. So [Bridge.Render] returns the headers with the bytes, and the
// test that pins the policy sits next to the script it is a policy for.
//
// Two negative requirements are as load-bearing as the positive ones, and both
// are easy to reintroduce by habit or by a middlebox default:
//
//   - No X-Frame-Options, no Cross-Origin-Opener-Policy, no
//     Cross-Origin-Embedder-Policy. The client's system-browser fallback loads
//     this document inside a frame owned by a loopback parent, and each of those
//     three headers breaks it.
//   - frame-ancestors names that loopback parent explicitly. It is the one
//     embedder allowed, and naming it is what makes the absence of
//     X-Frame-Options a decision rather than an omission.
package page

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	_ "embed"
)

// script is the bridge itself. Embedded rather than served as an asset so the
// page and the carrier it drives are versioned together, and so the document
// stays a single request with no second thing to cache, fingerprint or fail.
//
//go:embed bridge.js
var script string

// CarrierMode is the carrier the generated page runs. v1 defines four; this
// relay implements one, and the mode still travels because the bridge and the
// relay must agree about it and the client learns it from neither.
const CarrierMode = "websocket"

// nonceLength is the byte length of the per-response CSP nonce. 16 bytes is
// well past the 128 bits a nonce needs to be unguessable within one response.
const nonceLength = 16

// permissionsPolicy denies every feature the document has no use for. It is a
// belt on top of the CSP's braces: a WebView that honours one and not the other
// still refuses the same things.
const permissionsPolicy = "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), " +
	"camera=(), display-capture=(), document-domain=(), encrypted-media=(), " +
	"fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), " +
	"midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), " +
	"screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=()"

var (
	// ErrInvalidHost means the hostname is not the canonical LDH form. The
	// caller is expected to have canonicalised it already; this is the check
	// that stops a header from being forged out of one that was not.
	ErrInvalidHost = errors.New("bridge host is not a canonical hostname")

	// ErrInvalidToken means the bootstrap token is not the canonical unpadded
	// base64url spelling the relay mints.
	ErrInvalidToken = errors.New("bootstrap token is not canonical base64url")
)

// Bridge renders the document for one public hostname.
type Bridge struct {
	host   string
	csp    string
	header http.Header
}

// New builds a generator for host, which must already be the canonical
// lowercase LDH or A-label form the capability was derived over.
func New(host string) (*Bridge, error) {
	if err := checkHost(host); err != nil {
		return nil, err
	}

	bridge := &Bridge{host: host}

	// connect-src is the whole network surface of this document: its own origin
	// for the session endpoints, and the wss origin for the carrier. Nothing
	// else is reachable, which is also why a redirect anywhere is fatal rather
	// than followed.
	bridge.csp = strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"child-src 'none'",
		"connect-src 'self' wss://" + host,
		"font-src 'none'",
		"form-action 'none'",
		"frame-ancestors http://127.0.0.1:*",
		"frame-src 'none'",
		"img-src 'none'",
		"manifest-src 'none'",
		"media-src 'none'",
		"object-src 'none'",
		"script-src 'nonce-%s'",
		"style-src 'none'",
		"worker-src 'none'",
		"sandbox allow-same-origin allow-scripts",
	}, "; ")

	bridge.header = http.Header{
		"Content-Type":                 []string{"text/html; charset=utf-8"},
		"Cache-Control":                []string{"no-store"},
		"Pragma":                       []string{"no-cache"},
		"Referrer-Policy":              []string{"no-referrer"},
		"X-Content-Type-Options":       []string{"nosniff"},
		"X-Dns-Prefetch-Control":       []string{"off"},
		"Permissions-Policy":           []string{permissionsPolicy},
		"Cross-Origin-Resource-Policy": []string{"same-origin"},
	}

	return bridge, nil
}

// Document is one rendered bridge response.
type Document struct {
	HTML   []byte
	Header http.Header
}

// WriteTo writes the document's headers and body to w. It sets a status of 200
// itself, so the caller must not have written one.
func (d Document) WriteTo(w http.ResponseWriter) error {
	header := w.Header()

	for key, values := range d.Header {
		header[key] = values
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(d.HTML); err != nil {
		return fmt.Errorf("cannot write bridge document: %w", err)
	}

	return nil
}

// Render builds the document embedding one bootstrap token. Each call draws a
// fresh CSP nonce, so two responses never share the value that authorises their
// script.
func (b *Bridge) Render(token string) (Document, error) {
	if err := checkToken(token); err != nil {
		return Document{}, err
	}

	nonce, err := newNonce()
	if err != nil {
		return Document{}, err
	}

	// json.Marshal escapes <, > and & into \u00XX by default, which is exactly
	// what makes this safe to interpolate into a script element: neither the
	// host nor the token can close it, and both are already restricted to
	// alphabets that could not anyway. Two independent reasons, on purpose.
	boot, err := json.Marshal(map[string]string{
		"host":  b.host,
		"token": token,
		"mode":  CarrierMode,
	})
	if err != nil {
		return Document{}, fmt.Errorf("cannot encode bridge parameters: %w", err)
	}

	body := &bytes.Buffer{}
	body.Grow(len(script) + len(boot) + 256)
	body.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	body.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	body.WriteString(`</head><body><script nonce="`)
	body.WriteString(nonce)
	body.WriteString(`">var TPROXY_BOOT=`)
	body.Write(boot)
	body.WriteString(";\n")
	body.WriteString(script)
	body.WriteString(`</script></body></html>`)

	header := make(http.Header, len(b.header)+1)

	for key, values := range b.header {
		header[key] = values
	}

	header.Set("Content-Security-Policy", fmt.Sprintf(b.csp, nonce))

	return Document{HTML: body.Bytes(), Header: header}, nil
}

func newNonce() (string, error) {
	raw := make([]byte, nonceLength)

	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cannot draw a CSP nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// checkHost accepts only the lowercase LDH form. It is deliberately not an IDNA
// implementation: by the time a host reaches this package it has been through
// one, and the job here is to guarantee that whatever arrived cannot carry a
// CRLF, a quote or a space into a response header.
func checkHost(host string) error {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return fmt.Errorf("%w: %q", ErrInvalidHost, host)
	}

	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return fmt.Errorf("%w: %q", ErrInvalidHost, host)
		}
	}

	return nil
}

func checkToken(token string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("%w: %d characters", ErrInvalidToken, len(token))
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != token {
		return fmt.Errorf("%w: %d characters", ErrInvalidToken, len(token))
	}

	return nil
}
