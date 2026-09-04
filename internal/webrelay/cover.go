package webrelay

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
)

// The cover site is what this hostname is, as far as everyone who is not a
// Telegram client is concerned. It answers every request that carries no
// credential of ours, on every path, including the API ones.
//
// No default is shipped, and that is a decision rather than an omission. A
// starter page that many operators installed would become the signature: the
// body, the asset set and the response timing of "the thing tproxy operators
// serve" is a far better distinguisher than anything the protocol leaks.

// NewStaticCover serves a directory as the cover site.
//
// Directory listings are disabled. An index of the operator's files is both an
// information leak and a fingerprint -- Go's own listing markup is recognisable
// at a glance -- so a directory without an index page is a 404, exactly as it
// would be on an ordinary web server.
func NewStaticCover(root string) (http.Handler, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot serve the cover site from %q: %w", root, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("cover site root %q is not a directory", root)
	}

	files := http.FileServer(http.Dir(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := r.URL.Path
		if !strings.HasPrefix(upath, "/") {
			upath = "/" + upath
		}

		if strings.HasSuffix(upath, "/") {
			if _, err := os.Stat(path.Join(root, path.Clean(upath), "index.html")); err != nil {
				http.NotFound(w, r)

				return
			}
		}

		files.ServeHTTP(w, r)
	}), nil
}

// NewUpstreamCover reverse-proxies the cover site to an application.
//
// Method, path, raw query, headers and body all travel unchanged, because the
// point is that this hostname behaves exactly like the site behind it. The one
// thing deliberately not added is an X-Forwarded-* set: the relay is not
// announcing itself to the upstream, and a header that appears only on this
// deployment is one more thing to tell it apart by.
func NewUpstreamCover(target string) (http.Handler, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the cover upstream %q: %w", target, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("cover upstream %q must be an http or https URL", target)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = parsed.Scheme
			r.Out.URL.Host = parsed.Host
			r.Out.Host = r.In.Host
			r.Out.URL.Path = r.In.URL.Path
			r.Out.URL.RawQuery = r.In.URL.RawQuery
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// An upstream that is down must look like an ordinary bad gateway,
			// not like a relay reporting an internal failure.
			http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		},
	}

	return proxy, nil
}
