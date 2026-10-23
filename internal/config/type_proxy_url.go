package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
)

const typeProxyURLDefaultSOCKS5Port = "1080"

type TypeProxyURL struct {
	Value *url.URL
}

// Set takes a proxy URL, which may carry the proxy's credentials
// (socks5://user:password@host). A refusal therefore never quotes the text it
// was given: url.Parse's own error holds the whole URL, so only its reason is
// kept, and a URL that did parse is shown with its password redacted.
func (t *TypeProxyURL) Set(value string) error {
	parsedURL, err := url.Parse(value)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}

		return fmt.Errorf("value is not correct URL: %w", err)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("url has to have a schema: %s", parsedURL.Redacted())
	}

	switch parsedURL.Scheme {
	case "socks5", "socks5h":
	default:
		return fmt.Errorf("unsupported schema: %s", parsedURL.Scheme)
	}

	if _, _, err := net.SplitHostPort(parsedURL.Host); err != nil {
		parsedURL.Host = net.JoinHostPort(
			parsedURL.Host,
			typeProxyURLDefaultSOCKS5Port,
		)
	}

	t.Value = parsedURL

	return nil
}

func (t *TypeProxyURL) Get(defaultValue *url.URL) *url.URL {
	if t.Value == nil {
		return defaultValue
	}

	return t.Value
}

func (t *TypeProxyURL) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeProxyURL) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeProxyURL) String() string {
	if t.Value == nil {
		return ""
	}

	return t.Value.String()
}

// Redacted is the URL as a log line or a message may show it: the user and the
// address stay, so that it still says which upstream is meant, and the
// password does not (url.URL.Redacted: it becomes "xxxxx"). String keeps the
// password, because the config is written back from it and the dialer needs it.
func (t TypeProxyURL) Redacted() string {
	if t.Value == nil {
		return ""
	}

	return t.Value.Redacted()
}
