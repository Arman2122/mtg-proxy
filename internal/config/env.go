package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

// Environment variable names understood by ApplyEnvironment. The unprefixed
// names mirror the official telegrammessenger/proxy Docker image
// (https://hub.docker.com/r/telegrammessenger/proxy/), so its documented
// "docker run -e SECRET=... -e TAG=..." invocations work with mtg-proxy
// containers as well. MTG_-prefixed variants always win over the unprefixed
// ones, so generic names like SECRET cannot be captured by accident outside
// of a container.
const (
	// EnvSecret is the proxy secret. Either a full mtg secret (ee-prefixed
	// hex or base64) or, for parity with the official image, a bare 16-byte
	// hex key which is combined with EnvSecretHost into a FakeTLS secret.
	EnvSecret = "SECRET"

	// EnvSecretHost is the domain-fronting hostname used when EnvSecret
	// holds a bare 16-byte key. Ignored when EnvSecret is a full secret.
	EnvSecretHost = "SECRET_HOST"

	// EnvAdTag is the advertising tag issued by @MTProxybot (the official
	// image calls it TAG). An empty value clears the tag from the file.
	EnvAdTag = "TAG"

	// EnvBindTo is a comma-separated list of host:port pairs to listen on.
	// It has no unprefixed form: the official image does not document one.
	EnvBindTo = "MTG_BIND_TO"

	envPrefix = "MTG_"
)

// lookupEnv reads the MTG_-prefixed variant of name first and falls back to
// the bare official-image name.
func lookupEnv(name string) (string, bool) {
	if value, ok := os.LookupEnv(envPrefix + name); ok {
		return value, true
	}

	return os.LookupEnv(name)
}

// ApplyEnvironment overlays environment variables on top of a parsed config
// file. The environment always wins, mirroring how the official
// telegrammessenger/proxy image is configured per "docker run". It is applied
// on every config read, including hot reloads, so an env-pinned secret or tag
// survives a POST /reload.
func (c *Config) ApplyEnvironment() error {
	if err := c.applyEnvSecret(); err != nil {
		return err
	}

	if err := c.applyEnvAdTag(); err != nil {
		return err
	}

	return c.applyEnvBindTo()
}

func (c *Config) applyEnvSecret() error {
	value, ok := lookupEnv(EnvSecret)
	if !ok {
		return nil
	}

	secret, err := parseEnvSecret(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	// The environment fully defines the secret set: named [secrets] and
	// their [secret-ad-tags]/[secret-limits] from the file no longer apply.
	// Nor do its [[retiring-secret]] entries (D29): a previous key of a name
	// no longer in effect would dangle, and clearing it kills that old key,
	// which is the safe direction.
	c.Secret = secret
	c.Secrets = nil
	c.SecretAdTags = nil
	c.SecretLimits = nil
	c.RetiringSecrets = nil

	return nil
}

func parseEnvSecret(value string) (mtglib.Secret, error) {
	secret, err := mtglib.ParseSecret(value)
	if err != nil {
		return mtglib.Secret{}, fmt.Errorf("incorrect %s environment variable: %w", EnvSecret, err)
	}

	// The official telegrammessenger/proxy image uses bare 16-byte secrets, which
	// parse as hostless "plain". bind-to serves FakeTLS only and the environment
	// cannot declare the [[listener]] that would serve a hostless form, so pair it
	// with a fronting host rather than mint a secret nothing can accept. Keyed off
	// the parsed mode, not hex decodability: the same key also arrives base64url.
	if secret.Mode != mtglib.SecretModeFakeTLS {
		host, _ := lookupEnv(EnvSecretHost)
		if host = strings.TrimSpace(host); host == "" {
			return mtglib.Secret{}, fmt.Errorf(
				"%s is a %s-mode secret with no fronting hostname; the bind-to listener serves FakeTLS "+
					"only and the environment cannot declare a [[listener]], so either set %s to a fronting "+
					"domain, provide a full ee-prefixed secret, or move the secret into the config file's "+
					"[secrets] table alongside a matching [[listener]]", EnvSecret, secret.Mode, EnvSecretHost,
			)
		}

		secret.Host = host
		secret.Mode = mtglib.SecretModeFakeTLS
	}

	return secret, nil
}

func (c *Config) applyEnvAdTag() error {
	value, ok := lookupEnv(EnvAdTag)
	if !ok {
		return nil
	}

	if err := c.AdTag.Set(strings.TrimSpace(value)); err != nil {
		return fmt.Errorf("incorrect %s environment variable: %w", EnvAdTag, err)
	}

	return nil
}

func (c *Config) applyEnvBindTo() error {
	value, ok := os.LookupEnv(EnvBindTo)
	if !ok {
		return nil
	}

	parts := strings.Split(value, ",")
	binds := make([]TypeHostPort, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		hp := TypeHostPort{}
		if err := hp.Set(part); err != nil {
			return fmt.Errorf("incorrect %s environment variable: %w", EnvBindTo, err)
		}

		binds = append(binds, hp)
	}

	if len(binds) == 0 {
		return fmt.Errorf("%s must contain at least one host:port", EnvBindTo)
	}

	c.BindTo = binds

	return nil
}
