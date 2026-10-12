package network_test

import (
	"net/url"
	"testing"

	"github.com/Arman2122/mtg-proxy/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The error that refuses a proxy names it, and a proxy URL may carry the
// proxy's password.
func TestLoadBalancedSocks5RefusalNeverEchoesThePassword(t *testing.T) {
	t.Parallel()

	const password = "pr0xyP4ssw0rd"

	// No port: NewSocks5Dialer refuses it.
	_, err := network.NewLoadBalancedSocks5Dialer(&DialerMock{}, []*url.URL{
		{Scheme: "socks5", User: url.UserPassword("proxyuser", password), Host: "127.0.0.1"},
	})
	require.Error(t, err)

	assert.NotContains(t, err.Error(), password, "the refusal printed a proxy password")
	assert.Contains(t, err.Error(), "proxyuser", "the refusal must still name the proxy's user")
	assert.Contains(t, err.Error(), "127.0.0.1", "the refusal must still name the proxy's address")
}
