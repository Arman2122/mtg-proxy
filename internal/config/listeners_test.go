package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// eeSecret is a hosted secret in canonical ee form: every config below needs one
// so that V4 (the FakeTLS listener must have a cover site) is satisfied.
func eeSecret() string {
	return mtglib.GenerateSecret("cover.example.com").Hex()
}

// TestListenerScalarBindTo pins F1's first half: bind-to stays a scalar string
// and a [[listener]] sits alongside it without disturbing it.
func TestListenerScalarBindTo(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	require.Len(t, conf.BindTo, 1)
	assert.Equal(t, "0.0.0.0:443", conf.BindTo[0].Get(""))

	listeners := conf.GetListeners()
	require.Len(t, listeners, 1)
	assert.Equal(t, "127.0.0.1:2398", listeners[0].BindTo.Get(""))
	assert.Equal(t, []string{"dd", "plain"}, conf.GetListenerModes().Strings())
}

// TestListenerArrayBindTo pins F1's second half: bind-to as an array still
// works, and a [[listener]] coexists with it too.
func TestListenerArrayBindTo(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = ["127.0.0.1:443", "[::1]:443"]

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	require.Len(t, conf.BindTo, 2)
	assert.Equal(t, "127.0.0.1:443", conf.BindTo[0].Get(""))
	assert.Equal(t, "[::1]:443", conf.BindTo[1].Get(""))
	require.Len(t, conf.GetListeners(), 1)
	assert.Equal(t, []string{"dd"}, conf.GetListenerModes().Strings())
}

func TestNoListenersIsNil(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf("secret = \"%s\"\nbind-to = \"0.0.0.0:443\"\n", eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Nil(t, conf.GetListeners())
	assert.True(t, conf.GetListenerModes().Empty())
}

func TestListenerPolicyDefaults(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)

	policy, err := conf.GetListeners()[0].Policy()
	require.NoError(t, err)

	assert.True(t, policy.Modes.Has(mtglib.SecretModeDD))
	assert.True(t, policy.Modes.Has(mtglib.SecretModePlain))
	assert.False(t, policy.Modes.Has(mtglib.SecretModeFakeTLS))
	assert.False(t, policy.Public)
	assert.False(t, policy.ProxyProtocol)
	assert.Equal(t, mtglib.UnknownSecretClose, policy.OnUnknownSecret)
	assert.EqualValues(t, 30, policy.HandshakesPerIP)
}

func TestListenerPolicyExplicit(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "10.0.0.1:2398"
accept = ["plain"]
public = true
proxy-protocol = true
on-unknown-secret = "drain"
handshakes-per-ip = 7
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	policy, err := conf.GetListeners()[0].Policy()
	require.NoError(t, err)

	assert.Equal(t, []string{"plain"}, policy.Modes.Strings())
	assert.True(t, policy.Public)
	assert.True(t, policy.ProxyProtocol)
	assert.Equal(t, mtglib.UnknownSecretDrain, policy.OnUnknownSecret)
	assert.EqualValues(t, 7, policy.HandshakesPerIP)
}

// V1 -- one address serves one accept policy.
func TestValidateListenerDuplicatesBindTo(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:2398"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)

	err = conf.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two listeners bind 127.0.0.1:2398; one address serves one accept policy")
}

func TestValidateListenerDuplicatesAnotherListener(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["plain"]
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)

	err = conf.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two listeners bind 127.0.0.1:2398")
}

// An omitted [[listener]].bind-to never reaches V1's empty arm: TypeHostPort
// rejects "" at parse time. Pin both halves.
func TestListenerMissingBindToFailsAtParse(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
accept = ["dd"]
`, eeSecret())

	_, err := config.Parse([]byte(raw))
	assert.Error(t, err)
}

func TestValidateListenerEmptyAddress(t *testing.T) {
	t.Parallel()

	conf := &config.Config{}
	require.NoError(t, conf.Secret.Set(eeSecret()))

	var bind config.TypeHostPort
	require.NoError(t, bind.Set("0.0.0.0:443"))
	conf.BindTo = []config.TypeHostPort{bind}
	conf.Listeners = []config.ConfigListener{{
		Accept: []config.TypeSecretMode{{Value: mtglib.SecretModeDD}},
	}}

	err := conf.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect listener bind-to parameter: empty address")
}

// V2 -- accept must be a non-empty subset of ["dd","plain"].
func TestValidateListenerRejectsEE(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"ee", "faketls"} {
		raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "%s"]
`, eeSecret(), name)

		conf, err := config.Parse([]byte(raw))
		require.NoError(t, err, name)

		err = conf.Validate()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(),
			`listener 127.0.0.1:2398: accept must be a non-empty subset of ["dd","plain"]`, name)
	}
}

func TestValidateListenerRejectsEmptyAccept(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = []
`, eeSecret())

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)

	err = conf.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accept must be a non-empty subset")
}

func TestListenerRejectsUnknownAcceptValueAtParse(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["eee"]
`, eeSecret())

	_, err := config.Parse([]byte(raw))
	assert.Error(t, err)
}

func TestListenerRejectsUnknownActionAtParse(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
on-unknown-secret = "reset"
`, eeSecret())

	_, err := config.Parse([]byte(raw))
	assert.Error(t, err)
}

// V3 -- a non-loopback obfuscated2 listener must be acknowledged.
func TestValidateListenerPublicAcknowledgement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		addr   string
		public bool
		ok     bool
	}{
		{"127.0.0.1:2398", false, true},
		{"[::1]:2398", false, true},
		{"0.0.0.0:2398", false, false},
		{"0.0.0.0:2398", true, true},
		{"10.0.0.1:2398", false, false},
	} {
		raw := fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "%s"
accept = ["dd", "plain"]
public = %t
`, eeSecret(), tc.addr, tc.public)

		conf, err := config.Parse([]byte(raw))
		require.NoError(t, err, tc.addr)

		err = conf.Validate()

		if tc.ok {
			assert.NoError(t, err, tc.addr)

			continue
		}

		require.Error(t, err, tc.addr)
		assert.Contains(t, err.Error(),
			fmt.Sprintf("listener %s accepts [dd plain] on a public address.", tc.addr))
		assert.Contains(t, err.Error(), "Set public = true on this [[listener]] to confirm")
	}
}

// V4 -- the always-present FakeTLS listener must have a cover site.
func TestValidateNoFrontingHost(t *testing.T) {
	t.Parallel()

	raw := `
secret = "ee367a189aee18fa31c190054efd4a8e"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
`

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, mtglib.SecretModePlain, conf.Secret.Mode)

	err = conf.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(),
		"no secret carries a fronting hostname and domain-fronting.host is unset")
}

func TestValidateHostlessSecretWithFrontingHost(t *testing.T) {
	t.Parallel()

	raw := `
secret = "ee367a189aee18fa31c190054efd4a8e"
bind-to = "0.0.0.0:443"

[domain-fronting]
host = "cover.example.com"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
`

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	assert.NoError(t, conf.Validate())
}
