package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An upstream proxy URL may carry the proxy's password, and doctor output is
// what operators paste into bug reports. The line that names the proxy being
// checked shows its user and address, and never the password.
func TestDoctorNeverPrintsAProxyPassword(t *testing.T) {
	t.Parallel()

	const (
		user     = "proxyuser"
		password = "pr0xyP4ssw0rd"
	)

	// Nothing listens on port 1 of the loopback address, so the check through
	// the proxy fails at once; what is under test is the line before it.
	d, out := newDoctor(t, doctorConfig(`
[network]
proxies = ["socks5://`+user+`:`+password+`@127.0.0.1:1"]
`), time.Second, nil)
	d.SkipNativeCheck = true

	ntw := &doctorNetwork{dial: refuseAll, publicIP: map[string]string{}}

	_, err := d.diagnose(ntw, fakeResolver{})
	require.NoError(t, err)

	assert.NotContains(t, out.String(), password, "doctor printed a proxy password")
	assert.Contains(t, out.String(), "Validate network connectivity with proxy socks5://"+user+":xxxxx@127.0.0.1:1",
		"doctor must still name the proxy it checks, and its user")
}
