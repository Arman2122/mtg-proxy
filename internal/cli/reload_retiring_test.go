package cli

import (
	"os"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/antireplay"
	"github.com/Arman2122/mtg-proxy/events"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/ipblocklist"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reloadingProxy writes initial to path and builds a proxy on it the way run
// does: its first set from the file judged on the proxy's clock, and its
// reload through run's own reloader on that same clock. It reaches no network
// and listens on nothing; a test drives it through ReloadSecrets and reads it
// back through SnapshotSecrets.
func reloadingProxy(t *testing.T, path, initial string) *mtglib.Proxy {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte(initial), 0o600))

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	log := logger.NewNoopLogger()
	clock := mtglib.NewRotationClock(time.Now, nil)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Network:         &doctorNetwork{dial: refuseAll},
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     ipblocklist.NewNoop(),
		EventStream:     events.NewNoopStream(),
		Logger:          log,
		Secrets:         conf.GetSecrets(),
		RetiringSecrets: conf.GetRetiringSecrets(clock.Now()).Usable,
		RotationClock:   clock,
		SecretsReloader: makeSecretsReloader(path, log, clock),
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	return proxy
}

// snapshotOf is the proxy's view of one secret, as GET /secrets shows it.
func snapshotOf(t *testing.T, proxy *mtglib.Proxy, name string) mtglib.SecretInfo {
	t.Helper()

	for _, info := range proxy.SnapshotSecrets() {
		if info.Name == name {
			return info
		}
	}

	t.Fatalf("the proxy has no secret %q", name)

	return mtglib.SecretInfo{}
}

// D4, §10. A hand edit re-keys [secrets] and, in the same save, writes a block
// with a typo in until. Refusing the reload would keep the leaked key as the
// primary and the new one dead -- the opposite of what the operator asked for.
// So the block is dropped with a Warning, and the rest of the file applies: the
// new primaries, and the other, well-formed block.
func TestAReloadWithABadBlockAppliesTheRest(t *testing.T) {
	t.Parallel()

	aliceOld := mtglib.GenerateSecret("cover.example.com")
	aliceNew := mtglib.GenerateSecret("cover.example.com")
	bobOld := mtglib.GenerateSecret("cover.example.com")
	bobNew := mtglib.GenerateSecret("cover.example.com")

	until := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	bindTo := "127.0.0.1:3128"

	before := retiringFile(bindTo, map[string]mtglib.Secret{"alice": aliceOld, "bob": bobOld})
	after := retiringFile(bindTo, map[string]mtglib.Secret{"alice": aliceNew, "bob": bobNew},
		retiringBlock("alice", aliceOld, "2026-10-09 09:30"),
		retiringBlock("bob", bobOld, rfc3339(until)))

	const badBlock = `retiring-secret #1 (name "alice"): until is not an RFC 3339 date-time with an offset, ` +
		`such as 2026-10-09T09:30:00Z; the entry is ignored and its key is not accepted`

	t.Run("the reloader", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, before)
		log, sink := newFieldLogger()
		reload := makeSecretsReloader(path, log, mtglib.NewRotationClock(time.Now, nil))

		require.NoError(t, os.WriteFile(path, []byte(after), 0o600))

		cfg, err := reload()
		require.NoError(t, err, "a problem in a block never refuses the reload")

		assert.True(t, cfg.Secrets["alice"] == aliceNew, "alice's new primary is applied")
		assert.True(t, cfg.Secrets["bob"] == bobNew, "bob's new primary is applied")

		require.Equal(t, 1, len(cfg.Retiring), "bob's block, and nothing for alice's")
		assert.Equal(t, "bob", cfg.Retiring[0].Name)
		assert.True(t, cfg.Retiring[0].Secret == bobOld, "bob's entry holds bob's old key")
		assert.True(t, cfg.Retiring[0].Until.Equal(until))

		warnings := sink.recorded()
		require.Len(t, warnings, 1)
		assert.Equal(t, badBlock, warnings[0].msg)
		assert.Empty(t, warnings[0].fields)
		require.Empty(t, retiringLeaks(warnings[0].text(), aliceOld, aliceNew, bobOld, bobNew), "the Warning carries a key")
	})

	t.Run("the proxy", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, before)
		proxy := reloadingProxy(t, path, before)

		require.NoError(t, os.WriteFile(path, []byte(after), 0o600))
		require.NoError(t, proxy.ReloadSecrets(), "a problem in a block never refuses the reload")

		alice := snapshotOf(t, proxy, "alice")
		assert.True(t, alice.Secret == aliceNew.Base64(), "alice's new primary is in force")
		assert.Zero(t, alice.RetiringKeys, "alice's old key is not accepted")

		bob := snapshotOf(t, proxy, "bob")
		assert.True(t, bob.Secret == bobNew.Base64(), "bob's new primary is in force")
		assert.Equal(t, 1, bob.RetiringKeys, "bob's old key is accepted until its until")
	})
}
