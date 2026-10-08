package mtglib

import (
	"context"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refusals admission can make carry their reason: tryRegisterConn and
// attribute say why, so the doors and admit can tell one refusal from another.
// This file pins what a refusal does today -- the ip-limit one, the only one
// anything produces -- and the order and the rollback of the steps that
// admission is made of, so the refusals added later slot into a structure that
// already leaves the ledger as it found it.

// denyDenialMessage is the one log line every admission refusal writes.
const denyDenialMessage = "connection denied by per-user limit"

// denyProbeRecord keeps the log lines a probe proxy wrote, with the fields bound
// to each, so a test can assert on the reason a refusal names.
type denyProbeRecord struct {
	mu    sync.Mutex
	lines []denyProbeLine
}

type denyProbeLine struct {
	msg    string
	fields map[string]string
}

func (r *denyProbeRecord) add(msg string, fields map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines = append(r.lines, denyProbeLine{msg: msg, fields: fields})
}

// denyReasons lists the deny_reason of every refusal line, in order.
func (r *denyProbeRecord) denyReasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var reasons []string

	for _, line := range r.lines {
		if line.msg == denyDenialMessage {
			reasons = append(reasons, line.fields["deny_reason"])
		}
	}

	return reasons
}

// denyProbeLogger is a Logger that records what it is told to say.
type denyProbeLogger struct {
	record *denyProbeRecord
	fields map[string]string
}

func (l denyProbeLogger) bind(name, value string) Logger {
	fields := make(map[string]string, len(l.fields)+1)
	for k, v := range l.fields {
		fields[k] = v
	}

	fields[name] = value

	return denyProbeLogger{record: l.record, fields: fields}
}

func (l denyProbeLogger) Named(string) Logger              { return l }
func (l denyProbeLogger) BindInt(n string, v int) Logger   { return l.bind(n, strconv.Itoa(v)) }
func (l denyProbeLogger) BindStr(n, v string) Logger       { return l.bind(n, v) }
func (l denyProbeLogger) BindJSON(n, v string) Logger      { return l.bind(n, v) }
func (l denyProbeLogger) Printf(string, ...any)            {}
func (l denyProbeLogger) Info(msg string)                  { l.record.add(msg, l.fields) }
func (l denyProbeLogger) InfoError(msg string, _ error)    { l.record.add(msg, l.fields) }
func (l denyProbeLogger) Warning(msg string)               { l.record.add(msg, l.fields) }
func (l denyProbeLogger) WarningError(msg string, _ error) { l.record.add(msg, l.fields) }
func (l denyProbeLogger) Debug(string)                     {}
func (l denyProbeLogger) DebugError(string, error)         {}

// denyProbe is a hand-built proxy and the streams to put through its admission,
// with no sockets and no handshake: just the registry, the ledger, the counters,
// the observer and the log, which is everything admit touches.
type denyProbe struct {
	proxy  *Proxy
	events *recordingEventStream
	log    *denyProbeRecord
}

func newDenyProbe(t *testing.T) *denyProbe {
	t.Helper()

	events := &recordingEventStream{}
	record := &denyProbeRecord{}

	proxy := &Proxy{
		stats:       NewProxyStats(),
		liveConns:   make(map[string]map[*streamContext]struct{}),
		logger:      denyProbeLogger{record: record},
		eventStream: events,
	}
	proxy.stats.PreRegister("alice")

	return &denyProbe{proxy: proxy, events: events, log: record}
}

// stream is a stream of alice's as attribution leaves it, coming from addr with
// the address limit the secret had when it matched. When the probe holds a
// secret set, the stream carries alice's key in it, as a door would have
// attributed it then (attributeFromSet); a probe with no set leaves it none.
func (d *denyProbe) stream(t *testing.T, addr net.Addr, ipLimit int) *streamContext {
	t.Helper()

	server, peer := net.Pipe()
	t.Cleanup(func() {
		server.Close() //nolint: errcheck
		peer.Close()   //nolint: errcheck
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sc := &streamContext{
		ctx:          ctx,
		ctxCancel:    cancel,
		clientSocket: remoteAddrConn{Conn: essentials.WrapNetConn(server), addr: addr},
		streamID:     "probe",
		secretName:   "alice",
		ipLimit:      ipLimit,
		logger:       denyProbeLogger{record: d.log}.BindStr("secret_name", "alice"),
	}

	attributeFromSet(t, d.proxy, sc)

	return sc
}

// ledgerCounts is alice's live connections per address as the ledger holds
// them, or nil when she has no ledger at all.
func (d *denyProbe) ledgerCounts() map[addressKey]int {
	d.proxy.liveMu.Lock()
	defer d.proxy.liveMu.Unlock()

	ledger := d.proxy.addresses["alice"]
	if ledger == nil {
		return nil
	}

	counts := make(map[addressKey]int, len(ledger.local))
	for key, n := range ledger.local {
		counts[key] = n
	}

	return counts
}

func (d *denyProbe) registered() int {
	d.proxy.liveMu.Lock()
	defer d.proxy.liveMu.Unlock()

	return len(d.proxy.liveConns["alice"])
}

func (d *denyProbe) ipLimited() int {
	return d.events.count(func(evt Event) bool {
		limited, ok := evt.(EventIPLimited)

		return ok && limited.SecretName == "alice"
	})
}

// A user at their address limit is turned away from a new address: admit says
// no, the refusal is counted as an address-limit refusal, it is announced to the
// observer, it is logged under its reason, and nothing about the user's live
// connections or ledger moves.
func TestAdmitIPLimitRefusalIsAccounted(t *testing.T) {
	t.Parallel()

	probe := newDenyProbe(t)
	user := probe.proxy.stats.users["alice"]

	held := probe.stream(t, tcpFrom("198.51.100.7", 50001), 1)
	require.True(t, probe.proxy.admit(held))

	sibling := probe.stream(t, tcpFrom("198.51.100.7", 50002), 1)
	require.True(t, probe.proxy.admit(sibling), "a second socket from the same place is the same device")

	stranger := probe.stream(t, tcpFrom("203.0.113.9", 50003), 1)
	require.False(t, probe.proxy.admit(stranger))

	assert.EqualValues(t, 1, user.ipLimitRefused.Load())
	assert.Zero(t, user.clientConnsRefused.Load(), "the address limit is not the connection cap")
	assert.Equal(t, 1, probe.ipLimited(), "the observer is told, once, which secret")
	assert.Equal(t, []string{"ip_limit"}, probe.log.denyReasons())

	assert.EqualValues(t, 2, user.connections.Load(), "a refused connection was never counted")
	assert.Equal(t, 2, probe.registered())
	assert.Equal(t, map[addressKey]int{"198.51.100.7": 2}, probe.ledgerCounts(),
		"the refused address left nothing behind")
	assert.False(t, stranger.addrCounted)

	// And the refusal released nothing it did not take: the two live sockets
	// still hold the place, and letting go of them empties the ledger.
	probe.proxy.release(held)
	probe.proxy.release(sibling)

	assert.Nil(t, probe.ledgerCounts())
	assert.Zero(t, probe.registered())
}

// A limit with no address to count against fails closed, and is an address-limit
// refusal like any other; the same connection with no limit is admitted, and is
// not counted.
func TestAdmitIPLimitWithoutAnAddressFailsClosed(t *testing.T) {
	t.Parallel()

	nowhere := &net.UnixAddr{Name: "@nowhere", Net: "unix"}

	t.Run("limited", func(t *testing.T) {
		t.Parallel()

		probe := newDenyProbe(t)

		require.False(t, probe.proxy.admit(probe.stream(t, nowhere, 1)))

		assert.EqualValues(t, 1, probe.proxy.stats.users["alice"].ipLimitRefused.Load())
		assert.Equal(t, 1, probe.ipLimited())
		assert.Equal(t, []string{"ip_limit"}, probe.log.denyReasons())
		assert.Zero(t, probe.registered())
		assert.Nil(t, probe.ledgerCounts())
	})

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()

		probe := newDenyProbe(t)

		require.True(t, probe.proxy.admit(probe.stream(t, nowhere, 0)))

		assert.Zero(t, probe.proxy.stats.users["alice"].ipLimitRefused.Load())
		assert.Zero(t, probe.ipLimited())
		assert.Equal(t, 1, probe.registered())
		assert.Nil(t, probe.ledgerCounts(), "nothing to count, nothing counted")
	})
}

// The refusal reaches the client the same way on every door: the stream is
// closed after the handshake, so the connection ends rather than being relayed,
// and the refusal is counted and announced exactly once.
func TestIPLimitRefusalClosesTheStreamOnEveryDoor(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret},
				map[string]SecretLimits{"alice": {IPLimit: 1}})

			held, heldDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.7", 50001))
			heldUp := connectThrough(t, ec, h, held, "alice", secret.Key)

			defer endStream(held, heldUp, heldDone)

			client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50002))
			ec.openEntry(t, client, secret.Key)

			require.True(t, govAwait(done, govDenyBudget),
				"a connection from one address too many must be refused, not relayed")

			require.NoError(t, client.SetReadDeadline(time.Now().Add(govDenyBudget)))

			_, err := io.Copy(io.Discard, client)
			assert.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the proxy must have closed the connection")

			user := h.proxy.stats.users["alice"]

			assert.EqualValues(t, 1, user.ipLimitRefused.Load())
			assert.EqualValues(t, 1, user.connections.Load(), "only the held stream was counted")
			assert.Zero(t, user.clientConnsRefused.Load(), "the address limit is not the connection cap")
			assert.Equal(t, 1, h.events.count(func(evt Event) bool {
				limited, ok := evt.(EventIPLimited)

				return ok && limited.SecretName == "alice"
			}))
		})
	}
}

// The reasons have a label each, the labels are distinct, and the two new
// reasons sit after the existing ones so nothing already numbered moves.
func TestDenyReasonLabels(t *testing.T) {
	t.Parallel()

	labels := map[DenyReason]string{
		DenyNone:        "allowed",
		DenyDisabled:    "disabled",
		DenyExpired:     "expired",
		DenyQuota:       "quota_exceeded",
		DenyIPLimit:     "ip_limit",
		DenyClientConns: "client_conns",
		DenyBanned:      "banned",
	}

	seen := make(map[string]DenyReason, len(labels))

	for reason, label := range labels {
		assert.Equal(t, label, reason.String())

		if other, dup := seen[label]; dup {
			t.Errorf("reasons %d and %d share the label %q", other, reason, label)
		}

		seen[label] = reason
	}

	assert.Equal(t, DenyNone, DenyReason(0), "the zero value is the allowed one")
	assert.Less(t, DenyIPLimit, DenyClientConns)
	assert.Less(t, DenyClientConns, DenyBanned)
}

// tryRegisterConn says why it refused: the address limit is the only reason
// anything produces, with an address and without one.
func TestTryRegisterConnSaysWhy(t *testing.T) {
	t.Parallel()

	probe := newDenyProbe(t)

	assert.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.7", 50001), 1)))
	assert.Equal(t, DenyIPLimit, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.9", 50002), 1)),
		"a second place at a limit of one")
	assert.Equal(t, DenyIPLimit,
		probe.proxy.tryRegisterConn(probe.stream(t, &net.UnixAddr{Name: "@nowhere", Net: "unix"}, 1)),
		"a limit with no address to count fails closed, and says it is the address limit")
	assert.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.7", 50003), 1)),
		"the place already held is admitted again")
}

// attribute says why it refused, and binds what attribution binds whether or
// not it refuses.
func TestAttributeSaysWhy(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"alice": GenerateSecret("cover.example.com"),
		"bob":   GenerateSecret("cover.example.com"),
		"carol": GenerateSecret("cover.example.com"),
		"dave":  GenerateSecret("cover.example.com"),
		"erin":  GenerateSecret("cover.example.com"),
	}

	set := buildSecretSet(secrets, nil, nil, map[string]SecretLimits{
		"alice": {Disabled: true},
		"bob":   {ExpiresAt: time.Now().Add(-time.Hour)},
		"carol": {QuotaBytes: 1000},
		"dave":  {IPLimit: 3},
	})

	probe := newDenyProbe(t)
	probe.proxy.stats.PreRegister("carol")
	probe.proxy.stats.users["carol"].quotaUsed.Store(1000)

	for name, want := range map[string]DenyReason{
		"alice": DenyDisabled,
		"bob":   DenyExpired,
		"carol": DenyQuota,
		"dave":  DenyNone,
		"erin":  DenyNone,
	} {
		index := slices.Index(set.names, name)
		require.NotEqual(t, -1, index)

		sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)

		assert.Equal(t, want, probe.proxy.attribute(sc, set, index), name)
		assert.Equal(t, name, sc.secretName, "attribution binds the name even when it refuses")
	}

	sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)

	require.Equal(t, DenyNone, probe.proxy.attribute(sc, set, slices.Index(set.names, "dave")))
	assert.Equal(t, 3, sc.ipLimit, "and the limit the secret had when it matched")
}

// The seam the tests below use is a package variable, so the tests that swap it
// are not parallel: they run before any parallel test resumes, and put it back.
func installRegisterStepHook(t *testing.T, hook func(registerStep, *streamContext) DenyReason) {
	t.Helper()

	previous := registerStepHook
	registerStepHook = hook

	t.Cleanup(func() { registerStepHook = previous })
}

// The steps run in the stated order: the address ledger counts the stream, then
// the per-address table is asked for its entry, before the stream is entered
// into the registry, and nothing marks the stream counted until every step has
// passed. The hook runs under liveMu, so it reads the registry directly.
func TestRegisterStepsRunInOrder(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe := newDenyProbe(t)

	var (
		calls         []registerStep
		ledgerInHook  map[addressKey]int
		registeredNow int
		countedNow    bool
	)

	installRegisterStepHook(t, func(step registerStep, sc *streamContext) DenyReason {
		calls = append(calls, step)
		registeredNow = len(probe.proxy.liveConns["alice"])
		countedNow = sc.addrCounted
		ledgerInHook = map[addressKey]int{}

		if ledger := probe.proxy.addresses["alice"]; ledger != nil {
			for key, n := range ledger.local {
				ledgerInHook[key] = n
			}
		}

		return DenyNone
	})

	sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 1)

	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(sc))

	assert.Equal(t, []registerStep{stepLedgerAdmitted, stepEntryAcquired}, calls)
	assert.Equal(t, map[addressKey]int{"198.51.100.7": 1}, ledgerInHook, "the ledger has counted the stream by then")
	assert.Zero(t, registeredNow, "and the registry has not")
	assert.False(t, countedNow, "and the stream is not yet marked counted")

	assert.Equal(t, 1, probe.registered())
	assert.True(t, sc.addrCounted)
	assert.Equal(t, addressKey("198.51.100.7"), sc.addrKey)
}

// A refusal at a later step gives back what an earlier step took: the ledger is
// exactly as it was, an address that was the only thing in it leaves no ledger
// behind, and the slot it would have held is free for the next arrival.
func TestRefusalAfterTheLedgerStepLeavesTheLedgerAsItWas(t *testing.T) { //nolint: paralleltest // swaps a package variable
	t.Run("first attempt leaves no ledger", func(t *testing.T) {
		probe := newDenyProbe(t)

		refuse := true

		installRegisterStepHook(t, func(registerStep, *streamContext) DenyReason {
			if refuse {
				return DenyClientConns
			}

			return DenyNone
		})

		sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 1)

		assert.Equal(t, DenyClientConns, probe.proxy.tryRegisterConn(sc))
		assert.Nil(t, probe.ledgerCounts(), "a ledger the refusal created is gone with it")
		assert.Zero(t, probe.registered())
		assert.False(t, sc.addrCounted)

		// The slot was not leaked: at a limit of one, a different place is
		// admitted now that the refused one holds nothing.
		refuse = false

		other := probe.stream(t, tcpFrom("203.0.113.9", 50002), 1)

		assert.Equal(t, DenyNone, probe.proxy.tryRegisterConn(other))
		assert.Equal(t, map[addressKey]int{"203.0.113.9": 1}, probe.ledgerCounts())
	})

	t.Run("a held ledger is left equal", func(t *testing.T) {
		probe := newDenyProbe(t)

		require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.7", 50001), 2)))
		require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.7", 50002), 2)))
		require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.9", 50003), 2)))

		before := probe.ledgerCounts()
		require.Equal(t, map[addressKey]int{"198.51.100.7": 2, "203.0.113.9": 1}, before)

		installRegisterStepHook(t, func(registerStep, *streamContext) DenyReason { return DenyBanned })

		// From a place the ledger holds, and from one it does not: whichever it
		// took, the refusal took it back, and no more than it took. At a limit of
		// two the third place is refused by the address limit before the hook is
		// reached; the hook refuses the other two after the ledger counted them.
		for _, from := range []string{"198.51.100.7", "203.0.113.9", "192.0.2.44"} {
			sc := probe.stream(t, tcpFrom(from, 50100), 2)

			assert.NotEqual(t, DenyNone, probe.proxy.tryRegisterConn(sc), from)
			assert.False(t, sc.addrCounted, from)
			assert.Equal(t, before, probe.ledgerCounts(), "after a refusal from %s", from)
			assert.Equal(t, 3, probe.registered(), from)
		}
	})
}

// admit gives each reason its own accounting: the address limit keeps its
// counter and its event exactly as before, the connection cap has a counter of
// its own and no event, a ban has neither, and any other reason still refuses --
// a reason admit does not know about must never be let through.
func TestAdmitMapsEveryReasonToItsOwnAccounting(t *testing.T) { //nolint: paralleltest // swaps a package variable
	cases := []struct {
		reason      DenyReason
		ipLimited   int64
		clientConns int64
		events      int
	}{
		{DenyIPLimit, 1, 0, 1},
		{DenyClientConns, 0, 1, 0},
		{DenyBanned, 0, 0, 0},
		{DenyQuota, 0, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.reason.String(), func(t *testing.T) {
			probe := newDenyProbe(t)
			user := probe.proxy.stats.users["alice"]

			installRegisterStepHook(t, func(registerStep, *streamContext) DenyReason { return tc.reason })

			sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)

			require.False(t, probe.proxy.admit(sc))

			assert.Equal(t, tc.ipLimited, user.ipLimitRefused.Load(), "ip_limit_refused")
			assert.Equal(t, tc.clientConns, user.clientConnsRefused.Load(), "client_conns_refused")
			assert.Equal(t, tc.events, probe.ipLimited(), "EventIPLimited")
			assert.Equal(t, tc.events, probe.events.count(func(Event) bool { return true }),
				"no event type other than EventIPLimited is emitted")
			assert.Equal(t, []string{tc.reason.String()}, probe.log.denyReasons())

			assert.Zero(t, user.connections.Load(), "a refused connection was never counted")
			assert.Zero(t, probe.registered())
			assert.Nil(t, probe.ledgerCounts(), "whatever the reason, the ledger is as it was")
		})
	}
}
