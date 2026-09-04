package webrelay

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errReloadTest = errors.New("reload failed")

// A nil counter set must be usable everywhere, because most of this package's
// tests build an origin without one and the relay path calls these methods on
// every request and every frame.
//
// The nil receiver is a deliberate design choice rather than an accident, so it
// is asserted rather than assumed: a panic here would be a panic in the relay's
// hot path, reachable only in a configuration nothing else covers.
func TestNilCountersAreSafe(t *testing.T) {
	t.Parallel()

	var c *Counters

	require.NotPanics(t, func() {
		c.onSessionCreated()
		c.onSessionAttached()
		c.onStreamOpened()
		c.onStreamClosed()
		c.addBytesUp(10)
		c.addBytesDown(10)
		c.onCoverServed()
		c.onNotFound()
		c.onBadToken()
		c.onSessionLimit()
		c.SetProfiles([]string{"alice"})
		c.OnReload(time.Now(), nil)
	})

	require.Equal(t, RelayStats{}, c.Snapshot(time.Now(), 0, 0),
		"a nil set reports nothing rather than inventing zeroes with a start time")
}

// Uptime is measured from the relay starting, not from the first scrape.
func TestSnapshotMeasuresUptimeFromStart(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	c := NewCounters(start)

	stats := c.Snapshot(start.Add(90*time.Second), 1024, 3)

	require.Equal(t, start, stats.StartedAt)
	require.EqualValues(t, 90, stats.UptimeSeconds)
	require.EqualValues(t, 1024, stats.Sessions.Max)
	require.EqualValues(t, 3, stats.Sessions.Active,
		"active sessions come from the store, which is what enforces the limit")
}

// The refusal breakdown is the diagnostic. One number cannot tell "clients are
// presenting capabilities this relay does not recognise" from "this relay is at
// capacity", and those need different answers at three in the morning.
func TestRefusalsAreCountedSeparately(t *testing.T) {
	t.Parallel()

	c := NewCounters(time.Now())

	for range 3 {
		c.onCoverServed()
	}

	c.onNotFound()
	c.onNotFound()
	c.onBadToken()
	c.onSessionLimit()

	refused := c.Snapshot(time.Now(), 0, 0).Refused

	require.EqualValues(t, 3, refused.CoverServed)
	require.EqualValues(t, 2, refused.NotFound)
	require.EqualValues(t, 1, refused.BadToken)
	require.EqualValues(t, 1, refused.SessionLimit)
}

// A failed reload is counted separately from a successful one, and only a
// success moves the timestamp.
//
// This is what lets an operator tell "my SIGHUP did nothing" from "my SIGHUP
// was never delivered" -- two situations with no other visible difference.
func TestReloadOutcomesAreDistinguishable(t *testing.T) {
	t.Parallel()

	c := NewCounters(time.Now())

	require.Nil(t, c.Snapshot(time.Now(), 0, 0).LastReload,
		"a relay that has never reloaded reports null, not the zero time")

	good := time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC)
	c.OnReload(good, nil)

	c.OnReload(good.Add(time.Minute), errReloadTest)

	stats := c.Snapshot(time.Now(), 0, 0)

	require.EqualValues(t, 1, stats.Reloads)
	require.EqualValues(t, 1, stats.ReloadFails)
	require.NotNil(t, stats.LastReload)
	require.True(t, good.Equal(*stats.LastReload),
		"a failed reload must not advance the timestamp -- the profiles it left running are the old ones")
}

// Profile names replace the numbering, so the report lines up with the proxy's
// /stats instead of naming "profile 3".
func TestProfileNamesAreReported(t *testing.T) {
	t.Parallel()

	c := NewCounters(time.Now())

	require.Equal(t, []string{}, c.Snapshot(time.Now(), 0, 0).Profiles,
		"never null: something downstream will index this")

	c.SetProfiles([]string{"alice", "bob"})
	require.Equal(t, []string{"alice", "bob"}, c.Snapshot(time.Now(), 0, 0).Profiles)

	// A reload replaces the set rather than appending to it.
	c.SetProfiles([]string{"carol"})
	require.Equal(t, []string{"carol"}, c.Snapshot(time.Now(), 0, 0).Profiles)
}

// The snapshot must not hand out the slice it keeps, or a caller ranging over
// one report while a reload lands would race the writer.
func TestSnapshotProfilesAreACopy(t *testing.T) {
	t.Parallel()

	c := NewCounters(time.Now())
	c.SetProfiles([]string{"alice"})

	stats := c.Snapshot(time.Now(), 0, 0)
	stats.Profiles[0] = "mutated"

	require.Equal(t, []string{"alice"}, c.Snapshot(time.Now(), 0, 0).Profiles,
		"a caller must not be able to edit the relay's own profile list through a report")
}

// The stats handler answers GET /stats and nothing else.
func TestStatsHandlerServesOnlyItsOwnPath(t *testing.T) {
	t.Parallel()

	c := NewCounters(time.Now())
	c.SetProfiles([]string{"alice"})
	c.onSessionCreated()
	c.addBytesDown(4096)

	handler := NewStatsHandler(c, newStore(64, nil), time.Now)

	t.Run("GET /stats", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, StatsPath, nil))

		require.Equal(t, http.StatusOK, recorder.Code)
		require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))

		var stats RelayStats

		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &stats))
		require.Equal(t, []string{"alice"}, stats.Profiles)
		require.EqualValues(t, 1, stats.Sessions.Created)
		require.EqualValues(t, 64, stats.Sessions.Max)
		require.EqualValues(t, 4096, stats.Bytes.Down)
	})

	t.Run("another path", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

		require.Equal(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("a write method", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, StatsPath, nil))

		require.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		require.Equal(t, http.MethodGet, recorder.Header().Get("Allow"))
	})
}

// A stats address that other people can reach is refused outright.
//
// Refused rather than warned about, because this socket answers -- with no
// credential at all -- how many sessions the relay carries and how many bytes
// it has moved, which is exactly the traffic analysis the transport exists to
// deny. An operator who published that would have no reason to go looking in a
// log to find out.
func TestStatsBindMustBeLoopback(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		addr   string
		accept bool
	}{
		{name: "off by default", addr: "", accept: true},
		{name: "ipv4 loopback", addr: "127.0.0.1:8100", accept: true},
		{name: "another ipv4 loopback", addr: "127.0.0.2:8100", accept: true},
		{name: "ipv6 loopback", addr: "[::1]:8100", accept: true},
		{name: "all interfaces", addr: "0.0.0.0:8100", accept: false},
		{name: "all interfaces v6", addr: "[::]:8100", accept: false},
		{name: "a routable address", addr: "203.0.113.9:8100", accept: false},
		{name: "a name that could resolve anywhere", addr: "localhost:8100", accept: false},
		{name: "not an address at all", addr: "8100", accept: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateStatsBind(tc.addr)

			if tc.accept {
				require.NoError(t, err)

				return
			}

			require.Error(t, err, "%q must not be accepted", tc.addr)
		})
	}
}
