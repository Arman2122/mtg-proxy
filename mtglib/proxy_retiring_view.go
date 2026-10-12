package mtglib

import (
	"bytes"
	"time"
)

// The read-only view of an overlap (spec §5.3): what GET /stats and GET
// /secrets/{name} say about a name that still accepts a previous key. Four
// scalars, computed at read time from the set in force and the live registry,
// and never a key's value.

// retiringView is what the two read-backs say about one name's overlap. Only a
// name with at least one unexpired previous key has one, so keys is always
// positive, and the other three are meaningful only because it is.
type retiringView struct {
	// keys is how many previous keys of the name are still accepted at the read.
	keys int

	// until is the latest until among them, in UTC: when every old link of the
	// name has stopped working. Not the earliest, which is what the sweep waits
	// for (set.retiringNext).
	until time.Time

	// connections is how many live streams of the name hold a key that is not the
	// name's current primary.
	connections int

	// lastSeen is when a stream last came in on a previous key, or zero for never.
	// It is read from the counters whatever its age, and reported here only
	// because the name has a previous key now: a name whose overlap ended has no
	// view, so its stamp is kept and not shown.
	lastSeen time.Time
}

// retiringViews is the overlap of every name that has an unexpired previous key
// in set at now, by name, and nil when none has -- which is every set that keeps
// no retiring entry, answered without a clock read, a lock or an allocation (the
// callers check len(set.retiring) before reading the clock to pass in).
//
// now is the rotation clock's instant, read once by the caller for the whole
// response, so that a name's keys, its until and the streams counted against
// them are judged at the same time. An entry whose until is not after now is not
// counted: the sweep runs every few seconds, and between an until and the sweep
// the set still holds an entry that accepts nothing.
//
// connections is counted under liveMu, for the names in the result alone: each
// stream's matchedSecretKey is compared with the name's primary key in set. It
// is not an admission flag, deliberately. Right after a rotation every old-link
// stream was admitted as the primary, because it was one, and a flag set at
// admission would read zero exactly when the operator is watching the number
// fall. The stream's key was written by its own goroutine before it registered
// under this same lock, so the read here happens after the write.
//
// Nothing else is done under liveMu: the counters are read after it is let go,
// so no edge from the registry lock to the counters' lock is made. A name the
// counters hold no bucket for has no last seen.
//
// The result is for overlaying onto users that already exist. It is not a list
// of users, and a caller must never make one of a name only because it is here.
func (p *Proxy) retiringViews(set *secretSet, now time.Time) map[string]retiringView {
	if set == nil || len(set.retiring) == 0 {
		return nil
	}

	var (
		views map[string]retiringView
		names []int // the index in set.names of each name in views, in no order
	)

	for i, entries := range set.retiringOf {
		var view retiringView

		for _, r := range entries {
			entry := &set.retiring[r]
			if !now.Before(entry.until) {
				continue
			}

			view.keys++

			if entry.until.After(view.until) {
				view.until = entry.until
			}
		}

		// A name whose every entry has expired has no view, whatever its counters
		// say: this is the only place that decides retiring_last_seen is reported
		// only while the name has a key.
		if view.keys == 0 {
			continue
		}

		if views == nil {
			views = make(map[string]retiringView, len(set.retiringOf))
		}

		view.until = view.until.UTC()
		views[set.names[i]] = view
		names = append(names, i)
	}

	if views == nil {
		return nil
	}

	counts := make([]int, len(names))

	p.liveMu.Lock()

	for k, i := range names {
		primary := set.secrets[i].Key[:]

		for sc := range p.liveConns[set.names[i]] {
			if !bytes.Equal(sc.matchedSecretKey, primary) {
				counts[k]++
			}
		}
	}

	p.liveMu.Unlock()

	for k, i := range names {
		name := set.names[i]
		view := views[name]

		view.connections = counts[k]
		view.lastSeen = p.stats.retiringSeenAt(name)
		views[name] = view
	}

	return views
}

// times is the view's two times as the pointers a read-back carries: until
// always, since a view exists only for a name that has a key until something,
// and lastSeen only when a stream ever came in on a previous key, so that the
// omitempty tag leaves it out otherwise. Each is a copy of its own; the view
// is passed by value.
func (v retiringView) times() (*time.Time, *time.Time) {
	until := v.until

	if v.lastSeen.IsZero() {
		return &until, nil
	}

	lastSeen := v.lastSeen

	return &until, &lastSeen
}

// markRetiringSeen records an admission made under one of the name's retiring
// keys at at. A timestamp for the operator, not a decision: it is not read by the
// rotation clock and nothing acts on it.
func (s *ProxyStats) markRetiringSeen(name string, at time.Time) {
	s.getOrCreate(name).retiringLastSeen.Store(at.UnixNano())
}

// retiringSeenAt is when the last admission under a retiring key of the name was
// recorded, in UTC, and the zero time for never. Reading never creates a bucket.
func (s *ProxyStats) retiringSeenAt(name string) time.Time {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if !ok {
		return time.Time{}
	}

	nanos := st.retiringLastSeen.Load()
	if nanos == 0 {
		return time.Time{}
	}

	return time.Unix(0, nanos).UTC()
}
