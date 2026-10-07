package mtglib

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

// Kicking: a panel that counts a user's devices across systems itself, and has
// decided one is one too many, ends that device's streams here without
// touching the user's others. It is the address limit's counterpart: the limit
// refuses the next connection from a new place, the kick ends the ones a place
// already holds.

// ErrKickAddresses is wrapped by every validation failure of a kick request, so
// the API can map all of them to one status.
var ErrKickAddresses = errors.New("invalid kick addresses")

// ParseKickAddresses validates the places a kick names: at least one literal
// IP address, each without a zone. Every failure wraps ErrKickAddresses.
func ParseKickAddresses(ips []string) ([]netip.Addr, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses", ErrKickAddresses)
	}

	addrs := make([]netip.Addr, 0, len(ips))

	for _, text := range ips {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not an IP address", ErrKickAddresses, text)
		}

		if addr.Zone() != "" {
			return nil, fmt.Errorf("%w: %q carries a zone", ErrKickAddresses, text)
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// Kick closes every live stream of the named secret whose client is at one of
// addrs and reports how many it closed. An address is matched at the unit the
// address limit counts, so an IPv6 address kicks its whole /64: the device that
// rotated its low bits is still the device that was kicked. Streams are
// snapshotted under liveMu and closed outside it, because each stream's own
// unregister takes the lock too. The secret must exist; a user with no stream
// at those places is a kick of zero, not an error.
func (p *Proxy) Kick(name string, addrs []netip.Addr) (int, error) {
	if !p.hasSecret(name) {
		return 0, fmt.Errorf("%w: %q", ErrSecretNotFound, name)
	}

	keys := make(map[addressKey]struct{}, len(addrs))
	for _, addr := range addrs {
		keys[keyOfAddr(addr)] = struct{}{}
	}

	p.liveMu.Lock()
	kicked := p.streamsAtLocked(name, keys)
	p.liveMu.Unlock()

	for _, sc := range kicked {
		sc.Close()
	}

	if len(kicked) > 0 {
		p.logger.BindStr("secret_name", name).BindInt("closed", len(kicked)).Info("streams kicked through the API")
	}

	return len(kicked), nil
}

// streamsAtLocked lists the named secret's live streams counted at one of keys:
// the streams a kick or a ban of those places ends. Caller holds liveMu, and
// closes them after letting go of it.
func (p *Proxy) streamsAtLocked(name string, keys map[addressKey]struct{}) []*streamContext {
	var found []*streamContext

	for sc := range p.liveConns[name] {
		if !sc.addrCounted {
			continue
		}

		if _, hit := keys[sc.addrKey]; hit {
			found = append(found, sc)
		}
	}

	return found
}

// kickRequest is the POST /secrets/{name}/kick body: the places to end the
// user's streams at.
type kickRequest struct {
	IPs []string `json:"ips"`
}

// KickResult is its answer: how many streams were closed.
type KickResult struct {
	Closed int `json:"closed"`
}

// handleKick serves POST /secrets/{name}/kick.
func (p *Proxy) handleKick(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req kickRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	addrs, err := ParseKickAddresses(req.IPs)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	closed, err := p.Kick(name, addrs)
	if err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, KickResult{Closed: closed})
}
