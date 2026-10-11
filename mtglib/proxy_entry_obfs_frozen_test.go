package mtglib

import (
	"errors"

	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// frozenDoObfuscatedEntry is doObfuscatedEntry as it stood at commit 765ec21,
// before rotation existed: the key list built inline from the set's secrets
// under `if allowed`, and attribution by the primary's index. It is kept as it
// was, comments trimmed, so that a test can ask what the live door costs
// against what the door cost, rather than against figures that depend on the
// toolchain (TestTheObfuscatedDoorAllocatesAsBefore). It is the E2 pattern for
// the door: never edit it to follow the live one.
func (p *Proxy) frozenDoObfuscatedEntry(ctx *streamContext, policy ListenerPolicy) bool {
	allowed := p.obfsLimiter.Allow(policy, ctx.ClientIP())

	set := p.secrets.Load()

	var keys [][]byte

	if allowed {
		keys = make([][]byte, len(set.secrets))
		for i := range set.secrets {
			keys[i] = set.secrets[i].Key[:]
		}

		p.obfsStats.OnObfuscatedTrial()
	}

	res, err := obfuscation.MatchHandshake(ctx.client(), keys, policy.Tags())

	switch {
	case err != nil && !errors.Is(err, obfuscation.ErrNoMatchingSecret):
		ctx.logger.InfoError("cannot read obfuscated handshake", err)

		return false
	case !allowed:
		p.obfsStats.OnObfuscatedRateLimited()

		return p.denyRateLimited(ctx, policy)
	case err != nil:
		p.obfsStats.OnObfuscatedMiss()
		p.obfsLimiter.Fail(policy, ctx.ClientIP())

		return p.denyObfuscated(ctx, policy)
	}

	if p.antiReplayCache.SeenBefore(res.ReplayKey()) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))

		return p.denyObfuscated(ctx, policy)
	}

	if reason := p.attribute(ctx, set, res.Index); reason != DenyNone {
		if reason == DenyBanned {
			p.obfsLimiter.Fail(policy, ctx.ClientIP())
		}

		return p.denyObfuscated(ctx, policy)
	}

	ctx.dc = res.DC
	ctx.connTag = res.Tag
	ctx.setClient(res.Conn)
	ctx.logger = ctx.logger.BindInt("dc", res.DC).BindStr("conn_tag", res.Tag.String())

	return true
}
