package mtglib

import (
	"fmt"
	"net"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/dc"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/middleproxy"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// The Telegram leg: dialling the DC, directly or through a middle proxy
// when the stream carries an ad tag, and the traffic accounting around it.

// wrapTraffic wraps conn so per-read/write byte counts are emitted as
// EventTraffic, but only when a metrics observer is configured (emitTraffic).
// EventTraffic is consumed solely by the statsd/prometheus observers, so when
// none is enabled the wrapper is skipped entirely — avoiding a heap allocation
// (plus time.Now, a streamID hash and a channel send) on every relay read and
// write.
func (p *Proxy) wrapTraffic(conn essentials.Conn, ctx *streamContext) essentials.Conn {
	if !p.emitTraffic {
		return conn
	}

	return connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	// When this stream carries an advertising tag, route it through a Telegram
	// middle proxy so a sponsored channel appears. On any failure we log and
	// fall through to the direct path so the client stays online (availability
	// is favored over the sponsored channel).
	if ctx.adTag != nil && p.middleProxy != nil {
		switch ctx.connTag {
		case obfuscation.TagAbridged:
			// The middle proxy re-frames into RPC_PROXY_REQ and abridged is a
			// different framing with a different RPC mode (RPC_F_COMPACT).
			// Rather than ship a second, barely exercised reframer whose failure
			// mode is a silently corrupted stream to Telegram, an abridged
			// client takes the direct path: it loses the sponsored channel, not
			// its connection.
			p.stats.OnAdTagSkipped(ctx.secretName)
			ctx.logger.BindStr("conn_tag", ctx.connTag.String()).
				Info("advertising is not supported for this transport; using direct connection")
		default:
			if err := p.doMiddleProxyCall(ctx); err != nil {
				// Counted apart from the skip above. That one is by design;
				// this one is the middle proxy being unreachable or refusing
				// us, and an operator monetising through @MTProxybot has to
				// be able to see it without reading logs.
				p.stats.OnAdTagFailed(ctx.secretName)
				ctx.logger.WarningError("cannot route through middle proxy, using direct connection", err)
			} else {
				return nil
			}
		}
	}

	dcid := ctx.dc

	addresses := p.telegram.GetAddresses(dcid)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = dc.DefaultDC
		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.Dial(addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return fmt.Errorf("no available addresses for DC %d", ctx.dc)
	}

	// The client's own tag, not ours: the relay above is byte-transparent, so
	// announcing a different transport to Telegram corrupts every packet.
	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, ctx.dc, ctx.connTag)
	if err != nil {
		conn.Close() // nolint: errcheck
		return fmt.Errorf("cannot perform server handshake: %w", err)
	}

	ctx.setTelegram(p.wrapTraffic(tgConn, ctx))

	telegramHost, _, err := net.SplitHostPort(foundAddr.Address)
	if err != nil {
		conn.Close() //nolint: errcheck

		return fmt.Errorf("cannot parse telegram address %s: %w", foundAddr.Address, err)
	}

	p.eventStream.Send(
		ctx,
		NewEventConnectedToDC(ctx.streamID,
			net.ParseIP(telegramHost),
			ctx.dc),
	)

	return nil
}

// doMiddleProxyCall dials a Telegram middle proxy for the stream's DC and sets
// the stream's upstream socket to an RPC stream that carries the client's
// traffic together with the advertising tag. It returns an error (leaving that
// socket unset) if the middle proxy cannot be reached, so the caller can fall
// back to a direct connection.
func (p *Proxy) doMiddleProxyCall(ctx *streamContext) error {
	clientAddr, _ := ctx.client().RemoteAddr().(*net.TCPAddr)

	stream, middleIP, err := p.middleProxy.DialProxyStream(p.network, middleproxy.DialParams{
		DC:             ctx.dc,
		ClientAddr:     clientAddr,
		PublicIPv4:     p.ourIPv4,
		PublicIPv6:     p.ourIPv6,
		AdvertisedPort: p.advertisedPort,
		AdTag:          *ctx.adTag,

		PaddedIntermediate: ctx.connTag == obfuscation.TagPaddedIntermediate,
	})
	if err != nil {
		return fmt.Errorf("cannot dial middle proxy: %w", err)
	}

	ctx.setTelegram(p.wrapTraffic(stream, ctx))

	p.eventStream.Send(ctx, NewEventConnectedToDC(ctx.streamID, middleIP, ctx.dc))

	return nil
}
