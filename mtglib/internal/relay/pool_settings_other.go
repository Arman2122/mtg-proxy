//go:build !mips && !mipsle

package relay

import "github.com/Arman2122/mtg-proxy/mtglib/internal/tls"

const (
	bufPoolSize = tls.MaxRecordPayloadSize
)
