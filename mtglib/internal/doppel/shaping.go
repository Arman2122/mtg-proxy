package doppel

import (
	"fmt"
	"strings"
)

// Shaping is how the doppelganger spaces the records it writes in time.
type Shaping uint8

const (
	// ShapingRecord waits a delay drawn from Stats before every record: the
	// timing of a web page's records, applied to everything.
	ShapingRecord Shaping = iota

	// ShapingBurst waits one such delay when the connection wakes from idle
	// (nothing sent for TLSRecordSizeResetAfter) and then sends records back
	// to back, as a server streams a response, leaving the pace to TCP.
	ShapingBurst
)

// BurstWriteMax is how many bytes of records -- headers included -- burst
// shaping hands the socket in one write.
const BurstWriteMax = 64 << 10

// ParseShaping reads the configuration's spelling: "" or "record" is
// ShapingRecord, "burst" is ShapingBurst.
func ParseShaping(value string) (Shaping, error) {
	switch strings.ToLower(value) {
	case "", "record":
		return ShapingRecord, nil
	case "burst":
		return ShapingBurst, nil
	}

	return ShapingRecord, fmt.Errorf(`unknown doppelganger shaping %q: use "record" or "burst"`, value)
}
