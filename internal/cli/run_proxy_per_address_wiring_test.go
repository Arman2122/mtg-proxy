package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The emit has its own tests with a recording logger. What only a run of the
// loop proves is that runProxyWith calls it, with the sockets it really built,
// and that the line reaches the log in the form an operator reads: JSON on
// stdout, at warning level, with the listener and the keys as fields.
//
// It is not parallel because the run builds its logger on os.Stdout, so the
// test points os.Stdout at a pipe for as long as the run is starting. A serial
// test finishes before any parallel one resumes, so nothing else is writing to
// the pipe.
func TestRunLoopWarnsAboutPerAddressControlsBehindProxyProtocol(t *testing.T) {
	ports, held := holdPorts(t, 2)

	public := fmt.Sprintf("127.0.0.1:%d", held[0])
	extra := fmt.Sprintf("127.0.0.1:%d", held[1])

	secret, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "%s"
proxy-protocol-listener = true

[domain-fronting]
host = "127.0.0.1"
port = 1

[secret-limits.default]
client-conns = 3
client-speed = "2mbit"

[[listener]]
bind-to = "%s"
accept = ["dd"]
proxy-protocol = true
`, secret.Hex(), public, extra)

	conf, err := utils.ParseConfig([]byte(raw))
	require.NoError(t, err)

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	t.Cleanup(func() {
		writer.Close() //nolint: errcheck
		reader.Close() //nolint: errcheck
	})

	lines := make(chan string, 256)

	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}

		close(lines)
	}()

	stdout := os.Stdout
	os.Stdout = writer

	t.Cleanup(func() { os.Stdout = stdout })

	stop := make(chan struct{})

	var stopOnce sync.Once

	endRun := func() { stopOnce.Do(func() { close(stop) }) }

	// A failed assertion must not leave the run serving.
	t.Cleanup(endRun)

	done := runInBackground(stop, conf, "", ports.listen)

	var warnings []map[string]any

	deadline := time.After(10 * time.Second)

	for len(warnings) < 2 {
		select {
		case line, ok := <-lines:
			require.True(t, ok, "the log ended before both warnings were written")

			if !strings.Contains(line, "PROXY headers") {
				continue
			}

			var entry map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &entry), line)

			warnings = append(warnings, entry)
		case <-deadline:
			t.Fatalf("the run wrote %d of the 2 expected warnings", len(warnings))
		}
	}

	os.Stdout = stdout

	endRun()
	require.NoError(t, requireReturned(t, done))

	const message = "per-address controls are in use and this listener expects PROXY headers: " +
		"the address they see is the one the PROXY header claims, " +
		"and anyone who can reach this listener can forge it; " +
		"use them only behind a front proxy you control"

	for i, listener := range []string{public, extra} {
		assert.Equal(t, "warn", warnings[i]["level"])
		assert.Equal(t, message, warnings[i]["message"])
		assert.Equal(t, listener, warnings[i]["listener"])
		assert.Equal(t, "client-conns, client-speed", warnings[i]["keys"])
	}
}
