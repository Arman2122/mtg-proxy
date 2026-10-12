package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C8 (spec §6.1, D21; m13′ of the second review; Task 8b's review, m2; Task
// 9b's review, M-6). A scripted rotation, end to end, with every line anything
// prints collected by channel: rotate-secret --reload with debug = true on the
// proxy, the API's reads, problem lines, a refused scalar-shape file through
// run --check, run, doctor, POST /reload and rotate-secret, the 500 bodies, the
// five shapes that put a value where TOML reads a key or a number, through the
// same five, Validate's refusal of a file without a primary, and access over
// the rotated file. No spelling of the retiring value or of its key appears in
// any of them.
//
// The new primary, and bob's, are looked for too, except where a primary is
// the point of the channel: rotate-secret's stdout, GET /secrets and GET
// /secrets/{name} (the panel reads the primary there), and access, which prints
// links.

// sweepText is one thing a channel printed.
type sweepText struct {
	channel string
	text    string
	primary bool // a primary's value belongs here
}

type leakSweep struct{ texts []sweepText }

func (s *leakSweep) add(channel, text string, primary bool) {
	s.texts = append(s.texts, sweepText{channel: channel, text: text, primary: primary})
}

// leaks labels every spelling found, by channel and by which secret; it never
// returns a spelling.
func (s *leakSweep) leaks(retiring, primaries []mtglib.Secret) []string {
	var found []string

	for _, text := range s.texts {
		for _, leak := range retiringLeaks(text.text, retiring...) {
			found = append(found, text.channel+": a retiring "+leak)
		}

		if text.primary {
			continue
		}

		for _, leak := range retiringLeaks(text.text, primaries...) {
			found = append(found, text.channel+": a primary's "+leak)
		}
	}

	return found
}

// apiPost is one POST on api with the token: the status and the body.
func apiPost(t *testing.T, api, path string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+api+path, nil)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+reloadToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(body)
}

// captureStdout is what run writes to os.Stdout.
func captureStdout(t *testing.T, run func() error) (string, error) {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	read := make(chan string, 1)

	go func() {
		data, _ := io.ReadAll(reader)
		read <- string(data)
	}()

	stdout := os.Stdout
	os.Stdout = writer

	runErr := run()

	os.Stdout = stdout

	require.NoError(t, writer.Close())

	out := <-read

	require.NoError(t, reader.Close())

	return out, runErr
}

// beforeSecrets puts extra right before the [secrets] header: inside the block
// that rotate-secret wrote there, or as tables of their own.
func beforeSecrets(text, extra string) string {
	return strings.Replace(text, "\n[secrets]\n", "\n"+extra+"[secrets]\n", 1)
}

// withoutBlocks is text without its [[retiring-secret]] blocks: from the first
// block's header to the [secrets] header.
func withoutBlocks(text string) string {
	start := strings.Index(text, "[[retiring-secret]]")
	end := strings.Index(text, "[secrets]\n")

	if start < 0 || end < start {
		return text
	}

	return text[:start] + text[end:]
}

// withoutSecrets is text without the [secrets] table, which is last.
func withoutSecrets(text string) string {
	return text[:strings.Index(text, "[secrets]\n")]
}

// sweepShape is one of Task 8b's five shapes, over a file that holds a block of
// alice's right before [secrets].
type sweepShape struct {
	name   string
	apply  func(text string) string
	parses bool
}

func TestNoSpellingOfTheRetiringValueEverAppears(t *testing.T) {
	level := zerolog.GlobalLevel()
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	at := time.Now().UTC().Truncate(time.Second)
	clock := clockAt(at)
	until := rfc3339(at.Add(24 * time.Hour))

	alice := mustGenerate(t, mtglib.SecretModeDD, "")
	bob := mustGenerate(t, mtglib.SecretModeDD, "")

	// A plain value whose hex TOML reads as a float out of range (8b's row 12).
	floating, err := mtglib.ParseSecret("1234567890123456789012345678e999")
	require.NoError(t, err)

	var sweep leakSweep

	// 1. The proxy, with debug = true (reloadFile's): its log holds every Debug
	// line.
	file := func(public, extra uint, api string, blocks ...string) string {
		return reloadFile(public, extra, api, map[string]mtglib.Secret{"alice": alice, "bob": bob}, blocks...)
	}

	run := startRotationRun(t, func(public, extra uint, api string) string { return file(public, extra, api) }, clock)

	// 2. The rotation, reloaded and read back.
	res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
	sweep.add("rotate-secret --reload: stdout", res.stdout, true)
	sweep.add("rotate-secret --reload: stderr and error", res.printed(), false)
	require.Empty(t, sweep.leaks([]mtglib.Secret{alice}, []mtglib.Secret{bob}), "the rotation printed a key")
	require.NoError(t, res.err)

	renewed := newValue(t, res)
	retiring := []mtglib.Secret{alice, floating}
	primaries := []mtglib.Secret{renewed, bob}

	data, err := os.ReadFile(run.path)
	require.NoError(t, err)

	rotated := string(data)

	// 3. The API's reads.
	for _, path := range []string{"/stats", "/secrets", "/secrets/alice", "/secrets/bob"} {
		status, body := apiGet(t, run.api, path)
		require.Equal(t, http.StatusOK, status, path)
		sweep.add("GET "+path, body, path != "/stats")
	}

	reload := func(channel, text string) (int, string) {
		t.Helper()

		require.NoError(t, os.WriteFile(run.path, []byte(text), 0o600))

		status, body := apiPost(t, run.api, "/reload")
		sweep.add(channel+": POST /reload", body, false)

		return status, body
	}

	// The rest of the surfaces, over a copy of text: run --check, doctor and
	// rotate-secret (a dry run of bob's rotation, and a real one); run too, for
	// a file it refuses -- one it accepts is started below.
	surfaces := func(channel, text string, parses bool) {
		t.Helper()

		path := writeConfig(t, text)

		sweep.add(channel+": run --check", errText((&Run{ConfigPath: path, Check: true}).Run(nil, "test")), false)

		if parses {
			d, out := newDoctor(t, text, time.Second, nil)
			_, err := d.diagnose(&doctorNetwork{dial: refuseAll}, fakeResolver{})
			sweep.add(channel+": doctor", out.String()+"\n"+errText(err), false)
		} else {
			sweep.add(channel+": run", errText(runRefuses(t, path)), false)
			sweep.add(channel+": doctor", errText((&Doctor{ConfigPath: path}).Run(nil, "test")), false)
		}

		for _, dryRun := range []bool{true, false} {
			rotation := runRotate(t, RotateSecret{
				ConfigPath: writeConfig(t, text), Name: "bob", Overlap: "1h", DryRun: dryRun, now: clock,
			})
			sweep.add(channel+": rotate-secret: stderr and error", rotation.printed(), false)
			sweep.add(channel+": rotate-secret: stdout", rotation.stdout, true)
		}
	}

	// 4. Problem lines: blocks that hold the retiring value where it does not
	// belong -- a name that is not served, another name's, a malformed until.
	problems := beforeSecrets(rotated,
		retiringBlock("carol", alice, until)+
			"[[retiring-secret]]\nname = \"bob\"\nsecret = \""+alice.Base64()+"\"\nuntil = \""+until+"\"\n\n"+
			retiringBlock("alice", alice, "tomorrow"))

	status, _ := reload("problem lines", problems)
	require.Equal(t, http.StatusOK, status, "a problem in a block never refuses a reload")
	surfaces("problem lines", problems, true)

	// 5. The scalar shape, whose refused line holds the retiring value (m13′).
	scalar := "retiring-secret = \"" + alice.Hex() + "\"\n" + rotated

	status, _ = reload("a scalar retiring-secret", scalar)
	require.Equal(t, http.StatusInternalServerError, status)
	surfaces("a scalar retiring-secret", scalar, false)

	// 6. Task 8b's five shapes, each on every surface.
	shapes := []sweepShape{
		{name: "12: a plain value written unquoted, which reads as a float", apply: func(text string) string {
			return beforeSecrets(text, "[[retiring-secret]]\nname = \"bob\"\nsecret = "+floating.Hex()+"\nuntil = \""+until+"\"\n\n")
		}},
		{name: "13: a value in base64url written as a key inside a block", parses: true, apply: func(text string) string {
			return beforeSecrets(text, alice.Base64()+" = \"x\"\n\n")
		}},
		{name: "14: a value in hex written as a key, twice, inside a block", apply: func(text string) string {
			return beforeSecrets(text, alice.Hex()+" = 1\n"+alice.Hex()+" = 1\n\n")
		}},
		{name: "15: a subtable of a block named by a value", parses: true, apply: func(text string) string {
			return beforeSecrets(text, "[retiring-secret."+alice.Base64()+"]\nx = 1\n\n")
		}},
		{name: "16: a value in hex as a dotted key below the table's name", parses: true, apply: func(text string) string {
			return "retiring-secret." + alice.Hex() + " = 1\n" + withoutBlocks(text)
		}},
	}

	for _, shape := range shapes {
		text := shape.apply(rotated)

		status, body := reload(shape.name, text)

		if shape.parses {
			require.Equal(t, http.StatusOK, status, shape.name)
		} else {
			require.Equal(t, http.StatusInternalServerError, status, shape.name)
			assert.NotEmpty(t, body)
		}

		surfaces(shape.name, text, shape.parses)
	}

	// 7. Validate's refusal of a file with no primary at all (Task 9b's M-6): it
	// prints the all-zero placeholder, never a key of the file.
	noPrimary := withoutSecrets(rotated)

	status, _ = reload("no primary", noPrimary)
	require.Equal(t, http.StatusInternalServerError, status)
	surfaces("no primary", noPrimary, false)

	invalid := errText((&Run{ConfigPath: writeConfig(t, noPrimary), Check: true}).Run(nil, "test"))

	// The proxy back on the rotated file, and its whole log.
	status, _ = reload("the rotated file again", rotated)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, run.end(t))
	run.endLog()

	proxyLog := run.log.text()
	sweep.add("the proxy's log, debug = true", proxyLog, false)

	// 8. run on each shape it accepts: its start-up log.
	var shapeLogs []string

	for _, shape := range shapes {
		if !shape.parses {
			continue
		}

		started := startRotationRun(t, func(public, extra uint, api string) string {
			return shape.apply(file(public, extra, api, retiringBlock("alice", alice, until)))
		}, clock)

		require.NoError(t, started.end(t))
		started.endLog()

		shapeLogs = append(shapeLogs, started.log.text())
		sweep.add(shape.name+": run", started.log.text(), false)
	}

	// 9. access over the rotated file: primaries only (§6.1, §8.2).
	accessOut, accessErr := captureStdout(t, func() error {
		return (&Access{ConfigPath: run.path, PublicIPv4: net.ParseIP("127.0.0.1"), PublicIPv6: net.ParseIP("::1")}).Run(nil, "test")
	})
	sweep.add("access", accessOut+"\n"+errText(accessErr), true)

	// Every channel, before any assertion that could print one of them.
	require.Empty(t, sweep.leaks(retiring, primaries), "a channel carries a key")

	// What makes the sweep mean something: each channel said what it says.
	require.NoError(t, accessErr)
	assert.Contains(t, accessOut, renewed.Hex(), "access did not run over the rotated file")
	assert.Contains(t, proxyLog, `"message":"configuration"`, "the proxy's Debug lines were not collected")
	assert.Contains(t, proxyLog, "unknown config key is ignored", "a reload's unknown keys were not logged")
	assert.Contains(t, proxyLog, "secret reload failed", "a refused reload was not logged")
	assert.Contains(t, invalid, "invalid secret ", "Validate's refusal was not reached")

	for _, log := range shapeLogs {
		assert.Contains(t, log, "unknown config key is ignored", "a start did not log its unknown keys")
	}

	assert.Contains(t, res.stderr, "reloaded the proxy through its management API at "+run.api)
}
