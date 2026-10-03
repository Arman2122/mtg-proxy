// Package testclient is the client side of every door the proxy serves --
// FakeTLS (ee), obfuscated2 (dd, plain) and WEB -- for tests and for the load
// tool, tools/mtgbench. Nothing in the release binary imports it.
//
// It imports only mtglib/obfuscation, essentials, internal/webrelay/frame and
// the standard library. mtglib/internal/... is out of reach by Go's internal
// rule, and importing mtglib or internal/webrelay would put their in-package
// tests in an import cycle. The few TLS constants it needs are therefore
// copied, each beside the name of its source.
//
// It returns errors rather than taking a testing.TB, so a program can use it as
// readily as a test.
package testclient
