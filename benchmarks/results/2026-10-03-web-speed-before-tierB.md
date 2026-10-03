# Tier B, dd and WEB -- before the relay's lean data path

- **Code:** web-speed at 740eecc, cross-compiled (linux/amd64, `CGO_ENABLED=0`).
- **Box:** the same Linux 6.8 VM, 2 vCPU, loopback only, another project's
  database running alongside.
- **Run:** `taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -dir ... -out ...
  -scenarios bulk,handshake,latency,idle -doors dd,web`. The binary (the proxy,
  and the WEB relay) is pinned to core 0, mtgbench to core 1. dd is the
  reference row: it does not change in this project.

## Tier B, 2026-10-03 21:14 UTC

Each cell is the median of 3 runs (range in brackets), each a 2s warm-up, then 5s measured.

- Loopback on one machine: these are the binary's own costs, not the network's.
- CPU and RSS are every process of the binary: the proxy, and the WEB relay beside it.
- Handshake times include the proxy's SOCKS5 round trip to mtgbench's data centre.
- ee unpaced and the ad-tag leg are measured in Tier A only.
- The binary is pinned to core 0; run mtgbench on another, so the figures are per core.

### bulk

Every connection moves 1 MiB chunks, two commands in flight, each checked to the byte. CPU is every process of the binary (the proxy, and the relay), per GB moved.

| | MB/s | CPU-s per GB | binary cores busy | mtgbench cores busy |
|---|---|---|---|---|
| dd, 1 conn, download | 442 (434–453) | 2.08 (2.05–2.12) | 0.92 (0.92–0.93) | 0.84 (0.84–0.86) |
| dd, 1 conn, upload | 433 (392–453) | 2.12 (2.07–2.29) | 0.92 (0.90–0.94) | 0.85 (0.83–0.88) |
| dd, 64 conns, download | 593 (577–595) | 1.66 (1.66–1.67) | 0.98 (0.96–0.99) | 0.94 (0.92–0.94) |
| dd, 64 conns, upload | 581 (554–583) | 1.70 (1.69–1.75) | 0.99 (0.97–0.99) | 0.94 (0.92–0.94) |
| web, 1 conn, download | 148 (144–149) | 6.15 (6.10–6.25) | 0.91 (0.90–0.91) | 0.49 (0.49–0.51) |
| web, 1 conn, upload | 127 (127–133) | 7.51 (7.35–7.59) | 0.96 (0.96–0.98) | 0.54 (0.54–0.57) |
| web, 64 conns, download | 289 (259–297) | 3.42 (3.31–3.71) | 0.98 (0.96–0.99) | 0.67 (0.60–0.69) |
| web, 64 conns, upload | 187 (174–187) | 5.31 (5.31–5.68) | 0.99 (0.99–0.99) | 0.56 (0.53–0.58) |

### handshake

Whole connections back to back, 8 at a time: dial, a one-byte echo, close. Connect-to-first-byte includes the proxy's SOCKS5 round trip to the data centre. Fronted is hellos the anti-replay cache took for replays (by the client; the cover listener's own count beside it).

| | connections/s | first byte p50 ms | p99 ms | fronted | at the cover |
|---|---|---|---|---|---|
| dd | 3180 (3168–3284) | 2.15 (2.14–2.19) | 7.05 (6.55–8.00) | 0 | 0 |
| web | 657 (603–658) | 9.84 (9.80–10.5) | 26.3 (24.1–28.0) | 0 | 0 |

### latency

One connection, 100 bytes to the data centre and 100 back, over and over. Direct is the same with no proxy and no SOCKS5: a door's added latency is its figure minus that one. Samples is how many round trips the percentiles rest on.

| | p50 µs | p99 µs | p99.9 µs | samples |
|---|---|---|---|---|
| direct | 23.5 (23.5–23.6) | 53.1 (49.1–56.6) | 87.2 (80.4–88.9) | 190028 (187015–193529) |
| dd | 124 (122–126) | 395 (380–445) | 1323 (983–1579) | 34454 (33416–35334) |
| web | 263 (245–267) | 965 (902–1889) | 2162 (2144–3608) | 16273 (14729–17103) |

### idle

Connections opened and left open on a fresh process, each first proven with a one-byte echo. RSS is every process of the binary; per connection is the growth over the process before it, divided by the count. WEB is one session per connection.

| | RSS KiB per conn | seconds to open | mtgbench's own heap KiB per conn |
|---|---|---|---|
| dd, 1000 conns | 34.5 (34.2–34.6) | 0.59 (0.53–0.61) | 2.85 (2.85–3.24) |
| dd, 5000 conns | 32.7 (32.4–33.3) | 1.99 (1.92–2.16) | 2.83 (2.83–3.21) |
| web, 1000 conns | 168 (167–170) | 1.58 (1.56–1.69) | 9.23 (8.42–9.46) |

