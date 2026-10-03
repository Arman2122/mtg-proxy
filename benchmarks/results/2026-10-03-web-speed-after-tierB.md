# Tier B, dd and WEB -- after the relay's lean data path

- **Code:** web-speed at 1edf750, cross-compiled (linux/amd64, `CGO_ENABLED=0`).
- **Box:** the same Linux 6.8 VM, 2 vCPU, loopback only, another project's
  database running alongside.
- **Run:** `taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -dir ... -out ...
  -scenarios bulk,handshake,latency,idle -doors dd,web`. The binary (the proxy,
  and the WEB relay) is pinned to core 0, mtgbench to core 1. dd is the
  reference row: it does not change in this project.

## Tier B, 2026-10-03 22:03 UTC

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
| dd, 1 conn, download | 449 (448–463) | 2.09 (2.06–2.11) | 0.94 (0.94–0.96) | 0.88 (0.86–0.88) |
| dd, 1 conn, upload | 427 (426–456) | 2.10 (2.03–2.12) | 0.90 (0.90–0.93) | 0.83 (0.82–0.86) |
| dd, 64 conns, download | 600 (587–600) | 1.61 (1.60–1.63) | 0.96 (0.96–0.97) | 0.93 (0.93–0.94) |
| dd, 64 conns, upload | 587 (582–598) | 1.65 (1.64–1.67) | 0.97 (0.97–0.98) | 0.92 (0.91–0.93) |
| web, 1 conn, download | 276 (237–276) | 3.06 (3.01–3.45) | 0.83 (0.82–0.84) | 0.73 (0.72–0.74) |
| web, 1 conn, upload | 213 (130–221) | 4.53 (4.34–5.21) | 0.96 (0.68–0.97) | 0.77 (0.44–0.78) |
| web, 64 conns, download | 380 (372–390) | 2.62 (2.57–2.66) | 1.00 (0.99–1.00) | 0.83 (0.78–0.84) |
| web, 64 conns, upload | 280 (265–331) | 3.55 (2.99–3.67) | 0.99 (0.97–0.99) | 0.77 (0.75–0.84) |

### handshake

Whole connections back to back, 8 at a time: dial, a one-byte echo, close. Connect-to-first-byte includes the proxy's SOCKS5 round trip to the data centre. Fronted is hellos the anti-replay cache took for replays (by the client; the cover listener's own count beside it).

| | connections/s | first byte p50 ms | p99 ms | fronted | at the cover |
|---|---|---|---|---|---|
| dd | 3175 (2590–3359) | 2.20 (2.10–2.57) | 7.14 (6.84–9.68) | 0 | 0 |
| web | 707 (519–731) | 8.70 (8.16–10.2) | 24.7 (23.9–36.8) | 0 | 0 |

### latency

One connection, 100 bytes to the data centre and 100 back, over and over. Direct is the same with no proxy and no SOCKS5: a door's added latency is its figure minus that one. Samples is how many round trips the percentiles rest on.

| | p50 µs | p99 µs | p99.9 µs | samples |
|---|---|---|---|---|
| direct | 23.5 (23.5–23.6) | 49.8 (49.7–62.1) | 84.6 (77.4–100.0) | 191042 (179829–191709) |
| dd | 124 (122–128) | 481 (373–1826) | 1923 (1254–2698) | 32482 (27090–34947) |
| web | 496 (279–644) | 2902 (2394–3179) | 4942 (4487–20228) | 7317 (5958–12081) |

### idle

Connections opened and left open on a fresh process, each first proven with a one-byte echo. RSS is every process of the binary; per connection is the growth over the process before it, divided by the count. WEB is one session per connection.

| | RSS KiB per conn | seconds to open | mtgbench's own heap KiB per conn |
|---|---|---|---|
| dd, 1000 conns | 34.1 (33.6–34.3) | 1.24 (1.10–1.42) | 2.85 (2.84–3.27) |
| dd, 5000 conns | 32.0 (31.8–32.2) | 2.89 (2.81–3.68) | 2.84 (2.83–3.24) |
| web, 1000 conns | 83.9 (81.2–85.5) | 2.09 (2.04–2.13) | 9.41 (8.89–9.75) |

