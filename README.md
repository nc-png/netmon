# monserver

In-RAM network monitor with an HTTP dashboard. One static Go binary, no
dependencies, nothing written to disk.

- **200 ms resolution** for all metrics, kept at **full resolution** for the
  whole retention window (default 7 days) in preallocated RAM rings.
- Per interface: throughput, packets, drops, errors (from kernel counters —
  exact, not sampled).
- Global: TCP failures (attempt fails, listen drops/overflows, estab resets,
  retransmits), softnet backlog drops, CPU busy/softirq %, NET_RX/NET_TX
  softirq rates.
- **Top talkers** per interface/direction via AF_PACKET + an in-kernel
  classic-BPF random sampler (default 1-in-128; byte counts are estimates
  scaled by the sample rate — right for 25–100 Gbit/s links). Top-N kept per
  200 ms tick.
- **TCP event drill-down**: every SYN / SYN-ACK / RST is captured unsampled
  (kernel cBPF filter, so only control packets reach userspace) into a 1M-event
  in-RAM ring per interface (~32 MB). Click a point on the "TCP failures"
  chart to see which remote IPs/ports caused it. Caveats: VLAN-tagged frames
  aren't matched, and listen drops are silent on the wire — the inbound SYNs
  around them are what you'll see.
- Dashboard: uPlot graphs, drag to zoom (re-fetches at full resolution),
  double-click to zoom out, live ranges 5m–7d, peak readouts, talker tables.

## Build

    go build -o monserver .        # CGO not needed; binary is static

## Run

    sudo ./monserver -ifaces eth0,eth1 -listen 10.0.0.1:8676

Flags:

| flag | default | |
|---|---|---|
| `-ifaces` | (required) | comma-separated interfaces to monitor |
| `-listen` | `127.0.0.1:8676` | HTTP bind address |
| `-sample` | `128` | talker sampling 1-in-N (power of two; `1` = every packet, fine ≤ ~10 Gbit/s) |
| `-retention` | `168h` | in-RAM history window |
| `-topn` | `20` | talkers kept per 200 ms tick per direction |
| `-ping` | off | comma-separated IPv4 addresses to ICMP-probe every 200 ms (your nexthops); adds per-target RTT and loss charts |
| `-no-mlock` | off | skip `mlockall` (history may swap to disk) |

RAM: ≈ 0.45 GB for counters + ≈ 1.45 GB per interface for talker history at
defaults (printed at startup). `-topn 10` or a shorter `-retention` halves it.

Run from a shell it needs root or `CAP_NET_RAW` (talker sampling + TCP
events; counters need no privilege). Under systemd it runs unprivileged: the
unit uses `DynamicUser=yes` with only `CAP_NET_RAW`, and `LimitMEMLOCK` covers
the mlock. Without the capability it still runs: counters work, packet
capture is disabled with a log line.

## systemd

    go build -o monserver . && sudo ./install.sh

Installs the binary to `/usr/local/bin`, the unit to `/etc/systemd/system`,
and a config template to `/etc/default/monserver` (kept if it already exists),
then enables and starts the service. Set `-ifaces`/`-listen` in
`/etc/default/monserver` and `systemctl restart monserver`. The unit sets
`ProtectSystem=strict` (filesystem read-only to the service) and
`LimitMEMLOCK=infinity`.

Nothing-on-disk caveat: the daemon itself writes nothing, but its stderr goes
to journald — set `Storage=volatile` in `/etc/systemd/journald.conf` if logs
must stay off disk too.

## HTTP API

- `GET /api/meta` — interfaces, tick period, oldest data
- `GET /api/query?series=eth0.rx_bytes,sys.cpu_busy&from=<ms>&to=<ms>&points=800`
  — server-side downsampled `avg`+`max` per bucket; ask for a narrow range to
  get raw 200 ms ticks
- `GET /api/talkers?iface=eth0&from=<ms>&to=<ms>&n=25` — top IPs by estimated
  bytes, `rx` (sources) and `tx` (destinations)
- `GET /api/tcpevents?iface=eth0&from=<ms>&to=<ms>&n=30` — SYN/SYN-ACK/RST
  events in the window, grouped by (type, direction, remote IP, port)

## Accuracy notes

- Interface throughput/packets/drops come from `/proc` counters sampled every
  200 ms — exact totals, unaffected by talker sampling.
- Talker bytes are `sampled × N` estimates; error shrinks with flow size, so
  ranking of real "top" talkers is reliable, tail entries are noisy.
- A missed tick (scheduler stall) shows as a gap (null), never stale data.
