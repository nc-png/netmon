package main

import (
	"math"
	"os"
	"strconv"
	"strings"
)

// Collector polls /proc counters each tick and emits per-tick deltas
// (counters) plus cpu gauges. The first poll only primes prev.
type Collector struct {
	ifaces map[string]bool
	prev   map[string]uint64
}

func NewCollector(ifaces []string) *Collector {
	m := map[string]bool{}
	for _, i := range ifaces {
		m[i] = true
	}
	return &Collector{ifaces: m}
}

func (c *Collector) Collect() map[string]float64 {
	cur := map[string]uint64{}
	c.readNetDev(cur)
	readFileTable("/proc/net/snmp", "Tcp:", map[string]string{
		"AttemptFails": "tcp.attempt_fails",
		"EstabResets":  "tcp.estab_resets",
		"RetransSegs":  "tcp.retrans_segs",
	}, cur)
	readFileTable("/proc/net/netstat", "TcpExt:", map[string]string{
		"ListenDrops":     "tcp.listen_drops",
		"ListenOverflows": "tcp.listen_overflows",
	}, cur)
	readStat(cur)
	readSoftirqs(cur)
	readSoftnet(cur)

	out := map[string]float64{}
	if c.prev != nil {
		for k, v := range cur {
			if k[0] == '_' {
				continue
			}
			// counter went backwards (reset/reload) -> gap for this tick
			if p, ok := c.prev[k]; ok && v >= p {
				out[k] = float64(v - p)
			}
		}
		pt, ct := c.prev["_cpu_total"], cur["_cpu_total"]
		if ct > pt {
			dt := float64(ct - pt)
			out["sys.cpu_busy"] = 100 * float64(cur["_cpu_busy"]-c.prev["_cpu_busy"]) / dt
			out["sys.cpu_softirq"] = 100 * float64(cur["_cpu_si"]-c.prev["_cpu_si"]) / dt
		}
		// hottest single core's softirq% — a one-flow/one-RSS-queue overload
		// is invisible in the aggregate but pegs exactly one core
		mx := math.NaN()
		for k, si := range cur {
			if !strings.HasPrefix(k, "_si.") {
				continue
			}
			tk := "_tot." + k[4:]
			psi, ok1 := c.prev[k]
			ptot, ok2 := c.prev[tk]
			if ok1 && ok2 && cur[tk] > ptot {
				p := 100 * float64(si-psi) / float64(cur[tk]-ptot)
				if math.IsNaN(mx) || p > mx {
					mx = p
				}
			}
		}
		if !math.IsNaN(mx) {
			out["sys.cpu_softirq_max"] = mx
		}
	}
	readConntrack(out)
	readSockstat(out)
	c.prev = cur
	return out
}

func (c *Collector) readNetDev(cur map[string]uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	parseNetDev(string(b), c.ifaces, cur)
}

func parseNetDev(data string, ifaces map[string]bool, cur map[string]uint64) {
	for _, ln := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if !ifaces[name] {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		for _, col := range []struct {
			i   int
			suf string
		}{
			{0, "rx_bytes"}, {1, "rx_pkts"}, {2, "rx_errs"}, {3, "rx_drop"},
			{8, "tx_bytes"}, {9, "tx_pkts"}, {10, "tx_errs"}, {11, "tx_drop"},
		} {
			if v, err := strconv.ParseUint(f[col.i], 10, 64); err == nil {
				cur[name+"."+col.suf] = v
			}
		}
	}
}

func readFileTable(path, prefix string, want map[string]string, cur map[string]uint64) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	parseTable(string(b), prefix, want, cur)
}

// parseTable handles /proc/net/{snmp,netstat}: a "Prefix: Name Name..." header
// line followed by a "Prefix: val val..." value line.
func parseTable(data, prefix string, want map[string]string, cur map[string]uint64) {
	var hdr []string
	for _, ln := range strings.Split(data, "\n") {
		if !strings.HasPrefix(ln, prefix) {
			continue
		}
		f := strings.Fields(ln)
		if hdr == nil {
			hdr = f
			continue
		}
		for j := 1; j < len(hdr) && j < len(f); j++ {
			if name, ok := want[hdr[j]]; ok {
				if v, err := strconv.ParseUint(f[j], 10, 64); err == nil {
					cur[name] = v
				}
			}
		}
		return
	}
}

func readStat(cur map[string]uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	parseStat(string(b), cur)
}

func parseStat(data string, cur map[string]uint64) {
	for _, ln := range strings.Split(data, "\n") {
		if !strings.HasPrefix(ln, "cpu") {
			break // cpu lines lead the file
		}
		f := strings.Fields(ln)
		if len(f) < 8 {
			continue
		}
		v := make([]uint64, len(f)-1)
		for i := range v {
			v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
		}
		// user nice system idle iowait irq softirq steal
		busy := v[0] + v[1] + v[2] + v[5] + v[6]
		if len(v) > 7 {
			busy += v[7]
		}
		if f[0] == "cpu" { // aggregate
			cur["_cpu_busy"] = busy
			cur["_cpu_total"] = busy + v[3] + v[4]
			cur["_cpu_si"] = v[6]
		} else { // per-cpu: cpuN
			n := f[0][3:]
			cur["_si."+n] = v[6]
			cur["_tot."+n] = busy + v[3] + v[4]
		}
	}
}

func readSoftirqs(cur map[string]uint64) {
	b, err := os.ReadFile("/proc/softirqs")
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		var key string
		switch strings.TrimSpace(name) {
		case "NET_RX":
			key = "sys.softirq_net_rx"
		case "NET_TX":
			key = "sys.softirq_net_tx"
		default:
			continue
		}
		var sum uint64
		for _, f := range strings.Fields(rest) {
			v, _ := strconv.ParseUint(f, 10, 64)
			sum += v
		}
		cur[key] = sum
	}
}

func readSoftnet(cur map[string]uint64) {
	b, err := os.ReadFile("/proc/net/softnet_stat")
	if err != nil {
		return
	}
	// col 2 = packets dropped from the softnet backlog, col 3 = time_squeeze
	// (net_rx budget exhausted with work left — softirq saturation), per cpu
	var drop, squeeze uint64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 16, 64)
		drop += v
		v, _ = strconv.ParseUint(f[2], 16, 64)
		squeeze += v
	}
	cur["sys.softnet_drop"] = drop
	cur["sys.softnet_squeeze"] = squeeze
}

// readSockstat emits TCP socket-table gauges: a time-wait/orphan explosion
// (mass short-lived connections) looks very different from a few fat flows.
func readSockstat(out map[string]float64) {
	b, err := os.ReadFile("/proc/net/sockstat")
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(ln, "TCP:") {
			continue
		}
		f := strings.Fields(ln) // TCP: inuse N orphan N tw N alloc N mem N
		for i := 1; i+1 < len(f); i += 2 {
			var k string
			switch f[i] {
			case "inuse":
				k = "sys.tcp_inuse"
			case "orphan":
				k = "sys.tcp_orphan"
			case "tw":
				k = "sys.tcp_tw"
			default:
				continue
			}
			if v, err := strconv.ParseFloat(f[i+1], 64); err == nil {
				out[k] = v
			}
		}
		return
	}
}

// readConntrack emits table fill % — a full table silently eats new flows
// (the "table full" log is ratelimited and easy to miss).
func readConntrack(out map[string]float64) {
	c, err1 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	m, err2 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err1 != nil || err2 != nil {
		return
	}
	cv, _ := strconv.ParseFloat(strings.TrimSpace(string(c)), 64)
	mv, _ := strconv.ParseFloat(strings.TrimSpace(string(m)), 64)
	if mv > 0 {
		out["sys.conntrack_pct"] = 100 * cv / mv
	}
}
