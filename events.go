package main

import (
	"net"
	"sort"
	"sync"
)

const (
	evSYN = iota
	evSYNACK
	evRST
)

var evName = [...]string{"SYN", "SYN-ACK", "RST"}

type TCPEvent struct {
	Ms     int64
	Remote [16]byte
	RPort  uint16
	LPort  uint16
	Typ    uint8
	Out    bool
}

// EventRing is a fixed in-RAM ring of recent TCP control events (SYN/RST).
// ponytail: 1M events ≈ 32MB per iface; a sustained SYN flood shortens the
// lookback window instead of growing memory.
const eventRingSize = 1 << 20

type EventRing struct {
	mu  sync.Mutex
	buf []TCPEvent
	pos int64
}

func NewEventRing() *EventRing { return &EventRing{buf: make([]TCPEvent, eventRingSize)} }

type EventAgg struct {
	Type   string `json:"type"`
	Dir    string `json:"dir"`
	Remote string `json:"remote"`
	Port   uint16 `json:"port"`
	Count  uint64 `json:"count"`
}

func (r *EventRing) Add(e TCPEvent) {
	r.mu.Lock()
	r.buf[r.pos%eventRingSize] = e
	r.pos++
	r.mu.Unlock()
}

// Aggregate groups events in [fromMs,toMs] by (type, direction, remote IP,
// port). ponytail: "port" is min(sport,dport) — the server side in practice —
// so the ephemeral side folds away without connection tracking.
func (r *EventRing) Aggregate(fromMs, toMs int64, n int) (rows []EventAgg, total uint64) {
	type key struct {
		typ  uint8
		out  bool
		ip   [16]byte
		port uint16
	}
	agg := map[key]uint64{}
	r.mu.Lock()
	for i := range r.buf {
		e := &r.buf[i]
		if e.Ms == 0 || e.Ms < fromMs || e.Ms > toMs {
			continue
		}
		agg[key{e.Typ, e.Out, e.Remote, min(e.RPort, e.LPort)}]++
		total++
	}
	r.mu.Unlock()
	for k, c := range agg {
		dir := "in"
		if k.out {
			dir = "out"
		}
		ip := k.ip
		rows = append(rows, EventAgg{Type: evName[k.typ], Dir: dir,
			Remote: net.IP(ip[:]).String(), Port: k.port, Count: c})
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Count > rows[b].Count })
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows, total
}
