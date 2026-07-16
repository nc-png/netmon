package main

import (
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// One tick every 200ms; all rings share the same tick clock.
const tickMs = 200

type Series struct {
	Name  string
	Gauge bool // gauge: value as-is (e.g. cpu %); otherwise per-tick counter delta, scaled to /s on query
	data  []float64
}

// TalkerRing keeps the top-N (ip, estimated bytes) per tick, flat arrays.
type TalkerRing struct {
	idx []uint32 // slots*topN, index into ipDict; 0 = empty
	byt []uint64
}

type Talker struct {
	IP    string `json:"ip"`
	Bytes uint64 `json:"bytes"`
}

type Store struct {
	mu      sync.RWMutex
	epochMs int64
	slots   int64
	topN    int64
	last    int64 // last committed tick, -1 = none
	series  map[string]*Series
	names   []string
	talk    map[string]*TalkerRing // key: "<iface>/rx" or "<iface>/tx"
	dict    *ipDict
}

func NewStore(retention time.Duration, topN int) *Store {
	return &Store{
		epochMs: time.Now().UnixMilli(),
		slots:   int64(retention / (tickMs * time.Millisecond)),
		topN:    int64(topN),
		last:    -1,
		series:  map[string]*Series{},
		talk:    map[string]*TalkerRing{},
		dict:    newIPDict(),
	}
}

func (s *Store) tickOf(ms int64) int64 { return (ms - s.epochMs) / tickMs }
func (s *Store) msOf(tick int64) int64 { return s.epochMs + tick*tickMs }

func (s *Store) AddSeries(name string, gauge bool) {
	d := make([]float64, s.slots)
	for i := range d {
		d[i] = math.NaN()
	}
	s.series[name] = &Series{Name: name, Gauge: gauge, data: d}
	s.names = append(s.names, name)
}

func (s *Store) AddTalkers(key string) {
	s.talk[key] = &TalkerRing{
		idx: make([]uint32, s.slots*s.topN),
		byt: make([]uint64, s.slots*s.topN),
	}
}

// Commit writes one tick. vals: series -> per-tick value. tops: talker key -> ip -> estimated bytes.
// Skipped ticks (scheduler stalls) are cleared to NaN so they read as gaps, not stale data.
func (s *Store) Commit(tick int64, vals map[string]float64, tops map[string]map[[16]byte]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tick <= s.last {
		return
	}
	first := s.last + 1
	if s.last < 0 || tick-first >= s.slots {
		first = tick - s.slots + 1
		if first < 0 {
			first = 0
		}
	}
	for t := first; t <= tick; t++ {
		i := t % s.slots
		for _, sr := range s.series {
			sr.data[i] = math.NaN()
		}
		for _, tr := range s.talk {
			base := i * s.topN
			for j := int64(0); j < s.topN; j++ {
				tr.byt[base+j] = 0
			}
		}
	}
	i := tick % s.slots
	for name, v := range vals {
		if sr := s.series[name]; sr != nil {
			sr.data[i] = v
		}
	}
	for key, m := range tops {
		tr := s.talk[key]
		if tr == nil {
			continue
		}
		type kv struct {
			ip [16]byte
			b  uint64
		}
		list := make([]kv, 0, len(m))
		for ip, b := range m {
			list = append(list, kv{ip, b})
		}
		sort.Slice(list, func(a, b int) bool { return list[a].b > list[b].b })
		if int64(len(list)) > s.topN {
			list = list[:s.topN]
		}
		base := i * s.topN
		for j, e := range list {
			tr.idx[base+int64(j)] = s.dict.intern(e.ip)
			tr.byt[base+int64(j)] = e.b
		}
	}
	s.last = tick
}

// clamp maps a ms range onto available ticks. Lock must be held, s.last >= 0.
func (s *Store) clamp(fromMs, toMs int64) (int64, int64) {
	oldest := s.last - s.slots + 1
	if oldest < 0 {
		oldest = 0
	}
	f, t := s.tickOf(fromMs), s.tickOf(toMs)
	if f < oldest {
		f = oldest
	}
	if t > s.last {
		t = s.last
	}
	return f, t
}

type QueryResult struct {
	FromMs int64
	StepMs int64
	Avg    []float64 // NaN = no data in bucket
	Max    []float64
}

// Query buckets [fromMs,toMs] into <= points buckets at full underlying resolution.
// Counter series are returned as per-second rates; gauges as-is.
func (s *Store) Query(name string, fromMs, toMs int64, points int) (QueryResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sr := s.series[name]
	if sr == nil || s.last < 0 {
		return QueryResult{}, false
	}
	fromTick, toTick := s.clamp(fromMs, toMs)
	if fromTick > toTick {
		return QueryResult{FromMs: s.msOf(fromTick), StepMs: tickMs}, true
	}
	n := toTick - fromTick + 1
	bt := (n + int64(points) - 1) / int64(points) // ticks per bucket
	nb := (n + bt - 1) / bt
	scale := 1000.0 / tickMs
	if sr.Gauge {
		scale = 1
	}
	avg := make([]float64, nb)
	max := make([]float64, nb)
	// ponytail: linear scan of the ring per query (~ms for a full week); add
	// precomputed downsample tiers only if query latency ever matters.
	for b := int64(0); b < nb; b++ {
		sum, mx, cnt := 0.0, math.NaN(), 0
		end := fromTick + (b+1)*bt
		if end > toTick+1 {
			end = toTick + 1
		}
		for t := fromTick + b*bt; t < end; t++ {
			v := sr.data[t%s.slots]
			if math.IsNaN(v) {
				continue
			}
			sum += v
			cnt++
			if math.IsNaN(mx) || v > mx {
				mx = v
			}
		}
		if cnt == 0 {
			avg[b], max[b] = math.NaN(), math.NaN()
		} else {
			avg[b], max[b] = sum/float64(cnt)*scale, mx*scale
		}
	}
	return QueryResult{FromMs: s.msOf(fromTick), StepMs: bt * tickMs, Avg: avg, Max: max}, true
}

// TopTalkers aggregates estimated bytes per IP over [fromMs,toMs].
// ponytail: strides over at most maxScan ticks and scales up — exact for zoomed
// views, an estimate-of-an-estimate for week-wide tables, which is fine.
func (s *Store) TopTalkers(key string, fromMs, toMs int64, n int) []Talker {
	const maxScan = 200_000
	s.mu.RLock()
	defer s.mu.RUnlock()
	tr := s.talk[key]
	if tr == nil || s.last < 0 {
		return nil
	}
	fromTick, toTick := s.clamp(fromMs, toMs)
	if fromTick > toTick {
		return nil
	}
	stride := (toTick - fromTick + maxScan) / maxScan
	agg := map[uint32]uint64{}
	for t := fromTick; t <= toTick; t += stride {
		base := (t % s.slots) * s.topN
		for j := int64(0); j < s.topN; j++ {
			if b := tr.byt[base+j]; b > 0 {
				agg[tr.idx[base+j]] += b * uint64(stride)
			}
		}
	}
	list := make([]Talker, 0, len(agg))
	for i, b := range agg {
		list = append(list, Talker{IP: s.dict.name(i), Bytes: b})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Bytes > list[b].Bytes })
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// ipDict interns IPs (16-byte, v4-mapped) to uint32 indexes.
// ponytail: capped at ~2M uniques, overflow lumps into "other"; make it an LRU
// if week-long scans/DDoS churn ever matter.
const maxIPs = 2 << 20

type ipDict struct {
	m    map[[16]byte]uint32
	list [][16]byte
}

func newIPDict() *ipDict {
	return &ipDict{m: map[[16]byte]uint32{}, list: make([][16]byte, 2)} // 0=empty, 1=other
}

func (d *ipDict) intern(ip [16]byte) uint32 {
	if i, ok := d.m[ip]; ok {
		return i
	}
	if len(d.list) >= maxIPs {
		return 1
	}
	d.list = append(d.list, ip)
	i := uint32(len(d.list) - 1)
	d.m[ip] = i
	return i
}

func (d *ipDict) name(i uint32) string {
	switch {
	case i == 1:
		return "other"
	case i < 2 || int(i) >= len(d.list):
		return "?"
	}
	ip := d.list[i]
	return net.IP(ip[:]).String()
}
