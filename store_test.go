package main

import (
	"math"
	"testing"
	"time"
)

func TestRingQueryAndGaps(t *testing.T) {
	s := NewStore(time.Minute, 3) // 300 slots
	s.AddSeries("x", false)
	v := func(f float64) map[string]float64 { return map[string]float64{"x": f} }
	s.Commit(0, v(10), nil)
	s.Commit(1, v(20), nil)
	s.Commit(5, v(30), nil) // ticks 2-4 are a gap

	res, ok := s.Query("x", s.msOf(0), s.msOf(5), 6)
	if !ok || len(res.Avg) != 6 {
		t.Fatalf("ok=%v len=%d", ok, len(res.Avg))
	}
	// counter deltas scale to per-second (x5)
	if res.Avg[0] != 50 || res.Avg[1] != 100 || res.Avg[5] != 150 {
		t.Fatalf("avg=%v", res.Avg)
	}
	if !math.IsNaN(res.Avg[2]) || !math.IsNaN(res.Avg[4]) {
		t.Fatalf("gap not NaN: %v", res.Avg)
	}
	// bucketed: 6 ticks in 2 buckets -> avg and max
	res, _ = s.Query("x", s.msOf(0), s.msOf(5), 2)
	if res.Avg[0] != 75 || res.Max[0] != 100 || res.Avg[1] != 150 {
		t.Fatalf("bucketed avg=%v max=%v", res.Avg, res.Max)
	}
	// ring wrap: writing past capacity must not read back stale slots
	s.Commit(400, v(40), nil)
	res, _ = s.Query("x", s.msOf(0), s.msOf(400), 4000)
	if len(res.Avg) != 300 { // clamped to retention
		t.Fatalf("wrap len=%d", len(res.Avg))
	}
}

func TestGaugeNotScaled(t *testing.T) {
	s := NewStore(time.Minute, 3)
	s.AddSeries("g", true)
	s.Commit(0, map[string]float64{"g": 42}, nil)
	res, _ := s.Query("g", s.msOf(0), s.msOf(0), 1)
	if res.Avg[0] != 42 {
		t.Fatalf("gauge scaled: %v", res.Avg)
	}
}

func ip4(a, b, c, d byte) [16]byte {
	var ip [16]byte
	ip[10], ip[11] = 0xff, 0xff
	ip[12], ip[13], ip[14], ip[15] = a, b, c, d
	return ip
}

func TestTalkers(t *testing.T) {
	s := NewStore(time.Minute, 2) // topN=2 per tick
	s.AddTalkers("e/rx")
	a, b, c := ip4(1, 1, 1, 1), ip4(2, 2, 2, 2), ip4(3, 3, 3, 3)
	s.Commit(0, nil, map[string]map[[16]byte]uint64{"e/rx": {a: 100, b: 50, c: 10}}) // c cut by topN
	s.Commit(1, nil, map[string]map[[16]byte]uint64{"e/rx": {b: 200}})
	top := s.TopTalkers("e/rx", s.msOf(0), s.msOf(1), 10)
	if len(top) != 2 || top[0].IP != "2.2.2.2" || top[0].Bytes != 250 || top[1].Bytes != 100 {
		t.Fatalf("talkers=%+v", top)
	}
}

func TestParsePacket(t *testing.T) {
	// minimal IPv4 frame: eth(14) + ip header, total length 1000
	f := make([]byte, 34)
	f[12], f[13] = 0x08, 0x00
	f[14+2], f[14+3] = 0x03, 0xe8 // totlen 1000
	copy(f[14+12:], []byte{10, 0, 0, 1})
	copy(f[14+16:], []byte{10, 0, 0, 2})
	src, dst, wire, ok := parsePacket(f)
	if !ok || wire != 1018 || src != ip4(10, 0, 0, 1) || dst != ip4(10, 0, 0, 2) {
		t.Fatalf("ok=%v wire=%d src=%v dst=%v", ok, wire, src, dst)
	}
	// same frame behind a VLAN tag
	vf := append(append([]byte{}, f[:12]...), 0x81, 0x00, 0x00, 0x01)
	vf = append(vf, f[12:]...)
	_, _, wire, ok = parsePacket(vf)
	if !ok || wire != 1018 {
		t.Fatalf("vlan ok=%v wire=%d", ok, wire)
	}
	if _, _, _, ok := parsePacket([]byte{1, 2, 3}); ok {
		t.Fatal("runt accepted")
	}
}

func TestParseProcTables(t *testing.T) {
	cur := map[string]uint64{}
	parseTable("Tcp: RtoAlgorithm AttemptFails EstabResets\nTcp: 1 77 5\n", "Tcp:",
		map[string]string{"AttemptFails": "tcp.attempt_fails"}, cur)
	if cur["tcp.attempt_fails"] != 77 {
		t.Fatalf("snmp: %v", cur)
	}
	parseNetDev("Inter-|...\n face |...\n  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
		map[string]bool{"eth0": true}, cur)
	if cur["eth0.rx_bytes"] != 1000 || cur["eth0.tx_drop"] != 4 || cur["eth0.rx_errs"] != 1 {
		t.Fatalf("netdev: %v", cur)
	}
	parseStat("cpu  10 0 10 70 0 0 10 0 0 0\ncpu0 5 0 5 10 0 0 9 0 0 0\ncpu1 5 0 5 60 0 0 1 0 0 0\nintr 1 2 3\n", cur)
	if cur["_cpu_si"] != 10 || cur["_si.0"] != 9 || cur["_tot.1"] != 71 {
		t.Fatalf("stat: %v", cur)
	}
}
