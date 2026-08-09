package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestEchoRoundtrip(t *testing.T) {
	m := icmpEcho(0x1234, 7)
	var s uint32
	for i := 0; i < len(m); i += 2 {
		s += uint32(binary.BigEndian.Uint16(m[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	if s != 0xffff {
		t.Fatalf("checksum doesn't verify: %#x", s)
	}
	// wrap as the raw reply the kernel would deliver: IP header + type flipped to 0
	pkt := append(make([]byte, 20), m...)
	pkt[0] = 0x45
	pkt[20] = 0
	if seq, ok := parseEchoReply(pkt, 0x1234); !ok || seq != 7 {
		t.Fatalf("parse: ok=%v seq=%d", ok, seq)
	}
	if _, ok := parseEchoReply(pkt, 0x9999); ok {
		t.Fatal("accepted a reply with a foreign id")
	}
	if _, ok := parseEchoReply(pkt[:22], 0x1234); ok {
		t.Fatal("accepted a truncated packet")
	}
}

func TestFlushTimeout(t *testing.T) {
	p := &Pinger{targets: []string{"10.0.0.1"},
		sent:   map[uint16]probe{1: {0, time.Now().Add(-2 * pingTimeout)}, 2: {0, time.Now()}},
		rttSum: []float64{3}, rttN: []int{2}, lost: []int{0}}
	vals := map[string]float64{}
	p.Flush(vals)
	if vals["ping.10.0.0.1.lost"] != 1 || vals["ping.10.0.0.1.rtt"] != 1.5 {
		t.Fatalf("got %v", vals)
	}
	if len(p.sent) != 1 || p.rttN[0] != 0 {
		t.Fatalf("fresh probe expired or accumulators kept: %v %v", p.sent, p.rttN)
	}
}
