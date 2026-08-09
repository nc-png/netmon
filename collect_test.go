package main

import "testing"

func TestReadSockstat(t *testing.T) {
	// exercises the real /proc file; just assert the gauges come out sane
	out := map[string]float64{}
	readSockstat(out)
	if out["sys.tcp_inuse"] < 1 {
		t.Fatalf("expected at least one TCP socket in use, got %v", out)
	}
}
