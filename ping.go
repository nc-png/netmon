package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Pinger echoes every target once per tick over one raw ICMP socket (same
// CAP_NET_RAW the sniffers already need) and accumulates per-target RTT and
// timeouts. A probe unanswered after 1s counts as lost; a failed sendto (no
// route) is left pending and ages into lost, which is the right verdict.
// IPv4 only — nexthops are v4 here.
// ponytail: replies filtered in userspace — fine at nexthop rates; attach a
// cBPF like sniff.go if an ICMP flood ever makes this loop matter.
type Pinger struct {
	fd      int
	targets []string
	addrs   []syscall.SockaddrInet4
	id      uint16
	mu      sync.Mutex
	seq     uint16
	sent    map[uint16]probe // seq -> in flight
	rttSum  []float64        // ms, per target, since last Flush
	rttN    []int
	lost    []int
}

type probe struct {
	target int
	at     time.Time
}

const pingTimeout = time.Second

func NewPinger(targets []string) (*Pinger, error) {
	p := &Pinger{targets: targets, id: uint16(os.Getpid()),
		sent:   map[uint16]probe{},
		rttSum: make([]float64, len(targets)),
		rttN:   make([]int, len(targets)),
		lost:   make([]int, len(targets))}
	for _, t := range targets {
		ip := net.ParseIP(t).To4()
		if ip == nil {
			return nil, fmt.Errorf("%q: not an IPv4 address", t)
		}
		p.addrs = append(p.addrs, syscall.SockaddrInet4{Addr: [4]byte(ip)})
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w (needs root or CAP_NET_RAW)", err)
	}
	p.fd = fd
	go p.loop()
	return p, nil
}

// Probe sends one echo request per target. Called from the tick loop.
func (p *Pinger) Probe() {
	now := time.Now()
	seqs := make([]uint16, len(p.addrs))
	p.mu.Lock()
	for i := range p.addrs {
		p.seq++
		seqs[i] = p.seq
		p.sent[p.seq] = probe{i, now}
	}
	p.mu.Unlock()
	for i := range p.addrs {
		syscall.Sendto(p.fd, icmpEcho(p.id, seqs[i]), 0, &p.addrs[i])
	}
}

// Flush expires timed-out probes and moves this tick's results into vals:
// ping.<ip>.rtt (gauge, ms; absent = no reply this tick) and
// ping.<ip>.lost (counter of timeouts).
func (p *Pinger) Flush(vals map[string]float64) {
	cut := time.Now().Add(-pingTimeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	for seq, pr := range p.sent {
		if pr.at.Before(cut) {
			p.lost[pr.target]++
			delete(p.sent, seq)
		}
	}
	for i, t := range p.targets {
		if p.rttN[i] > 0 {
			vals["ping."+t+".rtt"] = p.rttSum[i] / float64(p.rttN[i])
		}
		vals["ping."+t+".lost"] = float64(p.lost[i])
		p.rttSum[i], p.rttN[i], p.lost[i] = 0, 0, 0
	}
}

func (p *Pinger) loop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(p.fd, buf, 0)
		if err != nil {
			return
		}
		seq, ok := parseEchoReply(buf[:n], p.id)
		if !ok {
			continue
		}
		now := time.Now()
		p.mu.Lock()
		if pr, hit := p.sent[seq]; hit {
			delete(p.sent, seq)
			p.rttSum[pr.target] += float64(now.Sub(pr.at)) / float64(time.Millisecond)
			p.rttN[pr.target]++
		}
		p.mu.Unlock()
	}
}

// parseEchoReply extracts our seq from a raw IPv4 packet holding an ICMP
// echo reply with our id. Raw ICMP sockets deliver the IP header too.
func parseEchoReply(b []byte, id uint16) (uint16, bool) {
	if len(b) < 20 {
		return 0, false
	}
	ihl := int(b[0]&0xf) * 4
	if ihl < 20 || len(b) < ihl+8 || b[ihl] != 0 || b[ihl+1] != 0 { // type 0 code 0
		return 0, false
	}
	if binary.BigEndian.Uint16(b[ihl+4:]) != id {
		return 0, false
	}
	return binary.BigEndian.Uint16(b[ihl+6:]), true
}

// icmpEcho builds a payload-less ICMP echo request (RTT lives in p.sent,
// not in the packet).
func icmpEcho(id, seq uint16) []byte {
	m := []byte{8, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], seq)
	var s uint32
	for i := 0; i < len(m); i += 2 {
		s += uint32(binary.BigEndian.Uint16(m[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(m[2:], ^uint16(s))
	return m
}
