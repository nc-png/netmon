package main

import (
	"syscall"
	"testing"
)

// runCBPF interprets the subset of classic BPF used by tcpEventFilter,
// pinning the hand-assembled program's behavior.
func runCBPF(prog []syscall.SockFilter, pkt []byte) uint32 {
	var A, X uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case 0x28: // ldh [k]
			if int(in.K)+2 > len(pkt) {
				return 0
			}
			A = uint32(pkt[in.K])<<8 | uint32(pkt[in.K+1])
		case 0x30: // ldb [k]
			if int(in.K)+1 > len(pkt) {
				return 0
			}
			A = uint32(pkt[in.K])
		case 0x50: // ldb [x+k]
			off := int(X) + int(in.K)
			if off+1 > len(pkt) {
				return 0
			}
			A = uint32(pkt[off])
		case 0xb1: // ldx 4*([k]&0xf)
			if int(in.K)+1 > len(pkt) {
				return 0
			}
			X = uint32(pkt[in.K]&0xf) * 4
		case 0x15: // jeq
			if A == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x45: // jset
			if A&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x06: // ret
			return in.K
		default:
			panic("unhandled opcode")
		}
	}
	return 0
}

// v4pkt builds eth+ipv4+tcp with the given tcp flags and frag field.
func v4pkt(flags byte, frag uint16) []byte {
	b := make([]byte, 54)
	b[12], b[13] = 0x08, 0x00
	b[14] = 0x45 // ihl 5
	b[14+6], b[14+7] = byte(frag>>8), byte(frag)
	b[14+9] = 6 // TCP
	copy(b[14+12:], []byte{192, 0, 2, 1})
	copy(b[14+16:], []byte{192, 0, 2, 2})
	b[34], b[35] = 0xE8, 0x5C // sport 59484
	b[36], b[37] = 0x21, 0xE4 // dport 8676
	b[34+13] = flags
	return b
}

func v6pkt(flags byte) []byte {
	b := make([]byte, 74)
	b[12], b[13] = 0x86, 0xdd
	b[14+6] = 6 // next header TCP
	b[14+8] = 0x20
	b[54+13] = flags
	return b
}

func TestEventFilter(t *testing.T) {
	acc := func(p []byte) bool { return runCBPF(tcpEventFilter, p) > 0 }
	if !acc(v4pkt(0x02, 0)) || !acc(v4pkt(0x12, 0)) || !acc(v4pkt(0x14, 0)) {
		t.Fatal("v4 SYN/SYN-ACK/RST not accepted")
	}
	if !acc(v6pkt(0x04)) {
		t.Fatal("v6 RST not accepted")
	}
	if acc(v4pkt(0x10, 0)) || acc(v6pkt(0x18)) {
		t.Fatal("plain ACK/PSH accepted")
	}
	if acc(v4pkt(0x02, 100)) {
		t.Fatal("non-first fragment accepted")
	}
	arp := make([]byte, 60)
	arp[12], arp[13] = 0x08, 0x06
	if acc(arp) {
		t.Fatal("ARP accepted")
	}
}

func TestParseTCPHdr(t *testing.T) {
	src, _, sport, dport, flags, ok := parseTCPHdr(v4pkt(0x14, 0))
	if !ok || sport != 59484 || dport != 8676 || flags != 0x14 || src != ip4(192, 0, 2, 1) {
		t.Fatalf("ok=%v sport=%d dport=%d flags=%x", ok, sport, dport, flags)
	}
	if _, _, _, _, _, ok := parseTCPHdr(v4pkt(0x02, 100)); ok {
		t.Fatal("fragment parsed")
	}
}

func TestEventAggregate(t *testing.T) {
	r := NewEventRing()
	a := ip4(1, 2, 3, 4)
	for i := 0; i < 3; i++ {
		r.Add(TCPEvent{Ms: 1000 + int64(i), Typ: evRST, Out: true, Remote: a, RPort: 50000 + uint16(i), LPort: 8676})
	}
	r.Add(TCPEvent{Ms: 5000, Typ: evSYN, Remote: a, RPort: 1234, LPort: 80}) // outside window
	rows, total := r.Aggregate(900, 1100, 10)
	if total != 3 || len(rows) != 1 || rows[0].Type != "RST" || rows[0].Dir != "out" ||
		rows[0].Remote != "1.2.3.4" || rows[0].Port != 8676 || rows[0].Count != 3 {
		t.Fatalf("rows=%+v total=%d", rows, total)
	}
}
