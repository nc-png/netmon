package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// Sniffer samples 1-in-N packets on one interface via AF_PACKET plus a
// classic-BPF random filter (sampling happens in the kernel; only sampled
// packets are copied out, truncated to 96 bytes). It accounts estimated wire
// bytes per remote IP: source IP for inbound, destination IP for outbound.
// ponytail: one socket per iface — plenty for sampled rates; add
// PACKET_FANOUT across cores if a reader ever saturates.
type Sniffer struct {
	iface  string
	sample uint64
	fd     int
	mu     sync.Mutex
	rx, tx map[[16]byte]uint64
}

func NewSniffer(iface string, sample uint64) (*Sniffer, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	// protocol 0: no packets delivered until bind, so the filter attaches to a quiet socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w (needs root or CAP_NET_RAW)", err)
	}
	if sample > 1 {
		filt := []syscall.SockFilter{
			{Code: 0x20, K: 0xfffff038},         // A = prandom_u32 (SKF_AD_OFF + SKF_AD_RANDOM)
			{Code: 0x54, K: uint32(sample - 1)}, // A &= sample-1  (sample is a power of two)
			{Code: 0x15, Jt: 0, Jf: 1, K: 0},    // A == 0 ? accept : drop
			{Code: 0x06, K: 96},                 // accept, snap 96 bytes
			{Code: 0x06, K: 0},                  // drop
		}
		if err := syscall.AttachLsf(fd, filt); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("attach filter: %w", err)
		}
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}
	s := &Sniffer{iface: iface, sample: sample, fd: fd,
		rx: map[[16]byte]uint64{}, tx: map[[16]byte]uint64{}}
	go s.loop()
	return s, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (s *Sniffer) loop() {
	buf := make([]byte, 256)
	for {
		n, from, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			log.Printf("sniffer %s stopped: %v", s.iface, err)
			return
		}
		sll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}
		src, dst, wire, ok := parsePacket(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		if sll.Pkttype == syscall.PACKET_OUTGOING {
			s.tx[dst] += wire
		} else {
			s.rx[src] += wire
		}
		s.mu.Unlock()
	}
}

// parsePacket extracts src/dst IP (v4-mapped into 16 bytes) and estimated wire
// length from a (possibly truncated) ethernet frame. Handles one VLAN tag.
// Wire length comes from the IP header, +18 for L2 framing, so truncation
// doesn't matter.
func parsePacket(b []byte) (src, dst [16]byte, wire uint64, ok bool) {
	if len(b) < 14 {
		return
	}
	et := uint16(b[12])<<8 | uint16(b[13])
	off := 14
	if et == 0x8100 || et == 0x88a8 {
		if len(b) < 18 {
			return
		}
		et = uint16(b[16])<<8 | uint16(b[17])
		off = 18
	}
	switch et {
	case 0x0800: // IPv4
		if len(b) < off+20 {
			return
		}
		wire = (uint64(b[off+2])<<8 | uint64(b[off+3])) + 18
		src[10], src[11] = 0xff, 0xff
		dst[10], dst[11] = 0xff, 0xff
		copy(src[12:], b[off+12:off+16])
		copy(dst[12:], b[off+16:off+20])
	case 0x86dd: // IPv6
		if len(b) < off+40 {
			return
		}
		wire = (uint64(b[off+4])<<8 | uint64(b[off+5])) + 40 + 18
		copy(src[:], b[off+8:off+24])
		copy(dst[:], b[off+24:off+40])
	default:
		return
	}
	return src, dst, wire, true
}

// tcpEventFilter is hand-assembled cBPF matching untagged IPv4/IPv6 TCP
// packets with SYN or RST set (behavior pinned by TestEventFilter).
// ponytail: VLAN-tagged frames don't match — extend the offsets if you run tagged.
var tcpEventFilter = []syscall.SockFilter{
	{Code: 0x28, K: 12},                   //  0: ldh ethertype
	{Code: 0x15, Jt: 0, Jf: 7, K: 0x0800}, //  1: IPv4? else -> 9
	{Code: 0x30, K: 23},                   //  2: ldb ip proto
	{Code: 0x15, Jt: 0, Jf: 11, K: 6},     //  3: TCP? else drop
	{Code: 0x28, K: 20},                   //  4: ldh frag field
	{Code: 0x45, Jt: 9, Jf: 0, K: 0x1fff}, //  5: non-first fragment -> drop
	{Code: 0xb1, K: 14},                   //  6: X = ip header len
	{Code: 0x50, K: 27},                   //  7: ldb tcp flags [14+ihl+13]
	{Code: 0x45, Jt: 5, Jf: 6, K: 0x06},   //  8: SYN|RST? accept : drop
	{Code: 0x15, Jt: 0, Jf: 5, K: 0x86dd}, //  9: IPv6? else drop
	{Code: 0x30, K: 20},                   // 10: ldb next header
	{Code: 0x15, Jt: 0, Jf: 3, K: 6},      // 11: TCP (no ext headers)? else drop
	{Code: 0x30, K: 67},                   // 12: ldb tcp flags [14+40+13]
	{Code: 0x45, Jt: 0, Jf: 1, K: 0x06},   // 13: SYN|RST? accept : drop
	{Code: 0x06, K: 96},                   // 14: accept, snap 96 bytes
	{Code: 0x06, K: 0},                    // 15: drop
}

// EventSniffer records every (unsampled) TCP SYN/SYN-ACK/RST on one interface
// into an EventRing — control packets are rare relative to line rate, and
// they are what TCP failures are made of.
func NewEventSniffer(iface string, ring *EventRing) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w (needs root or CAP_NET_RAW)", err)
	}
	if err := syscall.AttachLsf(fd, tcpEventFilter); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("attach filter: %w", err)
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bind %s: %w", iface, err)
	}
	go func() {
		buf := make([]byte, 128)
		for {
			n, from, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				log.Printf("event sniffer %s stopped: %v", iface, err)
				return
			}
			sll, ok := from.(*syscall.SockaddrLinklayer)
			if !ok {
				continue
			}
			src, dst, sport, dport, flags, ok := parseTCPHdr(buf[:n])
			if !ok {
				continue
			}
			e := TCPEvent{Ms: time.Now().UnixMilli(), Out: sll.Pkttype == syscall.PACKET_OUTGOING}
			switch {
			case flags&0x04 != 0:
				e.Typ = evRST
			case flags&0x12 == 0x12:
				e.Typ = evSYNACK
			case flags&0x02 != 0:
				e.Typ = evSYN
			default:
				continue
			}
			if e.Out {
				e.Remote, e.RPort, e.LPort = dst, dport, sport
			} else {
				e.Remote, e.RPort, e.LPort = src, sport, dport
			}
			ring.Add(e)
		}
	}()
	return nil
}

// parseTCPHdr extracts addresses, ports and TCP flags from an ethernet frame
// (handles one VLAN tag; IPv6 without extension headers).
func parseTCPHdr(b []byte) (src, dst [16]byte, sport, dport uint16, flags byte, ok bool) {
	if len(b) < 14 {
		return
	}
	et := uint16(b[12])<<8 | uint16(b[13])
	off := 14
	if et == 0x8100 || et == 0x88a8 {
		if len(b) < 18 {
			return
		}
		et = uint16(b[16])<<8 | uint16(b[17])
		off = 18
	}
	var tcp int
	switch et {
	case 0x0800:
		ihl := int(b[off]&0xf) * 4
		if len(b) < off+ihl+14 || b[off+9] != 6 {
			return
		}
		if (uint16(b[off+6])<<8|uint16(b[off+7]))&0x1fff != 0 { // non-first fragment
			return
		}
		src[10], src[11] = 0xff, 0xff
		dst[10], dst[11] = 0xff, 0xff
		copy(src[12:], b[off+12:off+16])
		copy(dst[12:], b[off+16:off+20])
		tcp = off + ihl
	case 0x86dd:
		if len(b) < off+40+14 || b[off+6] != 6 {
			return
		}
		copy(src[:], b[off+8:off+24])
		copy(dst[:], b[off+24:off+40])
		tcp = off + 40
	default:
		return
	}
	sport = uint16(b[tcp])<<8 | uint16(b[tcp+1])
	dport = uint16(b[tcp+2])<<8 | uint16(b[tcp+3])
	flags = b[tcp+13]
	return src, dst, sport, dport, flags, true
}

// Flush returns and resets the per-IP accumulators, scaled by the sample rate
// to estimated true bytes.
func (s *Sniffer) Flush() (rx, tx map[[16]byte]uint64) {
	s.mu.Lock()
	rx, tx = s.rx, s.tx
	s.rx, s.tx = map[[16]byte]uint64{}, map[[16]byte]uint64{}
	s.mu.Unlock()
	if s.sample > 1 {
		for _, m := range []map[[16]byte]uint64{rx, tx} {
			for k := range m {
				m[k] *= s.sample
			}
		}
	}
	return
}
