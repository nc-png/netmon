package main

import (
	"flag"
	"log"
	"math/bits"
	"net/http"
	"strings"
	"syscall"
	"time"
)

func main() {
	ifaces := flag.String("ifaces", "", "comma-separated interfaces to monitor (required), e.g. eth0,eth1")
	listen := flag.String("listen", "127.0.0.1:8676", "HTTP listen address (ip:port)")
	sample := flag.Uint64("sample", 128, "talker packet sampling, 1-in-N (rounded up to a power of two; 1 = every packet)")
	retention := flag.Duration("retention", 7*24*time.Hour, "in-RAM history retention")
	topn := flag.Int("topn", 20, "top talkers kept per 200ms tick per direction")
	ping := flag.String("ping", "", "comma-separated IPv4 addresses to ICMP-probe each tick (e.g. your nexthops)")
	noMlock := flag.Bool("no-mlock", false, "skip mlockall (history may be swapped to disk)")
	flag.Parse()
	if *ifaces == "" {
		log.Fatal("-ifaces is required, e.g. -ifaces eth0,eth1")
	}
	list := strings.Split(*ifaces, ",")
	if n := *sample; n > 1 && n&(n-1) != 0 {
		*sample = 1 << bits.Len64(n)
		log.Printf("sample rate rounded up to 1-in-%d", *sample)
	}

	if !*noMlock {
		// nothing-on-disk: pin history so it can't hit swap
		if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
			log.Printf("mlockall failed (%v); continuing, memory may swap", err)
		}
	}

	st := NewStore(*retention, *topn)
	for _, i := range list {
		for _, s := range []string{"rx_bytes", "tx_bytes", "rx_pkts", "tx_pkts", "rx_drop", "tx_drop", "rx_errs", "tx_errs"} {
			st.AddSeries(i+"."+s, false)
		}
		st.AddTalkers(i + "/rx")
		st.AddTalkers(i + "/tx")
	}
	for _, s := range []string{"tcp.attempt_fails", "tcp.estab_resets", "tcp.retrans_segs",
		"tcp.listen_drops", "tcp.listen_overflows",
		"sys.softirq_net_rx", "sys.softirq_net_tx", "sys.softnet_drop", "sys.softnet_squeeze"} {
		st.AddSeries(s, false)
	}
	st.AddSeries("sys.cpu_busy", true)
	st.AddSeries("sys.cpu_softirq", true)
	st.AddSeries("sys.cpu_softirq_max", true)
	st.AddSeries("sys.conntrack_pct", true)
	st.AddSeries("sys.tcp_inuse", true)
	st.AddSeries("sys.tcp_tw", true)
	st.AddSeries("sys.tcp_orphan", true)

	var pinger *Pinger
	var pingTargets []string
	if *ping != "" {
		pingTargets = strings.Split(*ping, ",")
		p, err := NewPinger(pingTargets)
		if err != nil {
			log.Printf("icmp probing DISABLED: %v", err)
			pingTargets = nil
		} else {
			pinger = p
			for _, t := range pingTargets {
				st.AddSeries("ping."+t+".rtt", true)
				st.AddSeries("ping."+t+".lost", false)
			}
		}
	}

	sniffers := map[string]*Sniffer{}
	events := map[string]*EventRing{}
	for _, i := range list {
		sn, err := NewSniffer(i, *sample)
		if err != nil {
			log.Printf("top-talker sampling DISABLED on %s: %v", i, err)
		} else {
			sniffers[i] = sn
		}
		events[i] = NewEventRing()
		if err := NewEventSniffer(i, events[i]); err != nil {
			log.Printf("tcp event capture DISABLED on %s: %v", i, err)
		}
	}

	col := NewCollector(list)
	col.Collect() // prime counters
	go func() {
		tk := time.NewTicker(tickMs * time.Millisecond)
		for now := range tk.C {
			vals := col.Collect()
			if pinger != nil {
				pinger.Flush(vals)
				pinger.Probe()
			}
			tops := map[string]map[[16]byte]uint64{}
			for i, sn := range sniffers {
				tops[i+"/rx"], tops[i+"/tx"] = sn.Flush()
			}
			st.Commit(st.tickOf(now.UnixMilli()), vals, tops)
		}
	}()

	histMB := (int64(len(st.names))*st.slots*8 + int64(len(list))*2*st.slots*st.topN*12) >> 20
	log.Printf("monserver: http://%s ifaces=%v sample=1/%d retention=%s history≈%dMB",
		*listen, list, *sample, *retention, histMB)
	log.Fatal(http.ListenAndServe(*listen, newAPI(st, list, pingTargets, events)))
}
