package main

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed ui
var uiFS embed.FS

type api struct {
	st     *Store
	ifaces []string
	ping   []string
	events map[string]*EventRing
}

func newAPI(st *Store, ifaces, ping []string, events map[string]*EventRing) http.Handler {
	a := &api{st, ifaces, ping, events}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serveAsset(w, "ui/index.html", "text/html; charset=utf-8")
	})
	mux.HandleFunc("/uplot.js", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "ui/uplot.js", "text/javascript")
	})
	mux.HandleFunc("/uplot.css", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, "ui/uplot.css", "text/css")
	})
	mux.HandleFunc("/api/meta", a.meta)
	mux.HandleFunc("/api/query", a.query)
	mux.HandleFunc("/api/talkers", a.talkers)
	mux.HandleFunc("/api/tcpevents", a.tcpevents)
	return gzipMW(mux)
}

// gzipMW compresses responses (~10x on the repetitive JSON) so the dashboard's
// own polling doesn't dominate the traffic it is measuring.
type gzWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g gzWriter) Write(b []byte) (int, error) { return g.gz.Write(b) }

func gzipMW(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		h.ServeHTTP(gzWriter{w, gz}, r)
	})
}

func serveAsset(w http.ResponseWriter, path, ctype string) {
	b, _ := uiFS.ReadFile(path)
	w.Header().Set("Content-Type", ctype)
	w.Write(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func atoi64(s string, def int64) int64 {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	return def
}

func (a *api) meta(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	oldest := a.st.msOf(a.st.last - a.st.slots + 1)
	a.st.mu.RUnlock()
	writeJSON(w, map[string]any{
		"ifaces":   a.ifaces,
		"ping":     a.ping,
		"periodMs": tickMs,
		"nowMs":    time.Now().UnixMilli(),
		"oldestMs": oldest,
	})
}

func (a *api) query(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now().UnixMilli()
	from := atoi64(q.Get("from"), now-15*60*1000)
	to := atoi64(q.Get("to"), now)
	points := int(atoi64(q.Get("points"), 800))
	points = max(1, min(points, 4000))
	type sd struct {
		Avg []any `json:"avg"`
		Max []any `json:"max"`
	}
	resp := struct {
		FromMs int64          `json:"fromMs"`
		StepMs int64          `json:"stepMs"`
		Series map[string]*sd `json:"series"`
	}{StepMs: tickMs, Series: map[string]*sd{}}
	for _, n := range strings.Split(q.Get("series"), ",") {
		res, ok := a.st.Query(n, from, to, points)
		if !ok {
			continue
		}
		resp.FromMs, resp.StepMs = res.FromMs, res.StepMs
		resp.Series[n] = &sd{Avg: jsonNums(res.Avg), Max: jsonNums(res.Max)}
	}
	writeJSON(w, resp)
}

func jsonNums(v []float64) []any {
	out := make([]any, len(v))
	for i, x := range v {
		if !math.IsNaN(x) {
			out[i] = math.Round(x*100) / 100
		}
	}
	return out
}

func (a *api) tcpevents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now().UnixMilli()
	from := atoi64(q.Get("from"), now-15*60*1000)
	to := atoi64(q.Get("to"), now)
	n := int(atoi64(q.Get("n"), 30))
	n = max(1, min(n, 200))
	rows, total := []EventAgg{}, uint64(0)
	if ring := a.events[q.Get("iface")]; ring != nil {
		if rs, t := ring.Aggregate(from, to, n); rs != nil {
			rows, total = rs, t
		}
	}
	writeJSON(w, map[string]any{"rows": rows, "total": total})
}

func (a *api) talkers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now().UnixMilli()
	from := atoi64(q.Get("from"), now-15*60*1000)
	to := atoi64(q.Get("to"), now)
	n := int(atoi64(q.Get("n"), 20))
	n = max(1, min(n, 200))
	iface := q.Get("iface")
	writeJSON(w, map[string]any{
		"rx": a.st.TopTalkers(iface+"/rx", from, to, n),
		"tx": a.st.TopTalkers(iface+"/tx", from, to, n),
	})
}
