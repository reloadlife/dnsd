package resolve

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reloadlife/dnsd/pkg/api"
)

// Telemetry holds live counters, query log, and top-N aggregates.
type Telemetry struct {
	started time.Time

	queryCount   atomic.Int64
	blockCount   atomic.Int64
	rewriteCount atomic.Int64
	errorCount   atomic.Int64
	refuseCount  atomic.Int64
	dropCount    atomic.Int64
	cacheHits    atomic.Int64
	cacheMisses  atomic.Int64

	// QPS window
	qpsMu     sync.Mutex
	qpsTimes  []time.Time
	qpsWindow time.Duration

	mu       sync.Mutex
	log      []api.QueryEvent
	logCap   int
	byRCode  map[string]int64
	byQType  map[string]int64
	byProto  map[string]int64
	byAction map[string]int64
	domains  map[string]*domainAcc
	clients  map[string]*clientAcc
	errRing  []api.QueryEvent
}

type domainAcc struct {
	queries  int64
	blocks   int64
	errors   int64
	lastSeen time.Time
}

type clientAcc struct {
	queries  int64
	blocks   int64
	errors   int64
	lastSeen time.Time
}

// NewTelemetry creates telemetry with ring capacity.
func NewTelemetry(logCap int) *Telemetry {
	if logCap <= 0 {
		logCap = 2000
	}
	return &Telemetry{
		started:   time.Now(),
		logCap:    logCap,
		qpsWindow: 10 * time.Second,
		byRCode:   map[string]int64{},
		byQType:   map[string]int64{},
		byProto:   map[string]int64{},
		byAction:  map[string]int64{},
		domains:   map[string]*domainAcc{},
		clients:   map[string]*clientAcc{},
	}
}

// Record ingests a completed query event.
func (t *Telemetry) Record(ev api.QueryEvent) {
	t.queryCount.Add(1)
	switch ev.Action {
	case "block":
		t.blockCount.Add(1)
	case "rewrite", "sinkhole":
		t.rewriteCount.Add(1)
	case "error":
		t.errorCount.Add(1)
	case "refuse":
		t.refuseCount.Add(1)
	case "drop":
		t.dropCount.Add(1)
	case "cache":
		t.cacheHits.Add(1)
	}
	if ev.Action == "allow" || ev.Action == "forward" {
		// miss counted when forward path used
	}
	if ev.Error != "" && ev.Action != "error" {
		// still count soft errors under rcode SERVFAIL etc.
	}

	now := time.Now()
	t.qpsMu.Lock()
	t.qpsTimes = append(t.qpsTimes, now)
	cut := now.Add(-t.qpsWindow)
	i := 0
	for i < len(t.qpsTimes) && t.qpsTimes[i].Before(cut) {
		i++
	}
	if i > 0 {
		t.qpsTimes = t.qpsTimes[i:]
	}
	t.qpsMu.Unlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.byRCode[ev.RCode]++
	t.byQType[ev.QType]++
	t.byProto[ev.Protocol]++
	t.byAction[ev.Action]++

	d := t.domains[ev.Name]
	if d == nil {
		d = &domainAcc{}
		t.domains[ev.Name] = d
	}
	d.queries++
	d.lastSeen = now
	if ev.Action == "block" {
		d.blocks++
	}
	if ev.Action == "error" || ev.RCode == "SERVFAIL" {
		d.errors++
	}

	c := t.clients[ev.Client]
	if c == nil {
		c = &clientAcc{}
		t.clients[ev.Client] = c
	}
	c.queries++
	c.lastSeen = now
	if ev.Action == "block" {
		c.blocks++
	}
	if ev.Action == "error" || ev.RCode == "SERVFAIL" {
		c.errors++
	}

	t.log = append(t.log, ev)
	if len(t.log) > t.logCap {
		t.log = t.log[len(t.log)-t.logCap:]
	}
	if ev.Action == "error" || ev.RCode == "SERVFAIL" || ev.Error != "" {
		t.errRing = append(t.errRing, ev)
		if len(t.errRing) > 100 {
			t.errRing = t.errRing[len(t.errRing)-100:]
		}
	}
}

// CacheHit increments cache hit counter.
func (t *Telemetry) CacheHit() { t.cacheHits.Add(1) }

// CacheMiss increments cache miss counter.
func (t *Telemetry) CacheMiss() { t.cacheMisses.Add(1) }

// QPS returns queries per second over the sliding window.
func (t *Telemetry) QPS() float64 {
	t.qpsMu.Lock()
	defer t.qpsMu.Unlock()
	n := len(t.qpsTimes)
	if n == 0 {
		return 0
	}
	return float64(n) / t.qpsWindow.Seconds()
}

// Counters returns primary counters.
func (t *Telemetry) Counters() (q, b, rw, err, ch, cm int64) {
	return t.queryCount.Load(), t.blockCount.Load(), t.rewriteCount.Load(),
		t.errorCount.Load(), t.cacheHits.Load(), t.cacheMisses.Load()
}

// Recent returns last n query events (newest last).
func (t *Telemetry) Recent(n int) []api.QueryEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n <= 0 || n > len(t.log) {
		n = len(t.log)
	}
	if n == 0 {
		return nil
	}
	out := make([]api.QueryEvent, n)
	copy(out, t.log[len(t.log)-n:])
	return out
}

// Snapshot builds StatsSnapshot.
func (t *Telemetry) Snapshot() api.StatsSnapshot {
	q, b, rw, er, ch, cm := t.Counters()
	snap := api.StatsSnapshot{
		CollectedAt:  time.Now().UTC().Format(time.RFC3339),
		UptimeSec:    time.Since(t.started).Seconds(),
		QueryCount:   q,
		BlockCount:   b,
		RewriteCount: rw,
		ErrorCount:   er,
		RefuseCount:  t.refuseCount.Load(),
		DropCount:    t.dropCount.Load(),
		CacheHits:    ch,
		CacheMisses:  cm,
		QPS:          t.QPS(),
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	snap.ByRCode = copyMap(t.byRCode)
	snap.ByQType = copyMap(t.byQType)
	snap.ByProto = copyMap(t.byProto)
	snap.ByAction = copyMap(t.byAction)

	type kv struct {
		name string
		acc  *domainAcc
	}
	var doms []kv
	for n, a := range t.domains {
		doms = append(doms, kv{n, a})
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].acc.queries > doms[j].acc.queries })
	for i, d := range doms {
		if i >= 50 {
			break
		}
		snap.TopDomains = append(snap.TopDomains, api.DomainStat{
			Name: d.name, Queries: d.acc.queries, Blocks: d.acc.blocks, Errors: d.acc.errors,
			LastSeen: d.acc.lastSeen.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].acc.blocks > doms[j].acc.blocks })
	for i, d := range doms {
		if i >= 30 || d.acc.blocks == 0 {
			break
		}
		snap.TopBlocked = append(snap.TopBlocked, api.DomainStat{
			Name: d.name, Queries: d.acc.queries, Blocks: d.acc.blocks,
			LastSeen: d.acc.lastSeen.UTC().Format(time.RFC3339),
		})
	}

	type ck struct {
		name string
		acc  *clientAcc
	}
	var cls []ck
	for n, a := range t.clients {
		cls = append(cls, ck{n, a})
	}
	sort.Slice(cls, func(i, j int) bool { return cls[i].acc.queries > cls[j].acc.queries })
	for i, c := range cls {
		if i >= 40 {
			break
		}
		snap.TopClients = append(snap.TopClients, api.ClientStat{
			Client: c.name, Queries: c.acc.queries, Blocks: c.acc.blocks, Errors: c.acc.errors,
			LastSeen: c.acc.lastSeen.UTC().Format(time.RFC3339),
		})
	}
	if len(t.errRing) > 0 {
		snap.RecentErrors = append([]api.QueryEvent(nil), t.errRing...)
	}
	return snap
}

func copyMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
