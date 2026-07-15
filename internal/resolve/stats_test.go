package resolve

import (
	"testing"

	"github.com/reloadlife/dnsd/pkg/api"
)

func TestTelemetryQPSAndRecent(t *testing.T) {
	tel := NewTelemetry(5)
	for i := 0; i < 7; i++ {
		tel.Record(api.QueryEvent{
			Name: "n.com", Action: "allow", RCode: "NOERROR", QType: "A",
			Protocol: "udp", Client: "10.0.0.1",
		})
	}
	tel.Record(api.QueryEvent{
		Name: "bad.com", Action: "block", RCode: "NXDOMAIN", QType: "A",
		Protocol: "tcp", Client: "10.0.0.2",
	})
	tel.Record(api.QueryEvent{
		Name: "err.com", Action: "error", RCode: "SERVFAIL", Error: "x",
		Protocol: "udp", Client: "10.0.0.1",
	})
	tel.CacheHit()
	tel.CacheMiss()

	if n := len(tel.Recent(3)); n != 3 {
		t.Fatalf("recent %d", n)
	}
	// ring cap 5
	if n := len(tel.Recent(100)); n != 5 {
		t.Fatalf("cap recent %d", n)
	}
	q, b, _, er, ch, cm := tel.Counters()
	if q < 8 || b != 1 || er != 1 || ch != 1 || cm != 1 {
		t.Fatalf("counters q=%d b=%d er=%d ch=%d cm=%d", q, b, er, ch, cm)
	}
	if tel.QPS() <= 0 {
		t.Fatal("qps")
	}
	snap := tel.Snapshot()
	if snap.QueryCount != q || len(snap.TopDomains) == 0 {
		t.Fatalf("%+v", snap)
	}
	if snap.ByProto["udp"] == 0 {
		t.Fatal(snap.ByProto)
	}
}
