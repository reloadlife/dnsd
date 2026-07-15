//go:build live

package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/store"
	"github.com/reloadlife/dnsd/pkg/api"
)

func TestLiveUpstreams(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	m.RecursionDesired = true
	ctx := context.Background()
	for _, u := range []api.Upstream{
		store.ParseUpstream("1.1.1.1:53", api.Upstream{}),
		store.ParseUpstream("tls://1.1.1.1:853", api.Upstream{ServerName: "cloudflare-dns.com"}),
		store.ParseUpstream("https://cloudflare-dns.com/dns-query", api.Upstream{}),
		store.ParseUpstream("https://1.1.1.1/dns-query", api.Upstream{}),
		store.ParseUpstream("https://dns.google/dns-query", api.Upstream{}),
	} {
		resp, used, err := Exchange(ctx, m, u, 10*time.Second)
		if err != nil {
			t.Logf("FAIL %s: %v", used, err)
			continue
		}
		t.Logf("OK %s rcode=%s n=%d", used, dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}
