// Command dnsd is the node DNS resolver / policy daemon.
// Sister to wireguardd / openvpnd / netpolicyd.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/reloadlife/dnsd/internal/api"
	"github.com/reloadlife/dnsd/internal/resolve"
	"github.com/reloadlife/dnsd/internal/store"
	pkg "github.com/reloadlife/dnsd/pkg/api"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}

	listen := flag.String("listen", "127.0.0.1:51920", "HTTP control API listen address")
	token := flag.String("token", "dev-token", "Bearer token for /v1/*")
	dnsListen := flag.String("dns-listen", "127.0.0.1:5353", "UDP/TCP DNS listen address")
	bindIP := flag.String("bind-ip", "", "default outbound source IP for upstream queries")
	bindIface := flag.String("bind-iface", "", "default outbound interface for upstream queries")
	upstream := flag.String("upstream", "1.1.1.1:53,8.8.8.8:53", "comma-separated default upstreams (dns/DoT/DoH URLs)")
	flag.Parse()

	st := store.New()
	cfg := st.Config()
	if *dnsListen != "" {
		cfg.Listeners.UDP = *dnsListen
		cfg.Listeners.TCP = *dnsListen
	}
	cfg.BindIP = *bindIP
	cfg.BindIface = *bindIface
	if *upstream != "" {
		var ups []pkg.Upstream
		for _, p := range splitCSV(*upstream) {
			ups = append(ups, store.ParseUpstream(p, pkg.Upstream{}))
		}
		if len(ups) > 0 {
			cfg.DefaultUpstreams = ups
		}
	}
	st.SetConfig(cfg)

	tel := resolve.NewTelemetry(cfg.QueryLogSize)
	eng := resolve.NewEngine(st, tel)
	dnsSrv := resolve.NewServer(eng)

	// Start DNS listeners immediately
	if err := dnsSrv.Start(cfg.Listeners); err != nil {
		log.Printf("dns listener warning: %v", err)
	}

	srv := &api.Server{
		Store:   st,
		Engine:  eng,
		DNS:     dnsSrv,
		Token:   *token,
		Version: version,
	}

	httpSrv := &http.Server{Addr: *listen, Handler: logRequest(srv.Handler())}
	go func() {
		log.Printf("dnsd %s control API on %s dns=%s go=%s",
			version, *listen, *dnsListen, runtime.Version())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("dnsd shutting down")
	dnsSrv.Stop()
	_ = httpSrv.Close()
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trim(s[start:i])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.URL.Path != "/metrics" && r.URL.Path != "/healthz" {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
	})
}
