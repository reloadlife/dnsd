// Command dnsd is the node DNS resolver / policy daemon.
// Sister to wireguardd / openvpnd / netpolicyd.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/reloadlife/dnsd/internal/api"
	"github.com/reloadlife/dnsd/internal/resolve"
	"github.com/reloadlife/dnsd/internal/store"
	pkg "github.com/reloadlife/dnsd/pkg/api"
)

// version set via -ldflags -X main.version=…
var version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmsgprefix)
	log.SetPrefix("dnsd ")

	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}

	var (
		listen       = flag.String("listen", env("DNSD_LISTEN", "127.0.0.1:51920"), "HTTP control API listen address")
		token        = flag.String("token", env("DNSD_TOKEN", ""), "Bearer token for /v1/* (required unless --allow-insecure)")
		dnsListen    = flag.String("dns-listen", env("DNSD_DNS_LISTEN", "127.0.0.1:5353"), "classic DNS listen (UDP+TCP, same addr; RFC 1035/7766)")
		dnsUDP       = flag.String("dns-udp", env("DNSD_DNS_UDP", ""), "override UDP listen only (default: --dns-listen)")
		dnsTCP       = flag.String("dns-tcp", env("DNSD_DNS_TCP", ""), "override TCP listen only (default: --dns-listen; empty disables TCP)")
		bindIP       = flag.String("bind-ip", env("DNSD_BIND_IP", ""), "default outbound source IP for upstream queries")
		bindIface    = flag.String("bind-iface", env("DNSD_BIND_IFACE", ""), "default outbound interface for upstream queries")
		upstream     = flag.String("upstream", env("DNSD_UPSTREAM", "1.1.1.1:53,8.8.8.8:53"), "comma-separated default upstreams")
		stateFile    = flag.String("state-file", env("DNSD_STATE_FILE", ""), "persist rules/profiles/config to this JSON path")
		blocklistDir = flag.String("blocklist-dir", env("DNSD_BLOCKLIST_DIR", ""), "directory of *.txt/*.list/hosts files (ad/malware block)")
		tlsCert      = flag.String("tls-cert", env("DNSD_TLS_CERT", ""), "optional TLS cert for control API")
		tlsKey       = flag.String("tls-key", env("DNSD_TLS_KEY", ""), "optional TLS key for control API")
		allowInsec   = flag.Bool("allow-insecure", envBool("DNSD_ALLOW_INSECURE", false), "allow empty token (dev only)")
		shutdown     = flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	)
	flag.Parse()

	// Token defaults: keep dev-token only for loopback + allow-insecure path via env empty
	tok := strings.TrimSpace(*token)
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("DNSD_TOKEN"))
	}
	if tok == "" && *allowInsec {
		tok = "dev-token"
		log.Printf("WARNING: --allow-insecure: using default token %q", tok)
	}
	if tok == "" || tok == "dev-token" {
		if !isLoopbackAddr(*listen) && !*allowInsec {
			log.Fatal("refusing to start: set --token / DNSD_TOKEN to a strong secret when binding a non-loopback control API (or pass --allow-insecure)")
		}
		if tok == "" {
			tok = "dev-token"
			log.Printf("WARNING: control API token not set; using %q (loopback only). Set DNSD_TOKEN in production.", tok)
		} else if tok == "dev-token" {
			log.Printf("WARNING: control API using default dev-token — change DNSD_TOKEN before production")
		}
	}

	st := store.New()
	persister := store.NewPersister(st, *stateFile)
	if persister.Enabled() {
		if err := persister.LoadInto(); err != nil {
			log.Fatalf("load state %s: %v", *stateFile, err)
		}
		log.Printf("loaded state from %s", *stateFile)
	}

	cfg := st.Config()
	// CLI overrides for listen/upstream take effect unless state already set non-default listeners
	// Always apply CLI dns-listen / bind / upstream as operational defaults on top of file.
	// Classic DNS: UDP + TCP (DoT/DoH are separate). Default both to --dns-listen.
	if *dnsListen != "" {
		cfg.Listeners.UDP = *dnsListen
		cfg.Listeners.TCP = *dnsListen
	}
	if *dnsUDP != "" {
		cfg.Listeners.UDP = *dnsUDP
	}
	if flagDNSTCPSet() {
		cfg.Listeners.TCP = *dnsTCP // may be "" to disable TCP
	}
	if *bindIP != "" {
		cfg.BindIP = *bindIP
	}
	if *bindIface != "" {
		cfg.BindIface = *bindIface
	}
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
	if *blocklistDir != "" {
		bl := resolve.NewBlocklist(*blocklistDir)
		if n, err := bl.Reload(); err != nil {
			log.Printf("blocklist load %s: %v", *blocklistDir, err)
		} else {
			log.Printf("blocklist loaded %d domains from %s", n, *blocklistDir)
		}
		eng.SetBlocklist(bl)
	}
	dnsSrv := resolve.NewServer(eng)

	if err := dnsSrv.Start(st.Config().Listeners); err != nil {
		log.Printf("dns listener error: %v", err)
		// still serve control API so operators can fix config
	}

	apiSrv := &api.Server{
		Store:   st,
		Engine:  eng,
		DNS:     dnsSrv,
		Persist: persister,
		Token:   tok,
		Version: version,
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("%s control API on %s dns=%s state=%q go=%s",
			version, *listen, st.DNSListen(), *stateFile, runtime.Version())
		var err error
		if *tlsCert != "" && *tlsKey != "" {
			log.Printf("control API TLS enabled")
			err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			if !isLoopbackAddr(*listen) {
				log.Printf("WARNING: control API is plain HTTP on non-loopback — prefer --tls-cert/--tls-key or bind loopback behind a reverse proxy")
			}
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("http server: %v", err)
		}
	case sigN := <-sig:
		log.Printf("signal %v — shutting down", sigN)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *shutdown)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("http shutdown: %v", err)
		_ = httpSrv.Close()
	}
	dnsSrv.Stop()
	if persister.Enabled() {
		if err := persister.SaveNow(); err != nil {
			log.Printf("save state: %v", err)
		} else {
			log.Printf("state saved to %s", *stateFile)
		}
	}
	log.Printf("stopped")
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// flagDNSTCPSet is true when operator explicitly set TCP listen (including empty = off).
func flagDNSTCPSet() bool {
	if os.Getenv("DNSD_DNS_TCP") != "" {
		return true
	}
	for _, a := range os.Args[1:] {
		if a == "-dns-tcp" || a == "--dns-tcp" || strings.HasPrefix(a, "-dns-tcp=") || strings.HasPrefix(a, "--dns-tcp=") {
			return true
		}
	}
	return false
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// bare host?
		host = addr
	}
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

