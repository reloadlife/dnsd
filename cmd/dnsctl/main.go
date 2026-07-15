// dnsctl — TUI (default) + CLI for dnsd.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/reloadlife/dnsd/internal/tui"
	pkgapi "github.com/reloadlife/dnsd/pkg/api"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	switch os.Args[1] {
	case "tui", "ui":
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("dnsctl", version)
	case "status":
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) { return c.Status(ctx) })
	case "stats":
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) { return c.Stats(ctx) })
	case "queries", "log":
		cliQueries()
	case "profiles":
		cliProfiles()
	case "rules":
		cliRules()
	case "config":
		cliConfig()
	case "resolve", "dig":
		cliResolve()
	case "apply":
		dry := len(os.Args) > 2 && (os.Args[2] == "--dry-run" || os.Args[2] == "-n")
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) { return c.Apply(ctx, dry) })
	case "block":
		cliBlock()
	case "rewrite":
		cliRewrite()
	case "overview":
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) { return c.Overview(ctx) })
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	base := env("DNSCTL_URL", "http://127.0.0.1:51920")
	fmt.Fprintf(os.Stderr, `dnsctl — control dnsd (TUI + CLI)

Usage:
  dnsctl                      # full-screen TUI
  dnsctl status
  dnsctl stats
  dnsctl queries [--limit N]
  dnsctl rules
  dnsctl profiles
  dnsctl config
  dnsctl resolve NAME [TYPE]
  dnsctl block PATTERN
  dnsctl rewrite PATTERN ANSWER
  dnsctl apply [--dry-run]
  dnsctl overview
  dnsctl version

Env:
  DNSCTL_URL      default %s
  DNSCTL_TOKEN    default dev-token
  DNSCTL_REFRESH  TUI refresh (default 1s)
`, base)
}

func runTUI() error {
	client, endpoint, err := loadClient()
	if err != nil {
		return err
	}
	refresh := time.Second
	if s := os.Getenv("DNSCTL_REFRESH"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			refresh = d
		} else if d, err := time.ParseDuration(s + "s"); err == nil {
			refresh = d
		}
	}
	return tui.Run(tui.Config{Client: client, Endpoint: endpoint, RefreshInterval: refresh})
}

func loadClient() (*pkgapi.Client, string, error) {
	base := env("DNSCTL_URL", "http://127.0.0.1:51920")
	token := env("DNSCTL_TOKEN", "dev-token")
	c, err := pkgapi.NewClient(base, pkgapi.WithToken(token))
	if err != nil {
		return nil, "", err
	}
	return c, base, nil
}

func mustClient() *pkgapi.Client {
	c, _, err := loadClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return c
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func cliJSON(fn func(context.Context, *pkgapi.Client) (any, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := fn(ctx, mustClient())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func cliQueries() {
	limit := 50
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--limit" && i+1 < len(os.Args) {
			fmt.Sscanf(os.Args[i+1], "%d", &limit)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().QueryLog(ctx, limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tCLIENT\tPROTO\tNAME\tTYPE\tACTION\tRCODE\tMS\tUPSTREAM")
	for _, q := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%s\n",
			q.Time, q.Client, q.Protocol, q.Name, q.QType, q.Action, q.RCode, q.LatencyMs, q.Upstream)
	}
	_ = w.Flush()
}

func cliRules() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListRules(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PRI\tACTION\tMATCH\tPATTERN\tHITS\tENABLED\tNAME\tID")
	for _, r := range list {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%v\t%s\t%s\n",
			r.Priority, r.Action, r.Match, r.Pattern, r.HitCount, r.Enabled, r.Name, r.ID)
	}
	_ = w.Flush()
}

func cliProfiles() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListProfiles(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DEF\tNAME\tUPSTREAMS\tBIND\tID")
	for _, p := range list {
		var ups []string
		for _, u := range p.Upstreams {
			ups = append(ups, u.Address)
		}
		fmt.Fprintf(w, "%v\t%s\t%s\t%s\t%s\n", p.Default, p.Name, strings.Join(ups, ","), p.BindIP+p.BindIface, p.ID)
	}
	_ = w.Flush()
}

func cliConfig() {
	cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) { return c.Config(ctx) })
}

func cliResolve() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: dnsctl resolve NAME [TYPE]")
		os.Exit(2)
	}
	name := os.Args[2]
	typ := "A"
	if len(os.Args) > 3 {
		typ = os.Args[3]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := mustClient().Resolve(ctx, pkgapi.ResolveRequest{Name: name, Type: typ})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(res)
		return
	}
	if res.Message != "" {
		fmt.Print(res.Message)
	} else {
		printJSON(res.Event)
	}
}

func cliBlock() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: dnsctl block PATTERN")
		os.Exit(2)
	}
	en := true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := mustClient().CreateRule(ctx, pkgapi.RuleCreateRequest{
		Pattern: os.Args[2], Match: pkgapi.MatchSuffix, Action: pkgapi.ActionBlock,
		Enabled: &en, Priority: 50, Name: "block:" + os.Args[2],
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printJSON(r)
}

func cliRewrite() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: dnsctl rewrite PATTERN ANSWER")
		os.Exit(2)
	}
	en := true
	req := pkgapi.RuleCreateRequest{
		Pattern: os.Args[2], Match: pkgapi.MatchExact, Action: pkgapi.ActionRewrite,
		Enabled: &en, Priority: 40, Name: "rewrite:" + os.Args[2],
	}
	ans := os.Args[3]
	if strings.Count(ans, ".") == 3 || netIsIP(ans) {
		req.Answers = []string{ans}
	} else {
		req.CNAME = ans
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := mustClient().CreateRule(ctx, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printJSON(r)
}

func netIsIP(s string) bool {
	return strings.Contains(s, ":")
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func wantsJSON() bool {
	for _, a := range os.Args[2:] {
		if a == "--json" || a == "-j" {
			return true
		}
	}
	return false
}
