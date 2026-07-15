package resolve

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/pkg/api"
)

// Server runs UDP/TCP/DoT/DoH listeners.
type Server struct {
	Engine *Engine

	mu      sync.Mutex
	udp     *dns.Server
	tcp     *dns.Server
	dot     *dns.Server
	dohHTTP *http.Server
	cfg     api.ListenerConfig

	udpUp, tcpUp, dotUp, dohUp bool
}

// NewServer wraps an engine.
func NewServer(eng *Engine) *Server {
	return &Server{Engine: eng}
}

// State reports which listeners are up.
func (s *Server) State() (udp, tcp, dot, doh bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpUp, s.tcpUp, s.dotUp, s.dohUp
}

// Config returns last applied listener config.
func (s *Server) Config() api.ListenerConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Start applies listener config (restarts all).
func (s *Server) Start(cfg api.ListenerConfig) error {
	s.Stop()
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()

	var errs []string
	if cfg.UDP != "" {
		udp := &dns.Server{Addr: cfg.UDP, Net: "udp", Handler: s.Engine, ReusePort: true}
		s.mu.Lock()
		s.udp = udp
		s.mu.Unlock()
		go func() {
			log.Printf("dnsd: UDP listen %s", cfg.UDP)
			if err := udp.ListenAndServe(); err != nil {
				log.Printf("dnsd: UDP exit: %v", err)
				s.mu.Lock()
				s.udpUp = false
				s.mu.Unlock()
			}
		}()
		// brief wait for bind
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		s.udpUp = true
		s.mu.Unlock()
	}
	if cfg.TCP != "" {
		tcp := &dns.Server{Addr: cfg.TCP, Net: "tcp", Handler: s.Engine, ReusePort: true}
		s.mu.Lock()
		s.tcp = tcp
		s.mu.Unlock()
		go func() {
			log.Printf("dnsd: TCP listen %s", cfg.TCP)
			if err := tcp.ListenAndServe(); err != nil {
				log.Printf("dnsd: TCP exit: %v", err)
				s.mu.Lock()
				s.tcpUp = false
				s.mu.Unlock()
			}
		}()
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		s.tcpUp = true
		s.mu.Unlock()
	}
	if cfg.DoT != "" {
		if cfg.DoTCert == "" || cfg.DoTKey == "" {
			errs = append(errs, "DoT requires dot_cert and dot_key")
		} else {
			cert, err := tls.LoadX509KeyPair(cfg.DoTCert, cfg.DoTKey)
			if err != nil {
				errs = append(errs, "DoT cert: "+err.Error())
			} else {
				tlsCfg := &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"dot"},
				}
				dot := &dns.Server{
					Addr:      cfg.DoT,
					Net:       "tcp-tls",
					Handler:   &protoHandler{inner: s.Engine, proto: "dot"},
					TLSConfig: tlsCfg,
				}
				s.mu.Lock()
				s.dot = dot
				s.mu.Unlock()
				go func() {
					log.Printf("dnsd: DoT listen %s", cfg.DoT)
					if err := dot.ListenAndServe(); err != nil {
						log.Printf("dnsd: DoT exit: %v", err)
						s.mu.Lock()
						s.dotUp = false
						s.mu.Unlock()
					}
				}()
				time.Sleep(50 * time.Millisecond)
				s.mu.Lock()
				s.dotUp = true
				s.mu.Unlock()
			}
		}
	}
	if cfg.DoH != "" {
		path := cfg.DoHPath
		if path == "" {
			path = "/dns-query"
		}
		mux := http.NewServeMux()
		mux.HandleFunc(path, s.handleDoH)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		hs := &http.Server{Addr: cfg.DoH, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		s.mu.Lock()
		s.dohHTTP = hs
		s.mu.Unlock()
		go func() {
			log.Printf("dnsd: DoH listen %s path=%s insecure=%v", cfg.DoH, path, cfg.DoHInsecure)
			var err error
			if cfg.DoHInsecure || cfg.DoHCert == "" {
				err = hs.ListenAndServe()
			} else {
				err = hs.ListenAndServeTLS(cfg.DoHCert, cfg.DoHKey)
			}
			if err != nil && err != http.ErrServerClosed {
				log.Printf("dnsd: DoH exit: %v", err)
				s.mu.Lock()
				s.dohUp = false
				s.mu.Unlock()
			}
		}()
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		s.dohUp = true
		s.mu.Unlock()
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Stop shuts down all listeners.
func (s *Server) Stop() {
	s.mu.Lock()
	udp, tcp, dot, doh := s.udp, s.tcp, s.dot, s.dohHTTP
	s.udp, s.tcp, s.dot, s.dohHTTP = nil, nil, nil, nil
	s.udpUp, s.tcpUp, s.dotUp, s.dohUp = false, false, false, false
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if udp != nil {
		_ = udp.ShutdownContext(ctx)
	}
	if tcp != nil {
		_ = tcp.ShutdownContext(ctx)
	}
	if dot != nil {
		_ = dot.ShutdownContext(ctx)
	}
	if doh != nil {
		_ = doh.Shutdown(ctx)
	}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		// ?dns=base64url
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns param", http.StatusBadRequest)
			return
		}
		wire, err = decodeBase64URL(q)
		if err != nil {
			http.Error(w, "bad dns param", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	client := r.RemoteAddr
	if h, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
		client = h
	}
	resp, ev := s.Engine.Handle(r.Context(), req, client, "doh")
	s.Engine.Tel.Record(ev)
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// protoHandler tags responses with protocol name.
type protoHandler struct {
	inner dns.Handler
	proto string
}

func (p *protoHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	p.inner.ServeDNS(&protoWriter{ResponseWriter: w, proto: p.proto}, r)
}

type protoWriter struct {
	dns.ResponseWriter
	proto string
}

func (p *protoWriter) Proto() string { return p.proto }
