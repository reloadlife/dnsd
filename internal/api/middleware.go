package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// wrap applies production middleware around the mux.
func (s *Server) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// recover panics
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("dnsd api panic: %v\n%s", rec, debug.Stack())
				writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		// security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		// limit body size for mutating methods
		if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}

		rw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(rw, r)

		// access log (skip noisy paths)
		path := r.URL.Path
		if path != "/metrics" && path != "/healthz" && path != "/readyz" {
			log.Printf("%s %s %d %s", r.Method, path, rw.code, time.Since(start).Round(time.Microsecond))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func bearerOK(got, want string) bool {
	if want == "" {
		return true
	}
	const p = "Bearer "
	if !strings.HasPrefix(got, p) {
		return false
	}
	token := strings.TrimSpace(got[len(p):])
	if len(token) != len(want) {
		// still compare to avoid timing leak on length-only (constant-time on padded)
		return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

