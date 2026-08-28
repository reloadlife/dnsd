package sni

import (
	"testing"
	"time"
)

// A relay that failed once and then recovered must stop reporting the failure.
// It reported it forever before: errors_total stayed frozen while last_error
// still named an ocserv outage that had ended days earlier.
func TestLastErrorClearsOnSuccess(t *testing.T) {
	p := &Proxy{}

	p.fail("fallback 127.0.0.1:9444: connect: connection refused")
	if got, _ := p.lastErr.Load().(string); got == "" {
		t.Fatal("fail() did not record the error")
	}
	at, _ := p.lastErrAt.Load().(time.Time)
	if at.IsZero() {
		t.Fatal("fail() did not stamp a time")
	}
	if p.errs != 1 {
		t.Fatalf("errors_total = %d, want 1", p.errs)
	}

	p.ok()
	if got, _ := p.lastErr.Load().(string); got != "" {
		t.Errorf("last_error survived a success: %q", got)
	}
	// The counter is the durable history and must NOT be rewound.
	if p.errs != 1 {
		t.Errorf("errors_total = %d after ok(), want it left at 1", p.errs)
	}
}

// ok() on a proxy that never failed must not panic or invent state.
func TestOkBeforeAnyFailure(t *testing.T) {
	p := &Proxy{}
	p.ok()
	if got, _ := p.lastErr.Load().(string); got != "" {
		t.Errorf("last_error = %q, want empty", got)
	}
}

// A later failure after recovery must be reported again, with a fresh stamp.
func TestFailAfterRecovery(t *testing.T) {
	p := &Proxy{}
	p.fail("first")
	p.ok()
	p.fail("second")
	if got, _ := p.lastErr.Load().(string); got != "second" {
		t.Errorf("last_error = %q, want %q", got, "second")
	}
	if at, _ := p.lastErrAt.Load().(time.Time); at.IsZero() {
		t.Error("re-failure did not stamp a time")
	}
	if p.errs != 2 {
		t.Errorf("errors_total = %d, want 2", p.errs)
	}
}
