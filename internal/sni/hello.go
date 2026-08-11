package sni

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// errPeeked aborts the fake handshake once the ClientHello has been seen.
var errPeeked = errors.New("sni: client hello captured")

// readOnlyConn hands tls.Server a stream to read and throws away everything it
// tries to write. We only want the parser, never a handshake.
type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error)    { return len(p), nil }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// peekClientHello returns the SNI server name, copying every byte it consumed
// into buf so the caller can replay the connection to a backend verbatim.
//
// The parsing is stdlib's: GetConfigForClient fires with the decoded hello,
// and we abort there. Hand-rolling a ClientHello parser is how you end up
// mis-framing a TLS record and corrupting someone's VPN session.
// ponytail: no extension parsing beyond SNI; add ALPN here if routing needs it.
func peekClientHello(c net.Conn, buf *bytes.Buffer, timeout time.Duration) string {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var name string
	_ = tls.Server(readOnlyConn{r: io.TeeReader(c, buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errPeeked
		},
	}).Handshake()
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// peekHTTPHost is the cleartext equivalent for the :80 listener.
func peekHTTPHost(c net.Conn, buf *bytes.Buffer, timeout time.Duration) string {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(c, buf)))
	if err != nil {
		return ""
	}
	host := req.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
