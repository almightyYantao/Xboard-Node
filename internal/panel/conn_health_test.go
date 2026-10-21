package panel

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
)

// blackholeProxy forwards TCP to target. freeze() turns every connection open
// at that moment into a black hole (bytes are swallowed in both directions,
// the sockets stay open) — what a silently dead NAT mapping looks like to the
// client. Connections accepted afterwards work normally.
type blackholeProxy struct {
	ln      net.Listener
	target  string
	mu      sync.Mutex
	flags   []*atomic.Bool
	accepts atomic.Int32
}

func newBlackholeProxy(t *testing.T, target string) *blackholeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &blackholeProxy{ln: ln, target: target}
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *blackholeProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepts.Add(1)
		u, err := net.Dial("tcp", p.target)
		if err != nil {
			c.Close()
			continue
		}
		frozen := &atomic.Bool{}
		p.mu.Lock()
		p.flags = append(p.flags, frozen)
		p.mu.Unlock()
		pipe := func(dst, src net.Conn) {
			buf := make([]byte, 32*1024)
			for {
				n, err := src.Read(buf)
				if n > 0 && !frozen.Load() {
					if _, werr := dst.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			dst.Close()
			src.Close()
		}
		go pipe(u, c)
		go pipe(c, u)
	}
}

func (p *blackholeProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.flags {
		f.Store(true)
	}
}

// newH2Client starts an HTTP/2 TLS server behind a black-hole proxy and a
// panel Client pointed at the proxy, with a 1s request timeout.
func newH2Client(t *testing.T) (*Client, *blackholeProxy) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{}`)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	p := newBlackholeProxy(t, ts.Listener.Addr().String())
	c := NewClient(config.PanelConfig{URL: "https://" + p.ln.Addr().String(), Token: "t", NodeID: 1})
	c.httpClient.Timeout = time.Second
	tlsCfg := ts.Client().Transport.(*http.Transport).TLSClientConfig
	rt := newResettableTransport(func() *http.Transport {
		tr := newTransport()
		tr.TLSClientConfig = tlsCfg.Clone()
		return tr
	})
	c.httpClient.Transport = rt
	t.Cleanup(rt.CloseIdleConnections)
	return c, p
}

func get(c *Client) (*http.Response, error) {
	resp, err := c.doRequest("GET", "/ping", nil, "")
	if err == nil {
		drainAndClose(resp.Body)
	}
	return resp, err
}

func mustH2(t *testing.T, c *Client) {
	t.Helper()
	resp, err := get(c)
	if err != nil {
		t.Fatalf("request before freeze: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("want HTTP/2, got %s", resp.Proto)
	}
}

func withH2Timeouts(t *testing.T, ping, pingTimeout time.Duration) {
	a, b, w := h2SendPingTimeout, h2PingTimeout, h2WriteByteTimeout
	h2SendPingTimeout, h2PingTimeout, h2WriteByteTimeout = ping, pingTimeout, 0
	t.Cleanup(func() { h2SendPingTimeout, h2PingTimeout, h2WriteByteTimeout = a, b, w })
}

// Baseline: with no health check and no pool reset, a dead HTTP/2 connection is
// reused forever (the bug seen in production).
func TestDeadH2Conn_NoRecoveryWithoutHealthCheck(t *testing.T) {
	withH2Timeouts(t, 0, 0)
	c, p := newH2Client(t)
	c.health = nil
	mustH2(t, c)
	p.freeze()
	for i := 0; i < 3; i++ {
		if _, err := get(c); err == nil || !isTimeout(err) {
			t.Fatalf("request %d: want timeout on dead conn, got %v", i, err)
		}
	}
	if n := p.accepts.Load(); n != 1 {
		t.Fatalf("expected the dead connection to be reused (1 dial), got %d dials", n)
	}
}

// Consecutive timeouts drop the pool, so the next request dials a fresh connection.
func TestDeadH2Conn_RecoversAfterConsecutiveTimeouts(t *testing.T) {
	withH2Timeouts(t, 0, 0)
	c, p := newH2Client(t)
	mustH2(t, c)
	p.freeze()
	for i := 0; i < resetAfterTimeouts; i++ {
		if _, err := get(c); err == nil || !isTimeout(err) {
			t.Fatalf("request %d: want timeout, got %v", i, err)
		}
	}
	if _, err := get(c); err != nil {
		t.Fatalf("request after pool reset: %v", err)
	}
	if n := p.accepts.Load(); n != 2 {
		t.Fatalf("want a new connection after reset (2 dials), got %d", n)
	}
}

// The HTTP/2 ping notices the dead connection on its own, even with no request
// timing out in between.
func TestDeadH2Conn_PingClosesIt(t *testing.T) {
	withH2Timeouts(t, 200*time.Millisecond, 200*time.Millisecond)
	c, p := newH2Client(t)
	c.health = nil
	mustH2(t, c)
	p.freeze()
	time.Sleep(1500 * time.Millisecond)
	if _, err := get(c); err != nil {
		t.Fatalf("request after ping timeout: %v", err)
	}
	if n := p.accepts.Load(); n != 2 {
		t.Fatalf("want a new connection after ping timeout (2 dials), got %d", n)
	}
}

func TestConnHealth_NonTimeoutErrorResets(t *testing.T) {
	c := NewClient(config.PanelConfig{URL: "https://127.0.0.1:1"})
	c.observe(&net.OpError{Op: "dial", Err: timeoutErr{}})
	if c.health.timeouts.Load() != 1 {
		t.Fatal("timeout not counted")
	}
	c.observe(&tls.RecordHeaderError{Msg: "boom"})
	if c.health.timeouts.Load() != 0 {
		t.Fatal("non-timeout error should reset the counter")
	}
	if fc := c.ForNode(2); fc.health != c.health {
		t.Fatal("ForNode clients must share connection health")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
