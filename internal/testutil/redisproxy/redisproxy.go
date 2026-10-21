// Package redisproxy puts a TCP proxy between a test's Redis client and
// the test Redis, so a test can take Redis away the two ways it fails in
// production: refusing connections (Down) and dropping packets
// (Blackhole). A paused container only queues commands, which looks like
// neither.
package redisproxy

import (
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
)

// Mode is how the proxy treats traffic.
type Mode int

const (
	// Up forwards traffic.
	Up Mode = iota
	// Down closes every open connection and refuses new ones.
	Down
	// Blackhole keeps connections open but forwards nothing, so every
	// command waits on the client's timeouts.
	Blackhole
)

// Proxy is a TCP proxy in front of one Redis address.
type Proxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	mode   Mode
	conns  []net.Conn
}

// Start proxies to the host of redisURL and returns the proxy and a copy
// of redisURL that points at it.
func Start(t *testing.T, redisURL string) (*Proxy, string) {
	t.Helper()
	u, err := url.Parse(redisURL)
	if err != nil {
		t.Fatalf("redisproxy: parse URL: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("redisproxy: listen: %v", err)
	}
	p := &Proxy{ln: ln, target: u.Host}
	t.Cleanup(func() { _ = ln.Close(); p.Set(Down) })
	go p.serve()
	pu := *u
	pu.Host = ln.Addr().String()
	return p, pu.String()
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		switch p.mode {
		case Down:
			_ = c.Close()
		case Blackhole:
			p.conns = append(p.conns, c)
			go func() { _, _ = io.Copy(io.Discard, c) }()
		default:
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				break
			}
			p.conns = append(p.conns, c, up)
			go p.pipe(up, c)
			go p.pipe(c, up)
		}
		p.mu.Unlock()
	}
}

// pipe copies src to dst while the proxy is Up and drops the bytes once
// it isn't, so a Blackhole also stalls connections opened before it.
func (p *Proxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.mu.Lock()
			up := p.mode == Up
			p.mu.Unlock()
			if up {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

// Set switches the mode. Down and a return to Up close every open
// connection, so the client reconnects and starts clean.
func (p *Proxy) Set(m Mode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = m
	if m != Blackhole {
		for _, c := range p.conns {
			_ = c.Close()
		}
		p.conns = nil
	}
}
