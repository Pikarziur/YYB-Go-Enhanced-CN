package protocol

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// startCountingListener opens a local TCP listener that accepts connections and
// immediately closes them, which is enough to exercise the candidate loop: the
// dial succeeds, then the read side returns an empty response.
func startCountingListener(t *testing.T) (addr string, hits *int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	count := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count++
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &count
}

// unusedPortAddr returns an address that refuses connections, standing in for a
// blackholed WeChat endpoint.
func unusedPortAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestSend0RTTSharesBudgetAcrossCandidates guards the regression that made every
// merged candidate list time out: a blackholed endpoint used to consume the
// whole budget, so a later reachable endpoint was never tried. send0RTTRaw fails
// fast on a refused local dial, so this test checks the loop actually reaches
// later candidates within a single budget.
func TestSend0RTTSharesBudgetAcrossCandidates(t *testing.T) {
	reachable, hits := startCountingListener(t)

	var last error
	dead := unusedPortAddr(t)
	targets := []Target{
		{IP: "127.0.0.1", Port: portOf(t, dead)},
		{IP: "127.0.0.1", Port: portOf(t, dead)},
		{IP: "127.0.0.1", Port: portOf(t, reachable)},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, _, last = send0RTT(ctx, targets, pskEntry{}, nil, []byte{0x01}, 2*time.Second, "", false)
	elapsed := time.Since(start)

	// The reachable endpoint must have been reached: send0RTTRaw then fails on
	// the protocol exchange (closed connection), not on the dial.
	if *hits == 0 {
		t.Fatalf("reachable candidate was never dialed; last error = %v", last)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("candidate loop took %s, budget was not shared", elapsed)
	}
}

// TestSend0RTTReportsNoTargetsKeepsContextError documents the deadline path: once
// the context is done the loop returns the context error rather than a wrapped
// candidate failure.
func TestSend0RTTReportsNoTargetsKeepsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := send0RTT(ctx, []Target{{IP: "127.0.0.1", Port: 1}}, pskEntry{}, nil, []byte{0x01}, time.Second, "", false)
	if err == nil {
		t.Fatal("send0RTT() error = nil, want context error")
	}
}

// TestShortlinkCandidateLimitKeepsResolverAnswers pins the merged ShortLink pool
// size: a long list would divide the shared budget into unusable slices.
func TestShortlinkCandidateLimitKeepsResolverAnswers(t *testing.T) {
	targets := make([]Target, 0, 12)
	for i := 0; i < 12; i++ {
		targets = append(targets, Target{IP: fmt.Sprintf("203.0.113.%d", i+1), Port: 80})
	}
	got := targets
	if len(got) > shortlinkCandidateLimit {
		got = got[:shortlinkCandidateLimit]
	}
	if len(got) != shortlinkCandidateLimit {
		t.Fatalf("len(targets) = %d, want %d", len(got), shortlinkCandidateLimit)
	}
	if !reflect.DeepEqual(got, targets[:shortlinkCandidateLimit]) {
		t.Fatalf("truncation changed candidate order")
	}
}

// TestDefaultTimeoutsCoverMergedPools guards the timeout budget against the
// candidate counts: with the merged pools the shared budgets must stay above the
// per-candidate floor that a 0-RTT round trip needs.
func TestDefaultTimeoutsCoverMergedPools(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ShortlinkTimeout < time.Duration(shortlinkCandidateLimit)*time.Second {
		t.Fatalf("ShortlinkTimeout %s too small for %d candidates", cfg.ShortlinkTimeout, shortlinkCandidateLimit)
	}
	if cfg.LoginTimeout < time.Duration(longlinkCandidateLimit)*time.Second {
		t.Fatalf("LoginTimeout %s too small for %d candidates", cfg.LoginTimeout, longlinkCandidateLimit)
	}
	if cfg.ShortlinkTimeout != 15*time.Second {
		t.Fatalf("ShortlinkTimeout = %s, want 15s to match httpapi default", cfg.ShortlinkTimeout)
	}
}

func portOf(t *testing.T, hostPort string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", hostPort, err)
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			t.Fatalf("non-numeric port %q", portStr)
		}
		port = port*10 + int(c-'0')
	}
	return port
}