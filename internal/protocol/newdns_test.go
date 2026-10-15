package protocol

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestOrderLonglinkTargetsRetainsPortsAndResolverOrder(t *testing.T) {
	input := []Target{
		{IP: "203.0.113.20", Port: 8080}, {IP: "203.0.113.10", Port: 8080},
		{IP: "203.0.113.20", Port: 443}, {IP: "203.0.113.10", Port: 443},
		{IP: "203.0.113.20", Port: 443}, {IP: "203.0.113.20", Port: 80},
		{IP: "203.0.113.20", Port: 5000}, {IP: "203.0.113.20", Port: 8443},
	}
	want := []Target{
		{IP: "203.0.113.20", Port: 443}, {IP: "203.0.113.10", Port: 443},
		{IP: "203.0.113.20", Port: 8080}, {IP: "203.0.113.10", Port: 8080},
		{IP: "203.0.113.20", Port: 80}, {IP: "203.0.113.20", Port: 5000},
		{IP: "203.0.113.20", Port: 8443},
	}
	for _, limit := range []int{0, 6} {
		expected := want
		if limit > 0 {
			expected = want[:limit]
		}
		if got := orderLonglinkTargets(input, limit); !reflect.DeepEqual(got, expected) {
			t.Fatalf("limit %d: got %v, want %v", limit, got, expected)
		}
	}
}

func TestGetLonglinkTargetsFallsBackToOfficialHostname(t *testing.T) {
	dnsCache.Lock()
	dnsCache.entries = map[string]dnsCacheEntry{
		"0|Windows": {
			ExpiresAt: time.Now().Add(time.Minute),
			Parsed:    map[string]dnsDomain{},
		},
	}
	dnsCache.Unlock()
	t.Cleanup(clearDNSCache)

	targets, err := getLonglinkTargets(context.Background(), time.Second, time.Minute)
	if err != nil {
		t.Fatalf("getLonglinkTargets() error = %v", err)
	}
	// The official hostname must be present as a candidate even when HTTPDNS
	// returns nothing, and 443 has to come first.
	if len(targets) == 0 {
		t.Fatalf("getLonglinkTargets() returned no candidates")
	}
	if targets[0].Port != 443 {
		t.Fatalf("getLonglinkTargets() first candidate = %#v, want port 443", targets[0])
	}
	if !containsTarget(targets, Target{IP: longlinkDomain, Port: 443}) {
		t.Fatalf("getLonglinkTargets() = %#v, want %s:443 present", targets, longlinkDomain)
	}
}

func TestGetLonglinkTargetsMergesResolverAndHTTPDNS(t *testing.T) {
	dnsCache.Lock()
	dnsCache.entries = map[string]dnsCacheEntry{
		"0|Windows": {
			ExpiresAt: time.Now().Add(time.Minute),
			Parsed: map[string]dnsDomain{
				longlinkDomain: {
					IPs:       []string{"203.0.113.10"},
					Protocols: map[string][]int{protoMMTLS: []int{8080}},
				},
			},
		},
	}
	dnsCache.Unlock()
	t.Cleanup(clearDNSCache)

	targets, err := getLonglinkTargets(context.Background(), time.Second, time.Minute)
	if err != nil {
		t.Fatalf("getLonglinkTargets() error = %v", err)
	}
	// HTTPDNS candidates are kept, and the official hostname is merged in rather
	// than being discarded, so a dead geo pool cannot fail the login by itself.
	if !containsTarget(targets, Target{IP: "203.0.113.10", Port: 8080}) {
		t.Fatalf("getLonglinkTargets() = %#v, want HTTPDNS candidate kept", targets)
	}
	if !containsTarget(targets, Target{IP: longlinkDomain, Port: 443}) {
		t.Fatalf("getLonglinkTargets() = %#v, want %s:443 merged in", targets, longlinkDomain)
	}
}

func TestGetLonglinkTargetsSurvivesUnresolvableHTTPDNS(t *testing.T) {
	dnsCache.Lock()
	dnsCache.entries = map[string]dnsCacheEntry{}
	dnsCache.Unlock()
	t.Cleanup(clearDNSCache)

	targets, err := getLonglinkTargets(context.Background(), time.Nanosecond, 0)
	if err != nil {
		t.Fatalf("getLonglinkTargets() error = %v", err)
	}
	if len(targets) == 0 {
		t.Fatalf("getLonglinkTargets() returned no candidates")
	}
}

func TestGetShortlinkTargetsKeepsResolverAndHTTPDNS(t *testing.T) {
	dnsCache.Lock()
	dnsCache.entries = map[string]dnsCacheEntry{
		"0|Windows": {
			ExpiresAt: time.Now().Add(time.Minute),
			Parsed: map[string]dnsDomain{
				shortlinkDomain: {
					IPs:       []string{"203.0.113.30"},
					Protocols: map[string][]int{"http": []int{80}},
				},
			},
		},
	}
	dnsCache.Unlock()
	t.Cleanup(clearDNSCache)

	targets := getShortlinkTargets(context.Background(), time.Second, time.Minute)
	if len(targets) == 0 {
		t.Fatalf("getShortlinkTargets() returned no candidates")
	}
	for _, tg := range targets {
		if tg.Port != 80 {
			t.Fatalf("getShortlinkTargets() = %#v, want port 80 only", targets)
		}
	}
	if !containsTarget(targets, Target{IP: "203.0.113.30", Port: 80}) {
		t.Fatalf("getShortlinkTargets() = %#v, want HTTPDNS candidate kept", targets)
	}
	if !containsTarget(targets, Target{IP: shortlinkDomain, Port: 80}) {
		t.Fatalf("getShortlinkTargets() = %#v, want %s:80 merged in", targets, shortlinkDomain)
	}
}

func TestMergeTargetsDeduplicates(t *testing.T) {
	a := []Target{{IP: "1.1.1.1", Port: 443}, {IP: "2.2.2.2", Port: 443}}
	b := []Target{{IP: "2.2.2.2", Port: 443}, {IP: "3.3.3.3", Port: 80}}
	got := mergeTargets(a, b)
	want := []Target{
		{IP: "1.1.1.1", Port: 443},
		{IP: "2.2.2.2", Port: 443},
		{IP: "3.3.3.3", Port: 80},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTargets() = %v, want %v", got, want)
	}
}

func containsTarget(list []Target, want Target) bool {
	for _, t := range list {
		if t == want {
			return true
		}
	}
	return false
}

func clearDNSCache() {
	dnsCache.Lock()
	dnsCache.entries = map[string]dnsCacheEntry{}
	dnsCache.Unlock()
}
