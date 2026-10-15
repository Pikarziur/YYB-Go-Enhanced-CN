package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	newdnsHost      = "aedns.weixin.qq.com"
	newdnsBackupIP  = "180.153.202.85"
	newdnsPath      = "/cgi-bin/default/getdns"
	longlinkDomain  = "longcloud.weixin.com"
	shortlinkDomain = "shortcloud.weixin.com"
	protoMMTLS      = "mmtlsovertcp"
	defaultUA       = "MicroMessenger Client"

	// shortlinkFallbackIP is the historical hard-coded ShortLink endpoint. It is
	// only used when neither the system resolver nor HTTPDNS offers anything.
	shortlinkFallbackIP = "120.241.131.173"
)

// Ports used for the system-resolver LongLink candidates. 443 is listed first
// and on its own is enough for the official hostname, but 8080/80 are appended as
// cheap extra chances because some exits or proxies narrow the usable ports.
var longlinkFallbackPorts = []int{443, 8080, 80}

// ShortLink only speaks plain HTTP on 80 for this protocol path.
var shortlinkFallbackPorts = []int{80}

// longlinkCandidateLimit caps how many LongLink endpoints one login attempt may
// probe. The upstream default of 6 truncates the merged pool too aggressively
// once resolver answers are prepended, so the limit is raised: the per-candidate
// budget in tryLonglinkCandidates divides the remaining login time by the number
// of remaining candidates, which keeps a dead endpoint from eating the timeout.
const longlinkCandidateLimit = 12

type Target struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type dnsDomain struct {
	IPs       []string
	Protocols map[string][]int
	Timeout   int
}

type dnsCacheEntry struct {
	ExpiresAt time.Time
	Parsed    map[string]dnsDomain
}

var dnsCache = struct {
	sync.Mutex
	entries map[string]dnsCacheEntry
}{entries: map[string]dnsCacheEntry{}}

func buildDNSQuery(clientVersion int, deviceType string, uin int) string {
	v := url.Values{}
	v.Set("clientversion", strconv.Itoa(clientVersion))
	v.Set("devicetype", deviceType)
	v.Set("uin", strconv.Itoa(uin))
	v.Set("format", "json")
	return v.Encode()
}

func requestNewDNS(ctx context.Context, connectTo string, timeout time.Duration) (int, map[string]any, string, error) {
	host := connectTo
	if host == "" {
		host = newdnsHost
	}
	conn, err := dialDirect(ctx, host, 80, timeout)
	if err != nil {
		return 0, nil, "", err
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	_ = conn.SetDeadline(ioDeadline(ctx, timeout))
	path := newdnsPath + "?" + buildDNSQuery(0, "Windows", 0)
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, newdnsHost, defaultUA)
	if _, err = conn.Write([]byte(req)); err != nil {
		return 0, nil, "", err
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		return 0, nil, "", err
	}
	head, body := splitHTTP(raw)
	status := 0
	if lines := strings.Split(head, "\n"); len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			status, _ = strconv.Atoi(parts[1])
		}
	}
	text := string(body)
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	return status, obj, text, nil
}

func getDNSParsed(ctx context.Context, timeout, cacheTTL time.Duration, force bool) (map[string]dnsDomain, error) {
	key := "0|Windows"
	now := time.Now()
	if !force && cacheTTL > 0 {
		dnsCache.Lock()
		if ent, ok := dnsCache.entries[key]; ok && ent.ExpiresAt.After(now) {
			dnsCache.Unlock()
			return ent.Parsed, nil
		}
		dnsCache.Unlock()
	}
	var last error
	for _, connectTo := range []string{"", newdnsBackupIP} {
		status, obj, text, err := requestNewDNS(ctx, connectTo, timeout)
		if err != nil {
			last = err
			continue
		}
		if status != 200 || obj == nil {
			last = fmt.Errorf("newdns HTTP %d body=%q", status, text[:min(len(text), 120)])
			continue
		}
		parsed, err := parseDomainList(obj)
		if err != nil {
			last = err
			continue
		}
		if cacheTTL > 0 {
			dnsCache.Lock()
			dnsCache.entries[key] = dnsCacheEntry{ExpiresAt: now.Add(cacheTTL), Parsed: parsed}
			dnsCache.Unlock()
		}
		return parsed, nil
	}
	if last == nil {
		last = fmt.Errorf("newdns request failed")
	}
	return nil, last
}

func parseDomainList(obj map[string]any) (map[string]dnsDomain, error) {
	dnsObj, ok := obj["dns"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dns missing in response")
	}
	if rc, ok := dnsObj["retcode"].(float64); ok && int(rc) != 0 {
		return nil, fmt.Errorf("newdns retcode=%d", int(rc))
	}
	list, ok := dnsObj["domainlist"].([]any)
	if !ok {
		return nil, fmt.Errorf("domainlist missing in response")
	}
	out := map[string]dnsDomain{}
	for _, item := range list {
		d, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := d["name"].(string)
		if name == "" {
			continue
		}
		dom := dnsDomain{Protocols: map[string][]int{}}
		if t, ok := d["timeout"].(float64); ok {
			dom.Timeout = int(t)
		}
		if ips, ok := d["iplist"].([]any); ok {
			for _, it := range ips {
				if m, ok := it.(map[string]any); ok {
					if ip, ok := m["ip"].(string); ok && net.ParseIP(ip) != nil {
						dom.IPs = append(dom.IPs, ip)
					}
				}
			}
		}
		if plist, ok := d["protocollist"].([]any); ok {
			for _, it := range plist {
				p, ok := it.(map[string]any)
				if !ok {
					continue
				}
				pname, _ := p["name"].(string)
				if pname == "" {
					continue
				}
				if ports, ok := p["portlist"].([]any); ok {
					for _, pv := range ports {
						if f, ok := pv.(float64); ok {
							dom.Protocols[pname] = append(dom.Protocols[pname], int(f))
						}
					}
				}
			}
		}
		out[name] = dom
	}
	return out, nil
}

func serversFor(parsed map[string]dnsDomain, domain, proto string) []Target {
	info, ok := parsed[domain]
	if !ok {
		return nil
	}
	ports := info.Protocols[proto]
	var out []Target
	for _, ip := range info.IPs {
		for _, p := range ports {
			out = append(out, Target{IP: ip, Port: p})
		}
	}
	return out
}

// resolveHostTargets asks the system resolver for one hostname and expands the
// answer into Target entries on the given ports.
//
// WeChat HTTPDNS is geo-aware and, from some mainland exits, answers with
// overseas nodes only. Those addresses are usually unroutable for a direct
// connection, while the ordinary resolver returns reachable mainland edges for
// the very same hostname. Probing both sources and merging them keeps a
// reachable endpoint in the pool instead of trusting a single answer.
//
// The hostname itself is kept as the last entry on purpose: net.Dialer will
// resolve it again, so it still works when the system resolver is temporarily
// unavailable and it keeps proxy setups that expect a host name.
func resolveHostTargets(ctx context.Context, host string, ports []int, timeout time.Duration) []Target {
	seen := map[Target]bool{}
	var out []Target
	add := func(t Target) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if timeout > 0 {
		var dialer net.Dialer
		dialer.Timeout = timeout
		if addrs, err := dialer.Resolver.LookupIPAddr(ctx, host); err == nil {
			for _, addr := range addrs {
				ip := addr.IP.String()
				// Skip IPv6 results: a box without IPv6 egress cannot reach them
				// and a bogus AAAA answer would only burn dial budget.
				if addr.IP.To4() == nil {
					continue
				}
				for _, p := range ports {
					add(Target{IP: ip, Port: p})
				}
			}
		}
	}
	for _, p := range ports {
		add(Target{IP: host, Port: p})
	}
	return out
}

// mergeTargets concatenates candidate lists while dropping duplicates, keeping
// the order of the first occurrence.
func mergeTargets(lists ...[]Target) []Target {
	seen := map[Target]bool{}
	out := make([]Target, 0, 16)
	for _, list := range lists {
		for _, t := range list {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func getLonglinkTargets(ctx context.Context, timeout, cacheTTL time.Duration) ([]Target, error) {
	// Resolver answers first: on mainland exits they are both reachable and
	// geographically correct, while HTTPDNS may hand back overseas-only nodes.
	hostTargets := resolveHostTargets(ctx, longlinkDomain, longlinkFallbackPorts, timeout)
	parsed, err := getDNSParsed(ctx, timeout, cacheTTL, false)
	if err != nil {
		if len(hostTargets) == 0 {
			return nil, err
		}
		return hostTargets, nil
	}
	// Some networks block or return an empty response from WeChat HTTPDNS while
	// normal DNS and the LongLink 443 port remain reachable. Keep both sources so
	// one dead pool can no longer fail the whole login.
	return mergeTargets(hostTargets, serversFor(parsed, longlinkDomain, protoMMTLS)), nil
}

func getShortlinkTargets(ctx context.Context, timeout, cacheTTL time.Duration) []Target {
	hostTargets := resolveHostTargets(ctx, shortlinkDomain, shortlinkFallbackPorts, timeout)
	parsed, err := getDNSParsed(ctx, timeout, cacheTTL, false)
	if err != nil {
		if len(hostTargets) == 0 {
			return []Target{{IP: shortlinkFallbackIP, Port: 80}}
		}
		return hostTargets
	}
	targets := serversFor(parsed, shortlinkDomain, "http")
	seen := map[string]bool{}
	var dnsTargets []Target
	for _, t := range targets {
		if t.Port == 80 && !seen[t.IP] {
			seen[t.IP] = true
			dnsTargets = append(dnsTargets, t)
		}
	}
	merged := mergeTargets(hostTargets, dnsTargets)
	if len(merged) == 0 {
		return []Target{{IP: shortlinkFallbackIP, Port: 80}}
	}
	return merged
}

func orderLonglinkTargets(targets []Target, max int) []Target {
	// A host can advertise several usable ports. Keep each endpoint, with 443
	// first because some CONNECT proxies restrict the available destination ports.
	pref := []int{443, 8080, 80, 5000}
	seen := map[Target]bool{}
	var out []Target
	add := func(t Target) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, p := range pref {
		for _, t := range targets {
			if t.Port == p {
				add(t)
			}
		}
	}
	for _, t := range targets {
		add(t)
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func splitHTTP(raw []byte) (string, []byte) {
	idx := strings.Index(string(raw), "\r\n\r\n")
	if idx < 0 {
		return "", raw
	}
	return string(raw[:idx]), raw[idx+4:]
}
