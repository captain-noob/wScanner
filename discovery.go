package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxExpandHosts caps how many addresses a single CIDR/range may expand to.
// A /16 (65 536 addresses) is the practical ceiling — anything larger should
// be narrowed by the user rather than silently scanned across every port.
const maxExpandHosts = 65536

// isRangeTarget reports whether a raw target string is a CIDR ("10.0.0.0/24")
// or a dash range ("10.0.0.1-10.0.0.50" / "10.0.0.1-50") rather than a single
// host or hostname.
func isRangeTarget(t string) bool {
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err == nil {
			return true
		}
	}
	if strings.Contains(t, "-") {
		// Only treat as a range when the left side is an IP.
		left := strings.SplitN(t, "-", 2)[0]
		if net.ParseIP(strings.TrimSpace(left)) != nil {
			return true
		}
	}
	return false
}

// nextIP returns the successor of ip (big-endian increment). It copies ip so
// the caller's slice is not mutated.
func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// hostsFromCIDR expands a CIDR to the list of scannable host addresses.
// For IPv4 blocks of /30 or larger the network and broadcast addresses are
// dropped. Ranges exceeding maxExpandHosts return an error.
func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones

	// Guard against absurd expansions (e.g. an IPv6 /64) before allocating.
	if hostBits > 20 || (uint64(1)<<uint(hostBits)) > maxExpandHosts {
		return nil, fmt.Errorf("range %s is too large (%d addresses); narrow it to /16 or smaller", cidr, uint64(1)<<uint(hostBits))
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		ips = append(ips, cur.String())
	}

	// Drop network + broadcast for IPv4 blocks that have room for hosts.
	if bits == 32 && hostBits >= 2 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// hostsFromDashRange expands "10.0.0.1-10.0.0.50" or the shorthand
// "10.0.0.1-50" (last octet only) into individual IPv4 addresses.
func hostsFromDashRange(r string) ([]string, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", r)
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	start := net.ParseIP(startStr).To4()
	if start == nil {
		return nil, fmt.Errorf("invalid range start: %s", startStr)
	}

	// Shorthand: only the final octet after the dash.
	if !strings.Contains(endStr, ".") {
		lastOctet, err := strconv.Atoi(endStr)
		if err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid range end: %s", endStr)
		}
		endStr = fmt.Sprintf("%d.%d.%d.%d", start[0], start[1], start[2], lastOctet)
	}

	end := net.ParseIP(endStr).To4()
	if end == nil {
		return nil, fmt.Errorf("invalid range end: %s", endStr)
	}

	startN := ipToUint32(start)
	endN := ipToUint32(end)
	if endN < startN {
		return nil, fmt.Errorf("range end %s is before start %s", endStr, startStr)
	}
	// Compute the span in uint64 — endN-startN+1 in uint32 wraps to 0 for the
	// full address space (0.0.0.0-255.255.255.255), bypassing the guard.
	span := uint64(endN) - uint64(startN) + 1
	if span > maxExpandHosts {
		return nil, fmt.Errorf("range %s is too large (%d addresses); narrow it", r, span)
	}

	var ips []string
	for n := startN; n <= endN; n++ {
		ips = append(ips, uint32ToIP(n).String())
		if n == ^uint32(0) { // avoid overflow wrap on 255.255.255.255
			break
		}
	}
	return ips, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// expandTargets turns a raw target list (which may contain CIDRs, dash ranges,
// single IPs and hostnames) into a flat, de-duplicated list of scan targets.
// The second return value reports whether any entry was expanded from a
// CIDR/range — the signal used to decide whether host discovery should run.
func expandTargets(raw []string) ([]string, bool) {
	var out []string
	seen := make(map[string]bool)
	expanded := false

	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}

	for _, r := range raw {
		r = normalizeTarget(r)
		if r == "" {
			continue
		}

		switch {
		case strings.Contains(r, "/") && func() bool { _, _, e := net.ParseCIDR(r); return e == nil }():
			hosts, err := hostsFromCIDR(r)
			if err != nil {
				fmt.Printf("%s[!] Warning:%s %v — skipping\n", Yellow, Reset, err)
				continue
			}
			expanded = true
			for _, h := range hosts {
				add(h)
			}
		case isRangeTarget(r) && strings.Contains(r, "-"):
			hosts, err := hostsFromDashRange(r)
			if err != nil {
				fmt.Printf("%s[!] Warning:%s %v — skipping\n", Yellow, Reset, err)
				continue
			}
			expanded = true
			for _, h := range hosts {
				add(h)
			}
		default:
			// Not a CIDR and not a range. If a path slipped through
			// (e.g. "example.com/path"), keep only the host portion.
			if i := strings.IndexByte(r, '/'); i >= 0 {
				r = r[:i]
			}
			add(r)
		}
	}

	return out, expanded
}

// normalizeTarget trims a raw target and, if the user pasted a URL, reduces it
// to just the host (e.g. "https://example.com/login" -> "example.com",
// "http://example.com:8443/x" -> "example.com"). The scheme, path, query and
// any URL port are dropped, because the scanner probes a host across the ports
// from -ports-file; a host:port target would be dialed as "[host:port]:<p>"
// and never connect. A bare host, IP, CIDR or dash range is returned unchanged.
func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return t
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return t
}

// sanitizePorts trims blanks and keeps only valid TCP port numbers (1-65535),
// preserving order and dropping duplicates.
func sanitizePorts(raw []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// parseDiscoveryPorts parses the -discovery-ports flag into a slice of ports,
// falling back to a sane default set if the value is empty or invalid.
func parseDiscoveryPorts(spec string) []string {
	var ports []string
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		ports = []string{"80", "443", "22", "8080", "8443", "445"}
	}
	return ports
}

// discoveryTimeout returns how long to wait for a liveness reply. It stays snappy
// and only tightens toward the user -timeout when that is positive and smaller —
// a 0/negative -timeout must not be propagated (net.Dialer treats a zero Timeout
// as "no timeout"). main() also clamps -timeout at startup.
func discoveryTimeout() time.Duration {
	to := 1500 * time.Millisecond
	if ut := time.Duration(*time_out) * time.Second; ut > 0 && ut < to {
		to = ut
	}
	return to
}

// discoverLiveHosts finds which hosts are alive, using the requested method:
//
//	auto  — ARP for local-subnet hosts (Linux+root) + ICMP for the rest,
//	        falling back to TCP-connect when the privileged method is unavailable.
//	icmp  — ICMP echo sweep (falls back to TCP if no ICMP socket can be opened).
//	arp   — ARP ping for local-subnet hosts; other hosts go to TCP.
//	tcp   — TCP-connect on the discovery ports (always available, unprivileged).
//
// Live hosts are written to live_hosts.txt; input ordering is preserved.
func discoverLiveHosts(hosts []string, method string, tcpPorts []string) []string {
	total := len(hosts)
	if total == 0 {
		return hosts
	}

	to := discoveryTimeout()
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		method = "auto"
	}

	live := make(map[string]bool)
	var used []string
	merge := func(m map[string]bool) {
		for h := range m {
			live[h] = true
		}
	}

	fmt.Printf("%s[*]%s Host discovery (%s%s%s) on %s%d%s hosts...\n",
		Cyan, Reset, Bold, method, Reset, Bold, total, Reset)

	switch method {
	case "tcp":
		merge(tcpDiscover(hosts, tcpPorts, to))
		used = append(used, "tcp")

	case "arp":
		v4, other := splitIPv4(hosts)
		local, remote := localSubnetHosts(v4)
		if arpAvailable() && len(local) > 0 {
			if s, ok := arpDiscover(local, to); ok {
				merge(s)
				used = append(used, "arp")
			} else {
				remote = append(remote, local...)
			}
		} else {
			if len(local) > 0 {
				fmt.Printf("%s[!]%s ARP unavailable (needs Linux + root) — using TCP for local hosts\n", Yellow, Reset)
			}
			remote = append(remote, local...)
		}
		rest := append(remote, other...)
		if len(rest) > 0 {
			merge(tcpDiscover(rest, tcpPorts, to))
			used = append(used, "tcp")
		}

	case "icmp":
		v4, other := splitIPv4(hosts)
		if len(v4) > 0 {
			if s, ok := icmpDiscover(v4, to); ok {
				merge(s)
				used = append(used, "icmp")
			} else {
				fmt.Printf("%s[!]%s ICMP unavailable (needs privileges) — falling back to TCP\n", Yellow, Reset)
				merge(tcpDiscover(v4, tcpPorts, to))
				used = append(used, "tcp")
			}
		}
		if len(other) > 0 {
			merge(tcpDiscover(other, tcpPorts, to))
			used = append(used, "tcp")
		}

	default: // auto
		v4, other := splitIPv4(hosts)
		local, remote := localSubnetHosts(v4)
		arpOK := false
		if arpAvailable() && len(local) > 0 {
			if s, ok := arpDiscover(local, to); ok {
				merge(s)
				used = append(used, "arp")
				arpOK = true
			}
		}
		pingTargets := remote
		if !arpOK {
			pingTargets = v4 // ARP unavailable/failed → ICMP-ping every IPv4 host
		}
		if len(pingTargets) > 0 {
			if s, ok := icmpDiscover(pingTargets, to); ok {
				merge(s)
				used = append(used, "icmp")
			} else {
				fmt.Printf("%s[!]%s ICMP unavailable (needs privileges) — falling back to TCP\n", Yellow, Reset)
				merge(tcpDiscover(pingTargets, tcpPorts, to))
				used = append(used, "tcp")
			}
		}
		if len(other) > 0 { // IPv6 / hostnames: ICMPv4 & ARP don't apply
			merge(tcpDiscover(other, tcpPorts, to))
			used = append(used, "tcp")
		}
	}

	// Preserve input order.
	var out []string
	for _, h := range hosts {
		if live[h] {
			out = append(out, h)
		}
	}

	writeLiveHosts(out)

	fmt.Printf("%s[+]%s Host discovery complete (%s): %s%d%s of %s%d%s hosts are live.\n",
		Green, Reset, dedupJoin(used, "+"), Bold, len(out), Reset, Bold, total, Reset)

	return out
}

// tcpDiscover marks a host live if any of the discovery ports accepts a TCP
// connection within the timeout. Always available and unprivileged.
func tcpDiscover(hosts []string, ports []string, timeout time.Duration) map[string]bool {
	live := make(map[string]bool)
	if len(hosts) == 0 {
		return live
	}
	if len(ports) == 0 {
		ports = []string{"80", "443", "22", "8080", "8443", "445"}
	}

	type out struct {
		host  string
		alive bool
	}
	jobs := make(chan string, 4096)
	outs := make(chan out, 4096)

	workerCount := getConcurrencyLimit()
	if len(hosts) < workerCount {
		workerCount = len(hosts)
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				alive := false
				for _, port := range ports {
					d := net.Dialer{Timeout: timeout}
					conn, err := d.Dial("tcp", net.JoinHostPort(h, port))
					if err == nil {
						conn.Close()
						alive = true
						break
					}
				}
				outs <- out{host: h, alive: alive}
				atomic.AddInt64(&activeGoroutines, -1)
			}
		}()
	}

	throttle, stopThrottle := newRPSThrottle()
	go func() {
		for _, h := range hosts {
			throttle()
			jobs <- h
		}
		close(jobs)
		stopThrottle()
	}()
	go func() {
		wg.Wait()
		close(outs)
	}()

	for o := range outs {
		if o.alive {
			live[o.host] = true
		}
	}
	return live
}

// splitIPv4 separates IPv4-literal hosts from everything else (IPv6 literals and
// hostnames), which are routed to TCP discovery since ICMPv4/ARP don't apply.
func splitIPv4(hosts []string) (v4 []string, other []string) {
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil && ip.To4() != nil {
			v4 = append(v4, h)
		} else {
			other = append(other, h)
		}
	}
	return v4, other
}

// localSubnetHosts partitions IPv4 hosts into those on a directly-connected,
// non-loopback interface subnet (ARP-reachable) and the rest.
func localSubnetHosts(v4 []string) (local []string, remote []string) {
	var nets []*net.IPNet
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || len(ifi.HardwareAddr) != 6 {
				continue
			}
			addrs, aerr := ifi.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					nets = append(nets, ipnet)
				}
			}
		}
	}
	for _, h := range v4 {
		ip := net.ParseIP(h)
		isLocal := false
		for _, n := range nets {
			if n.Contains(ip) {
				isLocal = true
				break
			}
		}
		if isLocal {
			local = append(local, h)
		} else {
			remote = append(remote, h)
		}
	}
	return local, remote
}

// writeLiveHosts persists the live host list for the record / resume inspection.
func writeLiveHosts(live []string) {
	fname := folderName + "/live_hosts.txt"
	if f, err := os.Create(fname); err == nil {
		for _, h := range live {
			f.WriteString(h + "\n")
		}
		f.Close()
	}
}

// dedupJoin joins the strings with sep after removing duplicates, preserving
// first-seen order (e.g. ["arp","icmp","tcp"] -> "arp+icmp+tcp").
func dedupJoin(items []string, sep string) string {
	seen := make(map[string]bool)
	var uniq []string
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			uniq = append(uniq, it)
		}
	}
	if len(uniq) == 0 {
		return "none"
	}
	return strings.Join(uniq, sep)
}
