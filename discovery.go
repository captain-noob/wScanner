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

// discoverLiveHosts performs a fast TCP-connect liveness sweep over the given
// hosts. A host is considered alive if any of the discovery ports accepts a
// connection within a short timeout. Live hosts are written to
// live_hosts.txt in the output folder. Ordering of the input is preserved.
func discoverLiveHosts(hosts []string, discoveryPorts []string) []string {
	total := len(hosts)
	if total == 0 {
		return hosts
	}

	fmt.Printf("%s[*]%s Host discovery on %s%d%s hosts (ports: %s)...\n",
		Cyan, Reset, Bold, total, Reset, strings.Join(discoveryPorts, ","))

	bar := NewProgressBar(total)

	// Short per-connection timeout keeps discovery snappy; a live host on a
	// LAN or nearby network answers in well under a second.
	// Keep discovery snappy. Only tighten toward the user timeout when it is a
	// positive value smaller than the default — a 0/negative -timeout must not
	// be propagated, since net.Dialer treats a zero Timeout as "no timeout"
	// and discovery would then hang on every filtered host (for the OS default,
	// which is ~2min on Linux vs ~21s on Windows).
	dialTimeout := 1500 * time.Millisecond
	if ut := time.Duration(*time_out) * time.Second; ut > 0 && ut < dialTimeout {
		dialTimeout = ut
	}

	type discoOut struct {
		Idx   int
		Alive bool
	}

	jobs := make(chan int, 4096)
	outs := make(chan discoOut, 4096)

	workerCount := getConcurrencyLimit()
	if total < workerCount {
		workerCount = total
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				alive := false
				for _, port := range discoveryPorts {
					d := net.Dialer{Timeout: dialTimeout}
					conn, err := d.Dial("tcp", net.JoinHostPort(hosts[idx], port))
					if err == nil {
						conn.Close()
						alive = true
						break
					}
				}
				outs <- discoOut{Idx: idx, Alive: alive}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	throttle, stopThrottle := newRPSThrottle()
	go func() {
		for i := range hosts {
			throttle()
			jobs <- i
		}
		close(jobs)
		stopThrottle()
	}()

	go func() {
		wg.Wait()
		close(outs)
	}()

	aliveFlags := make([]bool, total)
	for o := range outs {
		aliveFlags[o.Idx] = o.Alive
	}
	fmt.Println()

	var live []string
	for i, ok := range aliveFlags {
		if ok {
			live = append(live, hosts[i])
		}
	}

	// Persist live hosts for the record / resume inspection.
	fname := folderName + "/live_hosts.txt"
	if f, err := os.Create(fname); err == nil {
		for _, h := range live {
			f.WriteString(h + "\n")
		}
		f.Close()
	}

	fmt.Printf("%s[+]%s Host discovery complete: %s%d%s of %s%d%s hosts are live.\n",
		Green, Reset, Bold, len(live), Reset, Bold, total, Reset)

	return live
}
