package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpProtocolNumber is the IANA protocol number for ICMPv4, used by ParseMessage.
const icmpProtocolNumber = 1

// openICMPConn opens an ICMPv4 socket. It prefers an unprivileged datagram
// socket ("udp4", works for non-root users on Linux when net.ipv4.ping_group_range
// permits, and on macOS) and falls back to a privileged raw socket ("ip4:icmp",
// which needs root/CAP_NET_RAW on Unix or Administrator on Windows). The second
// return value reports whether the socket is a datagram ("udp") socket, which
// determines the destination address type used when sending.
func openICMPConn() (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, true, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false, err
	}
	return c, false, nil
}

// icmpDiscover sends a single ICMP echo request to each IPv4 host and returns
// the set of hosts (by their original string form) that replied within timeout.
// The second return value is false when no ICMP socket could be opened at all —
// the caller should then fall back to another method. Non-IPv4 / unresolvable
// hosts are ignored here (the dispatcher routes those elsewhere).
//
// The reader runs concurrently with (and continues past) the send loop so replies
// are drained as they arrive rather than piling up in the socket buffer, and the
// reply-window deadline is set AFTER the send loop so every host — including those
// pinged last in a large sweep — gets the full timeout to answer. Sends are
// retried on transient buffer-full errors, and any residual send failures are
// surfaced (never silently dropped) so a big sweep cannot quietly misreport hosts.
func icmpDiscover(hosts []string, timeout time.Duration) (map[string]bool, bool) {
	conn, isDatagram, err := openICMPConn()
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	// Map resolved IPv4 -> original host string, so a reply's source address
	// maps back to what the caller passed in.
	ipToHost := make(map[string]string)
	type dst struct {
		host string
		ip   net.IP
	}
	var dsts []dst
	for _, h := range hosts {
		ip := resolveIPv4(h)
		if ip == nil {
			continue
		}
		ipToHost[ip.String()] = h
		dsts = append(dsts, dst{host: h, ip: ip})
	}
	if len(dsts) == 0 {
		return map[string]bool{}, true
	}

	live := make(map[string]bool)
	var mu sync.Mutex

	// Reader: drain echo replies continuously. No deadline is set here — the
	// send loop sets it once all requests are out, giving every host a full
	// reply window. Reading during the send phase also keeps the socket receive
	// buffer from overflowing on large sweeps.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return // deadline reached or socket closed
			}
			rm, perr := icmp.ParseMessage(icmpProtocolNumber, buf[:n])
			if perr != nil || rm.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			peerIP := addrIP(peer)
			if peerIP == "" {
				continue
			}
			mu.Lock()
			if h, ok := ipToHost[peerIP]; ok {
				live[h] = true
			}
			mu.Unlock()
		}
	}()

	// Send one echo request per host, retrying briefly on transient buffer-full
	// errors (ENOBUFS/EAGAIN) instead of silently losing the probe.
	id := os.Getpid() & 0xffff
	var sendFailures int
	for i, d := range dsts {
		wm := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: i & 0xffff, Data: []byte("wScanner-disco")},
		}
		wb, merr := wm.Marshal(nil)
		if merr != nil {
			continue
		}
		var to net.Addr
		if isDatagram {
			to = &net.UDPAddr{IP: d.ip}
		} else {
			to = &net.IPAddr{IP: d.ip}
		}
		if !sendWithRetry(func() error { _, e := conn.WriteTo(wb, to); return e }) {
			sendFailures++
		}
	}

	// Now that every request is out, give replies the full timeout window.
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	<-done

	if sendFailures > 0 {
		fmt.Printf("%s[!]%s ICMP: %d/%d probes could not be sent (buffer limits) — some hosts may be under-reported; consider a smaller range or -discovery-method tcp\n",
			Yellow, Reset, sendFailures, len(dsts))
	}

	mu.Lock()
	defer mu.Unlock()
	return live, true
}

// sendWithRetry runs send up to 3 times, backing off briefly on error to ride
// out transient buffer-full conditions (ENOBUFS/EAGAIN) under a fast send burst.
// Returns true if a send eventually succeeded.
func sendWithRetry(send func() error) bool {
	for attempt := 0; attempt < 3; attempt++ {
		if send() == nil {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// resolveIPv4 returns the IPv4 address for a host string (IP or hostname), or
// nil if it is not IPv4 / cannot be resolved.
func resolveIPv4(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4()
	}
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil || addr.IP == nil {
		return nil
	}
	return addr.IP.To4()
}

// addrIP extracts the IP string from an ICMP reply's peer address, which is a
// *net.UDPAddr on datagram sockets and a *net.IPAddr on raw sockets.
func addrIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	return ""
}
