package main

import (
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

	// Reader: collect echo replies until the deadline elapses.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		for {
			n, peer, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return // deadline or closed
			}
			rm, perr := icmp.ParseMessage(icmpProtocolNumber, buf[:n])
			if perr != nil {
				continue
			}
			if rm.Type != ipv4.ICMPTypeEchoReply {
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

	// Send one echo request per host.
	id := os.Getpid() & 0xffff
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
		_, _ = conn.WriteTo(wb, to)
	}

	<-done

	mu.Lock()
	defer mu.Unlock()
	return live, true
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
