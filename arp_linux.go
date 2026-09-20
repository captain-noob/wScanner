//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host to network (big-endian) byte order. It is a
// no-op on big-endian hosts and a swap on little-endian ones — implemented via
// encoding/binary so it is correct on every architecture the linux build tag
// covers (amd64/arm64 little-endian, s390x/mips big-endian).
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// arpAvailable reports whether ARP discovery can run: Linux with permission to
// open an AF_PACKET raw socket (root or CAP_NET_RAW).
func arpAvailable() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// arpIface holds the L2 details needed to build ARP requests on an interface.
type arpIface struct {
	index int
	mac   net.HardwareAddr
	ip    net.IP // interface's own IPv4
}

// findArpIface returns the up, non-loopback interface (with a 6-byte MAC) whose
// IPv4 subnet contains ip, or nil if none is directly connected.
func findArpIface(ip net.IP) *arpIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifi.HardwareAddr) != 6 {
			continue
		}
		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(ip) {
				return &arpIface{index: ifi.Index, mac: ifi.HardwareAddr, ip: ipnet.IP.To4()}
			}
		}
	}
	return nil
}

// buildARPRequest crafts an Ethernet+ARP "who-has tpa" broadcast frame.
func buildARPRequest(src *arpIface, tpa net.IP) []byte {
	var b bytes.Buffer
	// Ethernet header
	b.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst = broadcast
	b.Write(src.mac)                                    // src MAC
	binary.Write(&b, binary.BigEndian, uint16(0x0806))  // ethertype = ARP
	// ARP payload
	binary.Write(&b, binary.BigEndian, uint16(1))      // htype = Ethernet
	binary.Write(&b, binary.BigEndian, uint16(0x0800)) // ptype = IPv4
	b.WriteByte(6)                                     // hlen
	b.WriteByte(4)                                     // plen
	binary.Write(&b, binary.BigEndian, uint16(1))      // oper = request
	b.Write(src.mac)                                   // sender MAC
	b.Write(src.ip.To4())                              // sender IP
	b.Write([]byte{0, 0, 0, 0, 0, 0})                  // target MAC (unknown)
	b.Write(tpa.To4())                                 // target IP
	return b.Bytes()
}

// arpDiscover ARP-pings the given (ideally local-subnet, IPv4) hosts and returns
// the set that replied. ok=false means ARP could not be used at all (no
// permission / no suitable interface), so the caller should fall back.
//
// A reader goroutine drains replies concurrently with the send loop so answers
// are not lost to a full socket buffer while requests are still going out, and
// sends are retried on transient buffer-full errors.
func arpDiscover(hosts []string, timeout time.Duration) (map[string]bool, bool) {
	// Group hosts by the interface that can reach them; map target IP -> host.
	type group struct {
		ifi     *arpIface
		targets map[string]string // ip string -> original host
	}
	byIface := map[int]*group{}
	for _, h := range hosts {
		ip := resolveIPv4(h)
		if ip == nil {
			continue
		}
		ifi := findArpIface(ip)
		if ifi == nil {
			continue
		}
		g := byIface[ifi.index]
		if g == nil {
			g = &group{ifi: ifi, targets: map[string]string{}}
			byIface[ifi.index] = g
		}
		g.targets[ip.String()] = h
	}
	if len(byIface) == 0 {
		return nil, false
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, false // typically EPERM (needs root/CAP_NET_RAW)
	}
	defer unix.Close(fd)

	// Short receive timeout so the reader can re-check the stop signal.
	tv := unix.Timeval{Sec: 0, Usec: 200000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	live := make(map[string]bool)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader: consume ARP replies until stopped. It owns `live`; the caller
	// only reads it after wg.Wait(), so no additional locking is needed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _, rerr := unix.Recvfrom(fd, buf, 0)
			if rerr != nil {
				continue // EAGAIN from SO_RCVTIMEO — loop and re-check stop
			}
			if n < 42 { // 14 (eth) + 28 (arp)
				continue
			}
			if binary.BigEndian.Uint16(buf[12:14]) != 0x0806 { // ethertype ARP
				continue
			}
			if binary.BigEndian.Uint16(buf[20:22]) != 2 { // ARP reply
				continue
			}
			senderIP := net.IP(buf[28:32]).String()
			for _, g := range byIface {
				if h, ok := g.targets[senderIP]; ok {
					live[h] = true
				}
			}
		}
	}()

	// Send an ARP request for every target, retrying on transient buffer-full.
	total := 0
	var sendFailures int
	for _, g := range byIface {
		for ipStr := range g.targets {
			total++
			frame := buildARPRequest(g.ifi, net.ParseIP(ipStr))
			sa := &unix.SockaddrLinklayer{
				Protocol: htons(unix.ETH_P_ARP),
				Ifindex:  g.ifi.index,
				Halen:    6,
				Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			}
			if !sendWithRetry(func() error { return unix.Sendto(fd, frame, 0, sa) }) {
				sendFailures++
			}
		}
	}

	// Let replies arrive, then stop the reader.
	time.Sleep(timeout)
	close(stop)
	wg.Wait()

	if sendFailures > 0 {
		fmt.Printf("%s[!]%s ARP: %d/%d requests could not be sent (buffer limits) — some hosts may be under-reported\n",
			Yellow, Reset, sendFailures, total)
	}

	return live, true
}
