package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

var version = "1.0.0-stable"

const remoteHeaders = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/headers.json"
const remoteUserAgents = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/user-agent.txt"
const remotePorts = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/ports.txt"
const intrestingPaths = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/paths.txt"

// const remoteWappalyzer = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/wappalyzer.json"

var folderName = "wScanner_" + time.Now().Format("20060102_150405")

var isProgressBarCompleted = false
var activeGoroutines int64

// Global error logger — initialized in main() after output folder is created.
var errLogger *ErrorLogger

var (
	portsFile    = flag.String("ports-file", "ports.txt", "File containing **newline-separated ports** to probe.")
	inputFile    = flag.String("input", "", "File containing **newline-separated hostnames or IP addresses** to scan.")
	host         = flag.String("host", "", "Single **hostname or IP address** to scan (alternative to -input).")
	verbose      = flag.Bool("v", false, "Enable **verbose** output mode.")
	time_out     = flag.Int("timeout", 15, "Timeout duration in **seconds** for each probe/request.")
	stdout       = flag.Bool("stdout", true, "Print results to **standard output** (stdout).")
	local        = flag.Bool("local", false, "Indicates running in a **local network** environment (without general internet access).")
	updateConfig = flag.Bool("update-config", false, "Fetch and update **configuration files** from remote sources.")
	maxRPS       = flag.Int("rps", 0, "Maximum requests dispatched per second (0 = unlimited)")
	concurrency  = flag.Int("c", 0, "Max concurrent workers/connections (0 = auto, default cap 1024)")
	outputDir    = flag.String("output", "", "Custom **output folder** name (default: wScanner_YYYYMMDD_HHMMSS).")
	csvOut       = flag.Bool("csv", false, "Generate a **CSV** results file in the output folder.")
	pathFile     = flag.String("path", "", "Custom **wordlist** file for directory/path fuzzing.")
	selfUpdate   = flag.Bool("update", false, "Self-update wScanner to the **latest** GitHub release.")
	forceCFScan  = flag.Bool("force-cf", false, "Force port scanning even for **Cloudflare** IPs.")
	maxRetries   = flag.Int("retries", 2, "Number of **retries** for failed HTTP requests (transport errors only).")
)

// CSV columns
var csvHeaders = []string{
	"target",
	"port",
	"scheme",
	"status_code",
	"content_length",
	"content_type",
	"redirect_location",
	"favicon_mmh3",
	"response_time_ms",
	"body_line_count",
	"body_word_count",
	"page_title",
	"server",
	"technologies",
	"http_method",
	"websocket_capable",
	"ip",
	"asn",
	"cdn_waf",
	"cname",
	"ptr",
	"ssl_cn",
	"ssl_sans",
}

// Cloudflare IP ranges (populated by init)
var cloudflareIPv4CIDRs []*net.IPNet
var cloudflareIPv6CIDRs []*net.IPNet

func init() {
	// Standard Cloudflare IPv4 ranges
	ipv4Ranges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
	ipv6Ranges := []string{
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
		"2c0f:f248::/32",
	}
	for _, cidr := range ipv4Ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			cloudflareIPv4CIDRs = append(cloudflareIPv4CIDRs, network)
		}
	}
	for _, cidr := range ipv6Ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			cloudflareIPv6CIDRs = append(cloudflareIPv6CIDRs, network)
		}
	}
}

// isCloudflareIP checks whether the given IP belongs to a Cloudflare range.
func isCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Might be a hostname — try resolving it first
		addrs, err := net.LookupHost(ipStr)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return false
		}
	}

	for _, cidr := range cloudflareIPv4CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	for _, cidr := range cloudflareIPv6CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveTarget performs CNAME and reverse DNS (PTR) lookups for a target.
func resolveTarget(target string) (string, string) {
	var cname, ptr string

	// CNAME lookup (only meaningful for hostnames, not IPs)
	if net.ParseIP(target) == nil {
		if c, err := net.LookupCNAME(target); err == nil && c != target+"." && c != "" {
			cname = strings.TrimSuffix(c, ".")
		}
	}

	// PTR lookup — resolve hostname to IP first if needed
	ipStr := target
	if net.ParseIP(target) == nil {
		addrs, err := net.LookupHost(target)
		if err == nil && len(addrs) > 0 {
			ipStr = addrs[0]
		} else {
			return cname, ptr
		}
	}

	names, err := net.LookupAddr(ipStr)
	if err == nil && len(names) > 0 {
		ptr = strings.TrimSuffix(names[0], ".")
	}

	return cname, ptr
}

// extractSSLCertInfo performs a TLS handshake and extracts CN + SANs.
func extractSSLCertInfo(host, port string) (string, []string) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return "", nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", nil
	}

	leaf := certs[0]
	return leaf.Subject.CommonName, leaf.DNSNames
}

var userAgentsFile *string
var headersFile *string
var pathsFile *string

// --- Cached data (loaded once at startup) ---
var cachedUserAgents []string
var cachedHeaderConfig HeaderConfig

// loadCaches reads user-agent and headers files once into memory.
// Must be called after checkAndDownloadAssets() sets the file paths.
func loadCaches() {
	// Cache user agents (Perf #9)
	agents, err := readInputFile(*userAgentsFile)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not load user-agent file: %v (will use default UA)\n", Yellow, Reset, err)
	} else {
		cachedUserAgents = agents
	}

	// Cache header config (Bug #6)
	rawJSON, err := readInputFile(*headersFile)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not load headers file: %v\n", Yellow, Reset, err)
		return
	}
	headersData := []byte(strings.Join(rawJSON, "\n"))
	if err := json.Unmarshal(headersData, &cachedHeaderConfig); err != nil {
		fmt.Printf("%s[!] Warning:%s Could not parse headers JSON: %v\n", Yellow, Reset, err)
	}
}

func downloadFile(url string, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func checkAndDownloadAssets() bool {
	currentUser, _ := user.Current()
	homeDir := currentUser.HomeDir
	assetDir := homeDir + string(os.PathSeparator) + ".config" + string(os.PathSeparator) + "wScanner" + string(os.PathSeparator)
	if _, err := os.Stat(assetDir); os.IsNotExist(err) {
		err := os.MkdirAll(assetDir, 0755)
		if err != nil {
			fmt.Printf("%s[!] Error:%s Failed to create asset directory: %v\n", Red, Reset, err)
			return false
		}
	}

	portsPath := assetDir + "ports.txt"
	if _, err := os.Stat(portsPath); os.IsNotExist(err) || *updateConfig {
		fmt.Printf("%s[+] Downloading ports file...%s\n", Cyan, Reset)
		err := downloadFile(remotePorts, portsPath)
		if err != nil {
			fmt.Printf("%s[!] Error:%s Failed to download ports file: %v\n", Red, Reset, err)
			return false
		}
	}
	uaPath := assetDir + "user-agent.txt"
	if _, err := os.Stat(uaPath); os.IsNotExist(err) || *updateConfig {
		fmt.Printf("%s[+] Downloading user-agent file...%s\n", Cyan, Reset)
		err := downloadFile(remoteUserAgents, uaPath)
		if err != nil {
			fmt.Printf("%s[!] Error:%s Failed to download user-agent file: %v\n", Red, Reset, err)
			return false
		}
	}

	headersPath := assetDir + "headers.json"
	if _, err := os.Stat(headersPath); os.IsNotExist(err) || *updateConfig {
		fmt.Printf("%s[+] Downloading headers file...%s\n", Cyan, Reset)
		err := downloadFile(remoteHeaders, headersPath)
		if err != nil {
			fmt.Printf("%s[!] Error:%s Failed to download headers file: %v\n", Red, Reset, err)
			return false
		}
	}

	// Download paths wordlist
	pathsPath := assetDir + "paths.txt"
	if _, err := os.Stat(pathsPath); os.IsNotExist(err) || *updateConfig {
		fmt.Printf("%s[+] Downloading paths wordlist...%s\n", Cyan, Reset)
		err := downloadFile(intrestingPaths, pathsPath)
		if err != nil {
			fmt.Printf("%s[!] Warning:%s Failed to download paths file: %v\n", Yellow, Reset, err)
			// Not fatal — fuzzing is optional
		}
	}

	pPath := portsPath
	portsFile = &pPath
	uPath := uaPath
	userAgentsFile = &uPath
	hPath := headersPath
	headersFile = &hPath
	pthPath := pathsPath
	pathsFile = &pthPath

	return true
}

func StartSpinner(stopChan chan bool) {
	spinner := []rune{'|', '/', '-', '\\'}
	i := 0

	for {
		select {
		case <-stopChan:
			fmt.Print("\r") // clear or reset
			return
		default:
			fmt.Printf("\r%c Probing...", spinner[i%len(spinner)])
			time.Sleep(120 * time.Millisecond)
			i++
		}
	}
}

func NewProgressBar(total int) *ProgressBar {
	const defaultWidth = 60
	return &ProgressBar{
		Total:     total,
		Current:   0,
		Width:     defaultWidth,
		BarChar:   "█",
		EmptyChar: "░",
		Mux:       sync.Mutex{},
	}
}

// Update increments the progress bar safely and prints the new state.
func (pb *ProgressBar) Update(step int) {
	// 1. Lock the Mutex before modifying shared state (Current)
	pb.Mux.Lock()
	// 2. Ensure the Mutex is unlocked when the function exits, regardless of how it exits
	defer pb.Mux.Unlock()

	// Now, only one goroutine can execute the following code block at a time

	pb.Current += step
	isProgressBarCompleted = false
	if pb.Current > pb.Total {
		pb.Current = pb.Total
	}

	percentage := float64(pb.Current) / float64(pb.Total)
	filledWidth := int(percentage * float64(pb.Width))

	filledPart := strings.Repeat(pb.BarChar, filledWidth)
	emptyPart := strings.Repeat(pb.EmptyChar, pb.Width-filledWidth)

	// Note: We use fmt.Fprint(os.Stdout, ...) or just fmt.Print here.
	// Console output for the progress bar itself is inherently tricky in concurrent contexts,
	// as multiple goroutines could try to print to the screen simultaneously.
	// However, the mutex ensures the *data calculation* is safe.
	// If you see garbled output, you may need a global lock around ALL printing too.
	// For this simple case, locking the Update function is usually sufficient.
	active := atomic.LoadInt64(&activeGoroutines)
	output := fmt.Sprintf("\r\tProgress: [%s%s] %.2f%% (%d/%d) | %s%d active%s",
		filledPart,
		emptyPart,
		percentage*100,
		pb.Current,
		pb.Total,
		Cyan,
		active,
		Reset,
	)

	fmt.Print(output)

	if pb.Current == pb.Total {
		fmt.Println()
		isProgressBarCompleted = true
	}
}

func CheckInternet() bool {
	timeout := 3 * time.Second
	_, err := net.DialTimeout("tcp", "8.8.8.8:53", timeout)
	return err == nil
}

func readInputFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

// readOpenPortsFile reads a file of "IP:Port" lines (written by probeTargets/probePorts)
// and returns a ScanResultList. Used to recover partial port scan results on resume.
func readOpenPortsFile(filePath string) (ScanResultList, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results ScanResultList
	seen := make(map[string]bool) // deduplicate
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Parse "IP:Port" — handle IPv6 [addr]:port format too
		host, port, splitErr := net.SplitHostPort(line)
		if splitErr != nil {
			continue
		}
		key := host + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, ScanResult{IP: host, Port: port})
	}

	return results, scanner.Err()
}

func getRandomUserAgent() string {
	if len(cachedUserAgents) == 0 {
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36"
	}
	return cachedUserAgents[rand.Intn(len(cachedUserAgents))]
}

func getMaxThreads() int {
	numCPU := runtime.NumCPU()
	maxThreads := numCPU * 10
	return maxThreads
}

func getConcurrencyLimit() int {
	// If user specified -c, use it directly (no cap).
	if *concurrency > 0 {
		return *concurrency
	}
	// Cross-platform: derive from CPU count instead of bash ulimit
	limit := runtime.NumCPU() * 256
	if limit > 1024 {
		limit = 1024
	}
	if limit < 100 {
		limit = 100
	}
	return limit
}

// rpsThrottle blocks until the rate limiter allows the next request.
// If -rps is not set (0), it returns immediately (no throttling).
// Caller must call the returned stop function when done dispatching.
func newRPSThrottle() (throttle func(), stop func()) {
	if *maxRPS <= 0 {
		return func() {}, func() {}
	}
	interval := time.Second / time.Duration(*maxRPS)
	ticker := time.NewTicker(interval)
	return func() { <-ticker.C }, ticker.Stop
}

func detectScheme(host string, port string) string {
	address := net.JoinHostPort(host, port)
	// Use a capped per-attempt timeout of 5 seconds for scheme detection
	schemeTimeout := 5 * time.Second
	userTimeout := time.Duration(*time_out) * time.Second
	if userTimeout < schemeTimeout {
		schemeTimeout = userTimeout
	}

	// --- Try HTTPS first (TLS handshake) ---
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // for detection purposes only
	}

	dialer := &net.Dialer{Timeout: schemeTimeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err == nil {
		conn.Close()
		return "https" // HTTPS valid → skip HTTP
	}

	// --- Fallback: Try HTTP ---
	client := http.Client{
		Timeout: schemeTimeout,
	}

	resp, err := client.Get("http://" + address)
	if err == nil {
		defer resp.Body.Close()
		return "http"
	}

	return ""
}

func checkForOpenPort(host string, port string) bool {
	address := net.JoinHostPort(host, port)
	// Use a short 3-second timeout for TCP port probing — fast but reliable.
	// TCP SYN/ACK handshake is inherently fast; 3s is generous even for
	// cross-continent latency while keeping thousand-port sweeps quick.
	portTimeout := 3 * time.Second
	dialer := &net.Dialer{
		Timeout: portTimeout,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func probePorts(target string, ports []string) ScanResultList {
	totalPorts := len(ports)

	bar := NewProgressBar(totalPorts)

	// We use the full length of ports for the channel buffer size
	jobs := make(chan string, totalPorts)
	results := make(chan ScanResult, totalPorts) // Perf #7: results now carry scheme

	var wg sync.WaitGroup

	// Concurrency Limit
	workerCount := getConcurrencyLimit()
	if totalPorts < workerCount {
		workerCount = totalPorts
	}

	fmt.Printf("%s[*]%s Workers: %s%d%s", Cyan, Reset, Bold, workerCount, Reset)
	if *maxRPS > 0 {
		fmt.Printf(" | RPS limit: %s%d%s", Bold, *maxRPS, Reset)
	}
	fmt.Println()

	// 1. Start Workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				if checkForOpenPort(target, port) {
					results <- ScanResult{
						IP:   target,
						Port: port,
						// Scheme is detected later in detectAndFillSchemes
					}
				} else if *verbose {
					fmt.Printf("Port %s is closed on %s\n", port, target)
				}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// 2. Send Jobs (rate-limited if -rps is set)
	throttle, stopThrottle := newRPSThrottle()
	defer stopThrottle()
	for _, port := range ports {
		throttle()
		jobs <- port
	}
	close(jobs)

	// 3. The Closer Routine: Wait for workers to finish, then close the results channel.
	go func() {
		wg.Wait()
		close(results)
	}()

	// 4. Collect Results (Main Thread) — also write to open_ports_initial.txt
	fname := folderName + "/open_ports_initial.txt"
	file, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create open ports file: %v\n", Yellow, Reset, err)
	}

	var openPorts ScanResultList
	for r := range results {
		if file != nil {
			file.WriteString(fmt.Sprintf("%s:%s\n", r.IP, r.Port))
		}
		openPorts = append(openPorts, r)
	}

	if file != nil {
		file.Close()
	}

	return openPorts
}

// cloudflareSkipped tracks targets that were Cloudflare-detected and skipped.
var cloudflareSkipped []string

func probeTargets(targets []string, ports []string) ScanResultList {
	// --- Cloudflare pre-filter ---
	var filteredTargets []string
	for _, t := range targets {
		if isCloudflareIP(t) {
			cloudflareSkipped = append(cloudflareSkipped, t)
			if !*forceCFScan {
				// fmt.Printf("%s[!] Target '%s' belongs to Cloudflare → Skipping port scan.%s (use -force-cf to override)\n",
				// 	Yellow, t, Reset)
				continue
			}
			fmt.Printf("%s[!] Target '%s' belongs to Cloudflare → Force scanning enabled.%s\n",
				Yellow, t, Reset)
		}
		filteredTargets = append(filteredTargets, t)
	}

	if len(filteredTargets) == 0 {
		fmt.Printf("%s[!] All targets are Cloudflare IPs and were skipped.%s\n", Yellow, Reset)
		return ScanResultList{}
	}

	totalIps := len(filteredTargets)
	totalPorts := len(ports)

	maxtotalJobs := totalIps * totalPorts

	maxWorkers := getConcurrencyLimit()
	if maxtotalJobs < maxWorkers {
		maxWorkers = maxtotalJobs
	}

	type targetItem struct {
		IP   string
		Port string
	}

	jobs := make(chan targetItem, maxtotalJobs)
	results := make(chan ScanResult, maxtotalJobs) // Perf #7: carry scheme in result

	var wg sync.WaitGroup

	workerCount := maxWorkers

	fmt.Printf("%s[*]%s Workers: %s%d%s", Cyan, Reset, Bold, workerCount, Reset)
	if *maxRPS > 0 {
		fmt.Printf(" | RPS limit: %s%d%s", Bold, *maxRPS, Reset)
	}
	fmt.Println()

	bar := NewProgressBar(maxtotalJobs)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for itemX := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				if checkForOpenPort(itemX.IP, itemX.Port) {
					results <- ScanResult{
						IP:   itemX.IP,
						Port: itemX.Port,
						// Scheme is detected later in detectAndFillSchemes
					}
				} else if *verbose {
					fmt.Printf("Port %s is closed on %s\n", itemX.Port, itemX.IP)
				}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// Send jobs (rate-limited if -rps is set)
	throttle, stopThrottle := newRPSThrottle()
	defer stopThrottle()
	for _, target := range filteredTargets {
		for _, port := range ports {
			throttle()
			jobs <- targetItem{IP: target, Port: port}
		}
	}

	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts ScanResultList

	fname := folderName + "/open_ports_initial.txt"
	file, err := os.Create(fname)
	if err != nil {
		fmt.Printf("%s[!] Error:%s Failed to create open ports file: %v\n", Red, Reset, err)
	}

	for r := range results {
		if isProgressBarCompleted {
			fmt.Printf("\r%s%s [*] %sWaiting for all goroutines to complete: %s[%d] left%s   ",
				Cyan, Bold,
				Reset,
				Red,
				len(results),
				Reset,
			)
		}
		if file != nil {
			line := fmt.Sprintf("%s:%s\n", r.IP, r.Port)
			file.WriteString(line)
		}
		openPorts = append(openPorts, r)
	}

	if file != nil {
		file.Close()
	}

	fmt.Println()

	return openPorts
}

// doHTTPRequestWithRetry wraps client.Do with retry logic and exponential backoff.
// Only retries on transport-level errors (timeouts, connection refused), not HTTP status errors.
func doHTTPRequestWithRetry(client *http.Client, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	retries := *maxRetries
	if retries < 0 {
		retries = 0
	}

	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}

		// Don't retry on the last attempt
		if attempt < retries {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if *verbose {
				fmt.Printf("\n%s[!] Retry %d/%d%s for %s (backoff %v): %v\n",
					Yellow, attempt+1, retries, Reset, req.URL.String(), backoff, err)
			}
			time.Sleep(backoff)

			// Rebuild request (body may have been consumed)
			newReq, cloneErr := http.NewRequest(req.Method, req.URL.String(), nil)
			if cloneErr != nil {
				return nil, err
			}
			newReq.Header = req.Header
			req = newReq
		}
	}

	return nil, err
}

func getResponse(item ScanResult) ResponseResult {
	var outx ResponseResult

	outx.TargetData = item

	// If scheme is still empty, try to detect it now as a last-resort fallback
	if len(item.Scheme) < 1 {
		item.Scheme = detectScheme(item.IP, item.Port)
		outx.TargetData = item
	}

	if len(item.Scheme) < 1 {
		// Truly no HTTP/HTTPS service on this port — skip
		return outx
	}

	InitialURI := fmt.Sprintf("%s://%s:%s", item.Scheme, item.IP, item.Port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(*time_out) * time.Second,
	}

	req, err := http.NewRequest("GET", InitialURI, nil)
	if err != nil {
		return outx
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := doHTTPRequestWithRetry(client, req)
	if err != nil {
		return outx
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return outx
	}

	// --- HTTP → HTTPS auto-handling ---
	if resp.StatusCode == 400 && strings.Contains(string(body), "The plain HTTP request was sent to HTTPS") {
		if *verbose {
			fmt.Printf("\n%s[!] HTTP→HTTPS:%s %s — retrying with HTTPS\n", Yellow, Reset, InitialURI)
		}
		resp.Body.Close()

		item.Scheme = "https"
		outx.TargetData = item
		InitialURI = fmt.Sprintf("https://%s:%s", item.IP, item.Port)

		req2, err2 := http.NewRequest("GET", InitialURI, nil)
		if err2 != nil {
			return outx
		}
		req2.Header.Set("User-Agent", getRandomUserAgent())

		resp2, err2 := doHTTPRequestWithRetry(client, req2)
		if err2 != nil {
			return outx
		}
		defer resp2.Body.Close()

		body, err = io.ReadAll(resp2.Body)
		if err != nil {
			return outx
		}
		resp = resp2
	}

	targetRedirect := ""
	if resp.Request.URL.String() != "" {
		targetRedirect = resp.Request.URL.String()
	}

	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	page_title := ""
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		page_title = matches[1]
	}

	// Bug #6: Use cached header config instead of re-reading file on every response
	v := reflect.ValueOf(cachedHeaderConfig)
	t := v.Type()

	// foundAny := false

	for i := 0; i < v.NumField(); i++ {

		var recx ReconInfo

		field := v.Field(i)

		CategoryName := t.Field(i).Name
		if t.Field(i).Name == "WebServer" {
			CategoryName = "Web Server"
		} else if t.Field(i).Name == "FrameworkRuntime" {
			CategoryName = "Framework / Runtime"
		} else if t.Field(i).Name == "WafSecurity" {
			CategoryName = "WAF / Security"
		} else if t.Field(i).Name == "CDNReverseProxyCloud" {
			CategoryName = "CDN / Reverse Proxy / Cloud"
		} else if t.Field(i).Name == "CacheOptimization" {
			CategoryName = "Cache / Optimization"
		} else if t.Field(i).Name == "HostingPlatform" {
			CategoryName = "Hosting Platform"
		} else if t.Field(i).Name == "ApplicationInternal" {
			CategoryName = "Internal / Application Metadata"
		} else if t.Field(i).Name == "CMS" {
			CategoryName = "CMS"
		} else if t.Field(i).Name == "EnterpriseBusinessApps" {
			CategoryName = "Enterprise / Business Apps"
		} else if t.Field(i).Name == "AnalyticsMarketingTesting" {
			CategoryName = "Analytics / Marketing / Testing"
		} else if t.Field(i).Name == "CulturalMisc" {
			CategoryName = "Cultural / Misc"
		}

		recx.CategoryID = t.Field(i).Name
		recx.CategoryName = CategoryName

		// Ensure the field is a slice (which they all are in your struct)
		if field.Kind() == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				item := field.Index(j).Interface().(HeaderPurpose)

				// 3. Check if the header exists in the Response
				if val := resp.Header.Get(item.Header); val != "" {

					recx.HeaderName = item.Header
					recx.HeaderValue = val
					recx.Purpose = item.Purpose

					outx.ReconInfo = append(outx.ReconInfo, recx)
				}
			}
		}
	}

	outx.PageTitle = page_title
	outx.InitialURI = InitialURI
	outx.RedirectURi = targetRedirect
	outx.StatusCode = strconv.Itoa(resp.StatusCode)
	outx.ContentType = resp.Header.Get("Content-Type")
	outx.Server = resp.Header.Get("Server")
	outx.ContentLength = resp.Header.Get("Content-Length")

	return outx
}

func probeAllResponses(openPorts ScanResultList) ResponseResultList {
	var wg sync.WaitGroup

	// Perf #8: Use a capped worker pool instead of unbounded goroutines
	jobs := make(chan ScanResult, len(openPorts))
	results := make(chan ResponseResult, len(openPorts))

	bar := NewProgressBar(len(openPorts))

	workerCount := getConcurrencyLimit()
	if len(openPorts) < workerCount {
		workerCount = len(openPorts)
	}

	// Start fixed number of workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				x := getResponse(p)
				results <- x
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// Send jobs (rate-limited if -rps is set)
	throttle, stopThrottle := newRPSThrottle()
	defer stopThrottle()
	for _, port := range openPorts {
		throttle()
		jobs <- port
	}
	close(jobs)

	// Close channel once all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	resp := ResponseResultList{}
	for r := range results {
		resp = append(resp, r)
	}

	return resp
}

// detectAndFillSchemes runs scheme detection concurrently on all open ports.
// This is separated from port scanning so that port scanning stays fast (TCP-only).
// Scheme detection (TLS handshake + HTTP GET) is only performed on the
// relatively small number of open ports, not all ports.
func detectAndFillSchemes(openPorts ScanResultList) ScanResultList {
	total := len(openPorts)
	if total == 0 {
		return openPorts
	}

	bar := NewProgressBar(total)

	type schemeJob struct {
		Idx  int
		Item ScanResult
	}
	type schemeResult struct {
		Idx    int
		Scheme string
	}

	jobs := make(chan schemeJob, total)
	results := make(chan schemeResult, total)

	var wg sync.WaitGroup

	workerCount := getConcurrencyLimit()
	if total < workerCount {
		workerCount = total
	}

	fmt.Printf("%s[*]%s Scheme detection workers: %s%d%s\n", Cyan, Reset, Bold, workerCount, Reset)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				scheme := detectScheme(job.Item.IP, job.Item.Port)
				results <- schemeResult{Idx: job.Idx, Scheme: scheme}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// Send jobs
	for idx, item := range openPorts {
		jobs <- schemeJob{Idx: idx, Item: item}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and fill in schemes
	for r := range results {
		openPorts[r.Idx].Scheme = r.Scheme
	}

	return openPorts
}

// fuzzPaths probes each discovered target with a list of paths.
// Only keeps 2xx, 3xx, and 403 responses.
// When a 403 is encountered, automatically tries bypass techniques.
// Performs wildcard baseline detection to filter false positives.
func fuzzPaths(results ResponseResultList, paths []string) ResponseResultList {
	if len(paths) == 0 {
		return results
	}

	// Count how many targets have a valid scheme
	validTargets := 0
	for _, r := range results {
		if len(r.TargetData.Scheme) > 0 {
			validTargets++
		}
	}

	if validTargets == 0 {
		return results
	}

	// --- Wildcard Baseline Detection ---
	// Send a canary request with a random path to each target.
	// If it returns 200, record status + content-length as the baseline.
	// Responses matching the baseline are likely custom 404 pages → filter them.
	type baseline struct {
		statusCode    int
		contentLength int64
	}
	baselines := make(map[int]baseline) // keyed by result index

	fmt.Printf("%s[*]%s Running wildcard baseline detection on %s%d%s targets...\n",
		Cyan, Reset, Bold, validTargets, Reset)

	bar := NewProgressBar(validTargets)

	baselineClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(*time_out) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type baselineJob struct {
		Idx     int
		BaseURL string
	}
	type baselineOut struct {
		Idx     int
		Status  int
		BodyLen int64
		Found   bool
	}

	// Collect jobs
	var blJobs []baselineJob
	for idx, r := range results {
		if len(r.TargetData.Scheme) < 1 {
			continue
		}
		baseURL := fmt.Sprintf("%s://%s:%s", r.TargetData.Scheme, r.TargetData.IP, r.TargetData.Port)
		blJobs = append(blJobs, baselineJob{Idx: idx, BaseURL: baseURL})
	}

	blJobsCh := make(chan baselineJob, len(blJobs))
	blOutsCh := make(chan baselineOut, len(blJobs))

	var blWg sync.WaitGroup
	blWorkers := getConcurrencyLimit()
	if len(blJobs) < blWorkers {
		blWorkers = len(blJobs)
	}

	for i := 0; i < blWorkers; i++ {
		blWg.Add(1)
		go func() {
			defer blWg.Done()
			for job := range blJobsCh {
				atomic.AddInt64(&activeGoroutines, 1)

				canaryPath := fmt.Sprintf("this-path-should-never-exist-%d-%d", rand.Intn(999999), rand.Intn(999999))
				req, err := http.NewRequest("GET", job.BaseURL+"/"+canaryPath, nil)
				if err != nil {
					blOutsCh <- baselineOut{Idx: job.Idx, Found: false}
					atomic.AddInt64(&activeGoroutines, -1)
					bar.Update(1)
					continue
				}
				req.Header.Set("User-Agent", getRandomUserAgent())

				resp, err := baselineClient.Do(req)
				if err != nil {
					blOutsCh <- baselineOut{Idx: job.Idx, Found: false}
					atomic.AddInt64(&activeGoroutines, -1)
					bar.Update(1)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if resp.StatusCode > 0 {
					blOutsCh <- baselineOut{Idx: job.Idx, Status: resp.StatusCode, BodyLen: int64(len(body)), Found: true}
					if *verbose {
						fmt.Printf("\n%s  [!]%s Wildcard detected on %s%s%s (status %d, ~%d bytes) → auto-filtering",
							Yellow, Reset, Bold, job.BaseURL, Reset, resp.StatusCode, len(body))
					}
				} else {
					blOutsCh <- baselineOut{Idx: job.Idx, Found: false}
				}

				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	for _, j := range blJobs {
		blJobsCh <- j
	}
	close(blJobsCh)

	go func() {
		blWg.Wait()
		close(blOutsCh)
	}()

	for o := range blOutsCh {
		if o.Found {
			baselines[o.Idx] = baseline{
				statusCode:    o.Status,
				contentLength: o.BodyLen,
			}
		}
	}

	fmt.Println()

	totalJobs := validTargets * len(paths)
	fmt.Printf("%s[*]%s Fuzzing %s%d%s paths across %s%d%s targets (%d total requests)...\n",
		Cyan, Reset, Bold, len(paths), Reset, Bold, validTargets, Reset, totalJobs)

	type fuzzJob struct {
		ResultIdx int
		BaseURL   string
		Path      string
	}

	type fuzzOut struct {
		ResultIdx int
		Result    FuzzResult
	}

	jobs := make(chan fuzzJob, totalJobs)
	resultsCh := make(chan fuzzOut, totalJobs)

	var wg sync.WaitGroup

	workerCount := getConcurrencyLimit()
	if totalJobs < workerCount {
		workerCount = totalJobs
	}

	bar = NewProgressBar(totalJobs)

	// Track wildcard-filtered count per target (thread-safe)
	var filteredCount int64

	// Workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(*time_out) * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // don't follow redirects
				},
			}

			for job := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)

				path := strings.TrimLeft(job.Path, "/")
				fullURL := job.BaseURL + "/" + path

				req, err := http.NewRequest("GET", fullURL, nil)
				if err != nil {
					atomic.AddInt64(&activeGoroutines, -1)
					bar.Update(1)
					continue
				}
				req.Header.Set("User-Agent", getRandomUserAgent())

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&activeGoroutines, -1)
					bar.Update(1)
					continue
				}

				// Read body to get accurate content length for baseline comparison
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				statusCode := resp.StatusCode
				bodyLen := int64(len(body))
				clHeader := resp.Header.Get("Content-Length")
				if clHeader == "" {
					clHeader = strconv.FormatInt(bodyLen, 10)
				}

				// --- Wildcard filter: skip if response matches baseline ---
				if bl, ok := baselines[job.ResultIdx]; ok {
					if statusCode == bl.statusCode {
						// Content-length within ±10% of baseline → likely the same catch-all page
						margin := bl.contentLength / 10
						if margin < 50 {
							margin = 50 // minimum margin of 50 bytes
						}
						if bodyLen >= bl.contentLength-margin && bodyLen <= bl.contentLength+margin {
							atomic.AddInt64(&filteredCount, 1)
							atomic.AddInt64(&activeGoroutines, -1)
							bar.Update(1)
							continue
						}
					}
				}

				// If 403, attempt bypass techniques
				if statusCode == 403 {
					bypassResult := try403Bypass(client, job.BaseURL, path)
					if bypassResult != nil {
						resultsCh <- fuzzOut{
							ResultIdx: job.ResultIdx,
							Result:    *bypassResult,
						}
					} else {
						// Report the original 403 as-is
						resultsCh <- fuzzOut{
							ResultIdx: job.ResultIdx,
							Result: FuzzResult{
								Path:          "/" + path,
								StatusCode:    403,
								ContentLength: clHeader,
							},
						}
					}
					atomic.AddInt64(&activeGoroutines, -1)
					bar.Update(1)
					continue
				}

				// Keep 2xx and 3xx
				keep := statusCode >= 200 && statusCode < 400

				if keep {
					redirectURL := ""
					if loc := resp.Header.Get("Location"); loc != "" {
						redirectURL = loc
					}
					resultsCh <- fuzzOut{
						ResultIdx: job.ResultIdx,
						Result: FuzzResult{
							Path:          "/" + path,
							StatusCode:    statusCode,
							ContentLength: clHeader,
							RedirectURL:   redirectURL,
						},
					}
				}

				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// Send jobs (rate-limited if -rps is set)
	throttle, stopThrottle := newRPSThrottle()
	defer stopThrottle()
	for idx, r := range results {
		if len(r.TargetData.Scheme) < 1 {
			continue
		}
		baseURL := fmt.Sprintf("%s://%s:%s", r.TargetData.Scheme, r.TargetData.IP, r.TargetData.Port)
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			throttle()
			jobs <- fuzzJob{ResultIdx: idx, BaseURL: baseURL, Path: p}
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect
	for fr := range resultsCh {
		results[fr.ResultIdx].PathResults = append(results[fr.ResultIdx].PathResults, fr.Result)
	}

	if fc := atomic.LoadInt64(&filteredCount); fc > 0 && *verbose {
		fmt.Printf("\n%s[*]%s Wildcard filter suppressed %s%d%s false-positive responses\n", Cyan, Reset, Bold, fc, Reset)
	}
	fmt.Println()
	return results
}

// try403Bypass attempts multiple 403 bypass techniques on a path.
// Returns a FuzzResult if any bypass succeeds (non-403 response), nil otherwise.
// Uses its own redirect-following client to properly validate if a bypass
// actually reaches the resource (the fuzz worker's client blocks redirects).
func try403Bypass(client *http.Client, baseURL string, path string) *FuzzResult {
	// Create a dedicated client that FOLLOWS redirects so we can see the
	// final status code. The fuzz worker's client has CheckRedirect =
	// ErrUseLastResponse which would make 3xx look like bypass successes.
	bypassClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: client.Timeout,
		// Default redirect policy — follows up to 10 redirects
	}

	// isBypassSuccess checks if the final status is a real bypass:
	// - Must not be 403 (the status we're trying to bypass)
	// - Must not be other 4xx/5xx errors (those aren't useful bypasses)
	// - 2xx = success, 3xx with Location = interesting redirect worth reporting
	isBypassSuccess := func(statusCode int) bool {
		return statusCode >= 200 && statusCode < 400 && statusCode != 403
	}

	fullURL := baseURL + "/" + path

	// --- Technique 1: Header-based bypasses (IP spoofing headers) ---
	ipBypassHeaders := []struct {
		header string
		value  string
	}{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"X-Originating-IP", "127.0.0.1"},
		{"X-Remote-IP", "127.0.0.1"},
		{"X-Remote-Addr", "127.0.0.1"},
		{"X-ProxyUser-Ip", "127.0.0.1"},
		{"Client-IP", "127.0.0.1"},
		{"X-Client-IP", "127.0.0.1"},
		{"X-Host", "127.0.0.1"},
		{"X-Forwarded-Host", "127.0.0.1"},
	}

	for _, h := range ipBypassHeaders {
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set(h.header, h.value)

		resp, err := bypassClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if isBypassSuccess(resp.StatusCode) {
			cl := resp.Header.Get("Content-Length")
			if cl == "" {
				cl = strconv.Itoa(len(body))
			}
			return &FuzzResult{
				Path:          "/" + path,
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				RedirectURL:   resp.Request.URL.String(),
				BypassMethod:  fmt.Sprintf("header: %s: %s", h.header, h.value),
			}
		}
	}

	// --- Technique 1b: X-Original-URL / X-Rewrite-URL (IIS/Nginx path override) ---
	// These headers override the path on the backend. The correct technique is
	// to request the ROOT "/" and set the header to the target path.
	for _, hdr := range []string{"X-Original-URL", "X-Rewrite-URL"} {
		rootURL := baseURL + "/"
		req, err := http.NewRequest("GET", rootURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set(hdr, "/"+path)

		resp, err := bypassClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if isBypassSuccess(resp.StatusCode) {
			cl := resp.Header.Get("Content-Length")
			if cl == "" {
				cl = strconv.Itoa(len(body))
			}
			return &FuzzResult{
				Path:          "/" + path,
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				RedirectURL:   resp.Request.URL.String(),
				BypassMethod:  fmt.Sprintf("header: %s: /%s", hdr, path),
			}
		}
	}

	// --- Technique 2: HTTP method bypass ---
	for _, method := range []string{"POST", "PUT", "PATCH", "OPTIONS", "TRACE"} {
		req, err := http.NewRequest(method, fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := bypassClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if isBypassSuccess(resp.StatusCode) {
			cl := resp.Header.Get("Content-Length")
			if cl == "" {
				cl = strconv.Itoa(len(body))
			}
			return &FuzzResult{
				Path:          "/" + path,
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				RedirectURL:   resp.Request.URL.String(),
				BypassMethod:  fmt.Sprintf("method: %s", method),
			}
		}
	}

	// --- Technique 3: Path mutation bypasses ---
	pathMutations := []struct {
		mutated string
		label   string
	}{
		{path + "/", "trailing slash"},
		{path + "/*", "wildcard /*"},
		{path + "/.", "trailing /."},
		{path + ";/", "semicolon ;/"},
		{path + "/..;/", "dot-dot-semicolon /..;/"},
		{"/" + path + "//", "double slash //"},
		{"//" + path + "//", "// prefix+suffix"},
		{"///" + path + "///", "triple slash ///"},
		{"./" + path + "/./", "dot-slash ./"},
		{"%2f" + path + "%2f", "URL-encoded %2f"},
		{path + "%20", "space %20"},
		{path + "%09", "tab %09"},
		{path + "..;/", "..;/ suffix"},
		{strings.ToUpper(path), "UPPERCASE"},
	}

	for _, pm := range pathMutations {
		mutURL := baseURL + "/" + strings.TrimLeft(pm.mutated, "/")

		req, err := http.NewRequest("GET", mutURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := bypassClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if isBypassSuccess(resp.StatusCode) {
			cl := resp.Header.Get("Content-Length")
			if cl == "" {
				cl = strconv.Itoa(len(body))
			}
			return &FuzzResult{
				Path:          "/" + pm.mutated,
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				RedirectURL:   resp.Request.URL.String(),
				BypassMethod:  fmt.Sprintf("path: %s", pm.label),
			}
		}
	}

	return nil
}

// SaveCSV writes scan results (and path fuzz results) to a CSV file.
func SaveCSV(results ResponseResultList) error {
	fname := folderName + "/results.csv"
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	// Header
	header := []string{"target", "port", "scheme", "status_code", "content_type",
		"content_length", "page_title", "server", "redirect_location",
		"cname", "ptr", "ssl_cn", "ssl_sans",
		"recon_info", "discovered_paths"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		// Build recon summary
		var reconParts []string
		for _, info := range r.ReconInfo {
			reconParts = append(reconParts, fmt.Sprintf("%s: %s=%s", info.CategoryName, info.HeaderName, info.HeaderValue))
		}
		reconStr := strings.Join(reconParts, "; ")

		// Build paths summary
		var pathParts []string
		for _, pr := range r.PathResults {
			entry := fmt.Sprintf("%s [%d]", pr.Path, pr.StatusCode)
			if pr.BypassMethod != "" {
				entry += " BYPASS(" + pr.BypassMethod + ")"
			}
			if pr.RedirectURL != "" {
				entry += " -> " + pr.RedirectURL
			}
			pathParts = append(pathParts, entry)
		}
		pathsStr := strings.Join(pathParts, "; ")

		row := []string{
			r.TargetData.IP,
			r.TargetData.Port,
			r.TargetData.Scheme,
			r.StatusCode,
			r.ContentType,
			r.ContentLength,
			r.PageTitle,
			r.Server,
			r.RedirectURi,
			r.CNAME,
			r.PTR,
			r.SSLCommonName,
			strings.Join(r.SSLSANs, "; "),
			reconStr,
			pathsStr,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// createOutputFolder creates the output directory.
// Returns (isResume, ok).
//   - If the folder doesn't exist: creates it, returns (false, true)
//   - If the folder exists AND has .resume.json: returns (true, true) — resume mode
//   - If the folder exists WITHOUT .resume.json: starts fresh in that folder (false, true)
func createOutputFolder() (bool, bool) {
	_, err := os.Stat(folderName)
	if err == nil {
		// Folder exists — check for resume file
		_, stErr := os.Stat(resumePath(folderName))
		if stErr == nil {
			// .resume.json exists → resume mode
			return true, true
		}
		// Folder exists but no resume file → previous scan was interrupted
		// before any phase completed, or scan finished normally. Start fresh.
		fmt.Printf("%s[*]%s Output folder '%s' exists (no resume state) → starting fresh scan\n",
			Cyan, Reset, folderName)
		return false, true
	}

	// Folder doesn't exist — create it
	if mkErr := os.MkdirAll(folderName, 0755); mkErr != nil {
		fmt.Printf("%s[!] Error:%s Failed to create output folder: %v\n", Red, Reset, mkErr)
		return false, false
	}
	return false, true
}

func SaveReport(results ResponseResultList) (string, error) {

	html, err := GenerateHTMLReport(results)
	if err != nil {
		return "", err
	}

	fname := folderName + "/output_report.html"
	if err := os.WriteFile(fname, []byte(html), 0644); err != nil {
		return "", err
	}

	fnameTxt := folderName + "/output_urls.txt"
	file, err := os.Create(fnameTxt)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, x := range results {
		if len(x.TargetData.Scheme) < 1 {
			continue
		}
		p := x.TargetData
		line := fmt.Sprintf("%s://%s:%s\n", p.Scheme, p.IP, p.Port)
		writer.WriteString(line)
	}

	writer.Flush()

	return folderName, nil
}

func printStdout(results ResponseResultList) {
	fmt.Printf("\n%s=== SCAN RESULTS ===%s\n", Bold, Reset)
	for _, x := range results {
		p := x.TargetData

		// Colorize Status Code (Green 2xx, Yellow 3xx, Red 4xx/5xx)
		statusColor := Green
		if len(x.StatusCode) > 0 {
			if x.StatusCode[0] == '3' {
				statusColor = Yellow
			}
			if x.StatusCode[0] == '4' || x.StatusCode[0] == '5' {
				statusColor = Red
			}
		}

		fmt.Println("------------------------------------------------------------")
		fmt.Printf("%s➤ TARGET:%s %s://%s:%s\n", Cyan, Reset, p.Scheme, p.IP, p.Port)
		fmt.Println("------------------------------------------------------------")

		fmt.Printf(" %s• Title         :%s %s\n", Bold, Reset, x.PageTitle)
		fmt.Printf(" %s• Status Code   :%s %s%s%s\n", Bold, Reset, statusColor, x.StatusCode, Reset)
		fmt.Printf(" %s• Server        :%s %s\n", Bold, Reset, x.Server)
		fmt.Printf(" %s• Content Type  :%s %s\n", Bold, Reset, x.ContentType)
		fmt.Printf(" %s• Content Len   :%s %s\n", Bold, Reset, x.ContentLength)
		fmt.Printf(" %s• Initial URI   :%s %s\n", Bold, Reset, x.InitialURI)

		if x.RedirectURi != "" {
			fmt.Printf(" %s• Redirect URI  :%s %s\n", Yellow, Reset, x.RedirectURi)
		}

		// --- DNS / SSL enrichment ---
		if x.CNAME != "" {
			fmt.Printf(" %s• CNAME         :%s %s%s%s\n", Bold, Reset, Cyan, x.CNAME, Reset)
		}
		if x.PTR != "" {
			fmt.Printf(" %s• PTR (rDNS)    :%s %s%s%s\n", Bold, Reset, Cyan, x.PTR, Reset)
		}
		if x.SSLCommonName != "" {
			fmt.Printf(" %s• SSL CN        :%s %s%s%s\n", Bold, Reset, Cyan, x.SSLCommonName, Reset)
		}
		if len(x.SSLSANs) > 0 {
			fmt.Printf(" %s• SSL SANs      :%s %s%s%s\n", Bold, Reset, Cyan, strings.Join(x.SSLSANs, ", "), Reset)
		}

		if len(x.ReconInfo) > 0 {
			fmt.Printf("\n %s[ Recon Information ]%s\n", Yellow, Reset)
			for _, info := range x.ReconInfo {
				fmt.Printf("   %s+%s [%s] %s: %s%s%s (%s)\n",
					Red, Reset,
					info.CategoryName,
					info.HeaderName,
					Cyan, info.HeaderValue, Reset,
					info.Purpose,
				)
			}
		}

		if len(x.PathResults) > 0 {
			fmt.Printf("\n %s[ Discovered Paths ]%s\n", Yellow, Reset)
			for _, pr := range x.PathResults {
				sc := Green
				if pr.StatusCode >= 300 && pr.StatusCode < 400 {
					sc = Yellow
				} else if pr.StatusCode == 403 {
					sc = Red
				}
				line := fmt.Sprintf("   %s+%s %s%d%s %s", Red, Reset, sc, pr.StatusCode, Reset, pr.Path)
				if pr.BypassMethod != "" {
					line += fmt.Sprintf(" %s[BYPASS: %s]%s", Green, pr.BypassMethod, Reset)
				}
				if pr.RedirectURL != "" {
					line += fmt.Sprintf(" %s→%s %s", Yellow, Reset, pr.RedirectURL)
				}
				if pr.ContentLength != "" {
					line += fmt.Sprintf(" [%s]", pr.ContentLength)
				}
				fmt.Println(line)
			}
		}
		fmt.Println()
	}
}

// enrichResults concurrently resolves CNAME, PTR, and extracts SSL cert info
// for each result. It also writes Cloudflare IPs to cloudflare_ips.txt.
func enrichResults(results ResponseResultList) ResponseResultList {
	if len(results) == 0 {
		return results
	}

	fmt.Printf("%s[*]%s Enriching %s%d%s results (CNAME, PTR, SSL)...\n", Cyan, Reset, Bold, len(results), Reset)

	bar := NewProgressBar(len(results))

	type enrichJob struct {
		Idx int
		R   ResponseResult
	}
	type enrichOut struct {
		Idx           int
		CNAME         string
		PTR           string
		SSLCommonName string
		SSLSANs       []string
	}

	jobs := make(chan enrichJob, len(results))
	outs := make(chan enrichOut, len(results))

	var wg sync.WaitGroup

	workerCount := getConcurrencyLimit()
	if len(results) < workerCount {
		workerCount = len(results)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)

				cname, ptr := resolveTarget(job.R.TargetData.IP)

				var cn string
				var sans []string
				if job.R.TargetData.Scheme == "https" || job.R.TargetData.Port == "443" {
					cn, sans = extractSSLCertInfo(job.R.TargetData.IP, job.R.TargetData.Port)
				}

				outs <- enrichOut{
					Idx:           job.Idx,
					CNAME:         cname,
					PTR:           ptr,
					SSLCommonName: cn,
					SSLSANs:       sans,
				}

				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	for idx, r := range results {
		jobs <- enrichJob{Idx: idx, R: r}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(outs)
	}()

	for o := range outs {
		results[o.Idx].CNAME = o.CNAME
		results[o.Idx].PTR = o.PTR
		results[o.Idx].SSLCommonName = o.SSLCommonName
		results[o.Idx].SSLSANs = o.SSLSANs
	}

	fmt.Println()
	return results
}

// sortResults sorts the results so 2xx status codes come first.
func sortResults(results ResponseResultList) ResponseResultList {
	sort.SliceStable(results, func(i, j int) bool {
		si, _ := strconv.Atoi(results[i].StatusCode)
		sj, _ := strconv.Atoi(results[j].StatusCode)
		iIs2xx := si >= 200 && si < 300
		jIs2xx := sj >= 200 && sj < 300
		if iIs2xx && !jIs2xx {
			return true
		}
		if !iIs2xx && jIs2xx {
			return false
		}
		return si < sj
	})
	return results
}

// recheckEmptyResults re-probes open ports that returned no meaningful data.
// Returns the updated results and a list of indices that were re-checked.
func recheckEmptyResults(results ResponseResultList) (ResponseResultList, []int) {
	var toRecheck []int
	for i, r := range results {
		if r.StatusCode == "" && len(r.TargetData.Scheme) > 0 {
			toRecheck = append(toRecheck, i)
		}
	}

	if len(toRecheck) == 0 {
		return results, nil
	}

	fmt.Printf("%s[*]%s Re-checking %s%d%s ports with no data...\n", Cyan, Reset, Bold, len(toRecheck), Reset)

	bar := NewProgressBar(len(toRecheck))

	type recheckJob struct {
		ResultIdx int
		Item      ScanResult
	}
	type recheckOut struct {
		ResultIdx int
		Result    ResponseResult
		Success   bool
	}

	jobs := make(chan recheckJob, len(toRecheck))
	outs := make(chan recheckOut, len(toRecheck))

	var wg sync.WaitGroup

	workerCount := getConcurrencyLimit()
	if len(toRecheck) < workerCount {
		workerCount = len(toRecheck)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)

				item := job.Item
				// Re-detect scheme
				item.Scheme = detectScheme(item.IP, item.Port)
				if len(item.Scheme) > 0 {
					newResult := getResponse(item)
					if newResult.StatusCode != "" {
						newResult.Rechecked = true
						if *verbose {
							fmt.Printf("\n%s  [+] Re-check success:%s %s:%s → %s",
								Green, Reset, item.IP, item.Port, newResult.StatusCode)
						}
						outs <- recheckOut{ResultIdx: job.ResultIdx, Result: newResult, Success: true}
						atomic.AddInt64(&activeGoroutines, -1)
						bar.Update(1)
						continue
					}
				}
				outs <- recheckOut{ResultIdx: job.ResultIdx, Success: false}

				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	for _, idx := range toRecheck {
		jobs <- recheckJob{ResultIdx: idx, Item: results[idx].TargetData}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(outs)
	}()

	var recheckedIndices []int
	for o := range outs {
		recheckedIndices = append(recheckedIndices, o.ResultIdx)
		if o.Success {
			results[o.ResultIdx] = o.Result
		}
	}

	fmt.Println()
	return results, recheckedIndices
}

// writeCloudflareIPs writes detected Cloudflare IPs to cloudflare_ips.txt.
func writeCloudflareIPs(cfIPs []string) {
	if len(cfIPs) == 0 {
		return
	}
	fname := folderName + "/cloudflare_ips.txt"
	file, err := os.Create(fname)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create cloudflare_ips.txt: %v\n", Yellow, Reset, err)
		return
	}
	defer file.Close()
	for _, ip := range cfIPs {
		file.WriteString(ip + "\n")
	}
	fmt.Printf("%s[✓] Cloudflare IPs saved to: %s ./%s/cloudflare_ips.txt\n", Green, Reset, folderName)
}

// --- Self-Update Logic ---

// ghRelease mirrors the subset of the GitHub releases/latest JSON we need.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func runSelfUpdate() {
	// 1. Resolve the installed binary path.
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("%s[!] Error:%s Could not determine executable path: %v\n", Red, Reset, err)
		os.Exit(1)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		fmt.Printf("%s[!] Error:%s Could not resolve symlinks: %v\n", Red, Reset, err)
		os.Exit(1)
	}

	fmt.Printf("%s[*]%s Installed binary : %s%s%s\n", Cyan, Reset, Bold, exePath, Reset)
	fmt.Printf("%s[*]%s Current version  : %s%s%s\n", Cyan, Reset, Bold, version, Reset)
	fmt.Printf("%s[*]%s Platform        : %s%s/%s%s\n", Cyan, Reset, Bold, runtime.GOOS, runtime.GOARCH, Reset)

	// 2. Fetch latest release metadata from GitHub.
	const apiURL = "https://api.github.com/repos/captain-noob/wScanner/releases/latest"

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Printf("%s[!] Error:%s %v\n", Red, Reset, err)
		os.Exit(1)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[!] Error:%s Could not reach GitHub API: %v\n", Red, Reset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] Error:%s GitHub API returned status %d\n", Red, Reset, resp.StatusCode)
		os.Exit(1)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Printf("%s[!] Error:%s Failed to parse release JSON: %v\n", Red, Reset, err)
		os.Exit(1)
	}

	fmt.Printf("%s[*]%s Latest release   : %s%s%s\n", Cyan, Reset, Bold, release.TagName, Reset)

	// 3. Check if already up to date.
	//    The tag may or may not contain the full version string; do a contains check.
	if strings.Contains(release.TagName, version) || strings.Contains(version, release.TagName) {
		fmt.Printf("%s[✓] Already up to date!%s\n", Green, Reset)
		return
	}

	// 4. Find the matching asset for this OS/ARCH.
	needle := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	var assetName string
	for _, a := range release.Assets {
		if strings.Contains(a.Name, needle) {
			downloadURL = a.BrowserDownloadURL
			assetName = a.Name
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("%s[!] Error:%s No release asset found for %s/%s\n", Red, Reset, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("    Available assets:\n")
		for _, a := range release.Assets {
			fmt.Printf("      - %s\n", a.Name)
		}
		os.Exit(1)
	}

	fmt.Printf("%s[+]%s Downloading %s%s%s ...\n", Cyan, Reset, Bold, assetName, Reset)

	// 5. Download the asset to a temp file in the same directory.
	dlResp, err := http.Get(downloadURL)
	if err != nil {
		fmt.Printf("%s[!] Error:%s Download failed: %v\n", Red, Reset, err)
		os.Exit(1)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		fmt.Printf("%s[!] Error:%s Download returned status %d\n", Red, Reset, dlResp.StatusCode)
		os.Exit(1)
	}

	// Write to temp file in the same dir so rename works (same filesystem).
	tmpPath := exePath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		fmt.Printf("%s[!] Error:%s Could not create temp file: %v\n", Red, Reset, err)
		fmt.Printf("    (Hint: you may need to run with elevated privileges)\n")
		os.Exit(1)
	}

	_, err = io.Copy(tmpFile, dlResp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		fmt.Printf("%s[!] Error:%s Failed to write downloaded binary: %v\n", Red, Reset, err)
		os.Exit(1)
	}

	// 6. Replace the installed binary.
	if runtime.GOOS == "windows" {
		// Windows locks the running executable, so rename-away first.
		oldPath := exePath + ".old"
		os.Remove(oldPath) // remove stale .old if present
		if err := os.Rename(exePath, oldPath); err != nil {
			os.Remove(tmpPath)
			fmt.Printf("%s[!] Error:%s Could not rename old binary: %v\n", Red, Reset, err)
			os.Exit(1)
		}
		if err := os.Rename(tmpPath, exePath); err != nil {
			// Attempt rollback
			os.Rename(oldPath, exePath)
			os.Remove(tmpPath)
			fmt.Printf("%s[!] Error:%s Could not install new binary: %v\n", Red, Reset, err)
			os.Exit(1)
		}
		os.Remove(oldPath)
	} else {
		// Unix: set executable bit, then atomic rename.
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			fmt.Printf("%s[!] Error:%s Could not set permissions: %v\n", Red, Reset, err)
			os.Exit(1)
		}
		if err := os.Rename(tmpPath, exePath); err != nil {
			os.Remove(tmpPath)
			fmt.Printf("%s[!] Error:%s Could not replace binary: %v\n", Red, Reset, err)
			fmt.Printf("    (Hint: try running with sudo)\n")
			os.Exit(1)
		}
	}

	fmt.Printf("%s[✓] Updated successfully!%s  %s → %s\n", Green, Reset, version, release.TagName)
}

// saveFuzzingResults writes all path fuzzing results grouped by target.
func saveFuzzingResults(results ResponseResultList) {
	fname := folderName + "/fuzzing.txt"
	file, err := os.Create(fname)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create fuzzing.txt: %v\n", Yellow, Reset, err)
		return
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	count := 0
	for _, r := range results {
		if len(r.PathResults) == 0 {
			continue
		}
		baseURL := fmt.Sprintf("%s://%s:%s", r.TargetData.Scheme, r.TargetData.IP, r.TargetData.Port)
		w.WriteString(fmt.Sprintf("=== %s ===\n", baseURL))
		for _, pr := range r.PathResults {
			line := fmt.Sprintf("  [%d] %s", pr.StatusCode, pr.Path)
			if pr.BypassMethod != "" {
				line += fmt.Sprintf(" BYPASS(%s)", pr.BypassMethod)
			}
			if pr.RedirectURL != "" {
				line += fmt.Sprintf(" -> %s", pr.RedirectURL)
			}
			if pr.ContentLength != "" {
				line += fmt.Sprintf(" [%s]", pr.ContentLength)
			}
			w.WriteString(line + "\n")
			count++
		}
		w.WriteString("\n")
	}

	if count > 0 {
		fmt.Printf("%s[✓] Fuzzing results saved to: %s ./%s/fuzzing.txt (%d entries)\n", Green, Reset, folderName, count)
	}
}

// saveRecheckedPorts writes the re-checked ports and their final status.
func saveRecheckedPorts(results ResponseResultList, recheckedIndices []int) {
	if len(recheckedIndices) == 0 {
		return
	}

	fname := folderName + "/rechecked_ports.txt"
	file, err := os.Create(fname)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create rechecked_ports.txt: %v\n", Yellow, Reset, err)
		return
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	w.WriteString(fmt.Sprintf("# Re-checked ports (%d total)\n\n", len(recheckedIndices)))

	for _, idx := range recheckedIndices {
		if idx < 0 || idx >= len(results) {
			continue
		}
		r := results[idx]
		status := r.StatusCode
		if status == "" {
			status = "no_response"
		}
		scheme := r.TargetData.Scheme
		if scheme == "" {
			scheme = "unknown"
		}
		line := fmt.Sprintf("%s:%s  scheme=%s  status=%s  title=%q\n",
			r.TargetData.IP, r.TargetData.Port, scheme, status, r.PageTitle)
		w.WriteString(line)
	}

	fmt.Printf("%s[✓] Re-checked ports saved to: %s ./%s/rechecked_ports.txt\n", Green, Reset, folderName)
}

// saveValidatedEndpoints writes endpoints that returned valid 2xx/3xx responses.
func saveValidatedEndpoints(results ResponseResultList) {
	fname := folderName + "/validated.txt"
	file, err := os.Create(fname)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create validated.txt: %v\n", Yellow, Reset, err)
		return
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	count := 0
	for _, r := range results {
		if len(r.TargetData.Scheme) < 1 || r.StatusCode == "" {
			continue
		}
		sc, _ := strconv.Atoi(r.StatusCode)
		if sc >= 200 && sc < 400 {
			line := fmt.Sprintf("%s://%s:%s  status=%s  title=%q  server=%s\n",
				r.TargetData.Scheme, r.TargetData.IP, r.TargetData.Port,
				r.StatusCode, r.PageTitle, r.Server)
			w.WriteString(line)
			count++
		}
	}

	if count > 0 {
		fmt.Printf("%s[✓] Validated endpoints saved to: %s ./%s/validated.txt (%d entries)\n", Green, Reset, folderName, count)
	}
}

func main() {
	// --- ANSI Color Definitions for "Cool" Output ---
	fmt.Println()

	fmt.Println("wScanner - Web Port Scanner")

	// Custom Usage Message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%sUsage:%s %s [options] \n", Bold, Reset, os.Args[0])
		fmt.Fprintf(os.Stderr, "%sOptions:%s\n", Bold, Reset)
		flag.PrintDefaults()
	}

	flag.Parse()

	// --- Self-Update ---
	if *selfUpdate {
		runSelfUpdate()
		os.Exit(0)
	}

	// --- Input Validation ---
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Banner / Internet Check

	if CheckInternet() {
		fmt.Printf("%s[+] Internet Connection:%s %sONLINE%s\n", Green, Reset, Bold, Reset)
	} else {
		fmt.Printf("%s[-] Internet Connection:%s %sOFFLINE%s\n", Red, Reset, Red, Reset)
		if !*local {
			fmt.Printf("%s[!] Error:%s Internet connection is required unless running in local mode (-local)\n", Red, Reset)
			os.Exit(1)
		}
	}

	if !checkAndDownloadAssets() {
		fmt.Printf("%s[!] Error:%s Failed to download necessary assets\n", Red, Reset)
		os.Exit(1)
	}

	// Load caches once at startup (Bug #6, Perf #9)
	loadCaches()

	// Apply custom output folder name if provided
	if *outputDir != "" {
		folderName = *outputDir
	}

	if *inputFile != "" && *host != "" {
		fmt.Printf("%s[!] Error:%s Please provide only one of -input or -host\n", Red, Reset)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *inputFile == "" && *host == "" {
		fmt.Printf("%s[!] Error:%s Please provide either a list of targets (-input) or a single target (-host)\n", Red, Reset)
		flag.Usage()
		os.Exit(1)
	}

	// --- Initialization ---
	ports, err := readInputFile(*portsFile)
	if err != nil {
		fmt.Printf("%s[!] Error reading ports file:%s %v\n", Red, Reset, err)
		os.Exit(1)
	}

	// --- Create Output Folder (with resume detection) ---
	isResume, ok := createOutputFolder()
	if !ok {
		os.Exit(1)
	}

	// --- Initialize Error Logger ---
	errLogger = NewErrorLogger(folderName)
	if errLogger != nil {
		defer errLogger.Close()
		// Redirect Go's default logger to capture HTTP transport noise
		log.SetOutput(errLogger)
		log.SetFlags(0) // we handle timestamps ourselves
	}

	// --- Resume State ---
	var state *ScanState
	if isResume {
		state, err = LoadState(folderName)
		if err != nil {
			fmt.Printf("%s[!] Error:%s Could not load resume state: %v\n", Red, Reset, err)
			os.Exit(1)
		}
		if state != nil {
			fmt.Printf("%s[*]%s Resuming scan from phase: %s%s%s\n",
				Cyan, Reset, Bold, PhaseNames[state.CompletedPhase], Reset)
		}
	}
	if state == nil {
		state = &ScanState{CompletedPhase: PhaseNone}
	}

	// --- Build targets list ---
	var targets []string
	if *inputFile != "" {
		targets, err = readInputFile(*inputFile)
		if err != nil {
			fmt.Printf("%s[!] Error reading input file:%s %v\n", Red, Reset, err)
			os.Exit(1)
		}
	} else if *host != "" {
		targets = []string{*host}
	}

	// Store targets & ports in state for resume validation
	if state.CompletedPhase == PhaseNone {
		state.Targets = targets
		state.Ports = ports
	}

	// --- Ctrl+C Signal Handler: save state before exiting ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!] Interrupt received — saving scan state...%s\n", Yellow, Reset)
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		} else {
			fmt.Printf("%s[✓] State saved to %s/.resume.json — re-run the same command to resume.%s\n",
				Green, folderName, Reset)
		}
		if errLogger != nil {
			errLogger.Close()
		}
		os.Exit(130)
	}()

	// --- Scanning Phase ---
	var probeResults ResponseResultList
	var openPorts ScanResultList
	var recheckedIndices []int

	// Phase 1: Port Scanning
	if state.CompletedPhase < PhasePortScan {
		// Check for partial results from a previous interrupted port scan
		partialFile := folderName + "/open_ports_initial.txt"
		if partialPorts, readErr := readOpenPortsFile(partialFile); readErr == nil && len(partialPorts) > 0 {
			fmt.Printf("%s[*]%s Recovered %s%d%s open ports from previous interrupted scan\n",
				Cyan, Reset, Bold, len(partialPorts), Reset)
			openPorts = partialPorts
		} else {
			if *inputFile != "" {
				fmt.Printf("%s[*]%s Start scanning on %s%d%s targets from : %s\n", Cyan, Reset, Bold, len(targets), Reset, *inputFile)
				openPorts = probeTargets(targets, ports)
			} else if *host != "" {
				// Single target — check Cloudflare
				if isCloudflareIP(*host) {
					cloudflareSkipped = append(cloudflareSkipped, *host)
					if !*forceCFScan {
						fmt.Printf("%s[!] Target '%s' belongs to Cloudflare → Skipping port scan.%s (use -force-cf to override)\n",
							Yellow, *host, Reset)
					} else {
						fmt.Printf("%s[!] Target '%s' belongs to Cloudflare → Force scanning enabled.%s\n",
							Yellow, *host, Reset)
						fmt.Printf("%s[*]%s Start scanning on single target: %s%s%s\n", Cyan, Reset, Bold, *host, Reset)
						openPorts = probePorts(*host, ports)
					}
				} else {
					fmt.Printf("%s[*]%s Start scanning on single target: %s%s%s\n", Cyan, Reset, Bold, *host, Reset)
					openPorts = probePorts(*host, ports)
				}
			}
		}

		fmt.Printf("\n%s[+]%s Port scan complete. %s%d%s open ports found.\n", Green, Reset, Bold, len(openPorts), Reset)

		state.OpenPorts = openPorts
		state.CompletedPhase = PhasePortScan
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		openPorts = state.OpenPorts
		fmt.Printf("%s[*]%s Skipping port scan (already completed, %s%d%s open ports)\n",
			Cyan, Reset, Bold, len(openPorts), Reset)
	}

	// Phase 2: Scheme Detection
	if state.CompletedPhase < PhaseSchemeDetect {
		if len(openPorts) > 0 {
			fmt.Printf("%s[*]%s Detecting scheme (HTTP/HTTPS) on %s%d%s open ports...\n", Cyan, Reset, Bold, len(openPorts), Reset)
			openPorts = detectAndFillSchemes(openPorts)
		}

		state.OpenPorts = openPorts
		state.CompletedPhase = PhaseSchemeDetect
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		fmt.Printf("%s[*]%s Skipping scheme detection (already completed)\n", Cyan, Reset)
	}

	// Phase 3: HTTP Probe
	if state.CompletedPhase < PhaseHTTPProbe {
		fmt.Printf("%s[+]%s Probing HTTP responses...\n", Green, Reset)
		probeResults = probeAllResponses(openPorts)

		state.ProbeResults = probeResults
		state.CompletedPhase = PhaseHTTPProbe
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		probeResults = state.ProbeResults
		fmt.Printf("%s[*]%s Skipping HTTP probe (already completed)\n", Cyan, Reset)
	}

	// Phase 4: Re-check ports with no data
	if state.CompletedPhase < PhaseRecheck {
		probeResults, recheckedIndices = recheckEmptyResults(probeResults)

		state.ProbeResults = probeResults
		state.RecheckedIndices = recheckedIndices
		state.CompletedPhase = PhaseRecheck
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		recheckedIndices = state.RecheckedIndices
		fmt.Printf("%s[*]%s Skipping re-check (already completed)\n", Cyan, Reset)
	}

	// Phase 5: Path Fuzzing
	if state.CompletedPhase < PhaseFuzz {
		// Determine which path wordlist to use
		pathWordlist := *pathsFile // default from assets
		if *pathFile != "" {
			pathWordlist = *pathFile // user override
		}

		if pathWordlist != "" {
			pathLines, pathErr := readInputFile(pathWordlist)
			if pathErr != nil {
				fmt.Printf("%s[!] Warning:%s Could not load paths wordlist: %v (skipping path fuzzing)\n", Yellow, Reset, pathErr)
			} else if len(pathLines) > 0 {
				probeResults = fuzzPaths(probeResults, pathLines)
			}
		}

		state.ProbeResults = probeResults
		state.CompletedPhase = PhaseFuzz
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		fmt.Printf("%s[*]%s Skipping path fuzzing (already completed)\n", Cyan, Reset)
	}

	// Phase 6: Enrichment (CNAME, PTR, SSL)
	if state.CompletedPhase < PhaseEnrich {
		probeResults = enrichResults(probeResults)

		state.ProbeResults = probeResults
		state.CompletedPhase = PhaseEnrich
		if saveErr := SaveState(folderName, state); saveErr != nil {
			fmt.Printf("%s[!] Warning:%s Could not save state: %v\n", Yellow, Reset, saveErr)
		}
	} else {
		probeResults = state.ProbeResults
		fmt.Printf("%s[*]%s Skipping enrichment (already completed)\n", Cyan, Reset)
	}

	// --- Sort results: 2xx first ---
	probeResults = sortResults(probeResults)

	// --- Write Cloudflare IPs file ---
	writeCloudflareIPs(cloudflareSkipped)

	// --- Results Display ---
	if *stdout {
		printStdout(probeResults)
	}

	// --- Report Saving ---
	reportFile, err := SaveReport(probeResults)
	if err != nil {
		fmt.Printf("%s[!] Error saving report:%s %v\n", Red, Reset, err)
	} else {
		fmt.Printf("%s[✓] Report saved to folder: %s ./%s/\n", Green, Reset, reportFile)
	}

	// --- CSV Output ---
	if *csvOut {
		if err := SaveCSV(probeResults); err != nil {
			fmt.Printf("%s[!] Error saving CSV:%s %v\n", Red, Reset, err)
		} else {
			fmt.Printf("%s[✓] CSV saved to: %s ./%s/results.csv\n", Green, Reset, folderName)
		}
	}

	// --- Separate Output Files ---
	saveFuzzingResults(probeResults)
	saveRecheckedPorts(probeResults, recheckedIndices)
	saveValidatedEndpoints(probeResults)

	// --- Mark scan as complete — remove resume state ---
	ClearState(folderName)
	fmt.Printf("%s[✓] Scan completed successfully.%s\n", Green, Reset)
}
