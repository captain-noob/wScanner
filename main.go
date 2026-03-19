package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
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

const version = "beta-v4.0.0"

const remoteHeaders = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/headers.json"
const remoteUserAgents = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/user-agent.txt"
const remotePorts = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/ports.txt"
const intrestingPaths = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/paths.txt"

// const remoteWappalyzer = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/wappalyzer.json"

var folderName = "wScanner_" + time.Now().Format("20060102_150405")

var isProgressBarCompleted = false
var activeGoroutines int64

var (
	portsFile    = flag.String("ports-file", "ports.txt", "File containing **newline-separated ports** to probe.")
	inputFile    = flag.String("input", "", "File containing **newline-separated hostnames or IP addresses** to scan.")
	host         = flag.String("host", "", "Single **hostname or IP address** to scan (alternative to -input).")
	verbose      = flag.Bool("v", false, "Enable **verbose** output mode.")
	time_out     = flag.Int("timeout", 15, "Timeout duration in **seconds** for each probe/request.")
	stdout       = flag.Bool("stdout", true, "Print results to **standard output** (stdout).")
	local        = flag.Bool("local", false, "Indicates running in a **local network** environment (without general internet access).")
	updateConfig = flag.Bool("update-config", false, "Fetch and update **configuration files** from remote sources.")
	maxRPS       = flag.Int("rps", 0, "Maximum concurrent requests per second (global)")
	outputDir    = flag.String("output", "", "Custom **output folder** name (default: wScanner_YYYYMMDD_HHMMSS).")
	csvOut       = flag.Bool("csv", false, "Generate a **CSV** results file in the output folder.")
	pathFile     = flag.String("path", "", "Custom **wordlist** file for directory/path fuzzing.")
	selfUpdate   = flag.Bool("update", false, "Self-update wScanner to the **latest** GitHub release.")
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
	// If user specified -rps, honour it as the concurrency limit (no cap).
	if *maxRPS > 0 {
		return *maxRPS
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

func detectScheme(host string, port string) string {
	address := net.JoinHostPort(host, port)

	// --- Try HTTPS (TLS handshake) ---
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // for detection Purposes only
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err == nil {
		conn.Close()
		return "https"
	}

	// --- Try HTTP (simple request) ---
	client := http.Client{
		Timeout: 2 * time.Second,
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
	timeout := time.Duration(*time_out) * time.Second
	dialer := &net.Dialer{
		Timeout: timeout,
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
	workerCount := 300
	if len(ports) < workerCount {
		workerCount = len(ports)
	}

	concurrencyLimit := getConcurrencyLimit()
	if workerCount > concurrencyLimit {
		workerCount = concurrencyLimit
	}

	if totalPorts < workerCount {
		workerCount = totalPorts
	}

	// 1. Start Workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				if checkForOpenPort(target, port) {
					results <- ScanResult{
						IP:     target,
						Port:   port,
						Scheme: detectScheme(target, port),
					}
				} else if *verbose {
					fmt.Printf("Port %s is closed on %s\n", port, target)
				}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// 2. Send Jobs
	for _, port := range ports {
		jobs <- port
	}
	close(jobs)

	// 3. The Closer Routine: Wait for workers to finish, then close the results channel.
	go func() {
		wg.Wait()
		close(results)
	}()

	// 4. Collect Results (Main Thread)
	var openPorts ScanResultList
	for r := range results {
		openPorts = append(openPorts, r)
	}

	return openPorts
}

func probeTargets(targets []string, ports []string) ScanResultList {
	totalIps := len(targets)
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

	fmt.Printf("%s[*]%s Setting concurrency limit to: %s%d%s\n", Cyan, Reset, Bold, workerCount, Reset)

	bar := NewProgressBar(maxtotalJobs)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for itemX := range jobs {
				atomic.AddInt64(&activeGoroutines, 1)
				if checkForOpenPort(itemX.IP, itemX.Port) {
					results <- ScanResult{
						IP:     itemX.IP,
						Port:   itemX.Port,
						Scheme: detectScheme(itemX.IP, itemX.Port),
					}
				} else if *verbose {
					fmt.Printf("Port %s is closed on %s\n", itemX.Port, itemX.IP)
				}
				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	for _, target := range targets {
		for _, port := range ports {
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

func getResponse(item ScanResult) ResponseResult {
	var outx ResponseResult

	outx.TargetData = item

	if len(item.Scheme) < 1 {
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

	resp, err := client.Do(req)
	if err != nil {
		return outx
	}

	defer resp.Body.Close()

	targetRedirect := ""
	if resp.Request.URL.String() != "" {
		targetRedirect = resp.Request.URL.String()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return outx
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

	// Send jobs
	for _, port := range openPorts {
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

// fuzzPaths probes each discovered target with a list of paths.
// Only keeps 2xx, 3xx, and 403 responses.
// When a 403 is encountered, automatically tries bypass techniques.
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

	bar := NewProgressBar(totalJobs)

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
				resp.Body.Close()

				statusCode := resp.StatusCode

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
								ContentLength: resp.Header.Get("Content-Length"),
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
							ContentLength: resp.Header.Get("Content-Length"),
							RedirectURL:   redirectURL,
						},
					}
				}

				atomic.AddInt64(&activeGoroutines, -1)
				bar.Update(1)
			}
		}()
	}

	// Send jobs
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

	fmt.Println()
	return results
}

// try403Bypass attempts multiple 403 bypass techniques on a path.
// Returns a FuzzResult if any bypass succeeds (non-403 response in 2xx/3xx range), nil otherwise.
func try403Bypass(client *http.Client, baseURL string, path string) *FuzzResult {
	// --- Technique 1: Header-based bypasses ---
	bypassHeaders := map[string]string{
		"X-Forwarded-For":  "127.0.0.1",
		"X-Real-IP":        "127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
		"X-Remote-IP":      "127.0.0.1",
		"X-Remote-Addr":    "127.0.0.1",
		"X-ProxyUser-Ip":   "127.0.0.1",
		"X-Original-URL":   "/" + path,
		"X-Rewrite-URL":    "/" + path,
		"Client-IP":        "127.0.0.1",
		"X-Client-IP":      "127.0.0.1",
		"X-Host":           "127.0.0.1",
		"X-Forwarded-Host": "127.0.0.1",
	}

	fullURL := baseURL + "/" + path

	for hdr, val := range bypassHeaders {
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set(hdr, val)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			redirectURL := ""
			if loc := resp.Header.Get("Location"); loc != "" {
				redirectURL = loc
			}
			return &FuzzResult{
				Path:          "/" + path,
				StatusCode:    resp.StatusCode,
				ContentLength: resp.Header.Get("Content-Length"),
				RedirectURL:   redirectURL,
				BypassMethod:  fmt.Sprintf("header: %s: %s", hdr, val),
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

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			redirectURL := ""
			if loc := resp.Header.Get("Location"); loc != "" {
				redirectURL = loc
			}
			return &FuzzResult{
				Path:          "/" + path,
				StatusCode:    resp.StatusCode,
				ContentLength: resp.Header.Get("Content-Length"),
				RedirectURL:   redirectURL,
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

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			redirectURL := ""
			if loc := resp.Header.Get("Location"); loc != "" {
				redirectURL = loc
			}
			return &FuzzResult{
				Path:          "/" + pm.mutated,
				StatusCode:    resp.StatusCode,
				ContentLength: resp.Header.Get("Content-Length"),
				RedirectURL:   redirectURL,
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
		"content_length", "page_title", "server", "redirect_location", "recon_info", "discovered_paths"}
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
			reconStr,
			pathsStr,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func createOutputFolder() bool {
	err := os.Mkdir(folderName, 0755)
	if err != nil {
		return false
	}
	return true
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

	if !createOutputFolder() {
		fmt.Printf("%s[!] Error:%s Failed to create output folder\n", Red, Reset)
		os.Exit(1)
	}

	// --- Scanning Phase ---
	var probeResults ResponseResultList
	var openPorts ScanResultList

	if *inputFile != "" {
		targets, err := readInputFile(*inputFile)
		if err != nil {
			fmt.Printf("%s[!] Error reading input file:%s %v\n", Red, Reset, err)
			os.Exit(1)
		}

		fmt.Printf("%s[*]%s Start scanning on %s%d%s targets from : %s\n", Cyan, Reset, Bold, len(targets), Reset, *inputFile)
		openPorts = probeTargets(targets, ports)

	} else if *host != "" {
		fmt.Printf("%s[*]%s Start scanning on single target: %s%s%s\n", Cyan, Reset, Bold, *host, Reset)
		openPorts = probePorts(*host, ports)
	}

	fmt.Printf("%s[+]%s Ports probing completed. Probing HTTP responses...\n", Green, Reset)
	probeResults = probeAllResponses(openPorts)

	// --- Path Fuzzing Phase ---
	// Determine which path wordlist to use
	pathWordlist := *pathsFile // default from assets
	if *pathFile != "" {
		pathWordlist = *pathFile // user override
	}

	if pathWordlist != "" {
		pathLines, err := readInputFile(pathWordlist)
		if err != nil {
			fmt.Printf("%s[!] Warning:%s Could not load paths wordlist: %v (skipping path fuzzing)\n", Yellow, Reset, err)
		} else if len(pathLines) > 0 {
			probeResults = fuzzPaths(probeResults, pathLines)
		}
	}

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
}
