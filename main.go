package main

import (
 "bufio"
 "crypto/tls"
  "flag"
  "fmt"
 "io"
 "encoding/json"
 "math/rand"
"net"
 "net/http"
  "os"
 "os/exec"
 "regexp"
 "runtime"
 "strconv"
 "strings"
 "sync"
  "time"
  "reflect"
  "os/user"
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

const version = "1.0.0"

const remoteHeaders = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/headers.json"
const remoteUserAgents = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/user-agent.txt"
const remotePorts = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/ports.txt"
// const remoteWappalyzer = "https://raw.githubusercontent.com/captain-noob/wScanner/refs/heads/main/Assets/wappalyzer.json"



var (
portsFile = flag.String("ports-file", "ports.txt", "File containing **newline-separated ports** to probe.")
inputFile = flag.String("input", "", "File containing **newline-separated hostnames or IP addresses** to scan.")
host = flag.String("host", "", "Single **hostname or IP address** to scan (alternative to -input).")
verbose = flag.Bool("v", false, "Enable **verbose** output mode.")
time_out = flag.Int("timeout", 15, "Timeout duration in **seconds** for each probe/request.")
stdout = flag.Bool("stdout", true, "Print results to **standard output** (stdout).")
local = flag.Bool("local", false, "Indicates running in a **local network** environment (without general internet access).")
updateConfig = flag.Bool("update-config", false, "Fetch and update **configuration files** from remote sources.")
// csvOut = flag.String("out", "results.csv", "CSV output file")
// randomUA = flag.Bool("random-ua", true, "enable random User-Agent selection")
// proxy = flag.String("proxy", "", "single HTTP proxy to use (eg http://127.0.0.1:8080)")
// proxiesFile = flag.String("proxies-file", "", "file with proxies (http,socks4,socks5) one per line")
// tenableTor = flag.Bool("tor", false, "enable Tor (NOTE: must configure proxy that routes to Tor) (default false)")
// threads = flag.Int("threads", 50, "number of concurrent workers")
// maxRPS = flag.Int("rps", 150, "maximum requests per second (global)")
// delayStr = flag.String("delay", "-1ns", "duration between each http request per worker (eg: 200ms, 1s). default -1ns (no delay)")
// screenshot = flag.Bool("screenshot", false, "save screenshot of page using headless browser")
// wappalyzerDB = flag.String("wappalyzer", "wappalyzer.json", "local Wappalyzer-like json dataset to detect technologies")
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

	portsFile = &portsPath
	userAgentsFile = &uaPath
	headersFile = &headersPath

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
	userAgents, err := readInputFile(*userAgentsFile)
	if err != nil || len(userAgents) == 0 {
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36"
	}
	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}


func getMaxThreads() int {
	numCPU := runtime.NumCPU()
	maxThreads := numCPU * 10
	return maxThreads
}

func getConcurrencyLimit() int {
	cmd := exec.Command("bash", "-c", "ulimit -n")
	output, err := cmd.Output()	
	if err != nil {
		fmt.Printf("Error getting ulimit: %v\n", err)
		return 100
	}

	ulimitStr := strings.TrimSpace(string(output))
	ulimit, err := strconv.Atoi(ulimitStr)
	if err != nil {
		fmt.Printf("Error parsing ulimit: %v\n", err)
		return 100
	}

	return ulimit
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
	conn, err := dialer.Dial("tcp", address )
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func probePorts(target string, ports []string) ScanResultList {
	totalPorts := len(ports)

    stop := make(chan bool)
    go StartSpinner(stop)

	// We use the full length of ports for the channel buffer size
	jobs := make(chan string, totalPorts)
	results := make(chan string, totalPorts)

	var wg sync.WaitGroup
	
	// TUNE THIS: Concurrency Limit (You had 1000, 200 is often a safer starting point)
	workerCount := 0
	if len(ports) < 300 { workerCount = len(ports) } else { workerCount = 300 }

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
				// The fixed probePorts now passes the timeout duration
				if checkForOpenPort(target, port) {
					// fmt.Printf("\r [%s] Probing for open ports ... \r", time.Now().Format("15:04:05"))
					results <- port
				} else if *verbose { // Using the global 'verbose' for output
					fmt.Printf("Port %s is closed on %s\n", port, target)
				}
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
	// var openPorts []string
	var openPorts ScanResultList
	for r := range results {
		openPorts = append(openPorts, ScanResult{
			IP:     target,
			Port:   r,
			Scheme: detectScheme(target, r),
		})
	}

    stop <- true

	return openPorts
}


func probeTargets(targets []string, ports []string) ScanResultList{
	totalIps := len(targets)
	totalPorts := len(ports)

    

	maxtotalJobs := totalIps * totalPorts


	maxWorkers := getConcurrencyLimit()
	if maxtotalJobs < maxWorkers {
		maxWorkers = maxtotalJobs
	}

    if verbose != nil && *verbose {
        fmt.Printf("Setting concurrency limit to %d based on system ulimit and job count\n", maxWorkers)
    }
	

    stop := make(chan bool)
    go StartSpinner(stop)


	type targetItem struct {
		IP      string 
		Port    string    
	}


	jobs := make(chan targetItem, maxtotalJobs)
	results := make(chan targetItem, maxtotalJobs)

	var wg sync.WaitGroup
	
	workerCount := 0
	if len(ports) < 300 { workerCount = len(ports) } else { workerCount = 300 }
	if totalPorts < workerCount {
		workerCount = totalPorts
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for itemX := range jobs {
				if checkForOpenPort(itemX.IP, itemX.Port) {
					// fmt.Printf("\r [%s] Probing for open ports ... \r", time.Now().Format("15:04:05"))
					results <- itemX
				} else if *verbose { // Using the global 'verbose' for output
					fmt.Printf("Port %s is closed on %s\n", itemX.Port, itemX.IP)
				}
			}
		}()
	}

	for _, target := range targets {
		// 2. Send Jobs
		for _, port := range ports {
			targetItem := targetItem{
				IP:   target,
				Port: port,
			}
			jobs <- targetItem
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts ScanResultList
	for r := range results {
		openPorts = append(openPorts, ScanResult{
			IP:     r.IP,
			Port:   r.Port,
			Scheme: detectScheme(r.IP, r.Port),
		})
	}

    stop <- true

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
        Timeout: time.Duration(*time_out) * time.Second,
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
	if resp.Request.URL.String() != ""{
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

	


	raw_json, err := readInputFile(*headersFile)
	headersData := []byte(strings.Join(raw_json, "\n"))
	if err != nil {
		fmt.Printf("Error reading headers file: %v\n", err)
		return outx
	}

	var config HeaderConfig
	err = json.Unmarshal(headersData, &config)
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return outx
	}

	v := reflect.ValueOf(config)
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

		// jobs := make(chan ScanResult, len(openPorts))
		results := make(chan ResponseResult, len(openPorts)) 

        stop := make(chan bool)
        go StartSpinner(stop)

		
		

		for _, port := range openPorts {
			wg.Add(1)

			go func(p ScanResult) { // pass as value to avoid loop variable capture
				defer wg.Done()
				// fmt.Printf("\r [%s] Probing Headers ... \r", time.Now().Format("15:04:05"))
				x := getResponse(p)
				results <- x

			}(port)
		}

		// Close channel once all goroutines finish
		go func() {
			
			wg.Wait()
			close(results)
		}()

		// Read concurrent results
		
		resp := ResponseResultList{}
		for r := range results {
			resp = append(resp, r)
		}
        stop <- true
		
		return resp
}

func SaveReport(results ResponseResultList) (string, error) {
    folderName := "wScanner_" + time.Now().Format("20060102_150405")
    err := os.Mkdir(folderName, 0755)
    if err != nil {
		fmt.Println("Error creating folder:", err)
        return "", err
	}


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
			if x.StatusCode[0] == '3' { statusColor = Yellow }
			if x.StatusCode[0] == '4' || x.StatusCode[0] == '5' { statusColor = Red }
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
		fmt.Println()
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

	// os.Exit(1)


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
}