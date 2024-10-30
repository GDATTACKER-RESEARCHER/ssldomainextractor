package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"bufio"
	"io/ioutil"
	"context"
)

var customUserAgent string
var resolversFile string
var concurrencyLimit int

// Function to extract domains from the SSL certificate (both wildcard and non-wildcard)
func getCertDomains(domain string, resolvers []string) ([]string, error) {
	var domains []string

	var dialer *net.Dialer
	if len(resolvers) > 0 {
		dialer = &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial:     customDialer(resolvers),
			},
		}
	} else {
		dialer = &net.Dialer{}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	for _, name := range cert.DNSNames {
		domains = append(domains, name)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no SANs found for %s", domain)
	}

	return domains, nil
}

func customDialer(resolvers []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if len(resolvers) > 0 {
			for _, resolver := range resolvers {
				conn, err := net.DialTimeout("tcp", resolver+":53", 5*time.Second)
				if err == nil {
					return conn, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to resolve using provided resolvers")
	}
}

func processDomain(domain string, wg *sync.WaitGroup, mu *sync.Mutex, progress *int64, total int, resolvers []string, rateLimiter chan struct{}, failedLogFile *os.File) {
	defer wg.Done()

	// Acquire a token from the rate limiter
	rateLimiter <- struct{}{}
	defer func() { <-rateLimiter }()

	domains, err := getCertDomains(domain, resolvers)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()

		if _, err := failedLogFile.WriteString(fmt.Sprintf("%s\n", domain)); err != nil {
			log.Fatalf("Error writing to failed_domains.txt: %v", err)
		}
		return
	}

	var wildcardDomains []string
	var nonWildcardDomains []string

	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			wildcardDomains = append(wildcardDomains, d)
		} else {
			nonWildcardDomains = append(nonWildcardDomains, d)
		}
	}

	// Save wildcard domains to ssl.txt
	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile("ssl.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening ssl.txt: %v", err)
	}
	defer f.Close()
	for _, d := range wildcardDomains {
		if _, err := f.WriteString(fmt.Sprintf("%s\n", d)); err != nil {
			log.Fatalf("Error writing to ssl.txt: %v", err)
		}
	}

	// Save non-wildcard domains to nonwild.txt
	fNonWild, err := os.OpenFile("nonwild.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening nonwild.txt: %v", err)
	}
	defer fNonWild.Close()
	for _, d := range nonWildcardDomains {
		if _, err := fNonWild.WriteString(fmt.Sprintf("%s\n", d)); err != nil {
			log.Fatalf("Error writing to nonwild.txt: %v", err)
		}
	}

	// Print progress
	atomic.AddInt64(progress, 1)
	fmt.Printf("\rProcessing %d/%d domains... Current domain: %s", atomic.LoadInt64(progress), total, domain)
}

func main() {
	var customUserAgentFlag string
	var resolversFlag string
	var concurrencyFlag int

	// Define command-line flags
	flag.StringVar(&customUserAgentFlag, "user-agent", "Mozilla/5.0 (X11; Linux i686; rv:131.0) Gecko/20100101 Firefox/131.0", "Custom User-Agent")
	flag.StringVar(&resolversFlag, "resolvers", "", "File containing custom DNS resolvers (one resolver per line)")
	flag.IntVar(&concurrencyFlag, "concurrency", 100, "Number of concurrent goroutines to process domains")

	flag.Parse()

	customUserAgent = customUserAgentFlag
	concurrencyLimit = concurrencyFlag

	var resolvers []string
	if resolversFlag != "" {
		data, err := ioutil.ReadFile(resolversFlag)
		if err != nil {
			log.Fatalf("Error reading resolvers file: %v", err)
		}
		resolvers = strings.Split(string(data), "\n")
	}

	var domains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	if len(domains) == 0 {
		log.Fatal("No domains provided")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var progress int64
	totalDomains := len(domains)

	// Create a rate limiter for concurrency
	rateLimiter := make(chan struct{}, concurrencyLimit)

	// Open the failed domains log file
	failedLogFile, err := os.OpenFile("failed_domains.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening failed_domains.txt: %v", err)
	}
	defer failedLogFile.Close()

	// Process each domain with concurrency control
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		wg.Add(1)
		go processDomain(domain, &wg, &mu, &progress, totalDomains, resolvers, rateLimiter, failedLogFile)
	}

	wg.Wait()
	fmt.Printf("\nProcessing complete. Results saved to ssl.txt, nonwild.txt, and failed_domains.txt\n")
}
