package main

import (
	"bufio"
	"crypto/tls"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var customUserAgent string
var resolversFile string
var concurrencyLimit int
var timeout = 50 * time.Second // Set the timeout to 50 seconds for both DNS resolution and TLS connection
var domainTimeout = 50 * time.Second // Timeout for processing a single domain

// Function to extract domains from SSL certificates for both ports 443 and 80
func getCertDomains(domain string, resolvers []string) ([]string, error) {
	var allDomains []string

	ports := []string{"443", "80"}
	for _, port := range ports {
		domains, err := getDomainsFromPort(domain, port, resolvers)
		if err == nil {
			allDomains = append(allDomains, domains...)
		}
	}

	if len(allDomains) == 0 {
		return nil, fmt.Errorf("no SANs found for %s", domain)
	}
	return allDomains, nil
}

// Function to establish TLS connection on a specific port and retrieve domains
func getDomainsFromPort(domain, port string, resolvers []string) ([]string, error) {
	var domains []string

	var dialer *net.Dialer
	if len(resolvers) > 0 {
		dialer = &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial:     customDialer(resolvers),
			},
			Timeout: timeout, // Set the connection timeout for DNS resolution
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout} // Set the connection timeout if no custom resolvers are used
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":"+port, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	for _, name := range cert.DNSNames {
		domains = append(domains, name)
	}
	return domains, nil
}

// Custom dialer function using provided DNS resolvers
func customDialer(resolvers []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		for _, resolver := range resolvers {
			conn, err := net.DialTimeout("tcp", resolver+":53", timeout) // Use the 50-second timeout for DNS resolution
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("failed to resolve using provided resolvers")
	}
}

// Process each domain and categorize SSL certificate names with a timeout for each domain
func processDomain(domain string, wg *sync.WaitGroup, mu *sync.Mutex, progress *int64, total int, resolvers []string, rateLimiter chan struct{}, failedLogFile *os.File) {
	defer wg.Done()

	// Create a context with timeout for the individual domain processing
	ctx, cancel := context.WithTimeout(context.Background(), domainTimeout)
	defer cancel()

	// Acquire a token from the rate limiter
	rateLimiter <- struct{}{}
	defer func() { <-rateLimiter }()

	// Process domain with the context timeout
	domains, err := getCertDomainsWithContext(ctx, domain, resolvers)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		if _, err := failedLogFile.WriteString(fmt.Sprintf("%s\n", domain)); err != nil {
			log.Printf("Error writing to failed_domains.txt: %v", err)
		}
		return
	}

	var wildcardDomains, nonWildcardDomains []string

	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			wildcardDomains = append(wildcardDomains, d)
		} else {
			nonWildcardDomains = append(nonWildcardDomains, d)
		}
	}

	// Write domains to respective files
	mu.Lock()
	defer mu.Unlock()

	writeToFile("ssl.txt", wildcardDomains)
	writeToFile("nonwild.txt", nonWildcardDomains)

	// Print progress
	atomic.AddInt64(progress, 1)
	fmt.Printf("\rProcessing %d/%d domains... Current domain: %s", atomic.LoadInt64(progress), total, domain)
}

// Function to get domains with context (supports timeout/cancellation)
func getCertDomainsWithContext(ctx context.Context, domain string, resolvers []string) ([]string, error) {
	var allDomains []string

	ports := []string{"443", "80"}
	for _, port := range ports {
		domains, err := getDomainsFromPortWithContext(ctx, domain, port, resolvers)
		if err == nil {
			allDomains = append(allDomains, domains...)
		}
	}

	if len(allDomains) == 0 {
		return nil, fmt.Errorf("no SANs found for %s", domain)
	}
	return allDomains, nil
}

// Function to establish TLS connection with context and timeout
func getDomainsFromPortWithContext(ctx context.Context, domain, port string, resolvers []string) ([]string, error) {
	var domains []string

	var dialer *net.Dialer
	if len(resolvers) > 0 {
		dialer = &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial:     customDialer(resolvers),
			},
			Timeout: timeout, // Set the connection timeout for DNS resolution
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout} // Set the connection timeout if no custom resolvers are used
	}

	// Use context with TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":"+port, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	for _, name := range cert.DNSNames {
		domains = append(domains, name)
	}
	return domains, nil
}

// Helper function to write domains to a file
func writeToFile(filename string, domains []string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening %s: %v", filename, err)
		return
	}
	defer f.Close()

	for _, d := range domains {
		if _, err := f.WriteString(fmt.Sprintf("%s\n", d)); err != nil {
			log.Printf("Error writing to %s: %v", filename, err)
		}
	}
}

func main() {
	// Command-line flags
	var customUserAgentFlag, resolversFlag string
	var concurrencyFlag int

	flag.StringVar(&customUserAgentFlag, "user-agent", "Mozilla/5.0 (X11; Linux i686; rv:131.0) Gecko/20100101 Firefox/131.0", "Custom User-Agent")
	flag.StringVar(&resolversFlag, "resolvers", "", "File containing custom DNS resolvers (one resolver per line)")
	flag.IntVar(&concurrencyFlag, "concurrency", 100, "Number of concurrent goroutines to process domains")
	flag.Parse()

	customUserAgent = customUserAgentFlag
	concurrencyLimit = concurrencyFlag

	// Load resolvers from file if provided
	var resolvers []string
	if resolversFlag != "" {
		file, err := os.Open(resolversFlag)
		if err != nil {
			log.Fatalf("Error reading resolvers file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			resolver := strings.TrimSpace(scanner.Text())
			if resolver != "" {
				resolvers = append(resolvers, resolver)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error scanning resolvers file: %v", err)
		}
	}

	// Read domains from standard input
	var domains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if len(domains) == 0 {
		log.Fatal("No domains provided")
	}

	// Prepare for processing
	var wg sync.WaitGroup
	var mu sync.Mutex
	var progress int64
	totalDomains := len(domains)
	rateLimiter := make(chan struct{}, concurrencyLimit)

	// Open the failed domains log file
	failedLogFile, err := os.OpenFile("failed_domains.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening failed_domains.txt: %v", err)
	}
	defer failedLogFile.Close()

	// Process domains concurrently
	for _, domain := range domains {
		wg.Add(1)
		go processDomain(domain, &wg, &mu, &progress, totalDomains, resolvers, rateLimiter, failedLogFile)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	fmt.Println("\nProcessing complete.")
}
