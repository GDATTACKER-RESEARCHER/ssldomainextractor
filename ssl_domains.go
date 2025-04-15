package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var customUserAgent string
var concurrencyLimit int
var timeout = 50 * time.Second
var domainTimeout = 50 * time.Second

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

func getDomainsFromPortWithContext(ctx context.Context, domain, port string, resolvers []string) ([]string, error) {
	var domains []string

	var dialer *net.Dialer
	if len(resolvers) > 0 {
		dialer = &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial:     customDialer(resolvers),
			},
			Timeout: timeout,
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":"+port, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		for _, name := range state.PeerCertificates[0].DNSNames {
			domains = append(domains, name)
		}
	}

	return domains, nil
}

func customDialer(resolvers []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		for _, resolver := range resolvers {
			conn, err := net.DialTimeout("tcp", resolver+":53", timeout)
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("failed to resolve using provided resolvers")
	}
}

func writeToHandle(f *os.File, domains []string) {
	for _, d := range domains {
		if _, err := f.WriteString(fmt.Sprintf("%s\n", d)); err != nil {
			log.Printf("Error writing to file: %v", err)
		}
	}
}

func processDomain(domain string, wg *sync.WaitGroup, mu *sync.Mutex, progress *int64, total int, resolvers []string, rateLimiter chan struct{}, failedLog, skipLog, sslFile, nonwildFile *os.File) {
	defer wg.Done()
	rateLimiter <- struct{}{}
	defer func() { <-rateLimiter }()

	ctx, cancel := context.WithTimeout(context.Background(), domainTimeout)
	defer cancel()

	domains, err := getCertDomainsWithContext(ctx, domain, resolvers)
	if err != nil {
		mu.Lock()
		if ctx.Err() == context.DeadlineExceeded {
			_, _ = skipLog.WriteString(domain + "\n")
		}
		_, _ = failedLog.WriteString(domain + "\n")
		mu.Unlock()
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

	mu.Lock()
	writeToHandle(sslFile, wildcardDomains)
	writeToHandle(nonwildFile, nonWildcardDomains)
	mu.Unlock()

	if atomic.AddInt64(progress, 1)%500 == 0 {
		runtime.GC() // Helps with memory on long runs
	}

	fmt.Printf("\rProcessing %d/%d domains... Current: %s", atomic.LoadInt64(progress), total, domain)
}

func main() {
	var customUserAgentFlag, resolversFlag string
	var concurrencyFlag int

	flag.StringVar(&customUserAgentFlag, "user-agent", "Mozilla/5.0", "Custom User-Agent")
	flag.StringVar(&resolversFlag, "resolvers", "", "File with custom DNS resolvers")
	flag.IntVar(&concurrencyFlag, "concurrency", 100, "Number of concurrent workers")
	flag.Parse()

	customUserAgent = customUserAgentFlag
	concurrencyLimit = concurrencyFlag

	var resolvers []string
	if resolversFlag != "" {
		file, err := os.Open(resolversFlag)
		if err != nil {
			log.Fatalf("Failed to read resolvers file: %v", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			resolver := strings.TrimSpace(scanner.Text())
			if resolver != "" {
				resolvers = append(resolvers, resolver)
			}
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	domainMap := make(map[string]struct{})
	var domains []string
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			if _, exists := domainMap[domain]; !exists {
				domainMap[domain] = struct{}{}
				domains = append(domains, domain)
			}
		}
	}

	if len(domains) == 0 {
		log.Fatal("No domains provided")
	}

	failedLog, _ := os.OpenFile("failed_domains.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer failedLog.Close()
	skipLog, _ := os.OpenFile("skip.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer skipLog.Close()
	sslFile, _ := os.OpenFile("ssl.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer sslFile.Close()
	nonwildFile, _ := os.OpenFile("nonwild.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer nonwildFile.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var progress int64
	total := len(domains)
	rateLimiter := make(chan struct{}, concurrencyLimit)

	for _, domain := range domains {
		wg.Add(1)
		go processDomain(domain, &wg, &mu, &progress, total, resolvers, rateLimiter, failedLog, skipLog, sslFile, nonwildFile)
	}

	wg.Wait()
	fmt.Println("\nProcessing complete.")
}
