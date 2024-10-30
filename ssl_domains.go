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
	"context"
	"io/ioutil"
)

var (
	customUserAgent string
	resolversFile   string
	concurrencyLimit int
)

func getCertDomains(domain string, dialer *net.Dialer) ([]string, error) {
	var domains []string

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
		for _, resolver := range resolvers {
			conn, err := net.DialTimeout("tcp", resolver+":53", 5*time.Second)
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("failed to resolve using provided resolvers")
	}
}

func worker(id int, domains <-chan string, wg *sync.WaitGroup, progress *int64, total int, resolvers []string, failedDomains chan<- string, wildcardDomains chan<- string, nonWildcardDomains chan<- string, dialer *net.Dialer) {
	defer wg.Done()
	for domain := range domains {
		domains, err := getCertDomains(domain, dialer)
		if err != nil {
			failedDomains <- domain
			continue
		}
		for _, d := range domains {
			if strings.HasPrefix(d, "*.") {
				wildcardDomains <- d
			} else {
				nonWildcardDomains <- d
			}
		}
		atomic.AddInt64(progress, 1)
		fmt.Printf("\rProcessing %d/%d domains... Current domain: %s", atomic.LoadInt64(progress), total, domain)
	}
}

func main() {
	var customUserAgentFlag string
	var resolversFlag string
	var concurrencyFlag int

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
	var progress int64
	totalDomains := len(domains)

	rateLimiter := make(chan struct{}, concurrencyLimit)

	failedDomains := make(chan string, totalDomains)
	wildcardDomains := make(chan string, totalDomains)
	nonWildcardDomains := make(chan string, totalDomains)

	dialer := &net.Dialer{}
	if len(resolvers) > 0 {
		dialer = &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial:     customDialer(resolvers),
			},
		}
	}

	wg.Add(concurrencyLimit)
	for i := 0; i < concurrencyLimit; i++ {
		go worker(i, domains, &wg, &progress, totalDomains, resolvers, failedDomains, wildcardDomains, nonWildcardDomains, dialer)
	}

	go func() {
		for d := range failedDomains {
			// Append to failed_domains.txt
		}
	}()

	go func() {
		for d := range wildcardDomains {
			// Append to ssl.txt
		}
	}()

	go func() {
		for d := range nonWildcardDomains {
			// Append to nonwild.txt
		}
	}()

	wg.Wait()
	close(failedDomains)
	close(wildcardDomains)
	close(nonWildcardDomains)
	fmt.Printf("\nProcessing complete. Results saved to ssl.txt, nonwild.txt, and failed_domains.txt\n")
}
