package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Configurable parameters
var (
	timeout          = 50 * time.Second
	concurrency      int
	resolversFile    string
	defaultUserAgent = "Mozilla/5.0 (X11; Linux i686; rv:131.0) Gecko/20100101 Firefox/131.0"
)

type Result struct {
	Index  int
	Domain string
	Error  error
}

// Reads lines from stdin or a file
func readDomains(inputPath string) ([]string, error) {
	var scanner *bufio.Scanner
	var file *os.File
	var err error

	if inputPath != "" {
		file, err = os.Open(inputPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var domains []string
	for scanner.Scan() {
		d := strings.TrimSpace(scanner.Text())
		if d != "" {
			domains = append(domains, d)
		}
	}
	return domains, scanner.Err()
}

// Extract SANs from SSL cert
func fetchSANs(domain string, resolvers []string) error {
	ports := []string{"443", "80"}
	for _, port := range ports {
		err := tryTLS(domain, port, resolvers)
		if err == nil {
			fmt.Printf("✔️  %s\n", domain)
			return nil
		}
	}
	return fmt.Errorf("no SANs found")
}

// TLS connection attempt
func tryTLS(domain, port string, resolvers []string) error {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":"+port, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return fmt.Errorf("no certs")
	}
	return nil
}

func worker(id int, jobs <-chan int, domains []string, results chan<- Result, resolvers []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := range jobs {
		err := fetchSANs(domains[i], resolvers)
		results <- Result{Index: i, Domain: domains[i], Error: err}
	}
}

func main() {
	var inputPath string
	flag.StringVar(&inputPath, "input", "", "Input file with domains (optional if using stdin)")
	flag.IntVar(&concurrency, "concurrency", 50, "Concurrency level (default 50)")
	flag.StringVar(&resolversFile, "resolvers", "", "File with custom DNS resolvers")
	flag.Parse()

	domains, err := readDomains(inputPath)
	if err != nil || len(domains) == 0 {
		log.Fatal("No valid domains provided.")
	}

	var resolvers []string
	if resolversFile != "" {
		file, err := os.Open(resolversFile)
		if err != nil {
			log.Fatalf("Failed to open resolvers file: %v", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				resolvers = append(resolvers, line)
			}
		}
	}

	jobs := make(chan int, len(domains))
	results := make(chan Result, len(domains))
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go worker(w, jobs, domains, results, resolvers, &wg)
	}

	// Dispatch jobs
	for i := range domains {
		jobs <- i
	}
	close(jobs)

	// Wait for workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Store ordered results
	ordered := make([]Result, len(domains))
	for res := range results {
		ordered[res.Index] = res
	}

	// Output in input order
	for _, res := range ordered {
		if res.Error != nil {
			fmt.Printf("❌  %s\n", res.Domain)
		}
	}
}
