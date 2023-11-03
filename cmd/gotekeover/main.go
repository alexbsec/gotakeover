package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alexbsec/gotakeover/pkg/digparser"
	"github.com/alexbsec/gotakeover/pkg/requests"
)

const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorReset  = "\033[0m"
	Bold        = "\033[1m"
)

func parseHeaders(headerStr string) ([]map[string]string, error) {
	headerPairs := strings.Split(headerStr, ";")

	var headers []map[string]string
	if headerStr == "" {
		return headers, nil
	}
	for _, pair := range headerPairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format: %s", pair)
		}

		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		headers = append(headers, map[string]string{headerName: headerValue})
	}

	return headers, nil
}

func main() {

	scanner := bufio.NewScanner(os.Stdin)

	verbose := flag.Bool("v", false, "Verbose mode")
	timeout := flag.Duration("t", 5, "Timeout time for quitting dig command")
	simpleOutput := flag.Bool("so", false, "Prints only vulnerable domains in stdout")
	header := flag.String("H", "", "Header for GET request semi-colon separated (Ex: HeaderName1: HeaderValue1; HeaderName2: HeaderValue2...)")

	flag.Parse()

	headers, err := parseHeaders(*header)

	if err != nil {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] %s\n"+ColorReset, err)
		os.Exit(1)
	}

	if !*simpleOutput {
		fmt.Println(ColorCyan)
		fmt.Println(` _____         _          _                                   `)
		fmt.Println(`|  __ \       | |        | |                                  `)
		fmt.Println(`| |  \/  ___  | |_  __ _ | | __ ___   ___ __   __  ___  _ __  `)
		fmt.Println(`| | __  / _ \ | __|/ _  || |/ // _ \ / _ \\ \ / / / _ \| '__| `)
		fmt.Println(`| |_\ \| (_) || |_| (_| ||   <|  __/| (_) |\ V / |  __/| |    `)
		fmt.Println(` \____/ \___/  \__|\__,_||_|\_\\___| \___/  \_/   \___||_|    `)
		fmt.Println()
		fmt.Println("------------------------------------------------------  v0.0.2" + ColorReset)
	}

	var vulnDomains []string

	for scanner.Scan() {
		domain := scanner.Text()
		if !*simpleOutput {
			fmt.Printf(ColorYellow+"[ INFO ] Requesting domain '%s'\n"+ColorReset, domain)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "dig", "CNAME", domain)
		out, err := cmd.CombinedOutput()

		if ctx.Err() == context.DeadlineExceeded && !*simpleOutput {
			fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] DIG command timed out for domain '%s'\n"+ColorReset, domain)
			continue
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] Could not run DIG command: %s\n"+ColorReset, err)
			os.Exit(1)
		}
		lines := digparser.ParseLine(string(out))
		header := digparser.GetHeader(lines)
		status := header["status"]
		if status == "NXDOMAIN" {
			if *verbose && !*simpleOutput {
				fmt.Printf("[ INFO ] Domain '%s' has NXDOMAIN status header\n", domain)
				fmt.Printf("[ INFO ] Requesting domain '%s'...\n", domain)
			}
			status, err := requests.GetStatusCode(domain, headers)
			if err != nil && !*simpleOutput {
				fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] %s\n"+ColorReset, err)
				continue
			}

			if status == 404 {
				if !*simpleOutput {
					fmt.Printf(Bold+ColorCyan+"[ VULN ] Domain '%s' seems to be vulnerable for subdomain takeover\n"+ColorReset, domain)
				} else {
					fmt.Println(Bold + ColorCyan + domain + ColorReset)
				}

				vulnDomains = append(vulnDomains, domain)
			}
		} else if *verbose && !*simpleOutput {
			fmt.Printf(ColorBlue+"[ RES ] Domain '%s' is not vulnerable to subdomain takeover\n"+ColorReset, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] Error reading standard input: %s\n"+ColorReset, err)
	}

	if !*simpleOutput {
		fmt.Println()
		fmt.Println(ColorCyan + "Results:")
		fmt.Printf(ColorCyan+"Found %d vulnerable domains\n"+ColorReset, len(vulnDomains))
		if len(vulnDomains) > 0 {
			fmt.Println(ColorRed, "Vulnerable domain list:")
			for _, d := range vulnDomains {
				fmt.Println(ColorRed, d)
			}
		}
	}

}
