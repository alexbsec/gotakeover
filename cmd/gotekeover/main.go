package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
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

func main() {

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println(ColorCyan)
	fmt.Println(` _____         _          _                                   `)
	fmt.Println(`|  __ \       | |        | |                                  `)
	fmt.Println(`| |  \/  ___  | |_  __ _ | | __ ___ __   __ ___    ___  _ __  `)
	fmt.Println(`| | __  / _ \ | __|/ _  || |/ // _ \\ \ / // _ \  / _ \| '__| `)
	fmt.Println(`| |_\ \| (_) || |_| (_| ||   <|  __/ \ V /| (_) ||  __/| |    `)
	fmt.Println(` \____/ \___/  \__|\__,_||_|\_\\___|  \_/  \___/  \___||_|    `)
	fmt.Println()
	fmt.Println("------------------------------------------------------  v0.0.1" + ColorReset)

	verbose := flag.Bool("v", false, "Verbose mode")
	timeout := flag.Duration("t", 5, "Timeout time for quitting dig command")
	flag.Parse()

	var vulnDomains []string

	for scanner.Scan() {
		domain := scanner.Text()
		fmt.Printf(ColorYellow+"[ INFO ] Requesting domain '%s'\n"+ColorReset, domain)

		ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "dig", "CNAME", domain)
		out, err := cmd.CombinedOutput()

		if ctx.Err() == context.DeadlineExceeded {
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
			if *verbose {
				fmt.Printf("[ INFO ] Domain '%s' has NXDOMAIN status header\n", domain)
				fmt.Printf("[ INFO ] Requesting domain '%s'...\n", domain)
			}
			status, err := requests.GetStatusCode(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] %s\n"+ColorReset, err)
				continue
			}

			if status == 404 {
				fmt.Printf(Bold+ColorCyan+"[ VULN ] Domain '%s' seems to be vulnerable for subdomain takeover\n"+ColorReset, domain)
				vulnDomains = append(vulnDomains, domain)
			}
		} else if *verbose {
			fmt.Printf(ColorBlue+"[ RES ] Domain '%s' is not vulnerable to subdomain takeover\n"+ColorReset, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] Error reading standard input: %s\n"+ColorReset, err)
	}

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
