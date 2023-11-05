package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alexbsec/gotakeover/pkg/digparser"
	"github.com/alexbsec/gotakeover/pkg/fingerprint"
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

func SaveOutput(save bool, writer *bufio.Writer, domain string) {
	var err error
	if save {
		_, err = writer.WriteString(domain + "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ ERROR ] Could not write to file: '%s'\n", err)
			os.Exit(1)
		}

		err = writer.Flush()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ ERROR ] Could not flush writer: '%s'\n", err)
			os.Exit(1)
		}
	}
}

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

func GetDomain(domain string, headers []map[string]string, mode string, vulnDomains []string, simpleOutput bool, timeout time.Duration, save bool, writer *bufio.Writer) []string {
	response, err := requests.Get(domain, headers, timeout)
	if err != nil && !simpleOutput {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] %s\n"+ColorReset, err)
		return vulnDomains
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)

	if err != nil && !simpleOutput {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] %s\n"+ColorReset, err)
		return vulnDomains
	}

	if mode == "fmode" {
		foundPrint, serviceName := fingerprint.CheckFingerprint(string(bodyBytes))
		if foundPrint {
			if !simpleOutput {
				fmt.Printf(Bold+ColorCyan+"[ INFO ] Domain '%s' is using '%s' as service and might be vulnerable\n"+ColorReset, domain, serviceName)
			} else {
				fmt.Println(domain)
			}

			SaveOutput(save, writer, domain)
			vulnDomains = append(vulnDomains, domain)
		} else if !simpleOutput {
			fmt.Printf(ColorBlue+"[ INFO ] Domain '%s' is not vulnerable\n", domain)
		}
	} else if mode == "smode" {
		if response.StatusCode == 404 {
			if !simpleOutput {
				fmt.Printf(Bold+ColorCyan+"[ VULN ] Domain '%s' seems to be vulnerable for subdomain takeover\n"+ColorReset, domain)
			} else {
				fmt.Println(domain)
			}

			SaveOutput(save, writer, domain)
			vulnDomains = append(vulnDomains, domain)
		} else if !simpleOutput {
			fmt.Printf(ColorBlue+"[ INFO ] Domain '%s' is not vulnerable\n", domain)
		}
	}

	return vulnDomains
}

func Printfv(format string, verbose bool, so bool, a ...any) {
	if verbose && !so {
		fmt.Printf(format, a...)
	}
}

func main() {

	scanner := bufio.NewScanner(os.Stdin)

	verbose := flag.Bool("v", false, "Verbose mode")
	smode := flag.Bool("smode", false, "Simple status mode. Look for 404 status code to evaluate vulnerability. Default mode")
	fmode := flag.Bool("fmode", false, "Fingerprint mode. Look for known fingerprints to evaluate vulnerability")
	timeout := flag.Duration("t", 5, "Timeout time for quitting dig command")
	simpleOutput := flag.Bool("so", false, "Prints only vulnerable domains in stdout")
	saveFile := flag.String("o", "", "Save the results into an output file specified by name")
	header := flag.String("H", "", "Header for GET request semi-colon separated (Ex: HeaderName1: HeaderValue1; HeaderName2: HeaderValue2...)")

	flag.Parse()

	var mode string
	var save bool
	var writer *bufio.Writer
	var file *os.File
	var fileErr error

	if !*smode && !*fmode {
		*smode = true
		mode = "smode"
	}

	if *saveFile != "" {
		save = true
		file, fileErr = os.OpenFile(*saveFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if fileErr != nil {
			fmt.Fprintf(os.Stderr, "[ ERROR ] Cannot open file '%s' to write: '%s", *saveFile, fileErr)
			return
		}
		defer file.Close()

		writer = bufio.NewWriter(file)
	}

	if *smode == *fmode {
		fmt.Println(ColorRed)
		fmt.Println("[ ERROR ] Cannot set two investigating modes at once")
		os.Exit(1)
	}

	if *fmode {
		mode = "fmode"
	}

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
		fmt.Println("------------------------------------------------------  v0.0.3" + ColorReset)
	}

	var vulnDomains []string

	for scanner.Scan() {
		domain := scanner.Text()
		if !*simpleOutput {
			fmt.Printf(ColorYellow+"[ INFO ] Requesting domain '%s'\n"+ColorReset, domain)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Second)

		cmd := exec.CommandContext(ctx, "dig", "CNAME", domain)
		out, err := cmd.CombinedOutput()
		defer cancel()

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
		if status == "NXDOMAIN" || status == "SERVFAIL" || status == "REFUSED" || status == "no servers could be reached." {
			Printfv(ColorBlue+"[ INFO ] Domain '%s' has %s status header. Investigating...\n"+ColorReset, *verbose, *simpleOutput, domain, status)
			vulnDomains = GetDomain(domain, headers, mode, vulnDomains, *simpleOutput, *timeout, save, writer)
		} else if status == "NOERROR" {
			Printfv(ColorBlue+"[ INFO ] Domain '%s' has %s status header. Investigating Answer Section...\n"+ColorReset, *verbose, *simpleOutput, domain, status)
			answerSection := digparser.GetAnswerSection(lines)
			if len(answerSection) > 0 {
				Printfv(ColorBlue+"[ INFO ] CNAME of %s points to %s. Requesting CNAME...\n"+ColorReset, *verbose, *simpleOutput, domain, answerSection["cname"])
				vulnDomains = GetDomain(domain, headers, mode, vulnDomains, *simpleOutput, *timeout, save, writer)
			} else {
				Printfv(ColorBlue+"[ INFO ] Empty Answer Section. Domain '%s' probably not vulnerable\n", *verbose, *simpleOutput, domain)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, ColorRed+"[ ERROR ] Error reading standard input: %s\n"+ColorReset, err)
	}

	if !*simpleOutput {
		fmt.Println()
		fmt.Println(ColorCyan + "Results:")
		fmt.Printf(ColorCyan+"Found %d domains possibly expired, prone to takeover\n"+ColorReset, len(vulnDomains))
		if len(vulnDomains) > 0 {
			for _, d := range vulnDomains {
				fmt.Println(ColorRed, d)
			}
		}
	}

}
