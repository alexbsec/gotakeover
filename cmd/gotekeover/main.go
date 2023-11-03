package main

import (
	"bufio"
	"fmt"
	"gotakeover/pkg/digparser"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// add flags

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		cmd := exec.Command("dig", "CNAME", domain)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to execute command: %s\n", err)
			continue
		}
		res := strings.TrimSpace(string(out))
		if res != "" {
			fmt.Printf("%s has CNAME record: %s\n", domain, out)
		} else {
			fmt.Printf("%s has no CNAME record", domain)
		}
	}
	digparser.ParseLine(out)

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading standard input: %s\n", err)
	}

}
