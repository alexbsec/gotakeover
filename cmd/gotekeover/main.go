package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"

	"github.com/alexbsec/gotakeover/pkg/digparser"
)

func main() {
	// add flags

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		cmd := exec.Command("dig", "CNAME", domain)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return
		}
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "Failed to execute command: %s\n", err)
		// 	continue
		// }
		// res := strings.TrimSpace(string(out))
		// if res != "" {
		// 	fmt.Printf("%s has CNAME record: %s\n", domain, out)
		// } else {
		// 	fmt.Printf("%s has no CNAME record", domain)
		// }
		lines := digparser.ParseLine(string(out))
		header := digparser.GetHeader(lines)
		fmt.Println(header)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading standard input: %s\n", err)
	}

}
