package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ServiceFingerprint struct {
	CicdPass      bool     `json:"cicd_pass"`
	Cname         []string `json:"cname"`
	Discussion    string   `json:"discussion"`
	Documentation string   `json:"documentation"`
	Fingerprint   string   `json:"fingerprint"`
	HttpStatus    *int     `json:"http_status"` // Pointer to int to handle null
	Nxdomain      bool     `json:"nxdomain"`
	Service       string   `json:"service"`
	Status        string   `json:"status"`
	Vulnerable    bool     `json:"vulnerable"`
}

func JSONtoServiceFingerprint() []ServiceFingerprint {
	res, err := http.Get("https://raw.githubusercontent.com/alexbsec/gotakeover/master/cmd/gotekeover/fingerprints.json")
	if err != nil {
		fmt.Println("Error fetching JSON file:", err)
		os.Exit(1)
	}

	if res.StatusCode != http.StatusOK {
		fmt.Printf("bad status: %s\n", res.Status)
		os.Exit(1)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("reading response body failed: %v\n", err)
		os.Exit(1)
	}

	var serviceFingerprints []ServiceFingerprint
	err = json.Unmarshal(body, &serviceFingerprints)
	if err != nil {
		fmt.Printf("unmarshalling JSON failed: %v\n", err)
		os.Exit(1)
	}

	return serviceFingerprints
}

func CheckFingerprint(responseBody string) (bool, string) {
	fingerprints := JSONtoServiceFingerprint()
	for _, sf := range fingerprints {
		if strings.Contains(responseBody, sf.Fingerprint) && sf.Vulnerable && sf.Fingerprint != "" {
			return true, sf.Service
		}
	}

	return false, ""
}
