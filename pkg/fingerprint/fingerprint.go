package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
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
	jsonFile, err := os.Open("fingerprints.json")
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		os.Exit(1)
	}
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		os.Exit(1)
	}

	var serviceFingerprints []ServiceFingerprint

	err = json.Unmarshal(byteValue, &serviceFingerprints)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
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
