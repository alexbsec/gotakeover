package requests

import (
	"net/http"
	"net/url"
	"strings"
)

func GetStatusCode(domain string, headers []map[string]string) (int, error) {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	client := &http.Client{}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		return 0, err
	}

	for _, headerMap := range headers {
		for key, value := range headerMap {
			req.Header.Set(key, value)
		}
	}

	response, err := client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			if urlErr.Op == "Get" && urlErr.URL == domain && urlErr.Err != nil {
				return 0, err
			} else {
				return 0, err
			}
		} else {
			return 0, err
		}
	}

	defer response.Body.Close()

	return response.StatusCode, nil
}
