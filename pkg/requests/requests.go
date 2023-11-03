package requests

import (
	"net/http"
	"net/url"
	"strings"
)

func Get(domain string, headers []map[string]string) (*http.Response, error) {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	client := &http.Client{}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		return nil, err
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
				return nil, err
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	defer response.Body.Close()

	return response, nil
}
