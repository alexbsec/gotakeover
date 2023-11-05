package requests

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func Get(domain string, headers []map[string]string, timeout time.Duration) (*http.Response, error) {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	client := &http.Client{
		Timeout: timeout * time.Second,
	}

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

	return response, nil
}
