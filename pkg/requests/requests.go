package requests

import (
	"net/http"
	"net/url"
	"strings"
)

func GetStatusCode(domain string) (int, error) {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	response, err := http.Get(domain)
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
