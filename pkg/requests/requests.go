package requests

import (
	"net/http"
)

func GetStatusCode(domain string) (int, error) {
	response, err := http.Get(domain)
	if err != nil {
		return 0, err
	}

	defer response.Body.Close()

	return response.StatusCode, nil
}
