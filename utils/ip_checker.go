package utils

import (
	"io"
	"net/http"
	"strings"
)

type IPChecker interface {
	GetIP(url string, client *http.Client) (string, error)
}

type DefaultIPChecker struct{}

func (c *DefaultIPChecker) GetIP(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ip)), nil
}
