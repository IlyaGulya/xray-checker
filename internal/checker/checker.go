package checker

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type defaultIPChecker struct {
	checkURL string
	client   *http.Client
}

func createDefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
	}
}

func (c *defaultIPChecker) GetDirectIP() (string, error) {
	return c.getIPUsingClient(c.client)
}

func (c *defaultIPChecker) GetProxiedIP(proxyAddr string) (string, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return "", fmt.Errorf("invalid proxy address: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 20 * time.Second,
	}

	return c.getIPUsingClient(client)
}

func (c *defaultIPChecker) getIPUsingClient(client *http.Client) (string, error) {
	resp, err := client.Get(c.checkURL)
	if err != nil {
		return "", fmt.Errorf("failed to get IP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}
