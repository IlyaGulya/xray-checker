package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

type TestConfigData struct {
	Provider struct {
		Name           string `json:"name"`
		ProxyStartPort int    `json:"proxyStartPort"`
		Interval       int    `json:"interval"`
		Workers        int    `json:"workers"`
		CheckIpService string `json:"checkIpService"`
		Configs        []struct {
			Link        string `json:"link"`
			MonitorLink string `json:"monitorLink"`
		} `json:"configs"`
	} `json:"provider"`
}

// SetupTestConfig creates a test configuration file and returns its path
func SetupTestConfig(t *testing.T, testEnv *TestEnvironment, protocol, port string) string {
	t.Helper()

	configData := TestConfigData{}
	configData.Provider.Name = "uptime-kuma"
	configData.Provider.ProxyStartPort = 20000
	configData.Provider.Interval = 1
	configData.Provider.Workers = 1
	configData.Provider.CheckIpService = testEnv.MockIPService.URL

	// Create link based on protocol with proper container DNS names
	link, err := getProtocolLink(protocol, fmt.Sprintf("%s-server", protocol), port)
	require.NoError(t, err, "Failed to generate protocol link")

	monitorLink := fmt.Sprintf("%s/%s", testEnv.MockUptime.URL, protocol)

	configData.Provider.Configs = []struct {
		Link        string `json:"link"`
		MonitorLink string `json:"monitorLink"`
	}{
		{
			Link:        link,
			MonitorLink: monitorLink,
		},
	}

	// Ensure build/configs directory exists
	configsDir := filepath.Join("build", "configs")
	require.NoError(t, os.MkdirAll(configsDir, 0755), "Failed to create configs directory")

	// Create config file path
	configPath := filepath.Join(configsDir, fmt.Sprintf("%s-test-config.json", protocol))

	// Marshal config data with proper error handling
	configBytes, err := json.MarshalIndent(configData, "", "    ")
	require.NoError(t, err, "Failed to marshal config data")

	// Write config file with proper error handling
	err = os.WriteFile(configPath, configBytes, 0644)
	require.NoError(t, err, "Failed to write config file")

	return configPath
}

func getProtocolLink(protocol, host, port string) (string, error) {
	switch protocol {
	case "vless":
		return fmt.Sprintf("vless://test-uuid@%s:%s?security=none&type=tcp&flow=&fp=chrome&pbk=&sid=#%s-test",
			host, port, protocol), nil
	case "trojan":
		// For Trojan, ensure SNI matches the container hostname
		return fmt.Sprintf("trojan://test-password@%s:%s?security=tls&type=tcp&host=%s&sni=%s&fp=chrome#%s-test",
			host, port, host, host, protocol), nil
	case "shadowsocks":
		userInfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:test-password"))
		return fmt.Sprintf("ss://%s@%s:%s#%s-test",
			userInfo, host, port, protocol), nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func validateConfig(t *testing.T, configPath string) error {
	t.Helper()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config TestConfigData
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate required fields
	if config.Provider.Name == "" {
		return fmt.Errorf("provider name is required")
	}

	if config.Provider.CheckIpService == "" {
		return fmt.Errorf("checkIpService is required")
	}

	if len(config.Provider.Configs) == 0 {
		return fmt.Errorf("at least one config is required")
	}

	for i, cfg := range config.Provider.Configs {
		if cfg.Link == "" {
			return fmt.Errorf("config[%d]: link is required", i)
		}
		if cfg.MonitorLink == "" {
			return fmt.Errorf("config[%d]: monitorLink is required", i)
		}
	}

	return nil
}
