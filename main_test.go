package main

import (
	"encoding/json"
	"fmt"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"xray-checker/mocks"
	"xray-checker/models"
	uptimekuma "xray-checker/providers/uptime-kuma"
	"xray-checker/utils"
)

type testCase struct {
	name             string
	sourceIP         string
	vpnIP            string
	webhookURL       string
	xrayError        error
	sourceIPError    error
	vpnIPError       error
	webhookError     error
	expectWebhook    bool
	expectedStatus   string
	shouldKillCmd    bool
	expectXrayStart  bool
	expectedWebhooks []string
}

func setupMocks(t *testing.T, tt testCase, configPath string, provider models.Provider) (*mocks.CommandRunner, *mocks.IPChecker) {
	mockCmd := mocks.NewCommandRunner(t)
	mockIP := mocks.NewIPChecker(t)

	// Setup CommandRunner expectations
	if tt.expectXrayStart {
		cmd := exec.Command("echo", "dummy")
		runCmdMock := mockCmd.EXPECT().RunCommand("xray", "-c", configPath)
		if tt.xrayError != nil {
			runCmdMock.Return(nil, tt.xrayError)
		} else {
			runCmdMock.Return(cmd, nil)
			if tt.shouldKillCmd {
				mockCmd.EXPECT().KillCommand(cmd).Return(nil)
			}
		}
	}

	// Setup IPChecker expectations
	ipMock := mockIP.EXPECT().GetIP(provider.GetCheckService(), mock.AnythingOfType("*http.Client"))
	if tt.sourceIPError != nil {
		ipMock.Return(tt.sourceIP, tt.sourceIPError).Once()
	} else {
		ipMock.Return(tt.sourceIP, nil).Once()

		if tt.xrayError == nil && tt.expectXrayStart {
			ipMock.Return(tt.vpnIP, tt.vpnIPError).Once()
		}
	}

	return mockCmd, mockIP
}

func setupWebhookResponders(tt testCase) {
	if tt.expectWebhook {
		for _, webhookURL := range tt.expectedWebhooks {
			if tt.webhookError != nil {
				httpmock.RegisterResponder("GET", webhookURL,
					httpmock.NewErrorResponder(tt.webhookError))
			} else {
				httpmock.RegisterResponder("GET", webhookURL,
					httpmock.NewStringResponder(200, "OK"))
			}
		}
	}
}

func verifyWebhookCalls(t *testing.T, tt testCase) {
	if tt.expectWebhook {
		info := httpmock.GetCallCountInfo()
		for _, webhookURL := range tt.expectedWebhooks {
			count := info[fmt.Sprintf("GET %s", webhookURL)]
			assert.Equal(t, 1, count, "Expected one call to webhook %s, got %d", webhookURL, count)
		}
	}
}

func TestE2EFlow(t *testing.T) {
	tests := []testCase{
		{
			name:            "Success - Different IPs",
			sourceIP:        "1.1.1.1",
			vpnIP:           "2.2.2.2",
			webhookURL:      "http://uptime-kuma/test?status=up&msg=OK&ping=",
			expectWebhook:   true,
			expectedStatus:  "Success",
			shouldKillCmd:   true,
			expectXrayStart: true,
			expectedWebhooks: []string{
				"http://uptime-kuma/test?status=up&msg=OK&ping=",
			},
		},
		{
			name:            "No Change - Same IPs",
			sourceIP:        "1.1.1.1",
			vpnIP:           "1.1.1.1",
			webhookURL:      "http://uptime-kuma/test?status=up&msg=OK&ping=",
			expectWebhook:   false,
			expectedStatus:  "IP addresses match, status not sent",
			shouldKillCmd:   true,
			expectXrayStart: true,
		},
		{
			name:            "Failure - Xray Error",
			sourceIP:        "1.1.1.1",
			vpnIP:           "",
			webhookURL:      "http://uptime-kuma/test",
			xrayError:       fmt.Errorf("xray failed"),
			expectWebhook:   false,
			expectedStatus:  "Error",
			shouldKillCmd:   false,
			expectXrayStart: true,
		},
		{
			name:            "Failure - Source IP Error",
			sourceIP:        "",
			vpnIP:           "",
			webhookURL:      "http://uptime-kuma/test",
			sourceIPError:   fmt.Errorf("failed to get source IP"),
			expectWebhook:   false,
			expectedStatus:  "Error",
			shouldKillCmd:   false,
			expectXrayStart: false,
		},
		{
			name:            "Failure - VPN IP Error",
			sourceIP:        "1.1.1.1",
			vpnIP:           "",
			webhookURL:      "http://uptime-kuma/test",
			vpnIPError:      fmt.Errorf("failed to get VPN IP"),
			expectWebhook:   false,
			expectedStatus:  "Error",
			shouldKillCmd:   true,
			expectXrayStart: true,
		},
		{
			name:            "Failure - Webhook Error",
			sourceIP:        "1.1.1.1",
			vpnIP:           "2.2.2.2",
			webhookURL:      "http://uptime-kuma/test?status=up&msg=OK&ping=",
			webhookError:    fmt.Errorf("webhook failed"),
			expectWebhook:   true,
			expectedStatus:  "Error",
			shouldKillCmd:   true,
			expectXrayStart: true,
			expectedWebhooks: []string{
				"http://uptime-kuma/test?status=up&msg=OK&ping=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup httpmock
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			provider := createUptimeKumaProvider(t)

			configPath := createTestConfig(t, tt.webhookURL)
			defer os.Remove(configPath)

			// Setup mocks using helper
			mockCmd, mockIP := setupMocks(t, tt, configPath, provider)

			// Setup webhook responders
			setupWebhookResponders(tt)

			service := &XrayCheckerService{
				commandRunner: mockCmd,
				ipChecker:     mockIP,
			}

			// Process the config
			service.ProcessConfigFile(configPath, provider)

			// Verify expectations
			mockCmd.AssertExpectations(t)
			mockIP.AssertExpectations(t)

			// Verify webhook calls
			verifyWebhookCalls(t, tt)
		})
	}
}

func TestDefaultIPChecker_GetIP(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tests := []struct {
		name        string
		url         string
		response    string
		statusCode  int
		err         error
		expectError bool
	}{
		{
			name:       "Successful IP Check",
			url:        "https://ifconfig.io",
			response:   "1.2.3.4\n",
			statusCode: 200,
		},
		{
			name:        "Server Error",
			url:         "https://ifconfig.io",
			statusCode:  500,
			expectError: true,
		},
		{
			name:        "Network Error",
			url:         "https://ifconfig.io",
			err:         fmt.Errorf("network error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err != nil {
				httpmock.RegisterResponder("GET", tt.url,
					httpmock.NewErrorResponder(tt.err))
			} else {
				httpmock.RegisterResponder("GET", tt.url,
					httpmock.NewStringResponder(tt.statusCode, tt.response))
			}

			checker := &utils.DefaultIPChecker{}
			client := &http.Client{}

			ip, err := checker.GetIP(tt.url, client)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, strings.TrimSpace(tt.response), ip)
			}
		})
	}
}

func TestProviderFactory(t *testing.T) {
	tests := []struct {
		name          string
		providerType  string
		config        string
		expectError   bool
		errorContains string
	}{
		{
			name:         "Valid UptimeKuma Config",
			providerType: "uptime-kuma",
			config: `{
				"name": "uptime-kuma",
				"proxyStartPort": 10000,
				"interval": 30,
				"workers": 1,
				"checkIpService": "http://ip-check.test",
				"configs": []
			}`,
			expectError: false,
		},
		{
			name:          "Unknown Provider",
			providerType:  "unknown",
			config:        "{}",
			expectError:   true,
			errorContains: "unknown provider",
		},
		{
			name:         "Invalid Config JSON",
			providerType: "uptime-kuma",
			config:       "{invalid json}",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := uptimekuma.ProviderFactory(tt.providerType, json.RawMessage(tt.config))

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				assert.Equal(t, tt.providerType, provider.GetName())
			}
		})
	}
}
