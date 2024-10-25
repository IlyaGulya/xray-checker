package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		envVars     map[string]string
		expectError bool
		validate    func(*testing.T, *Config)
	}{
		{
			name: "Valid config",
			configJSON: `{
				"templates_dir": "templates",
				"xray_configs_dir": "configs",
				"workers": {
					"count": 2,
					"check_interval": 60,
					"proxy_start_port": 10000,
					"check_ip_service": "http://ip-api.com"
				},
				"links": [
					{
						"name": "test-link",
						"url": "vless://test@example.com:443"
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "configs", cfg.XrayConfigsDir)
				assert.Equal(t, 2, cfg.Workers.Count)
				assert.Equal(t, 60, cfg.Workers.CheckInterval)
			},
		},
		{
			name: "Missing required fields",
			configJSON: `{
				"templates_dir": "templates"
			}`,
			expectError: true,
		},
		{
			name: "Invalid worker count",
			configJSON: `{
				"templates_dir": "templates",
				"xray_configs_dir": "configs",
				"workers": {
					"count": -1
				}
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			err := os.WriteFile(configPath, []byte(tt.configJSON), 0644)
			require.NoError(t, err)

			// Set environment variables
			t.Setenv("CONFIG_PATH", configPath)
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Test config loading
			cfg, err := NewConfig()
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}
