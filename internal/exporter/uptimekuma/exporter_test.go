package uptimekuma

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xray-checker/internal/domain"
)

func TestUptimeKumaExporter(t *testing.T) {
	tests := []struct {
		name        string
		metrics     domain.Metrics
		expectPing  bool
		serverError bool
	}{
		{
			name: "Different IPs - should ping",
			metrics: domain.Metrics{
				LinkName:  "test",
				Status:    "Success",
				SourceIP:  "1.1.1.1",
				VPNIP:     "2.2.2.2",
				TimeStamp: time.Now(),
			},
			expectPing: true,
		},
		{
			name: "Same IPs - should not ping",
			metrics: domain.Metrics{
				LinkName:  "test",
				Status:    "Failed",
				SourceIP:  "1.1.1.1",
				VPNIP:     "1.1.1.1",
				TimeStamp: time.Now(),
			},
			expectPing: false,
		},
		{
			name: "Server error",
			metrics: domain.Metrics{
				LinkName:  "test",
				Status:    "Success",
				SourceIP:  "1.1.1.1",
				VPNIP:     "2.2.2.2",
				TimeStamp: time.Now(),
			},
			expectPing:  true,
			serverError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pingCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pingCount++
				if tt.serverError {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			config := Config{
				MonitorURL: server.URL,
			}
			configJSON, err := json.Marshal(config)
			require.NoError(t, err)

			exporter, err := New(configJSON)
			require.NoError(t, err)

			err = exporter.Export(tt.metrics)
			if tt.serverError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectPing {
				assert.Equal(t, 1, pingCount)
			} else {
				assert.Equal(t, 0, pingCount)
			}
		})
	}
}
