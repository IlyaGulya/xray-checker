package link

import (
	"testing"
	"xray-checker/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
		validate    func(*testing.T, *domain.ParsedLink)
	}{
		{
			name: "Valid VLESS link",
			url:  "vless://uuid@example.com:443?security=reality&type=tcp&fp=chrome&pbk=publicKey&sid=shortId",
			validate: func(t *testing.T, p *domain.ParsedLink) {
				assert.Equal(t, "vless", p.Protocol)
				assert.Equal(t, "uuid", p.UID)
				assert.Equal(t, "example.com", p.Server)
				assert.Equal(t, "443", p.Port)
				assert.Equal(t, "reality", p.Security)
			},
		},
		{
			name: "Valid Trojan link",
			url:  "trojan://password@example.com:443?security=tls&type=ws&path=/path&host=example.com",
			validate: func(t *testing.T, p *domain.ParsedLink) {
				assert.Equal(t, "trojan", p.Protocol)
				assert.Equal(t, "password", p.UID)
				assert.Equal(t, "ws", p.Type)
				assert.Equal(t, "/path", p.Path)
			},
		},
		{
			name: "Valid Shadowsocks link",
			url:  "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:443",
			validate: func(t *testing.T, p *domain.ParsedLink) {
				assert.Equal(t, "shadowsocks", p.Protocol)
				assert.Equal(t, "chacha20-ietf-poly1305", p.Method)
				assert.Equal(t, "password", p.UID)
			},
		},
		{
			name:        "Invalid URL format",
			url:         "invalid://url",
			expectError: true,
		},
		{
			name:        "Unsupported protocol",
			url:         "unknown://test@example.com:443",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.url)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, parsed)

			if tt.validate != nil {
				tt.validate(t, parsed)
			}
		})
	}
}
