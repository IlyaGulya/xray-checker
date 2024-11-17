package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"xray-checker/internal/domain"
	"xray-checker/internal/metrics"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"xray-checker/internal/config"
)

type Service struct {
	runner     Runner
	logger     *zap.Logger
	configPath ConfigPath
	metrics    *metrics.Collector
	proxyPorts map[domain.LinkName]int // Maps link names to their ports
}

func NewService(
	lc fx.Lifecycle,
	cfg *config.Config,
	links []domain.ParsedLink,
	metrics *metrics.Collector,
	runner Runner,
	logger *zap.Logger,
) (*Service, error) {
	if cfg.Workers.ProxyStartPort <= 0 || cfg.Workers.ProxyStartPort > 65535 {
		return nil, fmt.Errorf("invalid proxy start port: %d", cfg.Workers.ProxyStartPort)
	}

	// Validate if there's enough ports available
	maxPort := cfg.Workers.ProxyStartPort + len(links) - 1
	if maxPort > 65535 {
		return nil, fmt.Errorf("not enough available ports for all links: need %d ports starting from %d",
			len(links), cfg.Workers.ProxyStartPort)
	}

	// Initialize proxy ports map
	proxyPorts := make(map[domain.LinkName]int, len(links))
	for i, link := range links {
		if link.LinkName == "" {
			return nil, fmt.Errorf("link name cannot be empty")
		}
		if _, exists := proxyPorts[link.LinkName]; exists {
			return nil, fmt.Errorf("duplicate link name found: %s", link.LinkName)
		}
		proxyPorts[link.LinkName] = cfg.Workers.ProxyStartPort + i
	}

	service := &Service{
		runner:     runner,
		logger:     logger,
		configPath: ConfigPath(filepath.Join(cfg.XrayConfigsDir, "unified-config.json")),
		metrics:    metrics,
		proxyPorts: proxyPorts,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := service.generateConfig(links); err != nil {
				return fmt.Errorf("failed to generate config: %w", err)
			}

			if err := service.runner.Start(service.configPath); err != nil {
				return fmt.Errorf("failed to start xray: %w", err)
			}
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return service.runner.Stop()
		},
	})

	return service, nil
}

// GetProxyConfig returns the proxy configuration for a given link
func (s *Service) GetProxyConfig(linkName domain.LinkName) (string, int, error) {
	if linkName == "" {
		return "", 0, fmt.Errorf("link name cannot be empty")
	}

	port, exists := s.proxyPorts[linkName]
	if !exists {
		return "", 0, fmt.Errorf("no proxy configuration found for link: %s", linkName)
	}

	return "127.0.0.1", port, nil
}

func (s *Service) generateConfig(links []domain.ParsedLink) error {
	if len(links) == 0 {
		return fmt.Errorf("no links provided for configuration")
	}

	cfg := &Config{
		Log: LogConfig{
			LogLevel: "debug",
		},
		Inbounds:  make([]InboundConfig, 0, len(links)),
		Outbounds: getDefaultOutbounds(),
		Routing: RoutingConfig{
			Rules: make([]RoutingRule, 0, len(links)),
		},
	}

	for _, l := range links {
		port := s.proxyPorts[l.LinkName] // Use stored port directly

		// Use sanitized names for tags
		inboundTag := fmt.Sprintf("inbound-%s", url.QueryEscape(string(l.LinkName)))
		outboundTag := fmt.Sprintf("outbound-%s", url.QueryEscape(string(l.LinkName)))

		// Add inbound configuration
		cfg.Inbounds = append(cfg.Inbounds, InboundConfig{
			Tag:      inboundTag,
			Listen:   "127.0.0.1",
			Port:     port,
			Protocol: "socks",
			Sniffing: SniffingConfig{
				Enabled:      true,
				DestOverride: []string{"http", "tls", "quic"},
				RouteOnly:    true,
			},
		})

		// Generate outbound configuration
		outbound, err := generateOutbound(l, outboundTag)
		if err != nil {
			return fmt.Errorf("failed to generate outbound for %s: %w", l.LinkName, err)
		}

		cfg.Outbounds = append(cfg.Outbounds, outbound)
		cfg.Routing.Rules = append(cfg.Routing.Rules, RoutingRule{
			Type:        "field",
			InboundTag:  inboundTag,
			OutboundTag: outboundTag,
		})
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(string(s.configPath)), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(string(s.configPath), data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	s.logger.Debug("generated xray config", zap.String("config", string(data)))

	return nil
}

func generateOutbound(l domain.ParsedLink, tag string) (OutboundConfig, error) {
	var settings, streamSettings json.RawMessage
	port, err := strconv.Atoi(l.Port)
	if err != nil {
		return OutboundConfig{}, fmt.Errorf("invalid port number: %w", err)
	}

	// Create clean settings without any URL-encoded characters
	switch l.Protocol {
	case "vless":
		settingsMap := map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": l.Server,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":         l.UID,
							"encryption": "none",
							"flow":       l.Flow,
						},
					},
				},
			},
		}

		settingsJSON, err := json.Marshal(settingsMap)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("failed to marshal vless settings: %w", err)
		}
		settings = settingsJSON

		// Create stream settings for VLESS
		streamSettingsMap := map[string]interface{}{
			"network":  l.Type,
			"security": l.Security,
		}

		// Always include tcpSettings for TCP transport
		if l.Type == "tcp" {
			headerType := "none"
			if l.HeaderType != "" {
				headerType = l.HeaderType
			}
			streamSettingsMap["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": headerType,
				},
			}
		}

		// Add reality settings if security is reality
		if l.Security == "reality" {
			streamSettingsMap["realitySettings"] = map[string]interface{}{
				"serverName":  l.SNI,
				"fingerprint": l.FP,
				"publicKey":   l.PBK,
				"shortId":     l.SID,
			}
		}

		streamSettingsJSON, err := json.Marshal(streamSettingsMap)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("failed to marshal stream settings: %w", err)
		}
		streamSettings = streamSettingsJSON

	case "trojan":
		settings = json.RawMessage(fmt.Sprintf(`{
        "servers": [{
            "address": "%s",
            "port": %d,
            "password": "%s"
        }]
    }`, l.Server, port, l.UID))

		// Enhanced stream settings with proper transport settings
		streamSettingsMap := map[string]interface{}{
			"network":  l.Type,
			"security": l.Security,
		}

		// Add transport-specific settings
		switch l.Type {
		case "tcp":
			headerType := "none"
			if l.HeaderType != "" {
				headerType = l.HeaderType
			}
			streamSettingsMap["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": headerType,
				},
			}
		case "ws":
			wsSettings := map[string]interface{}{}

			// Add path if specified
			if l.Path != "" {
				wsSettings["path"] = l.Path
			}

			// Add headers if host is specified
			if l.Host != "" {
				wsSettings["headers"] = map[string]interface{}{
					"Host": l.Host,
				}
			}

			// Always include wsSettings, even if empty
			streamSettingsMap["wsSettings"] = wsSettings
		}

		// Add TLS settings if security is tls
		if l.Security == "tls" {
			streamSettingsMap["tlsSettings"] = map[string]interface{}{
				"serverName":    l.SNI,
				"allowInsecure": false,
			}
		}

		streamSettingsJSON, err := json.Marshal(streamSettingsMap)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("failed to marshal stream settings: %w", err)
		}
		streamSettings = streamSettingsJSON
	case "shadowsocks":
		settingsMap := map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  l.Server,
					"method":   l.Method,
					"password": l.UID,
					"port":     port,
				},
			},
		}

		settingsJSON, err := json.Marshal(settingsMap)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("failed to marshal shadowsocks settings: %w", err)
		}
		settings = settingsJSON

		// Create stream settings for Shadowsocks
		streamSettingsMap := map[string]interface{}{
			"network":  l.Type,
			"security": l.Security,
		}

		// Add transport-specific settings
		switch l.Type {
		case "tcp":
			headerType := "none"
			if l.HeaderType != "" {
				headerType = l.HeaderType
			}
			streamSettingsMap["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": headerType,
				},
			}
		case "ws":
			wsSettings := map[string]interface{}{}

			// Add path if specified
			if l.Path != "" {
				wsSettings["path"] = l.Path
			}

			// Add headers if host is specified
			if l.Host != "" {
				wsSettings["headers"] = map[string]interface{}{
					"Host": l.Host,
				}
			}

			// Always include wsSettings, even if empty
			streamSettingsMap["wsSettings"] = wsSettings
		}

		streamSettingsJSON, err := json.Marshal(streamSettingsMap)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("failed to marshal stream settings: %w", err)
		}
		streamSettings = streamSettingsJSON

	default:
		return OutboundConfig{}, fmt.Errorf("unsupported protocol: %s", l.Protocol)
	}

	return OutboundConfig{
		Tag:            tag,
		Protocol:       l.Protocol,
		Settings:       settings,
		StreamSettings: streamSettings,
	}, nil
}

func getDefaultOutbounds() []OutboundConfig {
	return []OutboundConfig{
		{
			Tag:      "direct",
			Protocol: "freedom",
			Settings: json.RawMessage(`{"domainStrategy":"UseIP"}`),
		},
		{
			Tag:      "block",
			Protocol: "blackhole",
			Settings: json.RawMessage(`{}`),
		},
		{
			Tag:      "dns-out",
			Protocol: "dns",
			Settings: json.RawMessage(`{"port":53,"address":"119.29.29.29","network":"udp"}`),
		},
	}
}
