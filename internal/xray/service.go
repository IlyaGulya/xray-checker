package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"xray-checker/internal/domain"
	"xray-checker/internal/metrics"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"xray-checker/internal/config"
)

// Service manages a single XRay instance for all checks
type proxyConfig struct {
	address string
	port    int
}

type Service struct {
	runner       Runner
	logger       *zap.Logger
	configDir    string
	configPath   ConfigPath
	proxyConfigs map[domain.LinkName]proxyConfig
	metrics      *metrics.Collector
	mutex        sync.RWMutex // needed for proxyConfigs access
}

func NewService(
	lc fx.Lifecycle,
	cfg *config.Config,
	links []domain.ParsedLink,
	metrics *metrics.Collector,
	runner Runner,
	logger *zap.Logger,
) (*Service, error) {
	service := &Service{
		runner:       runner,
		logger:       logger,
		configDir:    cfg.XrayConfigsDir,
		configPath:   ConfigPath(filepath.Join(cfg.XrayConfigsDir, "unified-config.json")),
		proxyConfigs: make(map[domain.LinkName]proxyConfig),
		metrics:      metrics,
	}

	// Initialize proxy configurations first
	if err := service.initializeProxyConfigs(cfg, links); err != nil {
		return nil, fmt.Errorf("failed to initialize proxy configs: %w", err)
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			// Generate XRay config before starting
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

func (s *Service) initializeProxyConfigs(cfg *config.Config, links []domain.ParsedLink) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate inputs
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if len(links) == 0 {
		return fmt.Errorf("no links provided")
	}
	if cfg.Workers.ProxyStartPort <= 0 || cfg.Workers.ProxyStartPort > 65535 {
		return fmt.Errorf("invalid proxy start port: %d", cfg.Workers.ProxyStartPort)
	}

	// Check if there's enough available ports
	maxPort := cfg.Workers.ProxyStartPort + len(links) - 1
	if maxPort > 65535 {
		return fmt.Errorf("not enough available ports for all links: need %d ports starting from %d",
			len(links), cfg.Workers.ProxyStartPort)
	}

	// Initialize proxy configurations
	currentPort := cfg.Workers.ProxyStartPort
	for _, link := range links {
		if link.LinkName == "" {
			return fmt.Errorf("link name cannot be empty")
		}

		// Check for duplicate link names
		if _, exists := s.proxyConfigs[link.LinkName]; exists {
			return fmt.Errorf("duplicate link name found: %s", link.LinkName)
		}

		// Store proxy configuration
		s.proxyConfigs[link.LinkName] = proxyConfig{
			address: "127.0.0.1", // Using localhost for SOCKS5 proxy
			port:    currentPort,
		}

		s.logger.Debug("initialized proxy config",
			zap.String("link", string(link.LinkName)),
			zap.Int("port", currentPort))

		currentPort++
	}

	return nil
}

// GetProxyConfig returns the proxy configuration for a given link
func (s *Service) GetProxyConfig(linkName domain.LinkName) (string, int, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	cfg, exists := s.proxyConfigs[linkName]
	if !exists {
		return "", 0, fmt.Errorf("no proxy configuration found for link: %s", linkName)
	}

	return cfg.address, cfg.port, nil
}

func (s *Service) generateConfig(links []domain.ParsedLink) error {
	// Validate input
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
		if l.LinkName == "" {
			return fmt.Errorf("link name cannot be empty")
		}

		proxyConfig, exists := s.proxyConfigs[l.LinkName]
		if !exists {
			return fmt.Errorf("proxy configuration not found for link: %s", l.LinkName)
		}

		// Use sanitized names for tags
		inboundTag := fmt.Sprintf("inbound-%s", url.QueryEscape(string(l.LinkName)))
		outboundTag := fmt.Sprintf("outbound-%s", url.QueryEscape(string(l.LinkName)))

		// Add inbound configuration
		cfg.Inbounds = append(cfg.Inbounds, InboundConfig{
			Tag:      inboundTag,
			Listen:   proxyConfig.address,
			Port:     proxyConfig.port,
			Protocol: "socks",
			Sniffing: SniffingConfig{
				Enabled:      true,
				DestOverride: []string{"http", "tls", "quic"},
				RouteOnly:    true,
			},
		})

		// Generate and validate outbound configuration
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

	// Create cfg directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(string(s.configPath)), 0755); err != nil {
		return fmt.Errorf("failed to create cfg directory: %w", err)
	}

	// Write and validate the final cfg
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cfg: %w", err)
	}

	if err := os.WriteFile(string(s.configPath), data, 0644); err != nil {
		return fmt.Errorf("failed to write cfg file: %w", err)
	}

	// Log the cfg for debugging
	s.logger.Debug("generated xray cfg", zap.String("cfg", string(data)))

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
