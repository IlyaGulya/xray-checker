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
	"time"
	"xray-checker/internal/domain"
	"xray-checker/internal/metrics"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"xray-checker/internal/config"
)

// Config structures for XRay
type (
	Config struct {
		Log       LogConfig        `json:"log"`
		Inbounds  []InboundConfig  `json:"inbounds"`
		Outbounds []OutboundConfig `json:"outbounds"`
		Routing   RoutingConfig    `json:"routing"`
	}

	LogConfig struct {
		LogLevel string `json:"loglevel"`
	}

	InboundConfig struct {
		Tag      string         `json:"tag"`
		Listen   string         `json:"listen"`
		Port     int            `json:"port"`
		Protocol string         `json:"protocol"`
		Sniffing SniffingConfig `json:"sniffing"`
	}

	SniffingConfig struct {
		Enabled      bool     `json:"enabled"`
		DestOverride []string `json:"destOverride"`
		RouteOnly    bool     `json:"routeOnly"`
	}

	OutboundConfig struct {
		Tag            string          `json:"tag"`
		Protocol       string          `json:"protocol"`
		Settings       json.RawMessage `json:"settings"`
		StreamSettings json.RawMessage `json:"streamSettings,omitempty"`
	}

	RoutingConfig struct {
		Rules []RoutingRule `json:"rules"`
	}

	RoutingRule struct {
		Type        string `json:"type"`
		InboundTag  string `json:"inboundTag"`
		OutboundTag string `json:"outboundTag"`
	}
)

// Service manages a single XRay instance for all checks
type proxyConfig struct {
	address string
	port    int
}

type Service struct {
	logger        *zap.Logger
	runner        Runner
	configDir     string
	unifiedConfig ConfigPath
	proxyConfigs  map[domain.LinkName]proxyConfig
	mutex         sync.RWMutex
	metrics       *metrics.Collector
	health        *healthChecker
	retryConfig   retryConfig
}

type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

type healthChecker struct {
	lastCheck     time.Time
	status        bool
	checkInterval time.Duration
	initialized   bool
	mutex         sync.RWMutex
}

func NewService(
	lc fx.Lifecycle,
	cfg *config.Config,
	links []domain.ParsedLink,
	metrics *metrics.Collector,
	logger *zap.Logger,
) (*Service, error) {
	service := &Service{
		logger:        logger,
		runner:        NewRunner(logger),
		configDir:     cfg.XrayConfigsDir,
		proxyConfigs:  make(map[domain.LinkName]proxyConfig),
		unifiedConfig: ConfigPath(filepath.Join(cfg.XrayConfigsDir, "unified-config.json")),
		metrics:       metrics,
		health: &healthChecker{
			checkInterval: 30 * time.Second,
			// Initialize with false status
			status:      false,
			initialized: false,
		},
		retryConfig: retryConfig{
			maxAttempts: 3,
			baseDelay:   time.Second,
			maxDelay:    10 * time.Second,
		},
	}

	if err := service.initializeProxyConfigs(cfg, links); err != nil {
		return nil, fmt.Errorf("failed to initialize proxy configs: %w", err)
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := service.generateConfig(links); err != nil {
				return fmt.Errorf("failed to generate config: %w", err)
			}
			if err := service.start(); err != nil {
				return err
			}

			// Perform initial health check
			service.health.mutex.Lock()
			service.health.status = service.runner.IsRunning()
			service.health.initialized = true
			service.health.lastCheck = time.Now()
			service.health.mutex.Unlock()

			// Start health checker
			go service.healthCheckLoop(ctx)
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return service.stop()
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

func (s *Service) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.health.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkHealth()
		}
	}
}

func (s *Service) checkHealth() {
	s.health.mutex.Lock()
	defer s.health.mutex.Unlock()

	isHealthy := s.runner.IsRunning()
	if !isHealthy && s.health.status {
		// Service was healthy but now isn't - attempt recovery
		s.logger.Warn("xray service unhealthy, attempting recovery")
		if err := s.recoverService(); err != nil {
			s.logger.Error("failed to recover xray service", zap.Error(err))
		}
	}

	s.health.status = isHealthy
	s.health.lastCheck = time.Now()
}

func (s *Service) recoverService() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Stop existing service
	if err := s.runner.Stop(); err != nil {
		s.logger.Error("failed to stop unhealthy service", zap.Error(err))
	}

	// Attempt to restart with exponential backoff
	var lastErr error
	for attempt := 0; attempt < s.retryConfig.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := s.calculateBackoff(attempt)
			time.Sleep(delay)
		}

		if err := s.runner.Start(s.unifiedConfig); err != nil {
			lastErr = err
			s.logger.Error("failed to restart xray service",
				zap.Error(err),
				zap.Int("attempt", attempt+1))
			continue
		}

		s.metrics.RecordXrayRestart()
		s.logger.Info("xray service recovered successfully",
			zap.Int("attempt", attempt+1))
		return nil
	}

	return fmt.Errorf("failed to recover xray service after %d attempts: %w",
		s.retryConfig.maxAttempts, lastErr)
}

func (s *Service) calculateBackoff(attempt int) time.Duration {
	delay := s.retryConfig.baseDelay * time.Duration(1<<uint(attempt))
	if delay > s.retryConfig.maxDelay {
		delay = s.retryConfig.maxDelay
	}
	return delay
}

func (s *Service) GetProxyConfig(linkName domain.LinkName) (string, int, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.IsHealthy() {
		return "", 0, fmt.Errorf("xray service is unhealthy")
	}

	config, exists := s.proxyConfigs[linkName]
	if !exists {
		return "", 0, fmt.Errorf("no proxy configuration found for link: %s", linkName)
	}

	return config.address, config.port, nil
}

func (s *Service) IsHealthy() bool {
	s.health.mutex.RLock()
	defer s.health.mutex.RUnlock()

	if !s.health.initialized {
		return false
	}

	return s.health.status && time.Since(s.health.lastCheck) <= s.health.checkInterval*2
}

func (s *Service) WaitForInitialization(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.health.mutex.RLock()
			initialized := s.health.initialized
			s.health.mutex.RUnlock()

			if initialized {
				return nil
			}
		}
	}
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
	if err := os.MkdirAll(filepath.Dir(string(s.unifiedConfig)), 0755); err != nil {
		return fmt.Errorf("failed to create cfg directory: %w", err)
	}

	// Write and validate the final cfg
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cfg: %w", err)
	}

	if err := os.WriteFile(string(s.unifiedConfig), data, 0644); err != nil {
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

// Add transport protocol validation
func isValidTransportProtocol(protocol string) bool {
	validProtocols := map[string]bool{
		"tcp":  true,
		"ws":   true,
		"http": true,
		"grpc": true,
		"quic": true,
		"kcp":  true,
	}
	return validProtocols[protocol]
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

func (s *Service) start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.runner.Start(s.unifiedConfig); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}

	// Wait for XRay to initialize
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Keep checking XRay's running state
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for xray to start")
		case <-ticker.C:
			if s.runner.IsRunning() {
				s.logger.Info("xray service started and running")
				return nil
			}
		}
	}
}

func (s *Service) stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.runner.Stop()
}
