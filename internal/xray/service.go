package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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

	config := &Config{
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
		config.Inbounds = append(config.Inbounds, InboundConfig{
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

		// Validate the outbound configuration
		if err := validateOutboundConfig(outbound); err != nil {
			return fmt.Errorf("invalid outbound configuration for %s: %w", l.LinkName, err)
		}

		config.Outbounds = append(config.Outbounds, outbound)
		config.Routing.Rules = append(config.Routing.Rules, RoutingRule{
			Type:        "field",
			InboundTag:  inboundTag,
			OutboundTag: outboundTag,
		})
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(string(s.unifiedConfig)), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write and validate the final config
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(string(s.unifiedConfig), data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Log the config for debugging
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

// in internal/xray/service.go

// validateOutboundConfig ensures the outbound configuration is valid
func validateOutboundConfig(outbound OutboundConfig) error {
	// Check required fields
	if outbound.Tag == "" {
		return fmt.Errorf("outbound tag is required")
	}

	if outbound.Protocol == "" {
		return fmt.Errorf("outbound protocol is required")
	}

	// Validate protocol-specific settings
	var settings map[string]interface{}
	if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
		return fmt.Errorf("invalid settings JSON: %w", err)
	}

	switch outbound.Protocol {
	case "vless":
		if err := validateVlessSettings(settings); err != nil {
			return fmt.Errorf("invalid vless settings: %w", err)
		}
	case "trojan":
		if err := validateTrojanSettings(settings); err != nil {
			return fmt.Errorf("invalid trojan settings: %w", err)
		}
	case "shadowsocks":
		if err := validateShadowsocksSettings(settings); err != nil {
			return fmt.Errorf("invalid shadowsocks settings: %w", err)
		}
	case "freedom", "blackhole", "dns":
		// Built-in protocols don't need validation
		return nil
	default:
		return fmt.Errorf("unsupported protocol: %s", outbound.Protocol)
	}

	// Validate stream settings if present
	if outbound.StreamSettings != nil {
		var streamSettings map[string]interface{}
		if err := json.Unmarshal(outbound.StreamSettings, &streamSettings); err != nil {
			return fmt.Errorf("invalid stream settings JSON: %w", err)
		}

		if err := validateStreamSettings(streamSettings); err != nil {
			return fmt.Errorf("invalid stream settings: %w", err)
		}
	}

	return nil
}

func validateVlessSettings(settings map[string]interface{}) error {
	vnext, ok := settings["vnext"].([]interface{})
	if !ok || len(vnext) == 0 {
		return fmt.Errorf("vnext configuration is required")
	}

	for i, server := range vnext {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid server configuration at index %d", i)
		}

		// Check required fields
		if _, ok := serverMap["address"].(string); !ok {
			return fmt.Errorf("server address is required at index %d", i)
		}

		// Validate port is a number
		port, ok := serverMap["port"].(float64)
		if !ok {
			return fmt.Errorf("server port is required at index %d and must be a number", i)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number at index %d: must be between 1 and 65535", i)
		}

		users, ok := serverMap["users"].([]interface{})
		if !ok || len(users) == 0 {
			return fmt.Errorf("users configuration is required at index %d", i)
		}

		for j, user := range users {
			userMap, ok := user.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid user configuration at server %d, user %d", i, j)
			}

			if _, ok := userMap["id"].(string); !ok {
				return fmt.Errorf("user id is required at server %d, user %d", i, j)
			}
		}
	}

	return nil
}

func validateTrojanSettings(settings map[string]interface{}) error {
	servers, ok := settings["servers"].([]interface{})
	if !ok || len(servers) == 0 {
		return fmt.Errorf("servers configuration is required")
	}

	for i, server := range servers {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid server configuration at index %d", i)
		}

		// Check required fields
		if _, ok := serverMap["address"].(string); !ok {
			return fmt.Errorf("server address is required at index %d", i)
		}

		// Check port - can be float64 (from JSON number) or int
		port, ok := serverMap["port"].(float64)
		if !ok {
			// Try as integer
			portInt, ok := serverMap["port"].(int)
			if !ok {
				return fmt.Errorf("server port is required at index %d and must be a number", i)
			}
			port = float64(portInt)
		}

		// Validate port range
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number at index %d: must be between 1 and 65535", i)
		}

		if _, ok := serverMap["password"].(string); !ok {
			return fmt.Errorf("password is required at index %d", i)
		}
	}

	return nil
}

func validateShadowsocksSettings(settings map[string]interface{}) error {
	servers, ok := settings["servers"].([]interface{})
	if !ok || len(servers) == 0 {
		return fmt.Errorf("servers configuration is required")
	}

	for i, server := range servers {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid server configuration at index %d", i)
		}

		// Check required fields
		if _, ok := serverMap["address"].(string); !ok {
			return fmt.Errorf("server address is required at index %d", i)
		}

		// Check port - allow both number and string types
		switch port := serverMap["port"].(type) {
		case float64:
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port number at index %d: must be between 1 and 65535", i)
			}
		case int:
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port number at index %d: must be between 1 and 65535", i)
			}
		default:
			return fmt.Errorf("server port is required at index %d and must be a number", i)
		}

		if _, ok := serverMap["method"].(string); !ok {
			return fmt.Errorf("encryption method is required at index %d", i)
		}

		if _, ok := serverMap["password"].(string); !ok {
			return fmt.Errorf("password is required at index %d", i)
		}
	}

	return nil
}

func validateStreamSettings(settings map[string]interface{}) error {
	// Check network type
	network, ok := settings["network"].(string)
	if !ok {
		return fmt.Errorf("network type is required in stream settings")
	}

	if !isValidTransportProtocol(network) {
		return fmt.Errorf("invalid network type: %s", network)
	}

	// Check security settings
	security, ok := settings["security"].(string)
	if !ok {
		return fmt.Errorf("security type is required in stream settings")
	}

	// Validate security-specific settings
	switch security {
	case "tls":
		tlsSettings, ok := settings["tlsSettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("tlsSettings is required when security is tls")
		}
		if _, ok := tlsSettings["serverName"].(string); !ok {
			return fmt.Errorf("serverName is required in tlsSettings")
		}
	case "reality":
		realitySettings, ok := settings["realitySettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("realitySettings is required when security is reality")
		}
		required := []string{"serverName", "fingerprint", "publicKey", "shortId"}
		for _, field := range required {
			if _, ok := realitySettings[field].(string); !ok {
				return fmt.Errorf("%s is required in realitySettings", field)
			}
		}
	case "none":
		// No additional validation needed
	default:
		return fmt.Errorf("unsupported security type: %s", security)
	}

	// Validate transport-specific settings
	switch network {
	case "tcp":
		tcpSettings, ok := settings["tcpSettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("tcpSettings is required for network type tcp")
		}
		header, ok := tcpSettings["header"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("header is required in tcpSettings")
		}
		headerType, ok := header["type"].(string)
		if !ok {
			return fmt.Errorf("header type is required in tcpSettings")
		}
		if headerType == "" {
			return fmt.Errorf("header type cannot be empty in tcpSettings")
		}
	case "ws":
		wsSettings, ok := settings["wsSettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("wsSettings is required for network type ws")
		}

		// Validate path if present
		if path, exists := wsSettings["path"].(string); exists {
			if path != "" && !strings.HasPrefix(path, "/") {
				return fmt.Errorf("WebSocket path must start with / if specified")
			}
		}

		// Validate headers if present
		if headers, exists := wsSettings["headers"].(map[string]interface{}); exists {
			// If headers exist, validate Host if present
			if host, hasHost := headers["Host"].(string); hasHost {
				if host != "" && !isValidHostname(host) {
					return fmt.Errorf("invalid Host header in wsSettings")
				}
			}
		}
	}

	return nil
}

// Helper function to validate hostname format
func isValidHostname(host string) bool {
	// Basic hostname validation
	// Can be extended based on specific requirements
	if len(host) > 255 {
		return false
	}

	// Allow IPv4 addresses
	if net.ParseIP(host) != nil {
		return true
	}

	// Check hostname format
	for _, part := range strings.Split(host, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if !strings.ContainsAny(part, "-") && !isAlphanumeric(part) {
			return false
		}
	}
	return true
}

// Helper function to check if string is alphanumeric
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}
