package xray

import "encoding/json"

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
