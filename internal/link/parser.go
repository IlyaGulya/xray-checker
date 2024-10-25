package link

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"xray-checker/internal/domain"
)

func Parse(link string) (*domain.ParsedLink, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("error parsing link: %w", err)
	}

	// Extract the fragment but don't use it for configuration
	// Fragment is only used for display purposes
	decodedFragment, err := url.QueryUnescape(u.Fragment)
	if err != nil {
		// If we can't decode the fragment, just use it as-is
		// This won't affect the actual configuration
		decodedFragment = u.Fragment
	}

	protocol := u.Scheme
	userInfo := u.User

	// Parse host and port
	hostPort := strings.Split(u.Host, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid host:port format in URL: %s", u.Host)
	}

	parsed := &domain.ParsedLink{
		Protocol: protocol,
		Server:   hostPort[0],
		Port:     hostPort[1],
		Name:     decodedFragment, // Store decoded fragment as display name
	}

	// Clean and decode query parameters
	queryParams := make(url.Values)
	for k, v := range u.Query() {
		decoded, err := url.QueryUnescape(v[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode query parameter %s: %w", k, err)
		}
		queryParams.Set(k, decoded)
	}

	switch protocol {
	case "vless":
		if userInfo == nil {
			return nil, fmt.Errorf("missing user info in VLESS URL")
		}
		parsed.UID = userInfo.Username()
		parsed.Security = queryParams.Get("security")
		parsed.Type = queryParams.Get("type")
		if parsed.Type == "" {
			parsed.Type = "tcp" // Default to TCP if not specified
		}
		parsed.HeaderType = queryParams.Get("headerType")
		parsed.Flow = queryParams.Get("flow")
		parsed.Path = queryParams.Get("path")
		parsed.Host = queryParams.Get("host")
		parsed.SNI = queryParams.Get("sni")
		parsed.FP = queryParams.Get("fp")
		parsed.PBK = queryParams.Get("pbk")
		parsed.SID = queryParams.Get("sid")

	case "trojan":
		if userInfo == nil {
			return nil, fmt.Errorf("missing user info in Trojan URL")
		}
		parsed.UID = userInfo.Username()
		parsed.Security = queryParams.Get("security")
		parsed.Type = queryParams.Get("type")
		if parsed.Type == "" {
			parsed.Type = "tcp"
		}
		parsed.HeaderType = queryParams.Get("headerType")
		parsed.Path = queryParams.Get("path")
		parsed.Host = queryParams.Get("host")
		parsed.SNI = queryParams.Get("sni")
		parsed.FP = queryParams.Get("fp")

	case "ss":
		if userInfo == nil {
			return nil, fmt.Errorf("missing user info in Shadowsocks URL")
		}
		decodedUserInfo, err := base64.URLEncoding.DecodeString(userInfo.Username())
		if err != nil {
			// Try standard encoding if URL encoding fails
			decodedUserInfo, err = base64.StdEncoding.DecodeString(userInfo.Username())
			if err != nil {
				return nil, fmt.Errorf("error decoding base64: %w", err)
			}
		}
		parts := strings.Split(string(decodedUserInfo), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid shadowsocks user info format")
		}
		parsed.Method = parts[0]
		parsed.UID = parts[1]
		parsed.Protocol = "shadowsocks"
		// Set default transport type and security for Shadowsocks
		parsed.Type = "tcp"
		parsed.Security = "none"

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Validate required fields
	if parsed.Server == "" {
		return nil, fmt.Errorf("server address is required")
	}
	if parsed.Port == "" {
		return nil, fmt.Errorf("port is required")
	}
	if parsed.UID == "" {
		return nil, fmt.Errorf("user ID/password is required")
	}

	return parsed, nil
}
