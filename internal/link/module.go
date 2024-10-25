package link

import (
	"fmt"
	"go.uber.org/fx"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
)

var Module = fx.Provide(ProvideParsedLinks)

func ProvideParsedLinks(cfg *config.Config) ([]domain.ParsedLink, error) {
	links := make([]domain.ParsedLink, 0, len(cfg.Links))

	for _, rawLink := range cfg.Links {
		// Validate raw link name
		if rawLink.Name == "" {
			return nil, fmt.Errorf("link name is required in configuration")
		}

		parsed, err := Parse(rawLink.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse link %s: %w", rawLink.Name, err)
		}

		// Set the LinkName from configuration
		parsed.LinkName = rawLink.Name

		// Additional validation after setting LinkName
		if err := validateParsedLink(parsed); err != nil {
			return nil, fmt.Errorf("invalid link %s: %w", rawLink.Name, err)
		}

		links = append(links, *parsed)
	}

	return links, nil
}

func validateParsedLink(link *domain.ParsedLink) error {
	if link.LinkName == "" {
		return fmt.Errorf("link name cannot be empty")
	}

	// Add more validations as needed
	switch link.Protocol {
	case "vless":
		if link.Security == "" {
			return fmt.Errorf("security parameter is required for VLESS")
		}
	case "trojan":
		if link.Security == "" {
			return fmt.Errorf("security parameter is required for Trojan")
		}
	case "shadowsocks":
		if link.Method == "" {
			return fmt.Errorf("method is required for Shadowsocks")
		}
	}

	return nil
}
