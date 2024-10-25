package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"os"
	"xray-checker/internal/domain"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

type Config struct {
	XrayConfigsDir string           `json:"xray_configs_dir" validate:"required,dir"`
	Links          []domain.RawLink `json:"links" validate:"required,dive"`
	Workers        Workers          `json:"workers" validate:"required"`
	Exporters      []ExporterConfig `json:"exporters" validate:"dive"`
}

type Workers struct {
	Count          int    `json:"count"`
	CheckInterval  int    `json:"check_interval"`
	ProxyStartPort int    `json:"proxy_start_port"`
	CheckIPService string `json:"check_ip_service"`
}

// NewConfig creates a new Config instance from the environment
func NewConfig() (*Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.json"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Validate link names in configuration
	for _, link := range cfg.Links {
		if link.Name == "" {
			return nil, fmt.Errorf("link name is required in configuration")
		}
		if link.URL == "" {
			return nil, fmt.Errorf("URL is required for link %s", link.Name)
		}
	}

	// Create required directories if they don't exist
	if err := ensureDirectories(&cfg); err != nil {
		return nil, fmt.Errorf("failed to create required directories: %w", err)
	}

	// Validate the configuration
	if err := validate.Struct(cfg); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			return nil, formatValidationErrors(validationErrors)
		}
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// ensureDirectories creates required directories if they don't exist
func ensureDirectories(cfg *Config) error {
	dirs := []struct {
		path string
		name string
	}{
		{cfg.XrayConfigsDir, "xray configs"},
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory at %s: %w",
				dir.name, dir.path, err)
		}
	}

	return nil
}

// Custom directory validator
func init() {
	validate = validator.New()

	// Register custom directory validator
	if err := validate.RegisterValidation("dir", validateDir); err != nil {
		panic(fmt.Sprintf("failed to register dir validator: %v", err))
	}
}

func validateDir(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if info, err := os.Stat(path); err != nil {
		return false
	} else {
		return info.IsDir()
	}
}

// formatValidationErrors formats validation errors into a user-friendly error message
func formatValidationErrors(errors validator.ValidationErrors) error {
	var errMsgs []string
	for _, err := range errors {
		errMsgs = append(errMsgs, fmt.Sprintf(
			"field '%s' failed validation: %s",
			err.Field(),
			err.Tag(),
		))
	}
	return fmt.Errorf("validation errors: %v", errMsgs)
}
