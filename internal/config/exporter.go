package config

import (
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"xray-checker/internal/domain"
)

const (
	ExporterTypeUptimeKuma = "uptime-kuma"
)

type ExporterConfig struct {
	Type    string            `json:"type" validate:"required,exporterType"`
	Watches []domain.LinkName `json:"watches" validate:"required,dive,required"`
	Raw     json.RawMessage
}

func init() {
	if err := validate.RegisterValidation("exporterType", validateExporterType); err != nil {
		panic(fmt.Sprintf("failed to register exporter type validator: %v", err))
	}
}

func validateExporterType(fl validator.FieldLevel) bool {
	exporterType := fl.Field().String()
	switch exporterType {
	case ExporterTypeUptimeKuma:
		return true
	default:
		return false
	}
}

func (e *ExporterConfig) UnmarshalJSON(data []byte) error {
	// Store raw data
	e.Raw = data

	// Define an alias type to avoid recursion
	type alias ExporterConfig
	temp := struct {
		*alias
	}{
		alias: (*alias)(e),
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("failed to unmarshal exporter config: %w", err)
	}

	// Validate the config
	if err := validate.Struct(e); err != nil {
		// Pass through the validation errors directly
		return fmt.Errorf("invalid exporter config: %w", err)
	}

	return nil
}

// Ensure required interfaces are implemented
var _ json.Unmarshaler = (*ExporterConfig)(nil)
