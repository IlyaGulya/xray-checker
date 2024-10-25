package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"xray-checker/models"
	uptimekuma "xray-checker/providers/uptime-kuma"
)

func createTestConfig(t *testing.T, webhook string) string {
	config := models.XrayConfig{
		Inbounds: []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}{
			{
				Listen:   "127.0.0.1",
				Port:     10000,
				Protocol: "socks",
			},
		},
		Outbounds: []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": "test.com",
							"port":    443,
						},
					},
				},
			},
		},
		Webhook: webhook,
	}

	configData, err := json.Marshal(config)
	assert.NoError(t, err)

	tempFile, err := os.CreateTemp("", "xray-test-*.json")
	assert.NoError(t, err)

	_, err = tempFile.Write(configData)
	assert.NoError(t, err)

	err = tempFile.Close()
	assert.NoError(t, err)

	return tempFile.Name()
}

func createUptimeKumaProvider(t *testing.T) *uptimekuma.UptimeKuma {
	providerConfig := []byte(`{
		"name": "uptime-kuma",
		"proxyStartPort": 10000,
		"interval": 30,
		"workers": 1,
		"checkIpService": "http://ip-check.test",
		"configs": [
			{
				"link": "vless://uuid@test.com:443?security=reality&type=tcp",
				"monitorLink": "http://uptime-kuma/test?status=up&msg=OK&ping="
			}
		]
	}`)

	var provider uptimekuma.UptimeKuma
	err := json.Unmarshal(providerConfig, &provider)
	assert.NoError(t, err)
	return &provider
}
