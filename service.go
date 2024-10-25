package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
	"xray-checker/models"
	"xray-checker/utils"
)

type XrayCheckerService struct {
	commandRunner utils.CommandRunner
	ipChecker     utils.IPChecker
}

func NewXrayCheckerService(runner utils.CommandRunner, ipChecker utils.IPChecker) *XrayCheckerService {
	return &XrayCheckerService{
		commandRunner: runner,
		ipChecker:     ipChecker,
	}
}

func NewDefaultXrayCheckerService() *XrayCheckerService {
	runner := utils.DefaultCommandRunner{}
	checker := utils.DefaultIPChecker{}
	return NewXrayCheckerService(&runner, &checker)
}

func (s *XrayCheckerService) ProcessConfigFile(configPath string, provider models.Provider) {
	logData := models.ConnectionData{ConfigFile: configPath}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		logData.Error = fmt.Errorf("error reading xray config: %v", err)
		utils.LogResult(logData)
		return
	}

	var config models.XrayConfig
	err = json.Unmarshal(configData, &config)
	if err != nil {
		logData.Error = fmt.Errorf("error parsing xray config: %v", err)
		utils.LogResult(logData)
		return
	}

	logData.WebhookURL = config.Webhook
	if logData.WebhookURL == "" {
		logData.Error = fmt.Errorf("webhook URL not found in xray config")
		utils.LogResult(logData)
		return
	}

	logData.SourceIP, err = s.ipChecker.GetIP(provider.GetCheckService(), utils.GetIPv4Client())
	if err != nil {
		logData.Error = fmt.Errorf("error getting source IP: %v", err)
		utils.LogResult(logData)
		return
	}

	listen := config.Inbounds[0].Listen
	port := config.Inbounds[0].Port
	logData.ProxyAddress = fmt.Sprintf("socks5://%s:%d", listen, port)

	cmd, err := utils.RunXray(s.commandRunner, configPath)
	if err != nil {
		logData.Error = fmt.Errorf("error starting Xray: %v", err)
		utils.LogResult(logData)
		return
	}
	defer utils.KillXray(s.commandRunner, cmd)
	time.Sleep(4 * time.Second)

	proxyClient, err := utils.CreateProxyClient(logData.ProxyAddress)
	if err != nil {
		logData.Error = fmt.Errorf("error creating proxy client: %v", err)
		utils.LogResult(logData)
		return
	}

	logData.VPNIP, err = s.ipChecker.GetIP(provider.GetCheckService(), proxyClient)
	if err != nil {
		logData.Error = fmt.Errorf("error getting VPN IP through proxy: %v", err)
		utils.LogResult(logData)
		return
	}

	err = provider.ProcessResults(logData)
	if err != nil {
		logData.Error = fmt.Errorf("error processing results: %v", err)
	}
}
