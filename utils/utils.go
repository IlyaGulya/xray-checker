package utils

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
	"xray-checker/models"
)

func ParseLink(link string) (*models.ParsedLink, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("error parsing link: %v", err)
	}

	protocol := strings.Split(u.Scheme, "://")[0]
	userInfo := u.User
	hostPort := strings.Split(u.Host, ":")
	queryParams := u.Query()

	parsed := &models.ParsedLink{
		Protocol: protocol,
		Server:   hostPort[0],
		Port:     hostPort[1],
		Name:     u.Fragment,
	}

	switch protocol {
	case "vless":
		parsed.UID = userInfo.Username()
		parsed.Security = queryParams.Get("security")
		parsed.Type = queryParams.Get("type")
		parsed.HeaderType = queryParams.Get("headerType")
		parsed.Flow = queryParams.Get("flow")
		parsed.Path = queryParams.Get("path")
		parsed.Host = queryParams.Get("host")
		parsed.SNI = queryParams.Get("sni")
		parsed.FP = queryParams.Get("fp")
		parsed.PBK = queryParams.Get("pbk")
		parsed.SID = queryParams.Get("sid")

	case "trojan":
		parsed.UID = userInfo.Username()
		parsed.Security = queryParams.Get("security")
		parsed.Type = queryParams.Get("type")
		parsed.HeaderType = queryParams.Get("headerType")
		parsed.Path = queryParams.Get("path")
		parsed.Host = queryParams.Get("host")
		parsed.SNI = queryParams.Get("sni")
		parsed.FP = queryParams.Get("fp")

	case "ss":
		decodedUserInfo, err := base64.StdEncoding.DecodeString(userInfo.Username())
		if err != nil {
			return nil, fmt.Errorf("error decoding base64: %v", err)
		}
		parts := strings.Split(string(decodedUserInfo), ":")
		parsed.Method = parts[0]
		parsed.UID = parts[1]
		parsed.Protocol = "shadowsocks"
	}

	return parsed, nil
}

func GenerateXrayConfig(parsedLink *models.ParsedLink, templateDir, outputDir string) error {

	templatePath := filepath.Join(templateDir, fmt.Sprintf("%s.json.tmpl", parsedLink.Protocol))
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("error loading template: %v", err)
	}

	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s.json", parsedLink.Protocol, parsedLink.Server))
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating xray config: %v", err)
	}
	defer outputFile.Close()

	err = tmpl.Execute(outputFile, parsedLink)
	if err != nil {
		return fmt.Errorf("error generating xray config: %v", err)
	}

	return nil
}

func RunXray(r CommandRunner, configPath string) (*exec.Cmd, error) {
	return r.RunCommand("xray", "-c", configPath)
}

func KillXray(r CommandRunner, cmd *exec.Cmd) {
	err := r.KillCommand(cmd)
	if err != nil {
		log.Printf("error killing xray process: %v", err)
	}
}

func CreateProxyClient(proxyAddress string) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy format: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:       20 * time.Second,
			KeepAlive:     20 * time.Second,
			FallbackDelay: -1,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
	}

	return client, nil
}

func GetIPv4Client() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:       20 * time.Second,
			KeepAlive:     20 * time.Second,
			FallbackDelay: -1,
		}).DialContext,
	}

	return &http.Client{
		Transport: transport,
	}
}

func LogResult(logData models.ConnectionData) {
	var logMsg string

	if logData.Error != nil {
		logMsg = fmt.Sprintf("Error: %v | Config: %s | Source IP: %s | VPN IP: %s",
			logData.Error, logData.ConfigFile, logData.SourceIP, logData.VPNIP)
	} else {
		logMsg = fmt.Sprintf("Status: %s | Config: %s | Source IP: %s | VPN IP: %s",
			logData.Status, logData.ConfigFile, logData.SourceIP, logData.VPNIP)
	}

	log.Println(logMsg)
}
