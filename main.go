package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	"xray-checker/models"
	uptimekuma "xray-checker/providers/uptime-kuma"
	"xray-checker/utils"

	"github.com/go-co-op/gocron"
)

func loadProgramConfig(configPath string) (models.Provider, error) {
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading program configuration file: %v", err)
	}

	var rawProvider json.RawMessage
	var temp struct {
		Provider json.RawMessage `json:"provider"`
	}
	err = json.Unmarshal(configFile, &temp)
	if err != nil {
		return nil, fmt.Errorf("error parsing program configuration file: %v", err)
	}
	rawProvider = temp.Provider

	var providerType struct {
		Name string `json:"name"`
	}
	err = json.Unmarshal(rawProvider, &providerType)
	if err != nil {
		return nil, fmt.Errorf("error determining provider type: %v", err)
	}

	provider, err := uptimekuma.ProviderFactory(providerType.Name, rawProvider)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func worker(id int, jobs <-chan string, provider models.Provider, wg *sync.WaitGroup) {
	defer wg.Done()
	service := NewDefaultXrayCheckerService()
	for configPath := range jobs {
		log.Printf("Worker %d processing config: %s\n", id, configPath)
		service.ProcessConfigFile(configPath, provider)
	}
}

func scheduleConfigs(configDir string, scheduler *gocron.Scheduler, provider models.Provider, jobs chan<- string) {
	scheduler.Every(provider.GetInterval()).Seconds().Do(func() {
		log.Println("Starting a new check cycle")
		files, err := os.ReadDir(configDir)
		if err != nil {
			fmt.Println("error reading directory:", err)
			return
		}

		for _, file := range files {
			if filepath.Ext(file.Name()) == ".json" {
				configPath := filepath.Join(configDir, file.Name())
				jobs <- configPath
			}
		}
	})
}

func main() {
	configDir := "./configs"
	programConfigPath := "./config.json"
	templateDir := "./templates"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err := os.Mkdir(configDir, os.ModePerm)
		if err != nil {
			fmt.Println("error creating directory:", err)
			return
		}
	}

	provider, err := loadProgramConfig(programConfigPath)
	if err != nil {
		fmt.Println("error loading program configuration:", err)
		return
	}

	for i, config := range provider.GetConfigs() {
		parsedLink, err := utils.ParseLink(config.Link)
		if err != nil {
			fmt.Println("error parsing link:", err)
			continue
		}

		parsedLink.MonitorLink = config.MonitorLink
		parsedLink.RandomPort = provider.GetProxyStartPort() + i

		err = utils.GenerateXrayConfig(parsedLink, templateDir, configDir)
		if err != nil {
			fmt.Println("error generating Xray config:", err)
			continue
		}

		log.Printf("Xray config generated: %s-%s.json\n", parsedLink.Protocol, parsedLink.Server)
	}

	scheduler := gocron.NewScheduler(time.UTC)
	jobs := make(chan string, 10)

	var wg sync.WaitGroup
	numWorkers := provider.GetWorkers()
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, provider, &wg)
	}

	scheduleConfigs(configDir, scheduler, provider, jobs)

	go scheduler.StartBlocking()

	wg.Wait()

	fmt.Println("All checks are done")
}
