package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/docker/docker/api/types/network"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"io"
	"log"
	"math/big"
	mathRand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Container port configuration
const (
	VlessPort       = "10001/tcp"
	TrojanPort      = "10002/tcp"
	ShadowsocksPort = "10003/tcp"
)

type TestEnvironment struct {
	Containers     map[string]testcontainers.Container
	MockIPService  *httptest.Server
	MockUptime     *httptest.Server
	uptimeCalls    map[string]bool
	uptimeMutex    sync.Mutex
	networkLatency time.Duration
	network        *testcontainers.DockerNetwork
	packetLossRate float64
	testDataDir    string
	portMappings   map[string]string
	cleanupFuncs   []func()
	mu             sync.Mutex
}

func (env *TestEnvironment) registerContainer(name string, container testcontainers.Container) {
	env.lock()
	defer env.unlock()
	env.Containers[name] = container
}

func (env *TestEnvironment) registerCleanup(cleanup func()) {
	env.lock()
	defer env.unlock()
	env.cleanupFuncs = append(env.cleanupFuncs, cleanup)
}

func (env *TestEnvironment) registerPortMapping(protocol, port string) {
	env.lock()
	defer env.unlock()
	env.portMappings[protocol] = port
}

func (env *TestEnvironment) registerNetwork(network *testcontainers.DockerNetwork) {
	env.lock()
	defer env.unlock()
	env.network = network
}

// Add this function to generate SSL certificates
func (env *TestEnvironment) generateSSLCertificates() error {
	certsDir := filepath.Join(env.testDataDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %v", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save private key
	keyPath := filepath.Join(certsDir, "private.key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	// Save certificate
	certPath := filepath.Join(certsDir, "certificate.crt")
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	return nil
}

func SetupTestEnvironment() (*TestEnvironment, error) {
	env := &TestEnvironment{
		Containers:   make(map[string]testcontainers.Container),
		uptimeCalls:  make(map[string]bool),
		portMappings: make(map[string]string),
	}

	// Setup test directories and configs first
	if err := env.setupTestDirectories(); err != nil {
		return nil, fmt.Errorf("failed to setup test directories: %w", err)
	}

	// Generate SSL certificates for Trojan
	if err := env.generateSSLCertificates(); err != nil {
		return nil, fmt.Errorf("failed to generate SSL certificates: %w", err)
	}

	// Setup config files
	if err := env.setupConfigFiles(); err != nil {
		return nil, fmt.Errorf("failed to setup config files: %w", err)
	}

	// Create network manager
	networkManager := NewNetworkManager(context.Background())
	if err := networkManager.Setup(
		tcnetwork.WithLabels(map[string]string{
			"test-suite": "xray-checker",
		}),
	); err != nil {
		return nil, fmt.Errorf("failed to setup network: %w", err)
	}

	// Add container aliases for each protocol
	protocols := []string{"vless", "trojan", "shadowsocks"}
	for _, protocol := range protocols {
		if err := networkManager.AddContainer(
			protocol,
			[]string{fmt.Sprintf("%s-server", protocol)},
		); err != nil {
			networkManager.Cleanup()
			return nil, fmt.Errorf("failed to add container alias: %w", err)
		}
	}

	// Setup mock services before containers
	env.setupMockServices()

	// Setup containers with verified config paths
	if err := env.setupContainers(networkManager); err != nil {
		env.Cleanup(context.Background())
		return nil, err
	}

	// Verify network connectivity with retry mechanism
	var connectivityErr error
	for attempts := 1; attempts <= 3; attempts++ {
		if err := networkManager.VerifyConnectivity(30 * time.Second); err != nil {
			connectivityErr = err
			log.Printf("Network connectivity verification attempt %d failed: %v", attempts, err)
			time.Sleep(time.Second * time.Duration(attempts))
			continue
		}
		connectivityErr = nil
		break
	}

	if connectivityErr != nil {
		env.Cleanup(context.Background())
		return nil, fmt.Errorf("network connectivity verification failed after retries: %w", connectivityErr)
	}

	return env, nil
}

func (env *TestEnvironment) setupTestDirectories() error {
	// Get absolute path for current directory
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Set test data directory with absolute path
	env.testDataDir = filepath.Join(currentDir, "test-data")

	// Create required directories
	dirs := []string{
		env.testDataDir,
		filepath.Join(env.testDataDir, "configs"),
		filepath.Join(env.testDataDir, "certs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (env *TestEnvironment) setupConfigFiles() error {
	configsDir := filepath.Join(env.testDataDir, "configs")

	// Setup config files
	configs := map[string]string{
		"vless-config.json":       vlessServerConfig,
		"trojan-config.json":      trojanServerConfig,
		"shadowsocks-config.json": shadowsocksServerConfig,
	}

	for filename, content := range configs {
		path := filepath.Join(configsDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %v", filename, err)
		}
		// Print the path for debugging
		fmt.Printf("Created config file at: %s\n", path)
	}

	return nil
}

func (env *TestEnvironment) lock() {
	fmt.Println("Locking env")
	env.mu.Lock()
}

func (env *TestEnvironment) unlock() {
	fmt.Println("Unlocking env")
	env.mu.Unlock()
}

func (env *TestEnvironment) setupContainers(networkManager *NetworkManager) error {
	// Register network and its cleanup
	env.registerNetwork(networkManager.network)
	env.registerCleanup(func() {
		if env.network != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := env.network.Remove(ctx); err != nil {
				log.Printf("Warning: failed to remove network: %v", err)
			}
		}
	})

	// Setup each container type with network
	setupFuncs := map[string]func(networkManager *NetworkManager) error{
		"vless":       env.setupVlessContainer,
		"trojan":      env.setupTrojanContainer,
		"shadowsocks": env.setupShadowsocksContainer,
	}

	for name, setup := range setupFuncs {
		if err := setup(networkManager); err != nil {
			env.Cleanup(context.Background())
			return fmt.Errorf("failed to setup %s container: %v", name, err)
		}
	}

	return nil
}

func (env *TestEnvironment) verifyContainerConnectivity() error {
	ctx := context.Background()

	// Get Docker client for network validation
	dockerClient, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Validate network existence
	networks, err := dockerClient.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list networks: %v", err)
	}

	networkFound := false
	for _, n := range networks {
		if n.Name == env.network.Name {
			networkFound = true
			break
		}
	}

	if !networkFound {
		return fmt.Errorf("test network not found")
	}

	// Create test container with retry mechanism
	var testContainer testcontainers.Container
	var lastErr error

	for attempts := 1; attempts <= 3; attempts++ {
		testContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:    "alpine",
				Networks: []string{"xray_test_network"},
				Cmd:      []string{"sleep", "30"},
				WaitingFor: wait.ForAll(
					wait.ForLog("alpine"),
					wait.ForListeningPort(""),
				).WithStartupTimeout(10 * time.Second), // Changed from WithDeadline to WithStartupTimeout
			},
			Started: true,
		})

		if err == nil {
			break
		}

		lastErr = err
		time.Sleep(time.Second * time.Duration(attempts))
	}

	if testContainer == nil {
		return fmt.Errorf("failed to create test container after retries: %v", lastErr)
	}

	defer func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer terminateCancel()

		if err := testContainer.Terminate(terminateCtx); err != nil {
			log.Printf("Warning: failed to terminate test container: %v", err)
		}
	}()

	// Test connectivity to each service with proper error handling
	services := []struct {
		name    string
		address string
		port    string
	}{
		{"vless", "vless-server", strings.TrimSuffix(VlessPort, "/tcp")},
		{"trojan", "trojan-server", strings.TrimSuffix(TrojanPort, "/tcp")},
		{"shadowsocks", "shadowsocks-server", strings.TrimSuffix(ShadowsocksPort, "/tcp")},
	}

	for _, service := range services {
		if err := env.verifyServiceConnectivity(ctx, testContainer, service.name, service.address, service.port); err != nil {
			return fmt.Errorf("connectivity test failed for %s: %v", service.name, err)
		}
	}

	return nil
}

func (env *TestEnvironment) verifyServiceConnectivity(ctx context.Context, container testcontainers.Container, serviceName, serviceAddr, servicePort string) error {
	// Create service-specific timeout context
	serviceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use nc (netcat) for TCP connection test and wget as fallback
	commands := [][]string{
		{"nc", "-zv", "-w", "3", serviceAddr, servicePort},
		{"wget", "-q", "-T", "3", "-O", "-", fmt.Sprintf("http://%s:%s", serviceAddr, servicePort)},
	}

	var lastErr error
	for _, cmd := range commands {
		exitCode, output, err := container.Exec(serviceCtx, cmd)

		// Log command output for debugging
		log.Printf("Service %s connectivity test output (command: %v):\nExit Code: %d\nOutput: %s\nError: %v",
			serviceName, cmd, exitCode, output, err)

		// Connection refused is acceptable as services might not accept HTTP
		if exitCode == 0 || strings.Contains(fmt.Sprint(err), "Connection refused") {
			return nil
		}

		lastErr = err
	}

	return fmt.Errorf("all connectivity tests failed for %s: %v", serviceName, lastErr)
}

type containerHealthState struct {
	ready    bool
	critical bool
	messages []string
}

func (env *TestEnvironment) verifyContainerHealth(container testcontainers.Container, name string) error {
	logs, err := env.getContainerLogs(container)
	if err != nil {
		return fmt.Errorf("failed to get %s container logs: %v", name, err)
	}

	health := env.analyzeContainerHealth(name, logs)

	if health.critical {
		return fmt.Errorf("%s container has critical errors:\n%s",
			name, strings.Join(health.messages, "\n"))
	}

	if !health.ready {
		return fmt.Errorf("%s container is not ready:\n%s",
			name, strings.Join(health.messages, "\n"))
	}

	return nil
}

// analyzeContainerHealth analyzes container health based on protocol-specific criteria
func (env *TestEnvironment) analyzeContainerHealth(name string, logs string) containerHealthState {
	switch name {
	case "vless":
		return env.analyzeVlessHealth(strings.Split(logs, "\n"))
	case "trojan":
		return env.analyzeTrojanHealth(strings.Split(logs, "\n"))
	case "shadowsocks":
		return env.analyzeShadowsocksHealth(strings.Split(logs, "\n"))
	default:
		return containerHealthState{
			critical: true,
			messages: []string{fmt.Sprintf("unknown container type: %s", name)},
		}
	}
}

func (env *TestEnvironment) analyzeVlessHealth(logLines []string) containerHealthState {
	state := containerHealthState{}

	// Track key startup events
	var (
		started       bool
		listening     bool
		normalStartup bool
	)

	for _, line := range logLines {
		// Positive indicators
		if strings.Contains(line, "Xray") && strings.Contains(line, "started") {
			started = true
		}
		if strings.Contains(line, "listening TCP") {
			listening = true
		}

		// Normal startup EOF is acceptable
		if strings.Contains(line, "failed to read request version > EOF") {
			normalStartup = true
		}

		// Critical errors would be configuration or binding issues
		if strings.Contains(line, "Failed to start") ||
			strings.Contains(line, "invalid config") ||
			strings.Contains(line, "address already in use") {
			state.critical = true
			state.messages = append(state.messages, line)
		}
	}

	// Set ready state based on key indicators
	state.ready = started && listening

	// Collect status messages
	if !started {
		state.messages = append(state.messages, "Xray service not started")
	}
	if !listening {
		state.messages = append(state.messages, "TCP listener not established")
	}
	if normalStartup {
		// This is informational, not an error
		state.messages = append(state.messages, "Normal startup EOF detected")
	}

	return state
}

func (env *TestEnvironment) analyzeTrojanHealth(logLines []string) containerHealthState {
	state := containerHealthState{}

	var (
		serviceStarted bool
		sslReady       bool
	)

	for _, line := range logLines {
		// Positive indicators
		if strings.Contains(line, "trojan service") && strings.Contains(line, "started") {
			serviceStarted = true
		}
		if strings.Contains(line, "SSL handshake") {
			sslReady = true
		}

		// Critical errors
		if strings.Contains(line, "invalid config") ||
			strings.Contains(line, "failed to load certificate") ||
			strings.Contains(line, "address already in use") {
			state.critical = true
			state.messages = append(state.messages, line)
		}
	}

	state.ready = serviceStarted && sslReady

	if !serviceStarted {
		state.messages = append(state.messages, "Trojan service not started")
	}
	if !sslReady {
		state.messages = append(state.messages, "SSL not initialized")
	}

	return state
}

func (env *TestEnvironment) analyzeShadowsocksHealth(logLines []string) containerHealthState {
	state := containerHealthState{}

	var (
		serverListening bool
		ciphersInit     bool
	)

	for _, line := range logLines {
		// Positive indicators
		if strings.Contains(line, "server listening") {
			serverListening = true
		}
		if strings.Contains(line, "initializing ciphers") {
			ciphersInit = true
		}

		// Critical errors
		if strings.Contains(line, "failed to initialize") ||
			strings.Contains(line, "address already in use") {
			state.critical = true
			state.messages = append(state.messages, line)
		}
	}

	state.ready = serverListening && ciphersInit

	if !serverListening {
		state.messages = append(state.messages, "Server not listening")
	}
	if !ciphersInit {
		state.messages = append(state.messages, "Ciphers not initialized")
	}

	return state
}

// setupVlessContainer initializes the VLESS container with network configuration
func (env *TestEnvironment) setupVlessContainer(networkManager *NetworkManager) error {
	ctx := context.Background()

	// Use absolute path for config
	configPath := filepath.Join(env.testDataDir, "configs", "vless-config.json")

	// Verify config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("vless config file not found at %s", configPath)
	}

	req := testcontainers.ContainerRequest{
		Image:        "teddysun/xray:latest",
		ExposedPorts: []string{VlessPort},
		Networks:     []string{networkManager.network.Name},
		NetworkAliases: map[string][]string{
			networkManager.network.Name: {"vless-server"},
		},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(configPath, "/etc/xray/config.json"),
		),
		WaitingFor: wait.ForAll(
			wait.ForLog("Xray").WithStartupTimeout(30*time.Second),
			wait.ForListeningPort(VlessPort).WithStartupTimeout(30*time.Second),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start VLESS container: %v", err)
	}

	// Register container and its cleanup
	env.registerContainer("vless", container)
	env.registerCleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := container.Terminate(ctx); err != nil {
			log.Printf("Warning: failed to terminate vless container: %v", err)
		}
	})

	// Get and register mapped port
	mappedPort, err := container.MappedPort(ctx, VlessPort)
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %v", err)
	}
	env.registerPortMapping("vless", mappedPort.Port())

	// Verify container health
	if err := env.verifyContainerHealth(container, "vless"); err != nil {
		return fmt.Errorf("VLESS container health check failed: %v", err)
	}

	return nil
}

// setupTrojanContainer initializes the Trojan container with network configuration
func (env *TestEnvironment) setupTrojanContainer(networkManager *NetworkManager) error {
	ctx := context.Background()
	configPath := filepath.Join(env.testDataDir, "configs", "trojan-config.json")
	certsDir := filepath.Join(env.testDataDir, "certs")

	req := testcontainers.ContainerRequest{
		Image:        "trojangfw/trojan:latest",
		ExposedPorts: []string{TrojanPort},
		Networks:     []string{networkManager.network.Name},
		NetworkAliases: map[string][]string{
			networkManager.network.Name: {"trojan-server"},
		},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(configPath, "/config/config.json"),
			testcontainers.BindMount(filepath.Join(certsDir, "certificate.crt"), "/etc/trojan/certificate.crt"),
			testcontainers.BindMount(filepath.Join(certsDir, "private.key"), "/etc/trojan/private.key"),
		),
		WaitingFor: wait.ForAll(
			wait.ForLog("started").WithStartupTimeout(30*time.Second),
			wait.ForListeningPort(TrojanPort).WithStartupTimeout(30*time.Second),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start Trojan container: %v", err)
	}

	env.addContainerCleanup("trojan", container)

	// Store container info
	env.Containers["trojan"] = container

	// Get mapped port for external access
	mappedPort, err := container.MappedPort(ctx, TrojanPort)
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %v", err)
	}
	env.portMappings["trojan"] = mappedPort.Port()

	// Verify container health
	if err := env.verifyContainerHealth(container, "trojan"); err != nil {
		return fmt.Errorf("Trojan container health check failed: %v", err)
	}

	env.Containers["trojan"] = container
	return nil
}

// setupShadowsocksContainer initializes the Shadowsocks container with network configuration
func (env *TestEnvironment) setupShadowsocksContainer(networkManager *NetworkManager) error {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "shadowsocks/shadowsocks-libev",
		ExposedPorts: []string{ShadowsocksPort},
		Networks:     []string{networkManager.network.Name},
		NetworkAliases: map[string][]string{
			networkManager.network.Name: {"shadowsocks-server"},
		},
		Env: map[string]string{
			"PASSWORD":    "test-password",
			"METHOD":      "aes-256-gcm",
			"SERVER_PORT": strings.TrimSuffix(ShadowsocksPort, "/tcp"),
		},
		WaitingFor: wait.ForListeningPort(ShadowsocksPort).WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start Shadowsocks container: %v", err)
	}

	env.addContainerCleanup("shadowsocks", container)

	// Store container info
	env.Containers["shadowsocks"] = container

	// Get mapped port for external access
	mappedPort, err := container.MappedPort(ctx, ShadowsocksPort)
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %v", err)
	}
	env.portMappings["shadowsocks"] = mappedPort.Port()

	// Verify container health
	if err := env.verifyContainerHealth(container, "shadowsocks"); err != nil {
		return fmt.Errorf("Shadowsocks container health check failed: %v", err)
	}

	return nil
}

func (env *TestEnvironment) getContainerLogs(container testcontainers.Container) (string, error) {
	ctx := context.Background()
	reader, err := container.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	logs, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(logs), nil
}

func (env *TestEnvironment) setupMockServices() {
	// Setup mock IP service
	env.MockIPService = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if env.networkLatency > 0 {
			time.Sleep(env.networkLatency)
		}

		if env.packetLossRate > 0 && mathRand.Float64() < env.packetLossRate {
			http.Error(w, "simulated packet loss", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("X-Proxy-Used") == "true" {
			fmt.Fprint(w, "1.2.3.4")
		} else {
			fmt.Fprint(w, "5.6.7.8")
		}
	}))

	// Setup mock uptime service
	env.MockUptime = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.recordUptimeCall(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
}

// wasUptimeCalled checks if uptime monitoring was called for a specific protocol
func (env *TestEnvironment) wasUptimeCalled(protocol string) bool {
	env.uptimeMutex.Lock()
	defer env.uptimeMutex.Unlock()
	return env.uptimeCalls["/"+protocol]
}

// recordUptimeCall records that uptime monitoring was called for a path
func (env *TestEnvironment) recordUptimeCall(path string) {
	env.uptimeMutex.Lock()
	defer env.uptimeMutex.Unlock()
	env.uptimeCalls[path] = true
}

// clearUptimeCalls clears the record of uptime monitoring calls
func (env *TestEnvironment) clearUptimeCalls() {
	env.uptimeMutex.Lock()
	defer env.uptimeMutex.Unlock()
	env.uptimeCalls = make(map[string]bool)
}

func (env *TestEnvironment) addContainerCleanup(name string, container testcontainers.Container) {
	env.lock()
	defer env.unlock()

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := container.Terminate(ctx); err != nil {
			log.Printf("Warning: failed to terminate %s container: %v", name, err)
		}
	}
	env.cleanupFuncs = append(env.cleanupFuncs, cleanup)
}

func (env *TestEnvironment) SetNetworkConditions(latency time.Duration, lossRate float64) {
	env.networkLatency = latency
	env.packetLossRate = lossRate

	// Update the mock IP service handler to simulate packet loss
	env.MockIPService.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate packet loss
		if env.packetLossRate > 0 && mathRand.Float64() < env.packetLossRate {
			http.Error(w, "simulated packet loss", http.StatusInternalServerError)
			return
		}

		// Apply latency if configured
		if env.networkLatency > 0 {
			time.Sleep(env.networkLatency)
		}

		// Original IP response logic
		if r.Header.Get("X-Proxy-Used") == "true" {
			fmt.Fprint(w, "1.2.3.4")
		} else {
			fmt.Fprint(w, "5.6.7.8")
		}
	})
}

func (env *TestEnvironment) ResetNetworkConditions() {
	env.networkLatency = 0
	env.packetLossRate = 0

	// Reset the mock IP service handler to default behavior
	env.MockIPService.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Proxy-Used") == "true" {
			fmt.Fprint(w, "1.2.3.4")
		} else {
			fmt.Fprint(w, "5.6.7.8")
		}
	})
}

func (env *TestEnvironment) Cleanup(ctx context.Context) {
	env.lock()
	defer env.unlock()

	// Execute cleanup functions in reverse order
	for i := len(env.cleanupFuncs) - 1; i >= 0; i-- {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Warning: panic in cleanup function: %v", r)
				}
			}()
			env.cleanupFuncs[i]()
		}()
	}

	// Clear all state
	env.cleanupFuncs = nil
	env.Containers = make(map[string]testcontainers.Container)
	env.portMappings = make(map[string]string)
	env.network = nil
}

const (
	vlessServerConfig = `{
        "inbounds": [{
            "port": 10001,
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": "test-uuid",
                    "flow": ""
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }],
        "log": {
            "loglevel": "debug"
        }
    }`

	trojanServerConfig = `{
        "run_type": "server",
        "local_addr": "0.0.0.0",
        "local_port": 10002,
        "remote_addr": "127.0.0.1",
        "remote_port": 80,
        "password": ["test-password"],
        "ssl": {
            "cert": "/etc/trojan/certificate.crt",
            "key": "/etc/trojan/private.key",
            "sni": "localhost"
        }
    }`

	shadowsocksServerConfig = `{
        "server": "0.0.0.0",
        "server_port": 10003,
        "password": "test-password",
        "method": "aes-256-gcm",
        "mode": "tcp_and_udp"
    }`
)
