package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"xray-checker/internal/config"
	"xray-checker/internal/domain"
	"xray-checker/internal/ipchecker"
	"xray-checker/internal/worker"
)

// Mock Implementations

type MockIPChecker struct {
	DirectIP    string
	ProxyIP     string
	ShouldErr   bool
	CallCount   int
	mu          sync.Mutex
	RetryErrors int // Number of times to return error before succeeding
}

func (m *MockIPChecker) GetDirectIP() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallCount++

	if m.RetryErrors > 0 {
		m.RetryErrors--
		return "", fmt.Errorf("temporary error")
	}

	if m.ShouldErr {
		return "", fmt.Errorf("mock IP checker error")
	}
	return m.DirectIP, nil
}

func (m *MockIPChecker) GetProxiedIP(proxyAddr string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallCount++

	if m.RetryErrors > 0 {
		m.RetryErrors--
		return "", fmt.Errorf("temporary error")
	}

	if m.ShouldErr {
		return "", fmt.Errorf("mock IP checker error")
	}
	return m.ProxyIP, nil
}

type MockXrayService struct {
	running bool
	mu      sync.RWMutex
	logger  *zap.Logger
	configs map[domain.LinkName]proxyConfig
}

type proxyConfig struct {
	address string
	port    int
}

func NewMockXrayService(lc fx.Lifecycle, logger *zap.Logger, cfg *config.Config) (*MockXrayService, error) {
	service := &MockXrayService{
		logger:  logger,
		configs: make(map[domain.LinkName]proxyConfig),
	}

	// Initialize proxy configs
	port := cfg.Workers.ProxyStartPort
	for _, link := range cfg.Links {
		service.configs[link.Name] = proxyConfig{
			address: "127.0.0.1",
			port:    port,
		}
		port++
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			service.mu.Lock()
			defer service.mu.Unlock()
			service.running = true
			logger.Info("mock xray service started")
			return nil
		},
		OnStop: func(ctx context.Context) error {
			service.mu.Lock()
			defer service.mu.Unlock()
			service.running = false
			logger.Info("mock xray service stopped")
			return nil
		},
	})

	return service, nil
}

func (s *MockXrayService) GetProxyConfig(linkName domain.LinkName) (string, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return "", 0, fmt.Errorf("service not running")
	}

	config, exists := s.configs[linkName]
	if !exists {
		return "", 0, fmt.Errorf("no proxy configuration found for link: %s", linkName)
	}

	return config.address, config.port, nil
}

func (s *MockXrayService) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *MockXrayService) WaitForInitialization(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if s.IsHealthy() {
				return nil
			}
		}
	}
}

type MockMetricsCollector struct {
	mu            sync.Mutex
	CheckResults  []domain.CheckResult
	WorkerStarts  map[string]int
	WorkerStops   map[string]int
	ScheduledJobs map[string]int
	RetryCount    map[string]int
	RestartCount  int
}

func NewMockMetricsCollector() *MockMetricsCollector {
	return &MockMetricsCollector{
		WorkerStarts:  make(map[string]int),
		WorkerStops:   make(map[string]int),
		ScheduledJobs: make(map[string]int),
		RetryCount:    make(map[string]int),
	}
}

func (m *MockMetricsCollector) RecordCheck(result domain.CheckResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CheckResults = append(m.CheckResults, result)
}

func (m *MockMetricsCollector) RecordWorkerStart(workerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WorkerStarts[workerID]++
}

func (m *MockMetricsCollector) RecordWorkerStop(workerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WorkerStops[workerID]++
}

func (m *MockMetricsCollector) RecordSchedulerJob(linkName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ScheduledJobs[linkName]++
}

func (m *MockMetricsCollector) RecordCheckRetry(linkName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RetryCount[linkName]++
}

func (m *MockMetricsCollector) RecordXrayRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RestartCount++
}

// Test Helpers

func createTestConfig(t *testing.T, tmpDir string) *config.Config {
	t.Helper()

	cfg := &config.Config{
		XrayConfigsDir: filepath.Join(tmpDir, "configs"),
		Links: []domain.RawLink{
			{
				Name: "test-link-1",
				URL:  "vless://test-uuid@example.com:443?security=reality&type=tcp",
			},
			{
				Name: "test-link-2",
				URL:  "trojan://test-pass@example.com:443?security=tls&type=ws",
			},
		},
		Workers: config.Workers{
			Count:          2,
			CheckInterval:  1,
			ProxyStartPort: 10000,
			CheckIPService: "http://test.com",
		},
		Exporters: []config.ExporterConfig{
			{
				Type:    "uptime-kuma",
				Watches: []domain.LinkName{"test-link-1"},
				Raw:     json.RawMessage(`{"monitor_url": "http://test.com"}`),
			},
		},
	}

	require.NoError(t, os.MkdirAll(cfg.XrayConfigsDir, 0755))

	configPath := filepath.Join(tmpDir, "config.json")
	configData, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, configData, 0644))

	t.Setenv("CONFIG_PATH", configPath)
	return cfg
}

func createTestModule(mockChecker ipchecker.IPChecker, collector *MockMetricsCollector) fx.Option {
	return fx.Options(
		fx.Provide(func() ipchecker.IPChecker { return mockChecker }),
		fx.Provide(NewMockXrayService),
		fx.Provide(func() domain.MetricsCollector { return collector }),
		worker.Module,
	)
}

// Tests

func TestApplicationIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	var mockXrayService *MockXrayService
	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
		fx.Populate(&mockXrayService),
	)

	// Start application
	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Test application state
	t.Run("Application Started Successfully", func(t *testing.T) {
		assert.True(t, mockXrayService.IsHealthy())

		// Wait for initial checks
		time.Sleep(2 * time.Second)

		// Verify metrics
		mockMetrics.mu.Lock()
		defer mockMetrics.mu.Unlock()

		assert.Greater(t, len(mockMetrics.CheckResults), 0, "should have recorded checks")
		assert.Greater(t, mockMetrics.WorkerStarts["0"], 0, "worker 0 should have started")
		assert.Greater(t, mockMetrics.WorkerStarts["1"], 0, "worker 1 should have started")
	})

	// Test proxy configuration
	t.Run("Proxy Configuration", func(t *testing.T) {
		addr, port, err := mockXrayService.GetProxyConfig("test-link-1")
		assert.NoError(t, err)
		assert.Equal(t, "127.0.0.1", addr)
		assert.Equal(t, 10000, port)
	})

	// Test health check
	t.Run("Health Check", func(t *testing.T) {
		assert.True(t, mockXrayService.IsHealthy())
	})

	// Stop application
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))

	t.Run("Application Stopped Successfully", func(t *testing.T) {
		assert.False(t, mockXrayService.IsHealthy())
	})
}

func TestRetryMechanism(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP:    "1.1.1.1",
		ProxyIP:     "2.2.2.2",
		RetryErrors: 2, // Will fail twice then succeed
	}
	mockMetrics := NewMockMetricsCollector()

	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Wait for retries to occur
	time.Sleep(3 * time.Second)

	mockMetrics.mu.Lock()
	retryCount := mockMetrics.RetryCount["test-link-1"]
	mockMetrics.mu.Unlock()

	assert.Greater(t, retryCount, 0, "should have recorded retries")

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))
}

func TestFailureScenarios(t *testing.T) {
	tests := []struct {
		name          string
		modifyConfig  func(*config.Config)
		mockChecker   *MockIPChecker
		expectedError string
	}{
		{
			name: "Invalid Worker Count",
			modifyConfig: func(cfg *config.Config) {
				cfg.Workers.Count = -1
			},
			expectedError: "invalid worker count",
		},
		{
			name: "Invalid Port Range",
			modifyConfig: func(cfg *config.Config) {
				cfg.Workers.ProxyStartPort = 70000
			},
			expectedError: "invalid port",
		},
		{
			name: "IP Checker Failure",
			mockChecker: &MockIPChecker{
				ShouldErr: true,
			},
			expectedError: "failed to get IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfg := createTestConfig(t, tmpDir)

			if tt.modifyConfig != nil {
				tt.modifyConfig(cfg)
			}

			logger := zap.NewNop()
			mockChecker := tt.mockChecker
			if mockChecker == nil {
				mockChecker = &MockIPChecker{
					DirectIP: "1.1.1.1",
					ProxyIP:  "2.2.2.2",
				}
			}
			mockMetrics := NewMockMetricsCollector()

			app := fx.New(
				fx.Supply(logger),
				fx.Supply("test"),
				fx.Provide(func() *config.Config { return cfg }),
				createTestModule(mockChecker, mockMetrics),
			)

			startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := app.Start(startCtx)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				assert.NoError(t, app.Stop(stopCtx))
			}
		})
	}
}

func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)
	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Run for 10 seconds to gather performance metrics
	time.Sleep(10 * time.Second)

	mockMetrics.mu.Lock()
	checkCount := len(mockMetrics.CheckResults)
	jobCount := 0
	for _, count := range mockMetrics.ScheduledJobs {
		jobCount += count
	}
	mockMetrics.mu.Unlock()

	// Verify performance metrics
	t.Run("Check Performance", func(t *testing.T) {
		assert.Greater(t, checkCount, 0, "should have performed checks")
		assert.Greater(t, jobCount, 0, "should have scheduled jobs")

		// Calculate checks per second
		checksPerSecond := float64(checkCount) / 10.0
		t.Logf("Performed %.2f checks per second", checksPerSecond)

		// Verify resource usage is reasonable
		assert.Less(t, checksPerSecond, 100.0, "check rate should not be excessive")
	})

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))
}

func TestResourceCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	var mockXrayService *MockXrayService
	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
		fx.Populate(&mockXrayService),
	)

	// Start application
	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Create some temporary files
	tempFile := filepath.Join(cfg.XrayConfigsDir, "temp.json")
	require.NoError(t, os.WriteFile(tempFile, []byte("test"), 0644))

	// Stop application
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))

	// Verify cleanup
	t.Run("Resource Cleanup", func(t *testing.T) {
		assert.False(t, mockXrayService.IsHealthy(), "service should be stopped")

		// Verify worker cleanup
		mockMetrics.mu.Lock()
		workerStops := len(mockMetrics.WorkerStops)
		mockMetrics.mu.Unlock()
		assert.Greater(t, workerStops, 0, "workers should be stopped")
	})
}

func TestConcurrentOperations(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	var mockXrayService *MockXrayService
	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
		fx.Populate(&mockXrayService),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Run concurrent operations
	t.Run("Concurrent Operations", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				// Simulate concurrent proxy config requests
				_, _, err := mockXrayService.GetProxyConfig("test-link-1")
				assert.NoError(t, err)
			}(i)
		}
		wg.Wait()
	})

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))
}

func TestConfigReloading(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Modify configuration file
	cfg.Links = append(cfg.Links, domain.RawLink{
		Name: "test-link-3",
		URL:  "vless://test-uuid@example.com:443?security=reality&type=tcp",
	})

	configPath := os.Getenv("CONFIG_PATH")
	configData, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, configData, 0644))

	// Allow time for changes to be detected
	time.Sleep(2 * time.Second)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))
}

func TestGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	logger := zap.NewNop()
	mockChecker := &MockIPChecker{
		DirectIP: "1.1.1.1",
		ProxyIP:  "2.2.2.2",
	}
	mockMetrics := NewMockMetricsCollector()

	var mockXrayService *MockXrayService
	app := fx.New(
		fx.Supply(logger),
		fx.Supply("test"),
		fx.Provide(func() *config.Config { return cfg }),
		createTestModule(mockChecker, mockMetrics),
		fx.Populate(&mockXrayService),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, app.Start(startCtx))

	// Start some long-running checks
	time.Sleep(1 * time.Second)

	// Initiate graceful shutdown
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shutdownComplete := make(chan struct{})
	go func() {
		require.NoError(t, app.Stop(stopCtx))
		close(shutdownComplete)
	}()

	// Verify graceful shutdown
	select {
	case <-shutdownComplete:
		// Check metrics to ensure all operations completed
		mockMetrics.mu.Lock()
		workerStops := len(mockMetrics.WorkerStops)
		mockMetrics.mu.Unlock()
		assert.Equal(t, cfg.Workers.Count, workerStops, "all workers should be stopped")
	case <-time.After(35 * time.Second):
		t.Fatal("graceful shutdown timed out")
	}
}
