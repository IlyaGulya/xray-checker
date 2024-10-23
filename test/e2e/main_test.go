package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testEnv       *TestEnvironment
	ctx           = context.Background()
	setupComplete = false
)

func TestMain(m *testing.M) {
	var err error
	var exitCode int

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if testEnv, err = SetupTestEnvironment(); err != nil {
		log.Printf("Failed to setup test environment: %v", err)
		os.Exit(1)
	}

	if err := setupDirectories(); err != nil {
		log.Printf("Failed to setup directories: %v", err)
		os.Exit(1)
	}

	setupComplete = true
	exitCode = m.Run()
	cleanup()
	os.Exit(exitCode)
}

func cleanup() {
	if !setupComplete {
		return
	}

	if testEnv != nil {
		testEnv.Cleanup(ctx)
		time.Sleep(2 * time.Second)
	}
}

func setupDirectories() error {
	dirs := []string{"build", "build/configs"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

type TestResult struct {
	Success      bool
	ErrorMessage string
	Logs         string
	Duration     time.Duration
}

func TestProtocolConnectivity(t *testing.T) {
	protocols := []string{"vless", "trojan", "shadowsocks"}

	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			testEnv.clearUptimeCalls()

			mappedPort := testEnv.portMappings[protocol]
			require.NotEmpty(t, mappedPort, "No port mapping found for protocol: %s", protocol)

			configPath, err := filepath.Abs(SetupTestConfig(t, testEnv, protocol, mappedPort))
			require.NoError(t, err, "Failed to get absolute config path")
			require.NoError(t, validateConfig(t, configPath), "Config validation failed")

			req := createContainerRequest(configPath, testEnv.network.Name)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: req,
				Started:          true,
			})
			require.NoError(t, err, "Failed to start container")

			defer func() {
				if err := container.Terminate(ctx); err != nil {
					t.Logf("Warning: Failed to terminate container: %v", err)
				}
			}()

			// Wait for container to finish with timeout
			statusCh := make(chan struct{})
			go func() {
				defer close(statusCh)
				for {
					state, err := container.State(ctx)
					if err != nil {
						t.Logf("Warning: Failed to get container state: %v", err)
						return
					}
					if !state.Running {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			select {
			case <-statusCh:
				// Container finished
			case <-time.After(30 * time.Second):
				t.Errorf("Test timed out for protocol %s", protocol)
				return
			}

			exitCode, err := getContainerExitCode(ctx, container)
			require.NoError(t, err, "Failed to get exit code")

			logs, err := container.Logs(ctx)
			require.NoError(t, err, "Failed to get container logs")

			logContent, err := io.ReadAll(logs)
			require.NoError(t, err, "Failed to read container logs")

			t.Logf("Test Results for %s:", protocol)
			t.Logf("Exit Code: %d", exitCode)
			t.Logf("Container Logs:\n%s", string(logContent))

			assert.Equal(t, 0, exitCode, "Expected exit code 0 for successful test")
			assert.True(t, testEnv.wasUptimeCalled(protocol),
				"Expected uptime monitoring to be called for %s", protocol)

			if exitCode == 0 {
				switch protocol {
				case "vless":
					assert.Contains(t, string(logContent), "VLESS connection")
				case "trojan":
					assert.Contains(t, string(logContent), "Trojan connection")
				case "shadowsocks":
					assert.Contains(t, string(logContent), "Shadowsocks connection")
				}
			}

			t.Logf("Successfully tested %s protocol", protocol)
		})
	}
}

func runProtocolTest(t *testing.T, protocol string, env *TestEnvironment) TestResult {
	t.Helper()

	result := TestResult{}
	start := time.Now()

	containerPort := getContainerPort(protocol)
	if containerPort == "" {
		result.ErrorMessage = fmt.Sprintf("no port mapping found for protocol: %s", protocol)
		return result
	}

	configPath, err := filepath.Abs(SetupTestConfig(t, env, protocol, containerPort))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to get absolute config path: %v", err)
		return result
	}

	if err := validateConfig(t, configPath); err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to create valid config: %v", err)
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req := createContainerRequest(configPath, env.network.Name)

	xrayContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to start container: %v", err)
		return result
	}

	defer func() {
		if err := xrayContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	exitCode, err := getContainerExitCode(ctx, xrayContainer)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to get exit code: %v", err)
		return result
	}

	logReader, err := xrayContainer.Logs(ctx)
	if err == nil {
		defer logReader.Close()
		logContent, err := io.ReadAll(logReader)
		if err == nil {
			result.Logs = string(logContent)
		}
	}

	result.Success = exitCode == 0
	result.Duration = time.Since(start)

	return result
}

func getContainerPort(protocol string) string {
	switch protocol {
	case "vless":
		return strings.TrimSuffix(VlessPort, "/tcp")
	case "trojan":
		return strings.TrimSuffix(TrojanPort, "/tcp")
	case "shadowsocks":
		return strings.TrimSuffix(ShadowsocksPort, "/tcp")
	default:
		return ""
	}
}

func TestErrorHandling(t *testing.T) {
	testCases := []struct {
		name          string
		protocol      string
		modifyConfig  func(config *TestConfigData)
		expectedError string
	}{
		{
			name:     "Invalid VLESS UUID",
			protocol: "vless",
			modifyConfig: func(config *TestConfigData) {
				config.Provider.Configs[0].Link = "vless://invalid-uuid@vless-server:10001?security=none&type=tcp#test"
			},
			expectedError: "failed to verify UUID",
		},
		{
			name:     "Invalid Trojan Password",
			protocol: "trojan",
			modifyConfig: func(config *TestConfigData) {
				config.Provider.Configs[0].Link = "trojan://wrong-password@trojan-server:10002?security=tls&type=tcp#test"
			},
			expectedError: "failed to authenticate",
		},
		{
			name:     "Invalid Shadowsocks Method",
			protocol: "shadowsocks",
			modifyConfig: func(config *TestConfigData) {
				userInfo := base64.StdEncoding.EncodeToString([]byte("invalid-method:test-password"))
				config.Provider.Configs[0].Link = fmt.Sprintf("ss://%s@shadowsocks-server:10003#test", userInfo)
			},
			expectedError: "encryption method not supported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mappedPort := testEnv.portMappings[tc.protocol]
			require.NotEmpty(t, mappedPort, "No port mapping found for protocol: %s", tc.protocol)

			configPath := SetupTestConfig(t, testEnv, tc.protocol, mappedPort)
			require.FileExists(t, configPath, "Config file should exist")

			configData, err := os.ReadFile(configPath)
			require.NoError(t, err, "Failed to read config file")

			var config TestConfigData
			require.NoError(t, json.Unmarshal(configData, &config), "Failed to unmarshal config")

			tc.modifyConfig(&config)

			modifiedData, err := json.MarshalIndent(config, "", "    ")
			require.NoError(t, err, "Failed to marshal modified config")
			require.NoError(t, os.WriteFile(configPath, modifiedData, 0644), "Failed to write modified config")

			result := runProtocolTest(t, tc.protocol, testEnv)

			assert.False(t, result.Success, "Expected test to fail")
			assert.Contains(t, result.Logs, tc.expectedError, "Expected specific error message")
		})
	}
}

func TestNetworkConditions(t *testing.T) {
	testCases := []struct {
		name          string
		latency       time.Duration
		packetLoss    float64
		minDuration   time.Duration
		maxAttempts   int
		shouldSucceed bool
	}{
		{
			name:          "High Latency",
			latency:       500 * time.Millisecond,
			packetLoss:    0,
			minDuration:   450 * time.Millisecond,
			maxAttempts:   3,
			shouldSucceed: true,
		},
		{
			name:          "Moderate Packet Loss",
			latency:       0,
			packetLoss:    0.3,
			minDuration:   0,
			maxAttempts:   5,
			shouldSucceed: true,
		},
		{
			name:          "Combined Issues",
			latency:       200 * time.Millisecond,
			packetLoss:    0.2,
			minDuration:   180 * time.Millisecond,
			maxAttempts:   5,
			shouldSucceed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testEnv.SetNetworkConditions(tc.latency, tc.packetLoss)
			defer testEnv.ResetNetworkConditions()

			mappedPort := testEnv.portMappings["vless"]
			configPath, err := filepath.Abs(SetupTestConfig(t, testEnv, "vless", mappedPort))
			require.NoError(t, err, "Failed to get absolute config path")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			var succeeded bool
			var lastLogs string
			var duration time.Duration

			start := time.Now()

			for attempt := 1; attempt <= tc.maxAttempts; attempt++ {
				attemptStart := time.Now()

				req := createContainerRequest(configPath, testEnv.network.Name)

				container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: req,
					Started:          true,
				})

				if err != nil {
					t.Logf("Attempt %d: Failed to create container: %v", attempt, err)
					continue
				}

				defer func() {
					if err := container.Terminate(ctx); err != nil {
						t.Logf("Failed to terminate container: %v", err)
					}
				}()

				exitCode, err := getContainerExitCode(ctx, container)

				if logs, err := container.Logs(ctx); err == nil {
					logContent, _ := io.ReadAll(logs)
					lastLogs = string(logContent)
					t.Logf("Attempt %d logs:\n%s", attempt, lastLogs)
				}

				if err == nil && exitCode == 0 {
					succeeded = true
					duration = time.Since(attemptStart)
					break
				}

				t.Logf("Attempt %d failed with exit code %d", attempt, exitCode)
				time.Sleep(time.Second * time.Duration(attempt))
			}

			t.Logf("Test finished in %v", time.Since(start))
			t.Logf("Final logs:\n%s", lastLogs)

			if tc.shouldSucceed {
				assert.True(t, succeeded, "Expected test to eventually succeed")
			}

			if tc.minDuration > 0 {
				assert.Greater(t, duration, tc.minDuration, "Expected minimum duration not met")
			}
		})
	}
}

func TestConcurrentConnections(t *testing.T) {
	numConnections := 5
	results := make(chan TestResult, numConnections)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	configPath, err := filepath.Abs(SetupTestConfig(t, testEnv, "vless", testEnv.portMappings["vless"]))
	require.NoError(t, err, "Failed to create config")

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			req := createContainerRequest(configPath, testEnv.network.Name)

			result := TestResult{
				Success: false,
			}

			container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: req,
				Started:          true,
			})

			if err != nil {
				result.ErrorMessage = fmt.Sprintf("Container %d failed to start: %v", index, err)
				results <- result
				return
			}

			defer func() {
				terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer terminateCancel()

				if err := container.Terminate(terminateCtx); err != nil {
					t.Logf("Failed to terminate container %d: %v", index, err)
				}
			}()

			exitCode, err := getContainerExitCode(ctx, container)

			if logs, err := container.Logs(ctx); err == nil {
				logContent, _ := io.ReadAll(logs)
				result.Logs = string(logContent)
				t.Logf("Container %d logs:\n%s", index, result.Logs)
			}

			result.Success = err == nil && exitCode == 0
			if !result.Success {
				result.ErrorMessage = fmt.Sprintf("Container %d failed with exit code %d", index, exitCode)
			}

			results <- result
		}(i)
	}

	// Wait for all tests to complete
	wg.Wait()
	close(results)

	// Analyze results
	successCount := 0
	for result := range results {
		if result.Success {
			successCount++
		} else {
			t.Logf("Failed connection: %s", result.ErrorMessage)
			t.Logf("Logs:\n%s", result.Logs)
		}
	}

	// At least 60% of connections should succeed
	minSuccessful := int(float64(numConnections) * 0.6)
	assert.GreaterOrEqual(t, successCount, minSuccessful,
		"Expected at least %d of %d connections to succeed, got %d",
		minSuccessful, numConnections, successCount)
}

func TestCleanup(t *testing.T) {
	// Test proper cleanup of resources
	buildDir := filepath.Join("build")
	configsDir := filepath.Join(buildDir, "configs")

	files, err := os.ReadDir(buildDir)
	assert.NoError(t, err, "Failed to read build directory")

	// Verify build directory is clean
	for _, file := range files {
		if file.Name() != "configs" {
			assert.Fail(t, "Unexpected file in build directory",
				"Found file: %s", file.Name())
		}
	}

	// Verify configs directory is properly managed
	configFiles, err := os.ReadDir(configsDir)
	assert.NoError(t, err, "Failed to read configs directory")

	for _, file := range configFiles {
		assert.True(t, strings.HasSuffix(file.Name(), "-test-config.json"),
			"Unexpected file in configs directory: %s", file.Name())
	}
}

// Helper function to get container exit code
func getContainerExitCode(ctx context.Context, container testcontainers.Container) (int, error) {
	// Get container info to check exit code
	inspect, err := container.Inspect(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect container: %w", err)
	}

	if inspect.State == nil {
		return 0, fmt.Errorf("container state is nil")
	}

	return inspect.State.ExitCode, nil
}

// Helper function to create container request with logging
func createContainerRequest(configPath string, networkName string) testcontainers.ContainerRequest {
	return testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "../..",
			Dockerfile: "Dockerfile",
		},
		Networks: []string{networkName},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(configPath, "/app/config.json"),
		),
		Cmd: []string{"-config", "/app/config.json"},
		WaitingFor: wait.ForAll(
			wait.ForLog("Starting Xray").WithStartupTimeout(30*time.Second),
			wait.ForLog("Configuration OK").WithStartupTimeout(30*time.Second),
		),
		// Use environment variable for logging level instead of Logger field
		Env: map[string]string{
			"LOG_LEVEL": "debug",
		},
	}
}
