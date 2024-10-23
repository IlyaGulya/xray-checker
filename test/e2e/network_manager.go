package e2e

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
)

// NetworkManager handles test network operations
type NetworkManager struct {
	network *testcontainers.DockerNetwork
	aliases map[string][]string
	mu      sync.RWMutex
	created bool
	ctx     context.Context
}

// NewNetworkManager creates a new network manager instance
func NewNetworkManager(ctx context.Context) *NetworkManager {
	return &NetworkManager{
		aliases: make(map[string][]string),
		ctx:     ctx,
	}
}

// Setup creates a new test network with the given options
func (nm *NetworkManager) Setup(opts ...tcnetwork.NetworkCustomizer) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.created {
		return fmt.Errorf("network already created")
	}

	// Add default network options
	defaultOpts := []tcnetwork.NetworkCustomizer{
		tcnetwork.WithDriver("bridge"),
		tcnetwork.WithLabels(map[string]string{
			"testcontainers": "true",
			"purpose":        "xray-testing",
		}),
	}

	// Combine default and user options
	allOpts := append(defaultOpts, opts...)

	// Create network with retry mechanism
	var err error
	for attempts := 1; attempts <= 3; attempts++ {
		nm.network, err = tcnetwork.New(nm.ctx, allOpts...)
		if err == nil {
			break
		}
		log.Printf("Network creation attempt %d failed: %v", attempts, err)
		time.Sleep(time.Second * time.Duration(attempts))
	}

	if err != nil {
		return fmt.Errorf("failed to create network after retries: %w", err)
	}

	nm.created = true
	return nil
}

// AddContainer adds a container to the network with the given aliases
func (nm *NetworkManager) AddContainer(containerName string, aliases []string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.created {
		return fmt.Errorf("network not created")
	}

	nm.aliases[containerName] = aliases
	return nil
}

// GetNetworkRequest returns a container request option for network configuration
func (nm *NetworkManager) GetNetworkRequest(containerName string) testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) error {
		nm.mu.RLock()
		defer nm.mu.RUnlock()

		if !nm.created {
			return fmt.Errorf("network not created")
		}

		networkName := nm.network.Name
		req.Networks = []string{networkName}

		if aliases, ok := nm.aliases[containerName]; ok {
			if req.NetworkAliases == nil {
				req.NetworkAliases = make(map[string][]string)
			}
			req.NetworkAliases[networkName] = aliases
		}

		return nil
	}
}

// VerifyConnectivity checks network connectivity between containers
func (nm *NetworkManager) VerifyConnectivity(timeout time.Duration) error {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if !nm.created {
		return fmt.Errorf("network not created")
	}

	ctx, cancel := context.WithTimeout(nm.ctx, timeout)
	defer cancel()

	// Create test container for connectivity checks
	testContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:    "alpine",
			Networks: []string{nm.network.Name},
			Cmd:      []string{"tail", "-f", "/dev/null"},
		},
		Started: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create test container: %w", err)
	}
	defer func() {
		if err := testContainer.Terminate(context.Background()); err != nil {
			log.Printf("Warning: failed to terminate test container: %v", err)
		}
	}()

	// Test connectivity to each container
	for containerName, aliases := range nm.aliases {
		for _, alias := range aliases {
			if err := nm.checkConnectivity(ctx, testContainer, alias); err != nil {
				return fmt.Errorf("connectivity test failed for %s (%s): %w", containerName, alias, err)
			}
		}
	}

	return nil
}

// checkConnectivity tests network connectivity to a specific host
func (nm *NetworkManager) checkConnectivity(ctx context.Context, container testcontainers.Container, host string) error {
	cmd := []string{"ping", "-c", "1", "-W", "5", host}
	exitCode, output, err := container.Exec(ctx, cmd)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("ping failed: %v (exit code: %d, output: %s)", err, exitCode, output)
	}
	return nil
}

// Cleanup performs network cleanup operations
func (nm *NetworkManager) Cleanup() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.created {
		return nil
	}

	if nm.network != nil {
		if err := nm.network.Remove(nm.ctx); err != nil {
			return fmt.Errorf("failed to remove network: %w", err)
		}
	}

	nm.created = false
	nm.aliases = make(map[string][]string)
	return nil
}
