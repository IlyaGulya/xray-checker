package xray

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type (
	ConfigPath         string
	SocksListenPort    int
	SocksListenAddress string
)

// Runner interface defines the contract for XRay process management
type Runner interface {
	Start(configPath ConfigPath) error
	Stop() error
	IsRunning() bool
}

type runner struct {
	cmd      *exec.Cmd
	logger   *zap.Logger
	mutex    sync.Mutex
	stopped  bool
	waitDone chan struct{}
}

func NewRunner(logger *zap.Logger) Runner {
	return &runner{
		logger:   logger,
		waitDone: make(chan struct{}),
	}
}

func (r *runner) Start(configPath ConfigPath) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.IsRunning() {
		return fmt.Errorf("xray is already running")
	}

	// Reset state
	r.stopped = false
	r.waitDone = make(chan struct{})

	if _, err := exec.LookPath("xray"); err != nil {
		return fmt.Errorf("xray executable not found in PATH: %w", err)
	}

	// Validate config file exists
	if _, err := os.Stat(string(configPath)); err != nil {
		return fmt.Errorf("config file not found at %s: %w", configPath, err)
	}

	r.cmd = exec.Command("xray", "run", "-c", string(configPath))
	r.cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: runtime.GOOS != "windows",
	}

	stdout, err := r.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := r.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}

	r.logger.Debug("started xray process",
		zap.Int("pid", r.cmd.Process.Pid),
		zap.String("config", string(configPath)))

	go r.monitorOutput(stdout, "stdout")
	go r.monitorOutput(stderr, "stderr")

	// Monitor process status with proper cleanup
	go func() {
		defer close(r.waitDone)

		if err := r.cmd.Wait(); err != nil {
			if r.stopped {
				// Normal termination, log at debug level
				r.logger.Debug("xray process exited", zap.Error(err))
			} else {
				// Unexpected termination, log as error
				if exitErr, ok := err.(*exec.ExitError); ok {
					r.logger.Error("xray process exited with error",
						zap.Error(err),
						zap.Int("exit_code", exitErr.ExitCode()))
				} else {
					r.logger.Error("failed to wait for xray process", zap.Error(err))
				}
			}
		} else {
			r.logger.Info("xray process exited normally")
		}

		r.mutex.Lock()
		r.cmd = nil
		r.mutex.Unlock()
	}()

	return nil
}

func (r *runner) Stop() error {
	r.mutex.Lock()
	if !r.IsRunning() {
		r.mutex.Unlock()
		return nil
	}
	r.stopped = true
	cmd := r.cmd
	r.mutex.Unlock()

	if cmd != nil && cmd.Process != nil {
		// Try graceful shutdown first
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			r.logger.Warn("failed to send SIGTERM to xray process", zap.Error(err))
			if err := cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill xray process: %w", err)
			}
		}

		// Wait for process to exit with timeout
		select {
		case <-r.waitDone:
			return nil
		case <-time.After(5 * time.Second):
			if err := cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to force kill xray process: %w", err)
			}
			<-r.waitDone // Ensure cleanup is complete
		}
	}

	return nil
}

func (r *runner) IsRunning() bool {
	if r.cmd == nil || r.cmd.Process == nil {
		return false
	}

	// Check if process exists and can receive signals
	if err := r.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return false
	}

	return true
}

func (r *runner) monitorOutput(pipe io.ReadCloser, name string) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			r.logger.Debug("xray output",
				zap.String("pipe", name),
				zap.String("message", line))
		}
	}

	if err := scanner.Err(); err != nil {
		r.logger.Error("error reading xray output",
			zap.String("pipe", name),
			zap.Error(err))
	}
}
