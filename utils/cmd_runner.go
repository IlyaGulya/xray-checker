package utils

import "os/exec"

type CommandRunner interface {
	RunCommand(name string, args ...string) (*exec.Cmd, error)
	KillCommand(cmd *exec.Cmd) error
}

type DefaultCommandRunner struct{}

func (r *DefaultCommandRunner) RunCommand(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	err := cmd.Start()
	return cmd, err
}

func (r *DefaultCommandRunner) KillCommand(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
