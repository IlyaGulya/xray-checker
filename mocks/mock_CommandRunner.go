// Code generated by mockery v2.46.3. DO NOT EDIT.

package mocks

import (
	exec "os/exec"

	mock "github.com/stretchr/testify/mock"
)

// CommandRunner is an autogenerated mock type for the CommandRunner type
type CommandRunner struct {
	mock.Mock
}

type CommandRunner_Expecter struct {
	mock *mock.Mock
}

func (_m *CommandRunner) EXPECT() *CommandRunner_Expecter {
	return &CommandRunner_Expecter{mock: &_m.Mock}
}

// KillCommand provides a mock function with given fields: cmd
func (_m *CommandRunner) KillCommand(cmd *exec.Cmd) error {
	ret := _m.Called(cmd)

	if len(ret) == 0 {
		panic("no return value specified for KillCommand")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*exec.Cmd) error); ok {
		r0 = rf(cmd)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CommandRunner_KillCommand_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KillCommand'
type CommandRunner_KillCommand_Call struct {
	*mock.Call
}

// KillCommand is a helper method to define mock.On call
//   - cmd *exec.Cmd
func (_e *CommandRunner_Expecter) KillCommand(cmd interface{}) *CommandRunner_KillCommand_Call {
	return &CommandRunner_KillCommand_Call{Call: _e.mock.On("KillCommand", cmd)}
}

func (_c *CommandRunner_KillCommand_Call) Run(run func(cmd *exec.Cmd)) *CommandRunner_KillCommand_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*exec.Cmd))
	})
	return _c
}

func (_c *CommandRunner_KillCommand_Call) Return(_a0 error) *CommandRunner_KillCommand_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CommandRunner_KillCommand_Call) RunAndReturn(run func(*exec.Cmd) error) *CommandRunner_KillCommand_Call {
	_c.Call.Return(run)
	return _c
}

// RunCommand provides a mock function with given fields: name, args
func (_m *CommandRunner) RunCommand(name string, args ...string) (*exec.Cmd, error) {
	_va := make([]interface{}, len(args))
	for _i := range args {
		_va[_i] = args[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, name)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for RunCommand")
	}

	var r0 *exec.Cmd
	var r1 error
	if rf, ok := ret.Get(0).(func(string, ...string) (*exec.Cmd, error)); ok {
		return rf(name, args...)
	}
	if rf, ok := ret.Get(0).(func(string, ...string) *exec.Cmd); ok {
		r0 = rf(name, args...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*exec.Cmd)
		}
	}

	if rf, ok := ret.Get(1).(func(string, ...string) error); ok {
		r1 = rf(name, args...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CommandRunner_RunCommand_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RunCommand'
type CommandRunner_RunCommand_Call struct {
	*mock.Call
}

// RunCommand is a helper method to define mock.On call
//   - name string
//   - args ...string
func (_e *CommandRunner_Expecter) RunCommand(name interface{}, args ...interface{}) *CommandRunner_RunCommand_Call {
	return &CommandRunner_RunCommand_Call{Call: _e.mock.On("RunCommand",
		append([]interface{}{name}, args...)...)}
}

func (_c *CommandRunner_RunCommand_Call) Run(run func(name string, args ...string)) *CommandRunner_RunCommand_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(args[0].(string), variadicArgs...)
	})
	return _c
}

func (_c *CommandRunner_RunCommand_Call) Return(_a0 *exec.Cmd, _a1 error) *CommandRunner_RunCommand_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CommandRunner_RunCommand_Call) RunAndReturn(run func(string, ...string) (*exec.Cmd, error)) *CommandRunner_RunCommand_Call {
	_c.Call.Return(run)
	return _c
}

// NewCommandRunner creates a new instance of CommandRunner. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCommandRunner(t interface {
	mock.TestingT
	Cleanup(func())
}) *CommandRunner {
	mock := &CommandRunner{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}