package worker

import "fmt"

// CheckError represents an error that occurred during VPN checking
type CheckError struct {
	Stage   string // The stage where the error occurred
	Message string // Human-readable error message
	Err     error  // Original error
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("%s: %s: %v", e.Stage, e.Message, e.Err)
}

func (e *CheckError) Unwrap() error {
	return e.Err
}

func NewCheckError(stage, message string, err error) error {
	return &CheckError{
		Stage:   stage,
		Message: message,
		Err:     err,
	}
}
