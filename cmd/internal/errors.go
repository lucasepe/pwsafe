package internal

import (
	"fmt"
	"os"
	"path/filepath"
)

// AuthenticationError return an authentication failure message
type AuthenticationError struct {
	msg string
}

func (e AuthenticationError) Error() string {
	return e.msg
}

// FileNotFoundError return a file not found error message
type FileNotFoundError struct {
	msg string
}

func (e FileNotFoundError) Error() string {
	return e.msg
}

// NewFileNotFoundError build a file not found error message
func NewFileNotFoundError(fn string) error {
	return FileNotFoundError{
		msg: fmt.Sprintf("file %s not found", fn),
	}
}

// FileAlreadyExistError return a file already exist error message
type FileAlreadyExistError struct {
	msg string
}

func (e FileAlreadyExistError) Error() string {
	return e.msg
}

// NewFileAlreadyExistError build a file already exist error message
func NewFileAlreadyExistError(fn string) error {
	return FileAlreadyExistError{
		msg: fmt.Sprintf("file %s already exists", fn),
	}
}

// MissingParameterError return a missed option or argument error message
type MissingParameterError struct {
	msg string
}

func (e MissingParameterError) Error() string {
	return e.msg
}

// NewMissingParameterError build a file already exist error message
func NewMissingParameterError(param, cmdName string) error {
	m := fmt.Sprintf("missing %s - please type '%s help %s' for more details",
		param, filepath.Base(os.Args[0]), cmdName)
	return MissingParameterError{msg: m}
}
