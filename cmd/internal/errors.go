package internal

import "fmt"

type AuthenticationError struct {
	msg string
}

func (e AuthenticationError) Error() string {
	return e.msg
}

type FileNotFoundError struct {
	msg string
}

func (e FileNotFoundError) Error() string {
	return e.msg
}

func NewFileNotFoundError(fn string) error {
	return FileNotFoundError{
		msg: fmt.Sprintf("file %s not found", fn),
	}
}

type FileAlreadyExistError struct {
	msg string
}

func (e FileAlreadyExistError) Error() string {
	return e.msg
}

func NewFileAlreadyExistError(fn string) error {
	return FileAlreadyExistError{
		msg: fmt.Sprintf("file %s already exists", fn),
	}
}
