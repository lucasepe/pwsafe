package create

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lucasepe/cli"

	"github.com/lucasepe/pwsafe"
	utils "github.com/lucasepe/pwsafe/cmd/internal"
)

type createAction struct {
	filename string
}

const (
	cmdName   = "init"
	shortDesc = "initialize a new password secure store"
	longDesc  = `Initialize an brand new password secure store.

Usage: %s %s [options]

`
)

// NewCreateCommand create a 'init' cli command
func NewCreateCommand(filename string) *cli.Command {
	action := createAction{}

	cmd := &cli.Command{
		Name:             cmdName,
		ShortDescription: shortDesc,
		Action:           action.handler,
		Documentation:    fmt.Sprintf(longDesc, filepath.Base(os.Args[0]), cmdName),
		FlagInit:         action.flagHandler(filename),
	}

	return cmd
}

func (r *createAction) handler() error {
	p, err := utils.GetAbsolutePath(r.filename)
	if err != nil {
		return err
	}
	r.filename = p

	if ok, _ := utils.FileExist(r.filename); ok {
		return utils.NewFileAlreadyExistError(r.filename)
	}

	secret, err := utils.GetSecretPhraseDoubleCheck()
	if err != nil {
		return err
	}

	db := pwsafe.NewV3("", secret)

	err = pwsafe.WritePWSafeFile(db, r.filename)
	if err == nil {
		fmt.Printf("\U0001f44d password store '%s' successfully created\n", r.filename)
	}

	return err
}

func (r *createAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")
	}
}
