package remove

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasepe/cli"
	utils "github.com/lucasepe/pwsafe/cmd/internal"

	"github.com/lucasepe/pwsafe"
)

type removeAction struct {
	title    string
	filename string
}

const (
	cmdName   = "remove"
	shortDesc = "remove a record"
	longDesc  = `Remove the record with the specified title.

Usage: %s %s <Record Title>
`
)

// NewRemoveCommand create a 'remove' cli command
func NewRemoveCommand(filename string) *cli.Command {
	action := removeAction{}

	cmd := &cli.Command{
		Name:             cmdName,
		ShortDescription: shortDesc,
		Action:           action.handler,
		Documentation:    fmt.Sprintf(longDesc, filepath.Base(os.Args[0]), cmdName),
		FlagInit:         action.flagHandler(filename),
		FlagPostParse:    action.flagPostParser,
	}

	return cmd
}

func (r *removeAction) handler() error {
	if strings.TrimSpace(r.title) == "" {
		return fmt.Errorf("missed record title")
	}

	p, err := utils.GetAbsolutePath(r.filename)
	if err != nil {
		return err
	}
	r.filename = p

	_, err = utils.FileExist(r.filename)
	if err != nil {
		return err
	}

	secret, err := utils.GetEncryptedSecretPhrase(r.filename)
	if err != nil {
		secret, err = utils.GetSecretPhrase()
		if err != nil {
			return err
		}
	}

	db, err := pwsafe.OpenPWSafeFile(r.filename, secret)
	if err != nil {
		return err
	}

	titles := db.List()
	tot := len(titles)
	if tot == 0 {
		return nil
	}

	for _, t := range titles {
		if strings.EqualFold(r.title, t) {
			db.DeleteRecord(t)
			break
		}
	}

	err = pwsafe.WritePWSafeFile(db, r.filename)
	if err == nil {
		fmt.Printf("\U0001f44d record successfully removed from store '%s'\n", r.filename)
	}

	return err
}

func (r *removeAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")
	}
}

func (r *removeAction) flagPostParser(fs *flag.FlagSet) {
	if len(fs.Args()) > 0 {
		r.title = fs.Args()[0]
	}
}
