package clip

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasepe/cli"
	"github.com/lucasepe/pwsafe"

	"github.com/atotto/clipboard"
	utils "github.com/lucasepe/pwsafe/cmd/internal"
)

type clipAction struct {
	field    string
	title    string
	filename string
}

const (
	cmdName   = "clip"
	shortDesc = "copy the content of the specified field to the clipboard"
	longDesc  = `Copy the content of the specified field to the clipboard.

Usage: %s %s -field=user|pass|url|notes <Record Title>

 * accepted values for 'field' are: user, pass, url, notes
`
)

// NewClipCommand create a 'clip' cli command
func NewClipCommand(filename string) *cli.Command {
	action := clipAction{}

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

func (r *clipAction) handler() error {
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

	secret, err := utils.GetSecretPhrase()
	if err != nil {
		return err
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
			copyFieldContentToClipboard(r.field, t, db)
			break
		}
	}

	return nil
}

func (r *clipAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")
		fs.StringVar(&(r.field), "field", "pass", "the field to copy content - user, pass, url")
	}
}

func (r *clipAction) flagPostParser(fs *flag.FlagSet) {
	if len(fs.Args()) > 0 {
		r.title = fs.Args()[0]
	}
}

func copyFieldContentToClipboard(field, name string, db pwsafe.DB) {
	rec, ok := db.GetRecord(name)
	if !ok {
		return
	}

	switch strings.ToLower(field) {
	case "pass":
		clipboard.WriteAll(rec.Password)
	case "user":
		clipboard.WriteAll(rec.Username)
	case "notes":
		clipboard.WriteAll(rec.Notes)
	default:
		clipboard.WriteAll(rec.URL)
	}

	fmt.Printf("\U0001f44d check your clipboard for the content of the field '%s'\n", field)
}
