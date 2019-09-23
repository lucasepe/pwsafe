package push

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasepe/cli"

	"github.com/lucasepe/pwsafe"
	"github.com/lucasepe/pwsafe/cmd/internal"
	utils "github.com/lucasepe/pwsafe/cmd/internal"
)

type pushAction struct {
	title     string
	username  string
	password  string
	url       string
	withNotes bool
	category  string
	filename  string
}

const (
	cmdName   = "push"
	shortDesc = "create or update a record"
	longDesc  = `Create or Update the record with the specified title.

Usage: %s %s [options] "Title"

`
)

// NewPushCommand create a 'push' cli command
func NewPushCommand(filename string) *cli.Command {
	action := pushAction{}

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

func (r *pushAction) handler() error {
	c, err := r.validateParams()
	if err != nil {
		return err
	}

	if c == 0 {
		return nil
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

	var notes string
	if r.withNotes {
		fmt.Println("Enter notes content (empty line or CTRL+D to terminate):")
		notes, _ = utils.GetMultilineText(40)
	}

	rec := findRecord(r.title, db)
	rec.Title = r.title

	if r.username != "" {
		rec.Username = strings.TrimSpace(r.username)
	}

	if r.url != "" {
		rec.URL = strings.TrimSpace(r.url)
	}

	if r.category != "" {
		rec.Group = strings.TrimSpace(r.category)
	}

	if r.password != "" {
		rec.Password = strings.TrimSpace(r.password)
	}

	if notes != "" {
		rec.Notes = strings.TrimSpace(notes)
	}

	db.SetRecord(rec)

	err = pwsafe.WritePWSafeFile(db, r.filename)
	if err == nil {
		fmt.Printf("\U0001f44d record successfully pushed to store '%s'\n", r.filename)
	}

	return err
}

func (r *pushAction) validateParams() (int, error) {
	if strings.TrimSpace(r.title) == "" {
		return 0, internal.NewMissingParameterError("title", cmdName)
	}

	ret := 0
	if strings.TrimSpace(r.url) != "" {
		ret = ret + 1
	}

	if strings.TrimSpace(r.username) != "" {
		ret = ret + 1
	}

	if strings.TrimSpace(r.password) != "" {
		ret = ret + 1
	}

	if strings.TrimSpace(r.category) != "" {
		ret = ret + 1
	}

	if r.withNotes {
		ret = ret + 1
	}

	return ret, nil
}

func (r *pushAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")

		fs.StringVar(&(r.title), "title", "", "a friendly name for a password entry")
		fs.StringVar(&(r.category), "category", "", "a label for organizing several related entries")
		fs.StringVar(&(r.username), "user", "", "the username")
		fs.StringVar(&(r.password), "pass", "", "the password")
		fs.StringVar(&(r.url), "url", "", "the URL associated with the entry")
		fs.BoolVar(&(r.withNotes), "note", false, "enter some additional note for this entry")
	}
}

func (r *pushAction) flagPostParser(fs *flag.FlagSet) {
	if len(fs.Args()) > 0 {
		r.title = fs.Args()[0]
	}
}

func findRecord(title string, db pwsafe.DB) pwsafe.Record {
	titles := db.List()
	tot := len(titles)
	if tot == 0 {
		return pwsafe.Record{}
	}

	for _, x := range titles {
		if strings.EqualFold(title, x) {
			if rec, ok := db.GetRecord(x); ok {
				return rec
			}
		}
	}
	return pwsafe.Record{}
}
