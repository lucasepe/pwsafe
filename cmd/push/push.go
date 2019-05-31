package push

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasepe/cli"

	"github.com/lucasepe/pwsafe"
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

	var notes string
	if r.withNotes {
		fmt.Println("Enter notes content (empty line or CTRL+D to terminate):")
		notes, _ = utils.GetMultilineText(40)
	}

	rec := findRecord(r.title, db)
	rec.Title = r.title

	if r.username != "" {
		rec.Username = r.username
	}

	if r.url != "" {
		rec.URL = r.url
	}

	if r.category != "" {
		rec.Group = r.category
	}

	if r.password != "" {
		rec.Password = r.password
	}

	if notes != "" {
		rec.Notes = notes
	}

	db.SetRecord(rec)

	err = pwsafe.WritePWSafeFile(db, r.filename)
	if err == nil {
		fmt.Printf("\U0001f44d record successfully pushed to store '%s'\n", r.filename)
	}

	return err
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
