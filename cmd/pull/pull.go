package pull

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasepe/cli"
	utils "github.com/lucasepe/pwsafe/cmd/internal"

	"github.com/xlab/tablewriter"

	"github.com/lucasepe/pwsafe"
)

type pullAction struct {
	title    string
	filename string
}

const (
	cmdName   = "pull"
	shortDesc = "fetch the record with the specified title"
	longDesc  = `Fetch and show all the fields of the record with this title.

Usage: %s %s "Title"

`
)

func NewPullCommand(filename string) *cli.Command {
	action := pullAction{}

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

func (r *pullAction) handler() error {
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
			dumpRecord(r.filename, t, db)
			break
		}
	}

	return nil
}

func (r *pullAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")
	}
}

func (r *pullAction) flagPostParser(fs *flag.FlagSet) {
	if len(fs.Args()) > 0 {
		r.title = fs.Args()[0]
	}
}

func dumpRecord(caption, name string, db pwsafe.DB) {
	rec, ok := db.GetRecord(name)
	if !ok {
		return
	}

	table := tablewriter.CreateTable()
	table.AddTitle(caption)
	table.AddRow(fmt.Sprintf("TITLE        : %s", rec.Title))
	table.AddRow(fmt.Sprintf("GROUP        : %s", rec.Group))
	table.AddRow(fmt.Sprintf("URL          : %s", rec.URL))
	table.AddRow(fmt.Sprintf("USERNAME     : %s", rec.Username))
	table.AddRow(fmt.Sprintf("PASSWORD     : %s", rec.Password))
	table.AddRow(fmt.Sprintf("NOTES        : %s", rec.Notes))
	table.AddRow(fmt.Sprintf("LAST UPDATED : %s", rec.ModTime.Format("2006-02-01")))

	fmt.Println(table.Render())
}
