package list

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lucasepe/cli"

	"github.com/xlab/tablewriter"

	"github.com/lucasepe/pwsafe"
	utils "github.com/lucasepe/pwsafe/cmd/internal"
)

type listAction struct {
	query    string
	filename string
}

const (
	cmdName   = "list"
	shortDesc = "print a summary of all the records"
	longDesc  = `print a summary of all the records stored in the specified password store.

Usage: %s %s [pattern]

 * if a pattern is specified only records matching it will be listed
`
)

// NewListCommand create a 'list' cli command
func NewListCommand(filename string) *cli.Command {
	action := listAction{}

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

func (r *listAction) handler() error {
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

	str := dump(r.filename, r.query, db)
	fmt.Println(str)

	return nil
}

func (r *listAction) flagHandler(fn string) func(fs *flag.FlagSet) {
	return func(fs *flag.FlagSet) {
		fs.StringVar(&(r.filename), "file", fn, "secure password store file")
	}
}

func (r *listAction) flagPostParser(fs *flag.FlagSet) {
	if len(fs.Args()) > 0 {
		r.query = fs.Args()[0]
	}
}

func dump(caption, query string, db pwsafe.DB) string {
	table := tablewriter.CreateTable()
	table.AddTitle(caption)
	//tablewriter.EnableUTF8()
	table.AddHeaders("TITLE", "CATEGORY", "USERNAME", "URL")

	titles := db.List()
	tot := len(titles)
	if tot == 0 {
		return table.Render()
	}

	var exp *regexp.Regexp
	if strings.TrimSpace(query) != "" {
		exp = regexp.MustCompile(fmt.Sprintf("(?i)%s", query))
	}

	for _, x := range titles {
		dump := true
		if rec, ok := db.GetRecord(x); ok {
			if exp != nil {
				dump = exp.MatchString(rec.Title) || exp.MatchString(rec.Group)
			}

			if dump {
				table.AddRow(
					rec.Title,
					rec.Group,
					utils.TruncateText(rec.Username, 41),
					rec.URL,
				)
			}
		}
	}

	return table.Render()
}
