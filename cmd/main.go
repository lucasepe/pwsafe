package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lucasepe/cli"
	"github.com/lucasepe/homedir"
	"github.com/lucasepe/pwsafe/cmd/clip"
	"github.com/lucasepe/pwsafe/cmd/create"
	"github.com/lucasepe/pwsafe/cmd/internal"
	"github.com/lucasepe/pwsafe/cmd/list"
	"github.com/lucasepe/pwsafe/cmd/pull"
	"github.com/lucasepe/pwsafe/cmd/push"
)

const (
	appDir     = ".pwsafe"
	dbFilename = "vault.dat"
)

func main() {
	workDir, err := createWorkdir(appDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err.Error())
		os.Exit(1)
		return
	}

	headline := "PW Safe allows you to safely create a secured and encrypted username/password list."
	footer := "crafted with passion by Luca Sepe"

	binName := filepath.Base(os.Args[0])

	bin := cli.New(binName, fmt.Sprintf("%s\n\n  * %s", headline, footer))
	bin.IncludeHelp()

	filename := filepath.Join(workDir, dbFilename)

	err = bin.RegisterCommand(list.NewListCommand(filename))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = bin.RegisterCommand(pull.NewPullCommand(filename))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = bin.RegisterCommand(push.NewPushCommand(filename))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = bin.RegisterCommand(create.NewCreateCommand(filename))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = bin.RegisterCommand(clip.NewClipCommand(filename))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := bin.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\U0001f480  %s\n", err.Error())
		switch err.(type) {
		case internal.FileNotFoundError:
			fmt.Fprintln(os.Stderr, "  \U0001f4a1 specify a valid database using the -file option")
			fmt.Fprintf(os.Stderr, "  \U0001f4a1 create a brand new database using the '%s init' command\n", binName)
		case internal.FileAlreadyExistError:
			fmt.Fprintln(os.Stderr, "  \U0001f4a1 specify a new file using the -file option")
			fmt.Fprintf(os.Stderr, "  \U0001f4a1 add a new account to this database using the '%s push' command\n", binName)
		}
		os.Exit(1)
	}

	/*
		rec := pwsafe.Record{
			Email:    "luca.sepe@gmail.com",
			Username: "luca.sepe@gmail.com",
			Password: "piripicchiolo!",
			URL:      "http://www.twitter.com",
			Group:    "Social",
			Title:    "Twitter Account",
		}
		db := pwsafe.NewV3("Test DB", "Magick!")
		db.SetRecord(rec)

		err := pwsafe.WritePWSafeFile(db, "test.dat")
		if err != nil {
			panic(err)
		}
	*/

	/*
		db, err := pwsafe.OpenPWSafeFile("magick.dat", "SimmTuttPurtuall!")
		if err != nil {
			panic(err)
		}



		title := "Apple ID"
		rec, ok := db.GetRecord(title)
		if !ok {
			fmt.Printf("No record found for title: %s\n", title)
			return
		}

		fmt.Printf("Title    : %s\n", rec.Title)
		fmt.Printf("Username : %s\n", rec.Username)
		fmt.Printf("Password : %s\n", rec.Password)
		fmt.Printf("URL      : %s\n", rec.URL)
		fmt.Printf("Notes    : %s\n", rec.Notes)
	*/
}

func createWorkdir(name string) (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	workdir := filepath.Join(home, name)
	if _, err := os.Stat(workdir); os.IsNotExist(err) {
		err = os.MkdirAll(workdir, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	return workdir, nil
}
