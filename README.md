# PWSafe

[![Go Report Card](https://goreportcard.com/badge/github.com/lucasepe/pwsafe)](https://goreportcard.com/report/github.com/lucasepe/pwsafe) [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/gojp/goreportcard/blob/master/LICENSE)

Cross Platform simple and secure password management from commandline.

- Free open source software
- Works on [Linux](https://github.com/lucasepe/pwsafe/releases/download/v1.0.0/pwsafe-linux-amd64), [Mac OSX](https://github.com/lucasepe/pwsafe/releases/download/v1.0.0/pwsafe-darwin-amd64), [Windows](https://github.com/lucasepe/pwsafe/releases/download/v1.0.0/pwsafe-windows-amd64)

- Just a single portable binary file

Since the Password Safe [file format](https://raw.githubusercontent.com/jpvasquez/PasswordSafe/master/docs/formatV3.txt) is open-source and widely used, there are also compatible [clients](https://pwsafe.org/relatedprojects.shtml) for many platforms.

You can choose to store all your passwords in a single encrypted master password database, or use multiple databases to further organize your passwords (work and home, for example).

## Create a new password store (`init`)

```bash
| => pwsafe init -file test.dat
Secret phrase: *****
Secret phrase again: ***** 
👍 password store 'test.dat' successfully created
```

## Add a new account info (`push`)

```bash
| => pwsafe push -file test.dat -url http://www.mysecretsite.com -user pinco.pallo@gmail.com -pass abbraadabbra "My Cool Site"
Secret phrase: *****
👍 record successfully pushed to store 'test.dat'
```

## Show a summary of all records (`list`)

```bash
| => pwsafe list -file test.dat
Secret phrase: *****
+-------------------------------------------------------------------------------+
|                         /Users/lucasepe/Temp/test.dat                         |
+--------------+----------+-----------------------+-----------------------------+
| TITLE        | CATEGORY | USERNAME              | URL                         |
+--------------+----------+-----------------------+-----------------------------+
| My Cool Site |          | pinco.pallo@gmail.com | http://www.mysecretsite.com |
+--------------+----------+-----------------------+-----------------------------+
```

## Edit / Update a record (`push`)

```bash
| => pwsafe push -file test.dat -category Bank "My Cool Site"
Secret phrase: *****
👍 record successfully pushed to store 'test.dat'
```

## View a record by it's title (`pull`)

```bash
| => pwsafe pull -file test.dat "my cool site"
Secret phrase: *****
+--------------------------------------------+
|       /Users/lucasepe/Temp/test.dat        |
+--------------------------------------------+
| TITLE        : My Cool Site                |
| GROUP        : Bank                        |
| URL          : http://www.mysecretsite.com |
| USERNAME     : pinco.pallo@gmail.com       |
| PASSWORD     : abbraadabbra                |
| NOTES        :                             |
| LAST UPDATED : 2019-29-05                  |
+--------------------------------------------+
```

## Copy a specific field value to your clipboard (`clip`)

Usefull if you want to grab the password without showing the record content.

```bash
| => pwsafe clip -file test.dat "my cool site"
Secret phrase: *****
👍 check your clipboard for the content of the field 'pass'
````

by default the password value is copied to clipboard but (`-pass`) but you can specify `-url` or `-user`.

---

[![asciicast](https://asciinema.org/a/AFgCN5ooodf4l9kxl8O5LKEAd.svg)](https://asciinema.org/a/AFgCN5ooodf4l9kxl8O5LKEAd)

### Credits ###

PWSafe database file encryption/decryption derived from the original work of https://github.com/tkuhlman/gopwsafe 