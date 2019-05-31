# PWSafe

Cross Platform simple and secure password management from commandline.

- Free open source software
- Works on Linux, Mac OSX, Windows
- Just a single portable binary file

Since the Password Safe [file format](https://raw.githubusercontent.com/jpvasquez/PasswordSafe/master/docs/formatV3.txt) is open-source and widely used, there are also compatible [clients](https://pwsafe.org/relatedprojects.shtml) for many platforms.

You can choose to store all your passwords in a single encrypted master password database, or use multiple databases to further organize your passwords (work and home, for example).

## Create a new password store (ìnit`)

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
|                          /Users/sepelu/Temp/test.dat                          |
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

# View a record by it's title (`pull`)

```bash
| => pwsafe pull -file test.dat "my cool site"
Secret phrase: *****
+--------------------------------------------+
|        /Users/sepelu/Temp/test.dat         |
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

[![asciicast](https://asciinema.org/a/AFgCN5ooodf4l9kxl8O5LKEAd.svg)](https://asciinema.org/a/AFgCN5ooodf4l9kxl8O5LKEAd)

