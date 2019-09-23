# PWSafe

[![Go Report Card](https://goreportcard.com/badge/github.com/lucasepe/pwsafe)](https://goreportcard.com/report/github.com/lucasepe/pwsafe) [![Github All Releases](https://img.shields.io/github/downloads/lucasepe/pwsafe/total.svg)](https://github.com/lucasepe/pwsafe/releases) [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/gojp/goreportcard/blob/master/LICENSE)

Cross Platform simple and secure password management from commandline.

- Free open source software
- Works on [Linux](https://github.com/lucasepe/pwsafe/releases/download/v1.0.2/pwsafe-linux-amd64), [Mac OSX](https://github.com/lucasepe/pwsafe/releases/download/v1.0.2/pwsafe-darwin-amd64), [Windows](https://github.com/lucasepe/pwsafe/releases/download/v1.0.2/pwsafe-windows-amd64.exe)

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
                          /Users/lucasepe/Temp/test.dat 

  My Cool Site            pinco.pallo@gmail.com   http://www.mysecretsite.com
```

## Edit / Update a record (`push`)

```bash
| => pwsafe push -file test.dat -category Bank "My Cool Site"
Secret phrase: *****
👍 record successfully pushed to store 'test.dat'
```

## Fetch a specific field content (`pull`)

```bash
| => pwsafe pull -file test.dat "my cool site"
Secret phrase: *****
abbraadabbra
```

- by default `field=pass``

You can specify a field name

```bash
| => pwsafe pull -field url upwork
Secret phrase: 
https://www.upwork.com
```

## Copy a specific field value to clipboard (`clip`)

Useful if you want to grab the password without showing the record content.

```bash
| => pwsafe clip -file test.dat "my cool site"
Secret phrase: *****
👍 check your clipboard for the content of the field 'pass'
```

- by default the password value is copied to clipboard (`-pass`) 
  - you can also specify `-url` or `-user`.

## Remove a record (`remove`)

```bash
| => pwsafe remove "my cool site"
Secret phrase: *****
👍 record successfully removed from store '/Users/lucasepe/Temp/test.dat'
```

---

# How to avoid typing the secret phrase each time

**Caution**: use this method only if you are sure the <u>you are the only one accessing to your computer</u>!

Given `PWSAFE_HOME=$HOME/.pwsafe` as the `pwsafe` home folder.

The default database will reside in this folder named as `vault.dat`.

If you are tired to type each time the secret phrase, follow those steps:

## Goto the `$PWSAFE_HOME` folder

```bash
cd $PWSAFE_HOME
```

## Generate a private RSA key

Save it in a file called `vault-pri.pem`:

```bash
$ openssl genrsa -out vault-pri.pem 1024 
```

## Export the public key

Save it in a file called `vault-pub.pem`:

```bash
$ openssl rsa -in vault-pri.pem -pubout -out vault-pub.pem 
```

## Encrypt your secret phrase (base64 encode it)

Save it in a file called `vault.key`:

```bash
$ echo 'abbracadabbra!' | openssl rsautl -encrypt -inkey vault-pub.pem -pubin | base64 > vault.key
```

That's all! 

Now you can access to data in your default database (`vault.dat`) without typing the secret phrase.

If you wants to enable the secret phrase typing again, simply remove the following files:

- `vault.key`, `vault-pri.key`, `vault-pub.key`

---

### Credits ###

PWSafe database file encryption/decryption derived from the original work of https://github.com/tkuhlman/gopwsafe 