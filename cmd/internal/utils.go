package internal

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh/terminal"
)

// GetAbsolutePath return the absolute path of the specified file.
func GetAbsolutePath(fn string) (string, error) {
	if filepath.IsAbs(fn) {
		return fn, nil
	}

	return filepath.Abs(fn)
}

// FileExist check if the specified file exists
func FileExist(fn string) (bool, error) {
	if _, err := os.Stat(fn); os.IsNotExist(err) {
		return false, NewFileNotFoundError(fn)
	}

	return true, nil
}

// GetSecretPhrase read a password entry from terminal.
func GetSecretPhrase() (string, error) {
	var passBytes []byte
	var err error
	for len(passBytes) == 0 {
		fmt.Print("Secret phrase: ")
		passBytes, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Println("")
	}

	return string(passBytes), nil
}

// GetSecretPhraseDoubleCheck read a password entry from terminal.
// This routine ask for the password twice in order to be sure.
func GetSecretPhraseDoubleCheck() (string, error) {
	var passBytes []byte
	var passBytesAgain []byte
	var err error
	for {
		for len(passBytes) == 0 {
			fmt.Print("Secret phrase: ")
			passBytes, err = terminal.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return "", err
			}
			fmt.Println("")
		}

		fmt.Print("Secret phrase again: ")
		passBytesAgain, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Println("")

		if bytes.Equal(passBytes, passBytesAgain) {
			break
		} else {
			fmt.Fprintf(os.Stderr, "secret phrases do not match\n")
			passBytes = nil
			continue
		}
	}

	return string(passBytes), nil
}

// TruncateText truncate the specified string at defined number of chars
func TruncateText(s string, i int) string {
	runes := []rune(s)
	if len(runes) > i {
		return fmt.Sprintf("%s…", string(runes[:i]))
	}
	return s
}

// GetMultilineText read multiline text from terminal.
func GetMultilineText(cols uint) (string, error) {
	scn := bufio.NewScanner(os.Stdin)

	var lines []string
	for scn.Scan() {
		line := scn.Text()
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		} else {
			break
		}
	}

	if err := scn.Err(); err != nil {
		return "", err
	}

	if len(lines) > 0 {
		txt := strings.Join(lines, "\n")
		txt = textWrap(txt, cols)
		return txt, nil
	}

	return "", nil
}

// textWrap wraps the given string within lim width in characters.
//
// Wrapping is currently naive and only happens at white-space. A future
// version of the library will implement smarter wrapping. This means that
// pathological cases can dramatically reach past the limit, such as a very
// long word.
func textWrap(s string, lim uint) string {
	// Initialize a buffer with a slightly larger size to account for breaks
	init := make([]byte, 0, len(s))
	buf := bytes.NewBuffer(init)

	var current uint
	var wordBuf, spaceBuf bytes.Buffer

	for _, char := range s {
		if char == '\n' {
			if wordBuf.Len() == 0 {
				if current+uint(spaceBuf.Len()) > lim {
					current = 0
				} else {
					current += uint(spaceBuf.Len())
					spaceBuf.WriteTo(buf)
				}
				spaceBuf.Reset()
			} else {
				current += uint(spaceBuf.Len() + wordBuf.Len())
				spaceBuf.WriteTo(buf)
				spaceBuf.Reset()
				wordBuf.WriteTo(buf)
				wordBuf.Reset()
			}
			buf.WriteRune(char)
			current = 0
		} else if unicode.IsSpace(char) {
			if spaceBuf.Len() == 0 || wordBuf.Len() > 0 {
				current += uint(spaceBuf.Len() + wordBuf.Len())
				spaceBuf.WriteTo(buf)
				spaceBuf.Reset()
				wordBuf.WriteTo(buf)
				wordBuf.Reset()
			}

			spaceBuf.WriteRune(char)
		} else {

			wordBuf.WriteRune(char)

			if current+uint(spaceBuf.Len()+wordBuf.Len()) > lim && uint(wordBuf.Len()) < lim {
				buf.WriteRune('\n')
				current = 0
				spaceBuf.Reset()
			}
		}
	}

	if wordBuf.Len() == 0 {
		if current+uint(spaceBuf.Len()) <= lim {
			spaceBuf.WriteTo(buf)
		}
	} else {
		spaceBuf.WriteTo(buf)
		wordBuf.WriteTo(buf)
	}

	return buf.String()
}
