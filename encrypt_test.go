package pwsafe

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSaveSimpleDB - save simple DB, reopen and verify contents match the original but keys don't
func TestSaveSimpleDB(t *testing.T) {
	// This test relies on the simple password db found at ./test_db/simple.dat
	source, err := OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)

	//Set a new password, save a copy, open it and compare with the source
	source.SetPassword("passwordcopy")
	copyPath := "./test_dbs/simple-copy.dat"
	err = WritePWSafeFile(source, copyPath)
	defer os.Remove(copyPath)
	assert.Nil(t, err)
	dest, err := OpenPWSafeFile("./test_dbs/simple-copy.dat", "passwordcopy")
	assert.Nil(t, err)

	equal, err := source.Identical(dest)
	assert.Nil(t, err)
	assert.Equal(t, true, equal)

	// Reopen the original and verify keys have changed but content is the same
	orig, err := OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)

	// I expect the stretchedkey, salt, encryption key, hmac key and CBCIV to have changed
	// iter changes also but won't necessarily always
	equal, err = orig.Equal(dest)
	assert.Nil(t, err)
	assert.Equal(t, true, equal)
	identical, _ := orig.Identical(dest)
	assert.Equal(t, false, identical)
}

// TestNewV3 test creating a new DB, saving it to a file and loading it
func TestNewV3(t *testing.T) {
	newDB := NewV3("", "password")
	var record Record
	record.Title = "Test entry"
	record.Username = "test"
	record.Password = "password"
	record.Group = "test"
	record.URL = "http://test.com"
	record.Notes = "no notes"
	newDB.SetRecord(record)

	newPath := "./test_dbs/simple-new.dat"
	err := WritePWSafeFile(newDB, newPath)
	defer os.Remove(newPath)
	assert.Nil(t, err)

	readNew, err := OpenPWSafeFile("./test_dbs/simple-new.dat", "password")
	assert.Nil(t, err)
	orig, err := OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)

	equal, err := orig.Equal(readNew)
	assert.Nil(t, err)
	assert.Equal(t, true, equal)
}
