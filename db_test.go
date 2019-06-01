package pwsafe

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

/* The test databases simple.dat and three.dat were made using Loxodo (https://github.com/sommer/loxodo)
Some other test dbs can be found at https://github.com/ronys/pypwsafe/tree/master/test_safes
these all have the password 'bogus12345'
*/

func TestByteToInt(t *testing.T) {
	var testData = []struct {
		bytes []byte
		value int
	}{
		{bytes: []byte{5}, value: 5},
		{bytes: []byte{5, 5}, value: 1285},
		{bytes: []byte{5, 5, 5}, value: 328965},
		{bytes: []byte{5, 5, 5, 5}, value: 84215045},
		{bytes: []byte{255, 255, 255, 255}, value: 4294967295},
	}

	for _, test := range testData {
		derived := byteToInt(test.bytes)
		assert.Equal(t, test.value, derived)
	}
}

func TestIntToByte(t *testing.T) {
	var testData = []struct {
		bytes []byte
		value int
	}{
		{bytes: []byte{5, 0, 0, 0}, value: 5},
		{bytes: []byte{5, 5, 0, 0}, value: 1285},
		{bytes: []byte{5, 5, 5, 0}, value: 328965},
		{bytes: []byte{5, 5, 5, 5}, value: 84215045},
		{bytes: []byte{255, 255, 255, 255}, value: 4294967295},
	}

	for _, test := range testData {
		derived := intToBytes(test.value)
		assert.Equal(t, test.bytes, derived)
	}
}

func TestKeys(t *testing.T) {
	var db V3
	db.Iter = 2048
	db.Salt = [32]byte{224, 70, 145, 8, 59, 173, 47, 241, 203, 157, 83, 209, 22, 55, 151, 157, 96, 234, 194, 167, 175, 251, 199, 145, 7, 219, 203, 168, 6, 166, 238, 241}
	expectedKey := [32]byte{243, 201, 143, 194, 139, 58, 186, 186, 133, 14, 238, 200, 139, 153, 45, 247, 215, 251, 24, 49, 28, 170, 157, 181, 21, 174, 129, 231, 234, 62, 51, 203}

	// tests the stretchedKey
	db.calculateStretchKey("password")
	assert.Equal(t, db.StretchedKey, expectedKey)

	encryptedKeys := db.refreshEncryptedKeys()
	createdEncryptionKey := db.EncryptionKey
	createdHMACKey := db.HMACKey

	// extract the keys from the encrypted bytes and compare to the original
	db.extractKeys(encryptedKeys)
	assert.Equal(t, createdEncryptionKey, db.EncryptionKey)
	assert.Equal(t, createdHMACKey, db.HMACKey)
}

func TestInvalidFile(t *testing.T) {
	_, err := OpenPWSafeFile("./db.go", "password")
	assert.Equal(t, err, errors.New("File is not a valid Password Safe v3 file"))
	_, err = OpenPWSafeFile("./notafile", "password")
	assert.NotNil(t, err)
}
