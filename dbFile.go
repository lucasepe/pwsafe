package pwsafe

import (
	"os"
	"os/user"
)

//OpenPWSafeFile Opens a password safe v3 file and decrypts with the supplied password
func OpenPWSafeFile(dbPath string, passwd string) (DB, error) {
	var db V3

	// Open the file
	f, err := os.Open(dbPath)
	if err != nil {
		return &db, err
	}
	defer f.Close()

	_, err = db.Decrypt(f, passwd)

	db.LastSavePath = dbPath

	return &db, err
}

//WritePWSafeFile Writes a pwsafe.DB to disk, using either the specified path or the LastSavedPath
func WritePWSafeFile(db DB, path string) error {
	//Only type pwsafe.V3 is currently supported
	v3db := db.(*V3)

	var savePath string
	if path == "" {
		savePath = v3db.LastSavePath
	} else {
		savePath = path
		v3db.LastSavePath = path
	}

	// Store the last User who modified this file
	user, err := user.Current()
	if err == nil {
		v3db.LastSaveUser = []byte(user.Name)
	}
	// Store the hostname
	hostname, err := os.Hostname()
	if err == nil {
		v3db.LastSaveHost = []byte(hostname)
	}

	// Open the file
	f, err := os.Create(savePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = v3db.Encrypt(f)

	return err
}
