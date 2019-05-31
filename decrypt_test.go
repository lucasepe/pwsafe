package pwsafe

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleDB(t *testing.T) {
	// This test relies on the simple password db found at ./test_db/simple.dat
	dbInterface, err := OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)

	db := dbInterface.(*V3)

	assert.Equal(t, db.GetName(), "simple.dat")
	assert.Equal(t, len(db.Records), 1)
	record, exists := db.GetRecord("Test entry")
	assert.Equal(t, exists, true)
	assert.Equal(t, record.Username, "test")
	assert.Equal(t, record.Password, "password")
	assert.Equal(t, record.Group, "test")
	assert.Equal(t, record.URL, "http://test.com")
	assert.Equal(t, record.Notes, "no notes")
}

func TestBadHMAC(t *testing.T) {
	// This test relies on the simple password db found at ./test_db/badHMAC.dat
	_, err := OpenPWSafeFile("./test_dbs/badHMAC.dat", "password")
	assert.Equal(t, errors.New("Error Calculated HMAC does not match read HMAC"), err)
}

func TestThreeDB(t *testing.T) {
	// This test relies on the password db found at ./test_db/three.dat
	dbInterface, err := OpenPWSafeFile("./test_dbs/three.dat", "three3#;")
	assert.Nil(t, err)

	db := dbInterface.(*V3)

	assert.Equal(t, len(db.Records), 3)

	recordList := []string{"three entry 1", "three entry 2", "three entry 3"}
	assert.Equal(t, recordList, db.List())

	groupList := []string{"group 3", "group1", "group2"}
	assert.Equal(t, groupList, db.Groups())

	group3List := []string{"three entry 3"}
	assert.Equal(t, group3List, db.ListByGroup("group 3"))
	group2List := []string{"three entry 2"}
	assert.Equal(t, group2List, db.ListByGroup("group2"))
	group1List := []string{"three entry 1"}
	assert.Equal(t, group1List, db.ListByGroup("group1"))

	//record 1
	record, exists := db.GetRecord("three entry 1")
	assert.Equal(t, exists, true)
	assert.Equal(t, record.Username, "three1_user")
	assert.Equal(t, record.Password, "three1!@$%^&*()")
	assert.Equal(t, record.Group, "group1")
	assert.Equal(t, record.URL, "http://group1.com")
	assert.Equal(t, record.Notes, "three DB\r\nentry 1")

	//record 2
	record, exists = db.GetRecord("three entry 2")
	assert.Equal(t, exists, true)
	assert.Equal(t, record.Username, "three2_user")
	assert.Equal(t, record.Password, "three2_-+=\\\\|][}{';:")
	assert.Equal(t, record.Group, "group2")
	assert.Equal(t, record.URL, "http://group2.com")
	assert.Equal(t, record.Notes, "three DB\r\nsecond entry")

	//record 3
	record, exists = db.GetRecord("three entry 3")
	assert.Equal(t, exists, true)
	assert.Equal(t, record.Username, "three3_user")
	assert.Equal(t, record.Password, ",./<>?`~0")
	assert.Equal(t, record.Group, "group 3")
	assert.Equal(t, record.URL, "https://group3.com")
	assert.Equal(t, record.Notes, "three DB\r\nentry 3\r\nlast one")

}

func TestDBModifications(t *testing.T) {
	// This test relies on the simple password db found at ./test_db/simple.dat
	dbInterface, err := OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)
	db := dbInterface.(*V3)

	//No modifications yet
	assert.Equal(t, false, db.NeedsSave())

	//test Delete
	record, exists := db.GetRecord("Test entry")
	assert.Equal(t, true, exists)
	db.DeleteRecord("Test entry")
	record, exists = db.GetRecord("Test entry")
	assert.Equal(t, false, exists)
	assert.Equal(t, true, db.NeedsSave())

	//reload the db and test password change
	dbInterface, err = OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)
	db = dbInterface.(*V3)

	assert.Equal(t, false, db.NeedsSave())
	err = db.SetPassword("newpass")
	assert.Nil(t, err)
	assert.Equal(t, true, db.NeedsSave())

	//reload the db and test modifying a record
	dbInterface, err = OpenPWSafeFile("./test_dbs/simple.dat", "password")
	assert.Nil(t, err)
	db = dbInterface.(*V3)

	assert.Equal(t, false, db.NeedsSave())
	record, exists = db.GetRecord("Test entry")
	assert.Equal(t, true, exists)
	startTime := record.ModTime
	record.Username = "newuser"
	db.SetRecord(record)
	record, exists = db.GetRecord("Test entry")
	assert.Equal(t, true, exists)
	assert.NotEqual(t, startTime, record.ModTime)
	assert.Equal(t, true, db.NeedsSave())

}
func TestBadPassword(t *testing.T) {
	_, err := OpenPWSafeFile("./test_dbs/simple.dat", "badpass")
	assert.Equal(t, err, errors.New("Invalid Password"))
}
