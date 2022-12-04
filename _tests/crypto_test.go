package _tests

import (
	"github.com/euphoria-laxis/argon2/utils"
	"log"
	"testing"
)

var (
	randomString, hashedString string
)

func TestHashStringArgon2(t *testing.T) {
	var err error
	randomString, err = utils.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	hashedString, err = utils.HashStringArgon2(randomString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
}

func TestCompareStringToArgon2Hash(t *testing.T) {
	match, err := utils.CompareStringToArgon2Hash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if !match {
		log.Println("passwords comparison failed")
		log.Println("passwords should match")
		t.Fail()
	}
	randomString, err = utils.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	match, err = utils.CompareStringToArgon2Hash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if match {
		log.Println("passwords comparison failed")
		log.Println("passwords shouldn't match")
		t.Fail()
	}
}
