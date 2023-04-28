package utils

import (
	"log"
	"testing"
)

var (
	randomString, hashedString string
)

func TestHashStringArgon2(t *testing.T) {
	var err error
	randomString, err = RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	hashedString, err = HashStringArgon2(randomString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
}

func TestCompareStringToArgon2Hash(t *testing.T) {
	match, err := CompareStringToArgon2Hash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if !match {
		log.Println("passwords comparison failed")
		log.Println("passwords should match")
		t.Fail()
	}
	randomString, err = RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	match, err = CompareStringToArgon2Hash(randomString, hashedString)
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
