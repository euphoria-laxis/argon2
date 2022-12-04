package _tests

import (
	"argon2_utils"
	"log"
	"testing"
)

var (
	randomString, hashedString string
)

func TestHashStringArgon2(t *testing.T) {
	var err error
	randomString, err = argon2_utils.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	hashedString, err = argon2_utils.HashStringArgon2(randomString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
}

func TestCompareStringToArgon2Hash(t *testing.T) {
	match, err := argon2_utils.CompareStringToArgon2Hash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if !match {
		log.Println("passwords comparison failed")
		log.Println("passwords should match")
		t.Fail()
	}
	randomString, err = argon2_utils.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	match, err = argon2_utils.CompareStringToArgon2Hash(randomString, hashedString)
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
