package argon2

import (
	"log"
	"testing"
)

var (
	randomString, hashedString string
	opts                       []OptFunc
)

func TestOptions(t *testing.T) {
	opts = []OptFunc{
		SetMemory(32 * 1024), // 32 bits
		SetParallelism(4),    // 4 concurrent actions
		SetKeyLength(32),     // key length
		SetSaltLength(32),    // salt length
		SetIterations(4),     // 4 iterations, should be fast since there's 4 concurrent actions
	}
}

func TestEncoder(t *testing.T) {
	var err error
	encoder, _ := NewEncoder(opts...)
	randomString, err = encoder.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	hashedString, err = encoder.HashString(randomString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
}

func TestDecoder(t *testing.T) {
	decoder, _ := NewDecoder(opts...)
	match, err := decoder.CompareStringToHash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if !match {
		log.Println("passwords comparison failed")
		log.Println("passwords should match")
		t.Fail()
	}
	encoder, _ := NewEncoder(opts...)
	randomString, err = encoder.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	match, err = decoder.CompareStringToHash(randomString, hashedString)
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
