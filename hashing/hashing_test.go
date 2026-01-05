package hashing_test

import (
	"log"
	"testing"

	"github.com/euphoria-laxis/argon2/hashing"
)

var (
	randomString, hashedString string
	opts                       []hashing.OptFunc
)

// TestOptions test Hasher Options passed by function creational pattern.
func TestOptions(t *testing.T) {
	opts = []hashing.OptFunc{
		hashing.SetMemory(32 * 1024), // 32 bits
		hashing.SetParallelism(4),    // 4 concurrents actions
		hashing.SetKeyLength(32),     // key length
		hashing.SetSaltLength(32),    // salt length
		hashing.SetIterations(4),     // 4 iterations, should be fast since there's 4 concurrent actions
	}
}

// TestHasher test if hasher correctly hashes strings.
func TestHasher(t *testing.T) {
	var err error
	hasher := hashing.NewHasher(opts...)
	randomString, err = hasher.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	hashedString, err = hasher.HashString(randomString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
}

// TestHashesCompare test if hashed strings can be compared.
func TestHashesCompare(t *testing.T) {
	// Create hasher.
	hasher := hashing.NewHasher()
	// Compared hash with original string.
	match, err := hasher.CompareStringToHash(randomString, hashedString)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	if !match {
		log.Println("passwords comparison failed")
		log.Println("passwords should match")
		t.Fail()
	}
	//
	hasher = hashing.NewHasher(opts...)
	randomString, err = hasher.RandomString(32)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	match, err = hasher.CompareStringToHash(randomString, hashedString)
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
