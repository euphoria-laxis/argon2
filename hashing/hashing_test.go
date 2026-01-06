package hashing_test

import (
	"log"
	"testing"

	"github.com/euphoria-laxis/argon2/hashing"
)

var (
	opts []hashing.OptFunc
)

// testSetOptions set Hasher options values.
func testSetOptions() {
	opts = []hashing.OptFunc{
		hashing.SetMemory(32 * 1024), // 32 bits
		hashing.SetParallelism(4),    // 4 concurrents actions
		hashing.SetKeyLength(32),     // key length
		hashing.SetSaltLength(32),    // salt length
		hashing.SetIterations(4),     // 4 iterations, should be fast since there's 4 concurrent actions
	}
}

// TestOptions test Hasher Options passed by function creational pattern.
func TestOptions(_ *testing.T) {
	testSetOptions()
}

// TestRandomBytes test RandomBytes function.
func TestRandomBytes(t *testing.T) {
	testSetOptions()
	hasher := hashing.NewHasher(opts...)
	seeds := []uint32{32, 64, 128, 256, 512, 1024, 2048}
	for _, seed := range seeds {
		rdm, err := hasher.RandomBytes(seed)
		if err != nil {
			t.Errorf("error generating random bytes: %v", err)
		}
		if len(rdm) != int(seed) {
			t.Errorf("wrong random bytes length, expected 32, got %d", len(rdm))
		}
	}
}

// TestRandomString test RandomString function.
func TestRandomString(t *testing.T) {
	testSetOptions()
	hasher := hashing.NewHasher(opts...)
	seeds := []uint32{32, 64, 128, 256, 512, 1024, 2048}
	for _, seed := range seeds {
		rdm, err := hasher.RandomString(seed)
		if err != nil {
			t.Errorf("error generating random string: %v", err)
		}
		if len(rdm) != int(seed) {
			t.Errorf("wrong random string length: got %d, want 32", len(rdm))
		}
	}
}

// TestHasher test if hasher correctly hashes strings.
func TestHasher(t *testing.T) {
	testSetOptions()
	// Create a new Hasher instance.
	hasher := hashing.NewHasher(opts...)
	// Password shouldn't exceed 48 characters, so we'll avoid to go further.
	seeds := []uint32{12, 16, 18, 20, 24, 28, 32}
	for _, seed := range seeds {
		// Generate a random string.
		randomString, err := hasher.RandomString(seed)
		if err != nil {
			log.Print(err)
			t.Fail()
		}
		// Hash the random string.
		_, err = hasher.HashString(randomString)
		if err != nil {
			log.Print(err)
			t.Fail()
		}
	}
}

// TestHashesCompare test if hashed strings can be compared.
func TestHashesCompare(t *testing.T) {
	testSetOptions()
	// Create hasher.
	hasher := hashing.NewHasher(opts...)
	seeds := []uint32{12, 16, 18, 20, 24, 28, 32}
	for _, seed := range seeds {
		// Generate a random string
		randomString, err := hasher.RandomString(seed)
		if err != nil {
			t.Fatalf("failed to generate random string: %s", err)
		}
		// Hash the random string.
		hashedString, err := hasher.HashString(randomString)
		if err != nil {
			t.Fatalf("failed to hash random string: %s", err)
		}
		// Compared hash with original string.
		match, err := hasher.CompareStringToHash(randomString, hashedString)
		if err != nil {
			t.Fatalf("original and hashed strings don't match")
		}
		if !match {
			t.Fatalf("original and hashed strings don't match")
		}
		// Now we test the comparison when the original string and the hash don't match.
		hasher = hashing.NewHasher(opts...)
		randomString, err = hasher.RandomString(seed)
		if err != nil {
			t.Fatalf("failed to generate random string: %s", err)
		}
		match, err = hasher.CompareStringToHash(randomString, hashedString)
		if err != nil {
			t.Fatalf("failed to compare hash and original: %s", err)
		}
		if match {
			t.Fatalf("original and hashed shouldn't match, comparison failed")
		}
	}
}
