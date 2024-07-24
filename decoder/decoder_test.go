package decoder

import (
	"testing"

	"euphoria-laxis.fr/go-packages/argon2/encoder"
)

func TestDecoder(t *testing.T) {
	opts := []encoder.OptFunc{
		encoder.SetMemory(32 * 1024), // 32 bits
		encoder.SetParallelism(4),    // 4 concurrent actions
		encoder.SetKeyLength(32),     // key length
		encoder.SetSaltLength(32),    // salt length
		encoder.SetIterations(4),     // 4 iterations, should be fast since there's 4 concurrent actions
	}
	e, _ := encoder.NewEncoder(opts...)
	randomString, err := e.RandomString(32)
	if err != nil {
		t.Fatal(err)
	}
	var hashedString string
	hashedString, err = e.HashString(randomString)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder()
	var match bool
	match, err = d.CompareStringToHash(randomString, hashedString)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Log("passwords comparison failed")
		t.Log("passwords should match")
		t.Fail()
	}
	randomString, err = e.RandomString(32)
	if err != nil {
		t.Fatal(err)
	}
	match, err = d.CompareStringToHash(randomString, hashedString)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Log("passwords comparison failed")
		t.Log("passwords shouldn't match")
		t.Fail()
	}
}
