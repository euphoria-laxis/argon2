package encoder

import (
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
	e, _ := NewEncoder(opts...)
	randomString, err = e.RandomString(32)
	if err != nil {
		t.Fatal(err)
	}
	hashedString, err = e.HashString(randomString)
	if err != nil {
		t.Fatal(err)
	}
}
