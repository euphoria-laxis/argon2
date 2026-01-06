package argon2__test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/euphoria-laxis/argon2/hashing"
)

var (
	opts []hashing.OptFunc
)

// testSetOptions1 set Hasher options values.
func testSetOptions1() {
	opts = []hashing.OptFunc{
		hashing.SetMemory(32 * 1024), // 32 bits
		hashing.SetParallelism(4),    // 4 concurrents actions
		hashing.SetKeyLength(32),     // key length
		hashing.SetSaltLength(32),    // salt length
		hashing.SetIterations(4),     // 4 iterations, should be fast since there's 4 concurrent actions
	}
}

// testSetOptions2 set Hasher options values.
func testSetOptions2() {
	opts = []hashing.OptFunc{
		hashing.SetMemory(64 * 1024), // 64 bits
		hashing.SetParallelism(16),   // 16 concurrents actions
		hashing.SetKeyLength(64),     // key length
		hashing.SetSaltLength(64),    // salt length
		hashing.SetIterations(16),    // 16 iterations
	}
}

var (
	benchmarkInputs = []struct {
		input int
	}{
		{input: 8},
		{input: 12},
		{input: 16},
		{input: 24},
		{input: 32},
	}
)

// _testBenchmark run the benchmark tests. Cognitive complexity is voluntarily high to stress test the package.
// nolint:gocognit
func _testBenchmark(_ *testing.B, input int, hasher *hashing.Hasher) func(b *testing.B) {
	return func(b *testing.B) {
		b.Logf("benchmark %d", input)
		for range b.N {
			// Generate a random
			randomString, err := hasher.RandomString(uint32(rand.Int32N(32-12) + 12))
			if err != nil {
				b.Fatalf("hashing_test failed to generate random string: %v", err)
			}
			// Hash random string.
			hashedString, err := hasher.HashString(randomString)
			if err != nil {
				b.Fatalf("hashing_test failed to hash string: %v", err)
			}
			// Compared hashed string with original raw string.
			var match bool
			match, err = hasher.CompareStringToHash(randomString, hashedString)
			if err != nil {
				b.Fatalf("hashing_test failed to compare hash: %v", err)
			}
			if !match {
				b.Fatalf("passwords comparison failed, password should match")
			}
			// Now we test when the origin and hash don't match
			// Generate a random string.
			randomString, err = hasher.RandomString(uint32(rand.Int32N(32-12) + 12))
			if err != nil {
				b.Fatalf("hashing_test failed to generate random string: %v", err)
			}
			match, err = hasher.CompareStringToHash(randomString, hashedString)
			if err != nil {
				b.Fatalf("hashing_test failed to compare hash: %v", err)
			}
			if match {
				b.Fatalf("passwords comparison failed, password should not match")
			}
		}
	}
}

// BenchmarkHasherOptions1 benchmark Hasher functions.
func BenchmarkHasherOptions1(b *testing.B) {
	testSetOptions1()
	hasher := hashing.NewHasher(opts...)
	for _, v := range benchmarkInputs {
		b.Run(fmt.Sprintf("interations_%d", v.input), _testBenchmark(b, v.input, hasher))
	}
}

// BenchmarkHasherOptions2 benchmark Hasher functions.
func BenchmarkHasherOptions2(b *testing.B) {
	testSetOptions2()
	hasher := hashing.NewHasher(opts...)
	for _, v := range benchmarkInputs {
		b.Run(fmt.Sprintf("interations_%d", v.input), _testBenchmark(b, v.input, hasher))
	}
}
