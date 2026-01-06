package hashing

import "errors"

// Options passed to Hasher instance during creation.
type Options struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var (
	// ErrInvalidHash invalid format for given hash, check hash prefix if this error is thrown.
	ErrInvalidHash = errors.New("the encoded hash is not in the correct format")
	// ErrIncompatibleVersion given hash argon2 version is incompatible golang.org/x/crypto/argon2 version.
	ErrIncompatibleVersion = errors.New("incompatible version of hashing")
	defaultOptions         = Options{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
)

// OptFunc represents options for functional creation pattern.
type OptFunc func(*Options)

// SetMemory set hash memory allocated.
func SetMemory(memory uint32) OptFunc {
	return func(options *Options) {
		options.Memory = memory
	}
}

// SetIterations set hash iterations for hashing algorithm.
func SetIterations(iterations uint32) OptFunc {
	return func(options *Options) {
		options.Iterations = iterations
	}
}

// SetParallelism set parallel processes for hashing algorithm.
func SetParallelism(parallelism uint8) OptFunc {
	return func(options *Options) {
		options.Parallelism = parallelism
	}
}

// SetSaltLength set the hash salt length.
func SetSaltLength(saltLength uint32) OptFunc {
	return func(options *Options) {
		options.SaltLength = saltLength
	}
}

// SetKeyLength set hashing key length.
func SetKeyLength(keyLength uint32) OptFunc {
	return func(options *Options) {
		options.KeyLength = keyLength
	}
}
