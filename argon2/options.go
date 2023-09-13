package argon2

import "errors"

type Options struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	defaultOptions         = Options{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
)

type OptFunc func(*Options)

func SetMemory(memory uint32) OptFunc {
	return func(options *Options) {
		options.Memory = memory
	}
}

func SetIterations(iterations uint32) OptFunc {
	return func(options *Options) {
		options.Iterations = iterations
	}
}

func SetParallelism(parallelism uint8) OptFunc {
	return func(options *Options) {
		options.Parallelism = parallelism
	}
}

func SetSaltLength(saltLength uint32) OptFunc {
	return func(options *Options) {
		options.SaltLength = saltLength
	}
}

func SetKeyLength(keyLength uint32) OptFunc {
	return func(options *Options) {
		options.KeyLength = keyLength
	}
}
