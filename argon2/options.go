package argon2

import "errors"

type Options struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	defaultOptions         = Options{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
)

type OptFunc func(*Options)

func SetMemory(memory uint32) OptFunc {
	return func(options *Options) {
		options.memory = memory
	}
}

func SetIterations(iterations uint32) OptFunc {
	return func(options *Options) {
		options.iterations = iterations
	}
}

func SetParallelism(parallelism uint8) OptFunc {
	return func(options *Options) {
		options.parallelism = parallelism
	}
}

func SetSaltLength(saltLength uint32) OptFunc {
	return func(options *Options) {
		options.saltLength = saltLength
	}
}

func SetKeyLength(keyLength uint32) OptFunc {
	return func(options *Options) {
		options.keyLength = keyLength
	}
}
