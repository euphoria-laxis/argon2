package main

import (
	"github.com/euphoria-laxis/argon2/hashing"
)

func main() {
	const (
		saltLength  = 64
		iterations  = 4
		parallelism = 4
		memory      = 64 * 1024
		keyLength   = 32
	)
	hasher := hashing.NewHasher(
		hashing.SetIterations(iterations),
		hashing.SetParallelism(parallelism),
		hashing.SetMemory(memory),
		hashing.SetSaltLength(saltLength),
		hashing.SetKeyLength(keyLength),
	)
	hash, err := hasher.HashString("MyVerySecretPasswordString&!123)=")
	if err != nil {
		panic(err)
	}
	match, err := hasher.CompareStringToHash("MyVerySecretPasswordString&!123)=", hash)
	if err != nil {
		panic(err)
	}
	if !match {
		panic("The hash does not match")
	}
	match, err = hasher.CompareStringToHash("WrongPassword", hash)
	if err != nil {
		panic(err)
	}
	if match {
		panic("The hash should not match")
	}
	print("Success!")
}
