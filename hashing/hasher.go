package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Hasher struct {
	Options
}

// NewHasher creates a Hasher with given Options and returns a Hasher.
func NewHasher(opts ...OptFunc) *Hasher {
	o := defaultOptions
	for _, fn := range opts {
		fn(&o)
	}

	return &Hasher{o}
}

// setPrefix for argon2 hash.
func (hasher *Hasher) setPrefix() string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d",
		argon2.Version,
		hasher.Memory,
		hasher.Iterations,
		hasher.Parallelism,
	)
}

// generateRandomBytes.
func (hasher *Hasher) generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (hasher *Hasher) HashString(password string) (encodedHash string, err error) {
	salt, err := hasher.generateRandomBytes(hasher.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		hasher.Iterations,
		hasher.Memory,
		hasher.Parallelism,
		hasher.KeyLength,
	)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s$%s$%s", hasher.setPrefix(), b64Salt, b64Hash), nil
}

// RandomString.
func (hasher *Hasher) RandomString(s int) (string, error) {
	b, err := hasher.generateRandomBytes(uint32(s))

	return base64.URLEncoding.EncodeToString(b), err
}

// getHashOptions returns Options from hashed string.
func (hasher *Hasher) getHashOptions(encodedHash string) (o *Options, salt, hash []byte, err error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}
	var version int
	_, err = fmt.Sscanf(values[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}
	o = new(Options)
	_, err = fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &o.Memory, &o.Iterations, &o.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}
	o.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}
	o.KeyLength = uint32(len(hash))

	return o, salt, hash, nil
}

// CompareStringToHash compares if string and hash matches.
func (hasher *Hasher) CompareStringToHash(password string, hashedPassword string) (match bool, err error) {
	p, salt, hash, err := hasher.getHashOptions(hashedPassword)
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
