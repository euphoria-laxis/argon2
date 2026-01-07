package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Hasher represents the hashing options and methods.
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

// RandomBytes returns n length random byte slice.
func (hasher *Hasher) RandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// RandomString returns rand string with given size.
func (hasher *Hasher) RandomString(s uint32) (string, error) {
	b, err := hasher.RandomBytes(s)
	if err != nil {
		return "", err
	}
	// Decode bytes into a b64 encoded string.
	b64 := base64.RawURLEncoding.EncodeToString(b)
	// Remove base 64 encoding characters.
	b64 = strings.ReplaceAll(b64, "=", "")
	b64 = strings.ReplaceAll(b64, "-", "")
	b64 = strings.ReplaceAll(b64, "_", "")

	return b64[0:s], err
}

// HashString return argon2 hash.
func (hasher *Hasher) HashString(password string) (string, error) {
	salt, err := hasher.RandomBytes(hasher.SaltLength)
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

// ExtractOptions returns Options from hashed string.
func (hasher *Hasher) ExtractOptions(encodedHash string) (*Options, []byte, []byte, error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}
	var version int
	_, err := fmt.Sscanf(values[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}
	o := new(Options)
	_, err = fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &o.Memory, &o.Iterations, &o.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}
	o.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}
	o.KeyLength = uint32(len(hash))

	return o, salt, hash, nil
}

// CompareStringToHash compares if string and hash matches.
func (hasher *Hasher) CompareStringToHash(password string, hashedPassword string) (bool, error) {
	p, salt, hash, err := hasher.ExtractOptions(hashedPassword)
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
