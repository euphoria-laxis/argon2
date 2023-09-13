package argon2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
)

type Encoder struct {
	Options
}

func NewEncoder(opts ...OptFunc) (*Encoder, *Options) {
	o := defaultOptions
	for _, fn := range opts {
		fn(&o)
	}

	return &Encoder{o}, &o
}

func (encoder *Encoder) generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (encoder *Encoder) HashString(password string) (encodedHash string, err error) {
	salt, err := encoder.generateRandomBytes(encoder.saltLength)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		encoder.iterations,
		encoder.memory,
		encoder.parallelism,
		encoder.keyLength,
	)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash = fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		encoder.memory,
		encoder.iterations,
		encoder.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func (encoder *Encoder) RandomString(s int) (string, error) {
	b, err := encoder.generateRandomBytes(uint32(s))
	return base64.URLEncoding.EncodeToString(b), err
}
