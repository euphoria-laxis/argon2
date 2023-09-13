package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Decoder struct {
	Options
}

func NewDecoder(opts ...OptFunc) (*Decoder, *Options) {
	o := defaultOptions
	for _, fn := range opts {
		fn(&o)
	}

	return &Decoder{o}, &o
}

func (decoder *Decoder) decodeHash(encodedHash string) (d *Decoder, salt, hash []byte, err error) {
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
	_, err = fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &decoder.memory, &decoder.iterations, &decoder.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}
	d = decoder
	d.saltLength = uint32(len(salt))
	hash, err = base64.RawStdEncoding.DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}
	d.keyLength = uint32(len(hash))

	return d, salt, hash, nil
}

func (decoder *Decoder) CompareStringToHash(password string, hashedPassword string) (match bool, err error) {
	p, salt, hash, err := decoder.decodeHash(hashedPassword)
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
