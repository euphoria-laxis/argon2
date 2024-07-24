package decoder

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"euphoria-laxis.fr/go-packages/argon2/encoder"
	"golang.org/x/crypto/argon2"
)

type Decoder struct{}

func NewDecoder() *Decoder {
	return new(Decoder)
}

func (decoder *Decoder) decodeHash(encodedHash string) (o *encoder.Options, salt, hash []byte, err error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != 6 {
		return nil, nil, nil, encoder.ErrInvalidHash
	}
	var version int
	_, err = fmt.Sscanf(values[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, encoder.ErrIncompatibleVersion
	}
	o = new(encoder.Options)
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

func (decoder *Decoder) CompareStringToHash(password string, hashedPassword string) (match bool, err error) {
	p, salt, hash, err := decoder.decodeHash(hashedPassword)
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
