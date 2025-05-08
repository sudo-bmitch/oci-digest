package digest

import (
	"fmt"
	"hash"
	"io"
	"regexp"
)

type Digest struct {
	alg Algorithm
	hex string
}

var (
	DigestRegexp         = regexp.MustCompile(`[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`)
	DigestRegexpAnchored = regexp.MustCompile(`^` + DigestRegexp.String() + `$`)
	DigestRegexpParts    = regexp.MustCompile(`^([a-z0-9]+(?:[.+_-][a-z0-9]+)*):([a-zA-Z0-9=_-]+)$`)
	encodingRegexp       = regexp.MustCompile(`^[a-zA-Z0-9=_-]+$`)
)

func NewDigest(alg Algorithm, h hash.Hash) (Digest, error) {
	if alg.name == "" {
		return Digest{}, ErrAlgorithmInvalidName
	}
	if h == nil || h.Size() != alg.size {
		return Digest{}, ErrHashInterfaceInvalid
	}
	return Digest{
		alg: alg,
		hex: fmt.Sprintf("%x", h.Sum(nil)),
	}, nil
}

func NewDigestFromEncoded(alg Algorithm, encoded string) (Digest, error) {
	if alg.name == "" {
		return Digest{}, ErrAlgorithmInvalidName
	}
	if len(encoded) != alg.size*2 || !encodingRegexp.MatchString(encoded) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, encoded)
	}
	return Digest{
		alg: alg,
		hex: encoded,
	}, nil
}

func FromBytes(p []byte) (Digest, error) {
	return Canonical.FromBytes(p)
}

func FromReader(rd io.Reader) (Digest, error) {
	return Canonical.FromReader(rd)
}

func FromString(s string) (Digest, error) {
	return Canonical.FromString(s)
}

func Parse(s string) (Digest, error) {
	if s == "" {
		return Digest{}, nil
	}
	parts := DigestRegexpParts.FindStringSubmatch(s)
	if len(parts) != 3 {
		return Digest{}, fmt.Errorf("%w: %s", ErrDigestInvalid, s)
	}
	alg, err := AlgorithmLookup(parts[1])
	if err != nil {
		return Digest{}, err
	}
	if len(parts[2]) != alg.size*2 || !encodingRegexp.MatchString(parts[2]) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, parts[2])
	}
	return Digest{
		alg: alg,
		hex: parts[2],
	}, nil
}

func (d Digest) Algorithm() Algorithm {
	return d.alg
}

func (d Digest) AppendText(b []byte) ([]byte, error) {
	if d.IsZero() {
		return b, nil
	}
	if d.alg.name == "" || d.hex == "" {
		return b, ErrDigestInvalid
	}
	return fmt.Appendf(b, "%s:%s", d.alg.name, d.hex), nil
}

func (d Digest) Encoded() string {
	return d.hex
}

func (d Digest) Equal(cmp Digest) bool {
	return d.alg.name == cmp.alg.name && d.hex == cmp.hex
}

func (d Digest) IsZero() bool {
	return d.alg.name == "" && d.hex == ""
}

func (d Digest) MarshalText() (text []byte, err error) {
	return d.AppendText(nil)
}

func (d Digest) String() string {
	if d.alg.name == "" || d.hex == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", d.alg.name, d.hex)
}

func (d *Digest) UnmarshalText(text []byte) error {
	newD, err := Parse(string(text))
	if err != nil {
		return err
	}
	*d = newD
	return nil
}

type Digester interface {
	io.Writer
	Hash() hash.Hash
	Digest() Digest
}

type digester struct {
	alg  Algorithm
	hash hash.Hash
}

func (d *digester) Digest() Digest {
	return Digest{
		alg: d.alg,
		hex: fmt.Sprintf("%x", d.hash.Sum(nil)),
	}
}

func (d *digester) Hash() hash.Hash {
	return d.hash
}

func (d *digester) Write(p []byte) (n int, err error) {
	return d.hash.Write(p)
}
