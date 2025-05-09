package digest

import (
	"fmt"
	"hash"
	"io"
	"regexp"
)

type Digest struct {
	alg Algorithm
	enc string
}

var (
	DigestRegexp         = regexp.MustCompile(`[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`)
	DigestRegexpAnchored = regexp.MustCompile(`^` + DigestRegexp.String() + `$`)
	DigestRegexpParts    = regexp.MustCompile(`^([a-z0-9]+(?:[.+_-][a-z0-9]+)*):([a-zA-Z0-9=_-]+)$`)
)

func NewDigest(alg Algorithm, h hash.Hash) (Digest, error) {
	if alg.name == "" || alg.enc == nil {
		return Digest{}, ErrAlgorithmInvalidName
	}
	if h == nil || h.Size() != alg.size {
		return Digest{}, ErrHashInterfaceInvalid
	}
	enc, err := alg.enc.Encode(h.Sum(nil))
	if err != nil {
		return Digest{}, err
	}
	return Digest{
		alg: alg,
		enc: enc,
	}, nil
}

func NewDigestFromEncoded(alg Algorithm, encoded string) (Digest, error) {
	if alg.name == "" {
		return Digest{}, ErrAlgorithmInvalidName
	}
	if alg.enc == nil || !alg.enc.Validate(encoded) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, encoded)
	}
	return Digest{
		alg: alg,
		enc: encoded,
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
	if alg.enc == nil || !alg.enc.Validate(parts[2]) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, parts[2])
	}
	return Digest{
		alg: alg,
		enc: parts[2],
	}, nil
}

func (d Digest) Algorithm() Algorithm {
	return d.alg
}

func (d Digest) AppendText(b []byte) ([]byte, error) {
	if d.IsZero() {
		return b, nil
	}
	if d.alg.name == "" || d.enc == "" {
		return b, ErrDigestInvalid
	}
	return fmt.Appendf(b, "%s:%s", d.alg.name, d.enc), nil
}

func (d Digest) Encoded() string {
	return d.enc
}

func (d Digest) Equal(cmp Digest) bool {
	return d.alg.name == cmp.alg.name && d.enc == cmp.enc
}

func (d Digest) IsZero() bool {
	return d.alg.name == "" && d.enc == ""
}

func (d Digest) MarshalText() (text []byte, err error) {
	return d.AppendText(nil)
}

func (d Digest) String() string {
	if d.alg.name == "" || d.enc == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", d.alg.name, d.enc)
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
	enc, _ := d.alg.enc.Encode(d.hash.Sum(nil))
	return Digest{
		alg: d.alg,
		enc: enc,
	}
}

func (d *digester) Hash() hash.Hash {
	return d.hash
}

func (d *digester) Write(p []byte) (n int, err error) {
	return d.hash.Write(p)
}
