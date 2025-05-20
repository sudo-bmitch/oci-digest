package digest

import (
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

// Digest is the combination of an algorithm and the encoded hash value.
type Digest struct {
	alg string
	enc string
}

var (
	DigestRegexp         = regexp.MustCompile(`[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`)       // DigestRegexp validates a digest string follows the OCI character set.
	DigestRegexpAnchored = regexp.MustCompile(`^` + DigestRegexp.String() + `$`)                     // DigestRegexpAnchored is [DigestRegexp] with the beginning and end of the string anchored.
	DigestRegexpParts    = regexp.MustCompile(`^([a-z0-9]+(?:[.+_-][a-z0-9]+)*):([a-zA-Z0-9=_-]+)$`) // DigestRegexpParts is [DigestRegexp] with the algorithm and encoding captured in separate sub matches.
)

// NewDigest creates a [Digest] from an algorithm and the associated [hash.Hash].
// This will fail if the algorithm is not valid or the hash does not match.
func NewDigest(alg Algorithm, h hash.Hash) (Digest, error) {
	ai, _, err := algorithmInfoLookup(alg.name)
	if err != nil {
		return Digest{}, err
	}
	if h == nil || h.Size() != ai.size {
		return Digest{}, ErrHashInterfaceInvalid
	}
	enc, err := ai.enc.Encode(h.Sum(nil))
	if err != nil {
		return Digest{}, err
	}
	return Digest{
		alg: alg.name,
		enc: enc,
	}, nil
}

// NewDigestFromEncoded creates a [Digest] from an algorithm and the already encoded string.
// This will fail if the algorithm is not valid or the encoding does not match the algorithm requirements.
func NewDigestFromEncoded(alg Algorithm, encoded string) (Digest, error) {
	ai, _, err := algorithmInfoLookup(alg.name)
	if err != nil {
		return Digest{}, err
	}
	if !ai.enc.Validate(encoded) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, encoded)
	}
	return Digest{
		alg: alg.name,
		enc: encoded,
	}, nil
}

// FromBytes generates a [Digest] from the canonical algorithm using the provided byte slice.
func FromBytes(p []byte) (Digest, error) {
	return Canonical.FromBytes(p)
}

// FromReader generates a [Digest] from the canonical algorithm using the provided reader.
func FromReader(rd io.Reader) (Digest, error) {
	return Canonical.FromReader(rd)
}

// FromString generates a [Digest] from the canonical algorithm using the provided string.
func FromString(s string) (Digest, error) {
	return Canonical.FromString(s)
}

// Parse validates the string representation of a [Digest] and returns the parsed value.
// An empty string will not fail but will return an empty [Digest].
// This will fail if the string does not match the [DigestRegexp] requirements,
// the algorithm was not already registered, or the encoding does not match the algorithm requirements.
func Parse(s string) (Digest, error) {
	if s == "" {
		return Digest{}, nil
	}
	algPart, encPart, ok := strings.Cut(s, ":")
	if !ok {
		return Digest{}, fmt.Errorf("%w: %s", ErrDigestInvalid, s)
	}
	ai, _, err := algorithmInfoLookup(algPart)
	if err != nil {
		return Digest{}, err
	}
	if ai.enc == nil || !ai.enc.Validate(encPart) {
		return Digest{}, fmt.Errorf("%w: %s", ErrEncodingInvalid, encPart)
	}
	return Digest{
		alg: algPart,
		enc: encPart,
	}, nil
}

// Algorithm returns the [Algorithm] portion of the digest.
func (d Digest) Algorithm() Algorithm {
	return Algorithm{name: d.alg}
}

// AppendText is used to output the current value of the digest to the byte slice.
// This is used by marshalers.
// If the input byte slice is nil, a new slice may be allocated.
// This will return an unmodified byte slice with the digest is the zero value.
func (d Digest) AppendText(b []byte) ([]byte, error) {
	if d.IsZero() {
		if b == nil {
			b = []byte{}
		}
		return b, nil
	}
	if d.alg == "" || d.enc == "" {
		return b, ErrDigestInvalid
	}
	return fmt.Appendf(b, "%s:%s", d.alg, d.enc), nil
}

// Encoded returns the encoded portion of the digest.
func (d Digest) Encoded() string {
	return d.enc
}

// Equal returns true if two digests have the same algorithm name and encoded value.
func (d Digest) Equal(cmp Digest) bool {
	return d.alg == cmp.alg && d.enc == cmp.enc
}

// IsZero returns true if the digest has a zero value for the algorithm name and encoded value.
func (d Digest) IsZero() bool {
	return d.alg == "" && d.enc == ""
}

// MarshalText returns the text encoding of the digest as a byte slice.
// This is equivalent to d.AppendText(nil).
func (d Digest) MarshalText() (text []byte, err error) {
	return d.AppendText(nil)
}

// String returns the string encoding of the digest.
// If the algorithm name or encoding value is the zero value, an empty string is returned.
func (d Digest) String() string {
	if d.alg == "" || d.enc == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", d.alg, d.enc)
}

// UnmarshalText parses a given digest text with [Parse] and replaces the digest.
// This is used by marshalers.
// An invalid digest string will case the marshaler to fail.
func (d *Digest) UnmarshalText(text []byte) error {
	newD, err := Parse(string(text))
	if err != nil {
		return err
	}
	*d = newD
	return nil
}

// Digester is used to calculate a digest for an algorithm.
type Digester interface {
	io.Writer
	Hash() hash.Hash
	Digest() (Digest, error)
}
