package digest

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sync"
)

// Algorithm specifies an algorithm used to generate a digest.
// Algorithms each have a name, size, encoder, and a hash function.
type Algorithm struct {
	name  string
	size  int
	enc   Encoder
	newFn func() hash.Hash
}

var (
	algorithms      = map[string]Algorithm{}
	algorithmsMu    sync.RWMutex
	algorithmRegexp = regexp.MustCompile(`^[a-z0-9]+([+._-][a-z0-9]+)*$`)
	Canonical       Algorithm // Canonical is the default hashing algorithm, currently set to [SHA256].
	SHA256          Algorithm // SHA256 defines the registered sha256 digester based on [crypto/sha256].
	SHA512          Algorithm // SHA512 defines the registered sha512 digester based on [crypto/sha512].
)

func init() {
	// Ignore errors, do not panic.
	// Predefined algorithms would be invalid if they cannot be registered for some reason.
	SHA256, _ = AlgorithmRegister("sha256", EncodeHex{Len: 64}, sha256.New)
	SHA512, _ = AlgorithmRegister("sha512", EncodeHex{Len: 128}, sha512.New)
	Canonical = SHA256
}

// AlgorithmLookup is used to get a previously registered [Algorithm].
func AlgorithmLookup(name string) (Algorithm, error) {
	algorithmsMu.RLock()
	defer algorithmsMu.RUnlock()

	if a, ok := algorithms[name]; ok {
		return a, nil
	}
	return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmUnknown, name)
}

// AlgorithmRegister is used to register new hash algorithms.
// Attempting to register an already registered algorithm will fail.
// The name must follow the regexp "[a-z0-9]+([+._-][a-z0-9]+)*".
// The encoder and hash function are also verified to be valid interfaces.
func AlgorithmRegister(name string, enc Encoder, newFn func() hash.Hash) (Algorithm, error) {
	algorithmsMu.Lock()
	defer algorithmsMu.Unlock()

	if _, ok := algorithms[name]; ok {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmExists, name)
	}
	if !algorithmRegexp.MatchString(name) {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmInvalidName, name)
	}
	if enc == nil {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrEncodeInterfaceInvalid, name)
	}
	if newFn == nil {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrHashFunctionInvalid, name)
	}
	hasher := newFn()
	if hasher == nil {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrHashFunctionInvalid, name)
	}
	size := hasher.Size()
	if size <= 0 {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrHashFunctionInvalid, name)
	}
	alg := Algorithm{
		name:  name,
		size:  size,
		enc:   enc,
		newFn: newFn,
	}
	algorithms[name] = alg
	return alg, nil
}

// Digester creates a new [Digester] for the algorithm.
func (a Algorithm) Digester() (Digester, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	return NewWriter(nil, a), nil
}

// Encode converts the byte slice hash sum to an encoded string for a digest.
func (a Algorithm) Encode(p []byte) (string, error) {
	if a.enc == nil {
		return "", ErrEncodeInterfaceInvalid
	}
	return a.enc.Encode(p)
}

// FromBytes generates a digest on the input byte slice using the algorithm and returns a [Digest].
// This will fail if the algorithm is invalid.
func (a Algorithm) FromBytes(p []byte) (Digest, error) {
	dr, err := a.Digester()
	if err != nil {
		return Digest{}, err
	}
	if _, err := dr.Write(p); err != nil {
		return Digest{}, err
	}
	return dr.Digest()
}

// FromReader generates a digest on the input reader using the algorithm and returns a [Digest].
// This will fail if the algorithm is invalid or on read errors.
func (a Algorithm) FromReader(rd io.Reader) (Digest, error) {
	dr, err := a.Digester()
	if err != nil {
		return Digest{}, err
	}
	if _, err := io.Copy(dr, rd); err != nil {
		return Digest{}, err
	}
	return dr.Digest()
}

// FromString generates a digest on the input string using the algorithm and returns a [Digest].
// This will fail if the algorithm is invalid.
func (a Algorithm) FromString(s string) (Digest, error) {
	return a.FromBytes([]byte(s))
}

// Hash returns a new [hash.Hash] for the algorithm.
// nil is returned if the algorithm is invalid.
func (a Algorithm) Hash() hash.Hash {
	if a.newFn == nil {
		return nil
	}
	return a.newFn()
}

// Size returns the detected output byte size of the hash implementation.
func (a Algorithm) Size() int {
	return a.size
}

// String returns the name of the digest algorithm.
func (a Algorithm) String() string {
	return a.name
}

// validate is used to verify an algorithm before it is used.
func (a Algorithm) validate() error {
	if a.name == "" {
		return ErrAlgorithmInvalidName
	}
	if a.newFn == nil {
		return ErrHashFunctionInvalid
	}
	if a.enc == nil {
		return ErrEncodeInterfaceInvalid
	}
	return nil
}
