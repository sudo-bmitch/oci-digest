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

type Algorithm struct {
	name  string
	size  int
	newFn func() hash.Hash
}

var (
	algorithms                = map[string]Algorithm{}
	algorithmsMu              sync.RWMutex
	algorithmRegexp           = regexp.MustCompile(`^[a-z0-9]+([+._-][a-z0-9]+)*$`)
	Canonical, SHA256, SHA512 Algorithm
)

func init() {
	// Ignore errors, do not panic.
	// Predefined algorithms would be invalid if they cannot be registered for some reason.
	SHA256, _ = AlgorithmRegister("sha256", sha256.New)
	SHA512, _ = AlgorithmRegister("sha512", sha512.New)
	Canonical = SHA256
}

func AlgorithmLookup(name string) (Algorithm, error) {
	algorithmsMu.RLock()
	defer algorithmsMu.RUnlock()

	if a, ok := algorithms[name]; ok {
		return a, nil
	}
	return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmUnknown, name)
}

func AlgorithmRegister(name string, newFn func() hash.Hash) (Algorithm, error) {
	algorithmsMu.Lock()
	defer algorithmsMu.Unlock()

	if _, ok := algorithms[name]; ok {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmExists, name)
	}
	if !algorithmRegexp.MatchString(name) {
		return Algorithm{}, fmt.Errorf("%w: %s", ErrAlgorithmInvalidName, name)
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
		newFn: newFn,
	}
	algorithms[name] = alg
	return alg, nil
}

func (a Algorithm) Digester() (Digester, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &digester{
		alg:  a,
		hash: a.newFn(),
	}, nil
}

func (a Algorithm) FromBytes(p []byte) (Digest, error) {
	dr, err := a.Digester()
	if err != nil {
		return Digest{}, err
	}
	if _, err := dr.Write(p); err != nil {
		return Digest{}, err
	}
	return dr.Digest(), nil
}

func (a Algorithm) FromReader(rd io.Reader) (Digest, error) {
	dr, err := a.Digester()
	if err != nil {
		return Digest{}, err
	}
	if _, err := io.Copy(dr, rd); err != nil {
		return Digest{}, err
	}
	return dr.Digest(), nil
}

func (a Algorithm) FromString(s string) (Digest, error) {
	return a.FromBytes([]byte(s))
}

func (a Algorithm) Hash() hash.Hash {
	if a.newFn == nil {
		return nil
	}
	return a.newFn()
}

func (a Algorithm) Size() int {
	return a.size
}

func (a Algorithm) String() string {
	return a.name
}

func (a Algorithm) validate() error {
	if a.name == "" {
		return ErrAlgorithmInvalidName
	}
	if a.newFn == nil {
		return ErrHashFunctionInvalid
	}
	return nil
}
