package digest

import (
	"errors"
	"hash"
	"io"
)

// Reader is used to calculate a digest using a [io.Reader].
type Reader struct {
	r    io.Reader
	alg  Algorithm
	hash hash.Hash
}

// NewReader creates a [Reader].
// If the the reader is not provided, other requests to the returned reader will fail.
// If Algorithm is the zero value, the [Canonical] value will be used.
func NewReader(r io.Reader, alg Algorithm) Reader {
	ret := Reader{
		r:   r,
		alg: alg,
	}
	if alg.name == "" || alg.newFn == nil {
		ret.alg = Canonical
	}
	ret.hash = ret.alg.newFn()
	return ret
}

// Digest returns the current digest value.
func (r Reader) Digest() (Digest, error) {
	if r.hash == nil {
		return Digest{}, ErrReaderInvalid
	}
	return NewDigest(r.alg, r.hash)
}

// Hash returns the underlying [hash.Hash].
// Direct writes to this hash will affect the returned digest.
func (r Reader) Hash() hash.Hash {
	return r.hash
}

// Read will pass through the read requests to the underlying reader.
// All read data is included in the digest computation.
func (r Reader) Read(p []byte) (int, error) {
	if r.r == nil {
		return 0, ErrReaderInvalid
	}
	n, err := r.r.Read(p)
	if n <= 0 {
		return n, err
	}
	_, hErr := r.hash.Write(p[:n])
	if hErr != nil {
		if err != nil {
			err = errors.Join(err, hErr)
		} else {
			err = hErr
		}
	}
	return n, err
}

// ReadAll reads everything from the underlying reader, computing the digest, and then discarding the read value.
func (r Reader) ReadAll() error {
	if r.r == nil {
		return ErrReaderInvalid
	}
	_, err := io.Copy(r.hash, r.r)
	return err
}

// Verify returns true if the compared digest matches the current digest.
// Any errors in computing the digest will also return false.
func (r Reader) Verify(cmp Digest) bool {
	d, err := r.Digest()
	if err != nil {
		return false
	}
	return !cmp.IsZero() && d.Equal(cmp)
}
