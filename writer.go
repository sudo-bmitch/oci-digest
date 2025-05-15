package digest

import (
	"errors"
	"hash"
	"io"
)

// Writer is used to calculate the digest with a writer.
// It will pass through calls to a [io.Writer] if one is provided.
type Writer struct {
	w    io.Writer
	alg  Algorithm
	hash hash.Hash
}

// NewWriter creates a [Writer].
// If the Writer is provided, write calls are passed through while digesting.
// If Algorithm is the zero value, the [Canonical] value will be used.
func NewWriter(w io.Writer, alg Algorithm) Writer {
	ret := Writer{
		w:   w,
		alg: alg,
	}
	if alg.name == "" || alg.newFn == nil {
		ret.alg = Canonical
	}
	ret.hash = ret.alg.newFn()
	return ret
}

// Digest returns the digest for the bytes that have received by Write.
func (w Writer) Digest() (Digest, error) {
	if w.hash == nil {
		return Digest{}, ErrWriterInvalid
	}
	return NewDigest(w.alg, w.hash)
}

// Hash returns the underlying [hash.Hash].
// Direct writes to this hash will affect the returned digest.
func (w Writer) Hash() hash.Hash {
	return w.hash
}

// Verify returns true if the compared digest matches the current digest.
// Any errors in computing the digest will also return false.
func (w Writer) Verify(cmp Digest) bool {
	d, err := w.Digest()
	if err != nil {
		return false
	}
	return !cmp.IsZero() && d.Equal(cmp)
}

// Write passes through the bytes to the underlying writer if provided.
// The processed bytes are then added to the digest.
func (w Writer) Write(p []byte) (n int, err error) {
	if w.hash == nil {
		return 0, ErrWriterInvalid
	}
	if w.w != nil {
		n, err = w.w.Write(p)
	} else {
		n = len(p)
	}
	if n <= 0 {
		return n, err
	}
	_, hErr := w.hash.Write(p[:n])
	if hErr != nil {
		if err != nil {
			err = errors.Join(err, hErr)
		} else {
			err = hErr
		}
	}
	return n, err
}
