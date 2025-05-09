package digest

import (
	"fmt"
	"regexp"
)

// Encoder is used to generate or verify the encoded portion of a digest for a given algorithm.
type Encoder interface {
	Encode(p []byte) (string, error) // Encode outputs the encoded string for an input hash sum.
	Validate(string) bool            // Validate verifies a string matches the encoder requirements.
}

// EncodeHex is the hex encoder used by the current registered digest algorithms.
type EncodeHex struct {
	Len int // Len is the length of the encoded text, which is 2x the hash sum length.
}

var hexRe = regexp.MustCompile(`^[0-9a-f]*$`)

// Encode outputs the encoded string for the hash sum.
func (e EncodeHex) Encode(p []byte) (string, error) {
	if len(p)*2 != e.Len {
		return "", ErrEncodingInvalid
	}
	return fmt.Sprintf("%*x", e.Len, p), nil
}

// Validate verifies the string matches the encoded requirements.
// The string must match the regexp "[0-9a-f]*".
// The length must match the Len value of EncodeHex.
func (e EncodeHex) Validate(s string) bool {
	if len(s) == e.Len && hexRe.MatchString(s) {
		return true
	}
	return false
}
