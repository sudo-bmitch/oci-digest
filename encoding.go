package digest

import (
	"fmt"
	"regexp"
)

type Encoder interface {
	Encode([]byte) (string, error)
	Validate(string) bool
}

type EncodeHex struct {
	Len int
}

var hexRe = regexp.MustCompile(`^[a-f0-9]*$`)

func (e EncodeHex) Encode(p []byte) (string, error) {
	if len(p)*2 != e.Len {
		return "", ErrEncodingInvalid
	}
	return fmt.Sprintf("%*x", e.Len, p), nil
}

func (e EncodeHex) Validate(s string) bool {
	if len(s) == e.Len && hexRe.MatchString(s) {
		return true
	}
	return false
}
