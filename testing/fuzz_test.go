package testing

import (
	"testing"

	upstream "github.com/opencontainers/go-digest"

	digest "github.com/sudo-bmitch/oci-digest"
)

func FuzzDigestParse(f *testing.F) {
	d1, err := digest.SHA256.FromString("hello world")
	if err != nil {
		f.Fatalf("failed to generate sha256 digest: %v", err)
	}
	d2, err := digest.SHA512.FromString("hello fuzz")
	if err != nil {
		f.Fatalf("failed to generate sha512 digest: %v", err)
	}
	f.Add(d1.String())
	f.Add(d2.String())
	f.Fuzz(func(t *testing.T, a string) {
		dDig, errDig := digest.Parse(a)
		dUp, errUp := upstream.Parse(a)
		if errDig != nil || errUp != nil {
			// digest parses empty strings without an error intentionally
			if a == "" && errDig == nil {
				return
			}
			if errDig == nil {
				t.Errorf("digest did not fail, parsing %s, upstream failed with %v", a, errUp)
			}
			// upstream may have registered additional algorithms
			if errUp == nil && (dUp.Algorithm().String() == "sha256" || dUp.Algorithm().String() == "sha512") {
				t.Errorf("upstream did not fail, parsing %s, digest failed with %v", a, errDig)
			}
			return
		}
		if dDig.String() != a {
			t.Errorf("digest did not return original string, expected %s, received %s", a, dDig.String())
		}
		if dDig.Encoded() != dUp.Encoded() {
			t.Errorf("encoded strings did not match, parsing %s, digest %s, upstream %s", a, dDig.Encoded(), dUp.Encoded())
		}
	})
}
