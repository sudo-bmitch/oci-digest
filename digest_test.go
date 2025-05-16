package digest

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"testing"
)

// Verify interface implementation
var _ Digester = Writer{}

func TestNewDigest(t *testing.T) {
	emptyJSON := sha256.New()
	_, err := emptyJSON.Write([]byte("{}"))
	if err != nil {
		t.Fatalf("failed to populate emptyJson hash: %v", err)
	}
	tt := []struct {
		name string
		alg  Algorithm
		h    hash.Hash
		out  string
		err  error
	}{
		{
			name: "undef-algorithm",
			err:  ErrAlgorithmInvalidName,
		},
		{
			name: "undef-hash",
			alg:  SHA256,
			err:  ErrHashInterfaceInvalid,
		},
		{
			name: "sha256-empty",
			alg:  SHA256,
			h:    sha256.New(),
			out:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "sha256-empty-json",
			alg:  SHA256,
			h:    emptyJSON,
			out:  "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDigest(tc.alg, tc.h)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			out := d.String()
			if out != tc.out {
				t.Errorf("expected %s, received %s", tc.out, out)
			}
		})
	}
}

func TestNewDigestFromEncoded(t *testing.T) {
	tt := []struct {
		name string
		alg  Algorithm
		enc  string
		out  string
		err  error
	}{
		{
			name: "undef-algorithm",
			err:  ErrAlgorithmInvalidName,
		},
		{
			name: "nil-byte",
			alg:  SHA256,
			err:  ErrEncodingInvalid,
		},
		{
			name: "sha256-empty",
			alg:  SHA256,
			enc:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			out:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "sha256-empty-json",
			alg:  SHA256,
			enc:  "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			out:  "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDigestFromEncoded(tc.alg, tc.enc)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			out := d.String()
			if out != tc.out {
				t.Errorf("expected %s, received %s", tc.out, out)
			}
		})
	}
}

func TestNewDigestCanonical(t *testing.T) {
	tt := []struct {
		name   string
		in     string
		expect string
	}{
		{
			name:   "sha256-empty",
			expect: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "sha256-empty-json",
			in:     "{}",
			expect: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("fromBytes", func(t *testing.T) {
				d, err := FromBytes([]byte(tc.in))
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				out := d.String()
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
			t.Run("fromReader", func(t *testing.T) {
				d, err := FromReader(strings.NewReader(tc.in))
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				out := d.String()
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
			t.Run("fromString", func(t *testing.T) {
				d, err := FromString(tc.in)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				out := d.String()
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
		})
	}
}

func TestDigestString(t *testing.T) {
	var d Digest
	out := d.String()
	if out != "" {
		t.Errorf("expected empty string, received: %s", out)
	}
}

func TestParse(t *testing.T) {
	tt := []struct {
		name string
		s    string
		err  error
		alg  string
		enc  string
	}{
		{
			name: "empty",
			s:    "",
		},
		{
			name: "algorithm-only",
			s:    "sha256",
			err:  ErrDigestInvalid,
		},
		{
			name: "invalid-hex",
			s:    "sha256:e3b0c4*298fc1c149afb@4c8996fb92427^e41e4649b934c$495991b7852b85!",
			err:  ErrEncodingInvalid,
		},
		{
			name: "unknown-alg",
			s:    "unknown:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			err:  ErrAlgorithmUnknown,
		},
		{
			name: "sha256-long-hex",
			s:    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8551234",
			err:  ErrEncodingInvalid,
		},
		{
			name: "sha256-valid",
			s:    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			alg:  "sha256",
			enc:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "sha512-valid",
			s:    "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			alg:  "sha512",
			enc:  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Parse(tc.s)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			out := d.String()
			if out != tc.s {
				t.Errorf("expected %s, received %s", tc.s, out)
			}
			a := d.Algorithm()
			if a.String() != tc.alg {
				t.Errorf("expected algorithm %s, received %s", tc.alg, a.String())
			}
			e := d.Encoded()
			if e != tc.enc {
				t.Errorf("expected encoding %s, received %s", tc.enc, e)
			}
		})
	}
}

func TestEqual(t *testing.T) {
	tt := []struct {
		name string
		a, b Digest
		eq   bool
	}{
		{
			name: "empty",
			eq:   true,
		},
		{
			name: "sha256-same",
			a: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			b: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			eq: true,
		},
		{
			name: "sha256-encoding-different",
			a: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			b: Digest{
				alg: SHA256,
				enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			},
		},
		{
			name: "alg-different",
			a: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			b: Digest{
				alg: SHA512,
				enc: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			eq := tc.a.Equal(tc.b)
			if eq != tc.eq {
				t.Errorf("expected Equal %t, received %t", tc.eq, eq)
			}
		})
	}
}

func TestIsZero(t *testing.T) {
	tt := []struct {
		name string
		d    Digest
		zero bool
	}{
		{
			name: "empty",
			zero: true,
		},
		{
			name: "sha256",
			d: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			zero: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			zero := tc.d.IsZero()
			if zero != tc.zero {
				t.Errorf("expected IsZero %t, received %t", tc.zero, zero)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	tt := []struct {
		name   string
		d      Digest
		expect string
		err    error
	}{
		{
			name: "empty",
		},
		{
			name: "invalid",
			d: Digest{
				alg: SHA256,
				enc: "",
			},
			err: ErrDigestInvalid,
		},
		{
			name: "sha256-empty",
			d: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			expect: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "sha512-empty",
			d: Digest{
				alg: SHA512,
				enc: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
			expect: "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.d.MarshalText()
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if string(out) != tc.expect {
				t.Errorf("expected %s, received %s", tc.expect, string(out))
			}
		})
	}
}

func TestMarshalJSON(t *testing.T) {
	tt := []struct {
		name   string
		d      Digest
		expect string
		err    error
	}{
		{
			name:   "empty",
			expect: `""`,
		},
		{
			name: "invalid",
			d: Digest{
				alg: SHA256,
				enc: "",
			},
			err: ErrDigestInvalid,
		},
		{
			name: "sha256-empty",
			d: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			expect: `"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
		},
		{
			name: "sha512-empty",
			d: Digest{
				alg: SHA512,
				enc: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
			expect: `"sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"`,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.d)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if string(out) != tc.expect {
				t.Errorf("expected %s, received %s", tc.expect, string(out))
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	tt := []struct {
		name   string
		in     string
		expect Digest
		err    error
	}{
		{
			name: "empty",
		},
		{
			name: "invalid",
			in:   "sha256",
			err:  ErrDigestInvalid,
		},
		{
			name: "sha256-empty",
			in:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expect: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		{
			name: "sha512-empty",
			in:   "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			expect: Digest{
				alg: SHA512,
				enc: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var out Digest
			err := out.UnmarshalText([]byte(tc.in))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !out.Equal(tc.expect) {
				t.Errorf("expected %s, received %s", tc.expect.String(), out.String())
			}
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tt := []struct {
		name   string
		in     string
		expect Digest
		err    error
	}{
		{
			name: "empty",
			in:   `""`,
		},
		{
			name: "invalid",
			in:   `"sha256"`,
			err:  ErrDigestInvalid,
		},
		{
			name: "sha256-empty",
			in:   `"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
			expect: Digest{
				alg: SHA256,
				enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		{
			name: "sha512-empty",
			in:   `"sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"`,
			expect: Digest{
				alg: SHA512,
				enc: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var out Digest
			err := json.Unmarshal([]byte(tc.in), &out)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !out.Equal(tc.expect) {
				t.Errorf("expected %s, received %s", tc.expect.String(), out.String())
			}
		})
	}
}
