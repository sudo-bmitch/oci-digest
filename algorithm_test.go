package digest

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strings"
	"testing"
)

func TestAlgorithmRegister(t *testing.T) {
	tt := []struct {
		name  string
		alg   string
		enc   Encoder
		newFn func() hash.Hash
		err   error
	}{
		{
			name:  "sha384",
			alg:   "sha384",
			enc:   EncodeHex{Len: 96},
			newFn: sha512.New384,
		},
		{
			name:  "existing",
			alg:   "sha256",
			enc:   EncodeHex{Len: 64},
			newFn: sha512.New,
			err:   ErrAlgorithmExists,
		},
		{
			name:  "invalid name",
			alg:   "invalid*name",
			enc:   EncodeHex{Len: 123},
			newFn: sha256.New,
			err:   ErrAlgorithmInvalidName,
		},
		{
			name:  "nil hash fn",
			alg:   "nil-hash",
			enc:   EncodeHex{Len: 64},
			newFn: nil,
			err:   ErrHashFunctionInvalid,
		},
		{
			name:  "nil enc fn",
			alg:   "nil-enc",
			enc:   nil,
			newFn: sha256.New,
			err:   ErrEncodeInterfaceInvalid,
		},
		{
			name:  "nil hash fn return",
			alg:   "nil-hash-ret",
			enc:   EncodeHex{Len: 64},
			newFn: func() hash.Hash { return nil },
			err:   ErrHashFunctionInvalid,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			a, err := AlgorithmRegister(tc.alg, tc.enc, tc.newFn)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if a.name != tc.alg {
				t.Errorf("name mismatch, expected %s, received %s", tc.alg, a.name)
			}
		})
	}
}

func TestAlgorithmLookup(t *testing.T) {
	tt := []struct {
		name string
		alg  string
		err  error
	}{
		{
			name: "sha256",
			alg:  "sha256",
		},
		{
			name: "sha512",
			alg:  "sha512",
		},
		{
			name: "unknown",
			alg:  "unknown",
			err:  ErrAlgorithmUnknown,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			a, err := AlgorithmLookup(tc.alg)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if a.name != tc.alg {
				t.Errorf("name mismatch, expected %s, received %s", tc.alg, a.name)
			}
		})
	}
}

func TestAlgorithmDigest(t *testing.T) {
	tt := []struct {
		name   string
		a      Algorithm
		in     string
		expect string
		err    error
	}{
		{
			name: "uninitialized",
			err:  ErrAlgorithmInvalidName,
		},
		{
			name:   "sha256-empty",
			a:      SHA256,
			expect: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "sha256-empty-json",
			a:      SHA256,
			in:     "{}",
			expect: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		{
			name:   "sha512-empty",
			a:      SHA512,
			expect: "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:   "sha512-empty-json",
			a:      SHA512,
			in:     "{}",
			expect: "sha512:27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("digester", func(t *testing.T) {
				d, err := tc.a.Digester()
				if tc.err != nil {
					if !errors.Is(err, tc.err) {
						t.Errorf("expected err %v, received %v", tc.err, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				_, err = d.Write([]byte(tc.in))
				if err != nil {
					t.Fatalf("failed to write to digester: %v", err)
				}
				dig, err := d.Digest()
				if err != nil {
					t.Fatalf("unexpected error from digest: %v", err)
				}
				out := dig.String()
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
			t.Run("fromBytes", func(t *testing.T) {
				d, err := tc.a.FromBytes([]byte(tc.in))
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
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
			t.Run("fromReader", func(t *testing.T) {
				d, err := tc.a.FromReader(strings.NewReader(tc.in))
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
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
			t.Run("fromString", func(t *testing.T) {
				d, err := tc.a.FromString(tc.in)
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
				if out != tc.expect {
					t.Errorf("expected %s, received %s", tc.expect, out)
				}
			})
		})
	}
}

func TestAlgorithmHash(t *testing.T) {
	tt := []struct {
		name  string
		a     Algorithm
		undef bool
		s     int
	}{
		{
			name: "sha256",
			a:    SHA256,
			s:    32,
		},
		{
			name: "sha512",
			a:    SHA512,
			s:    64,
		},
		{
			name:  "undefined",
			undef: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.a.Hash()
			if tc.undef {
				if h != nil {
					t.Errorf("hash is not nil for an undefined algorithm")
				}
				return
			}
			if h == nil {
				t.Fatalf("hash is nil")
			}
			s := h.Size()
			if s != tc.s {
				t.Errorf("expected %d, received %d", tc.s, s)
			}
		})
	}
}

func TestAlgorithmSize(t *testing.T) {
	tt := []struct {
		name string
		a    Algorithm
		s    int
	}{
		{
			name: "sha256",
			a:    SHA256,
			s:    32,
		},
		{
			name: "sha512",
			a:    SHA512,
			s:    64,
		},
		{
			name: "undefined",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.a.Size()
			if out != tc.s {
				t.Errorf("expected %d, received %d", tc.s, out)
			}
		})
	}
}

func TestAlgorithmString(t *testing.T) {
	tt := []struct {
		name string
		a    Algorithm
		s    string
	}{
		{
			name: "sha256",
			a:    SHA256,
			s:    "sha256",
		},
		{
			name: "sha512",
			a:    SHA512,
			s:    "sha512",
		},
		{
			name: "undefined",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.a.String()
			if out != tc.s {
				t.Errorf("expected %s, received %s", tc.s, out)
			}
		})
	}
}
