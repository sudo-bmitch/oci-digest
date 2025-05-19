package digest

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReader(t *testing.T) {
	tt := []struct {
		name      string
		r         Reader
		bytes     []byte
		expect    Digest
		mismatch  Digest
		errRead   error
		errDigest error
	}{
		{
			name:      "nil",
			errRead:   ErrReaderInvalid,
			errDigest: ErrReaderInvalid,
		},
		{
			name:     "nil-reader",
			r:        NewReader(nil, SHA256),
			errRead:  ErrReaderInvalid,
			expect:   Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
		{
			name:     "canonical-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), Algorithm{}),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha256-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), SHA256),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha512-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), SHA512),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha512", enc: "27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// read all bytes
			out, err := io.ReadAll(tc.r)
			if tc.errRead != nil {
				if !errors.Is(err, tc.errRead) {
					t.Errorf("expected read err %v, received %v", tc.errRead, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected read err: %v", err)
			}
			if !bytes.Equal(out, tc.bytes) {
				t.Errorf("expected bytes %s, received %s", tc.bytes, out)
			}
			// compare digest
			dig, err := tc.r.Digest()
			if tc.errDigest != nil {
				if !errors.Is(err, tc.errDigest) {
					t.Errorf("expected digest err %v, received %v", tc.errDigest, err)
				}
			} else if err != nil {
				t.Errorf("unexpected digest err: %v", err)
			}
			if !dig.Equal(tc.expect) {
				t.Errorf("expected digest %s, received %s", tc.expect.String(), dig.String())
			}
			// verify mismatch
			if tc.r.Verify(tc.mismatch) {
				t.Errorf("unexpected verify of mismatch")
			}
			// verify expected value
			if tc.errDigest == nil && !tc.r.Verify(tc.expect) {
				t.Errorf("verify failed")
			}
			// access hash directly
			if tc.errDigest == nil {
				h := tc.r.Hash()
				dig, err = NewDigest(tc.r.alg, h)
				if err != nil {
					t.Errorf("failed to create digest from hash: %v", err)
				}
				if !dig.Equal(tc.expect) {
					t.Errorf("expected digest %s, received %s", tc.expect.String(), dig.String())
				}
			}
		})
	}
}

func TestReadAll(t *testing.T) {
	tt := []struct {
		name      string
		r         Reader
		bytes     []byte
		expect    Digest
		mismatch  Digest
		errRead   error
		errDigest error
	}{
		{
			name:      "nil",
			errRead:   ErrReaderInvalid,
			errDigest: ErrReaderInvalid,
		},
		{
			name:     "nil-reader",
			r:        NewReader(nil, SHA256),
			errRead:  ErrReaderInvalid,
			expect:   Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
		{
			name:     "canonical-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), Algorithm{}),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha256-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), SHA256),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha512-empty-json",
			r:        NewReader(bytes.NewReader([]byte("{}")), SHA512),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha512", enc: "27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// read all bytes
			err := tc.r.ReadAll()
			if tc.errRead != nil {
				if !errors.Is(err, tc.errRead) {
					t.Errorf("expected read err %v, received %v", tc.errRead, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected read err: %v", err)
			}
			// compare digest
			dig, err := tc.r.Digest()
			if tc.errDigest != nil {
				if !errors.Is(err, tc.errDigest) {
					t.Errorf("expected digest err %v, received %v", tc.errDigest, err)
				}
			} else if err != nil {
				t.Errorf("unexpected digest err: %v", err)
			}
			if !dig.Equal(tc.expect) {
				t.Errorf("expected digest %s, received %s", tc.expect.String(), dig.String())
			}
			// verify mismatch
			if tc.r.Verify(tc.mismatch) {
				t.Errorf("unexpected verify of mismatch")
			}
			// verify expected value
			if tc.errDigest == nil && !tc.r.Verify(tc.expect) {
				t.Errorf("verify failed")
			}
		})
	}
}
