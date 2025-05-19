package digest

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriter(t *testing.T) {
	buf := bytes.Buffer{}
	tt := []struct {
		name      string
		w         Writer
		buf       *bytes.Buffer
		bytes     []byte
		expect    Digest
		mismatch  Digest
		errWrite  error
		errDigest error
	}{
		{
			name:      "nil",
			bytes:     []byte("{}"),
			errWrite:  ErrWriterInvalid,
			errDigest: ErrWriterInvalid,
		},
		{
			name:     "nil-writer",
			w:        NewWriter(nil, SHA256),
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "canonical-empty",
			w:        NewWriter(&buf, Algorithm{}),
			buf:      &buf,
			bytes:    []byte(""),
			expect:   Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
		{
			name:     "canonical-empty-json",
			w:        NewWriter(&buf, Algorithm{}),
			buf:      &buf,
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha256-empty-json",
			w:        NewWriter(&buf, SHA256),
			buf:      &buf,
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			mismatch: Digest{alg: "sha256", enc: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		{
			name:     "sha512-empty-json",
			w:        NewWriter(&buf, SHA512),
			buf:      &buf,
			bytes:    []byte("{}"),
			expect:   Digest{alg: "sha512", enc: "27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd"},
			mismatch: Digest{alg: "sha256", enc: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.buf != nil {
				tc.buf.Reset()
			}
			// write all bytes
			if tc.bytes != nil {
				n, err := tc.w.Write(tc.bytes)
				if tc.errWrite != nil {
					if !errors.Is(err, tc.errWrite) {
						t.Errorf("expected write err %v, received %v", tc.errWrite, err)
					}
				} else if err != nil {
					t.Fatalf("unexpected write err: %v", err)
				} else {
					if n != len(tc.bytes) {
						t.Errorf("expected length %d, received %d", len(tc.bytes), n)
					}
					if tc.buf != nil && !bytes.Equal(buf.Bytes(), tc.bytes) {
						t.Errorf("expected bytes %s, received %s", tc.bytes, buf.Bytes())
					}
				}
			}
			// compare digest
			dig, err := tc.w.Digest()
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
			if tc.w.Verify(tc.mismatch) {
				t.Errorf("unexpected verify of mismatch")
			}
			// verify expected value
			if tc.errDigest == nil && !tc.w.Verify(tc.expect) {
				t.Errorf("verify failed")
			}
			// access hash directly
			if tc.errDigest == nil {
				h := tc.w.Hash()
				dig, err = NewDigest(tc.w.alg, h)
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
