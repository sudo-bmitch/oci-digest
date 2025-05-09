package digest

import (
	"errors"
	"testing"
)

// Verify interface implementation
var _ Encoder = EncodeHex{Len: 32}

func TestEncoderEncode(t *testing.T) {
	tt := []struct {
		name   string
		enc    Encoder
		in     []byte
		expect string
		err    error
	}{
		{
			name:   "hex-valid",
			enc:    EncodeHex{Len: 10},
			in:     []byte("hello"),
			expect: "68656c6c6f",
		},
		{
			name: "hex-empty",
			enc:  EncodeHex{Len: 10},
			err:  ErrEncodingInvalid,
		},
		{
			name: "hex-too-long",
			enc:  EncodeHex{Len: 10},
			in:   []byte("hello world"),
			err:  ErrEncodingInvalid,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.enc.Encode(tc.in)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("expected err %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if out != tc.expect {
				t.Errorf("expected %s, received %s", tc.expect, out)
			}
		})
	}
}

func TestEncoderValidate(t *testing.T) {
	tt := []struct {
		name  string
		enc   Encoder
		check string
		valid bool
	}{
		{
			name:  "hex-valid",
			enc:   EncodeHex{Len: 10},
			check: "68656c6c6f",
			valid: true,
		},
		{
			name:  "hex-invalid-char",
			enc:   EncodeHex{Len: 10},
			check: "68656c6c6g",
		},
		{
			name:  "hex-too-long",
			enc:   EncodeHex{Len: 10},
			check: "68656c6c6f1234",
		},
		{
			name: "hex-too-short",
			enc:  EncodeHex{Len: 10},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			valid := tc.enc.Validate(tc.check)
			if valid != tc.valid {
				t.Errorf("expected %t, received %t", tc.valid, valid)
			}
		})
	}
}
