// Copyright the oci-digest contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest

import (
	"fmt"
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

// Encode outputs the encoded string for the hash sum.
func (e EncodeHex) Encode(p []byte) (string, error) {
	if len(p)*2 != e.Len {
		return "", ErrEncodingInvalid
	}
	return fmt.Sprintf("%*x", e.Len, p), nil
}

// Validate verifies the string matches the encoded requirements.
// The string must only contain hex characters 0-9 and a-f (lower case).
// The length must match the Len value of EncodeHex.
func (e EncodeHex) Validate(s string) bool {
	if len(s) == e.Len && isHex(s) {
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
