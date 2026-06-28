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

import "errors"

var (
	// ErrAlgorithmExists is returned when attempting to register an algorithm twice.
	ErrAlgorithmExists = errors.New("algorithm is already registered")
	// ErrAlgorithmInvalidName is returned when attempting to register an algorithm that does not follow the OCI naming requirements.
	ErrAlgorithmInvalidName = errors.New("invalid algorithm name")
	// ErrAlgorithmUnknown is returned when trying to use an algorithm name that was not registered.
	ErrAlgorithmUnknown = errors.New("algorithm is not registered")
	// ErrDigestInvalid is returned when parsing an invalid digest string or using an undefined digest.
	ErrDigestInvalid = errors.New("digest is invalid")
	// ErrEncodeInterfaceInvalid is returned when trying to use an invalid encoding interface.
	ErrEncodeInterfaceInvalid = errors.New("invalid encoding interface")
	// ErrEncodingInvalid is returned when trying to create a digest with an invalid hex value.
	ErrEncodingInvalid = errors.New("encoding contains invalid characters or the wrong length for the algorithm")
	// ErrHashFunctionInvalid is returned when the hash function is nil or does not return a valid hash.
	ErrHashFunctionInvalid = errors.New("invalid hash function")
	// ErrHashInterfaceInvalid is returned when the hash interface is nil or does not return a valid hash.
	ErrHashInterfaceInvalid = errors.New("invalid hash interface")
	// ErrReaderInvalid is returned when a reader wasn't created with the appropriate function.
	ErrReaderInvalid = errors.New("invalid reader")
	// ErrWriterInvalid is returned when a writer wasn't created with the appropriate function.
	ErrWriterInvalid = errors.New("invalid writer")
)
