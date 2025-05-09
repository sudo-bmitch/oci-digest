// Package digest implements the OCI digest as defined by the OCI [image-spec descriptor].
// This is an alternative implementation to the OCI [go-digest].
// The key differences include:
//
//   - Data types are structs with private fields that are verified on creation rather than parsing strings on usage.
//   - The package should return an error or empty values rather than panic.
//   - Alternate encodings are supported per algorithm.
//   - Pass-through reader and writer implementations allow the calculation and/or verification of a digest without a separate [io.TeeReader] or [io.MultiWriter].
//
// [image-spec descriptor]: https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md#digests
// [go-digest]: https://github.com/opencontainers/go-digest/
package digest
