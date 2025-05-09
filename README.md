# OCI Digest

[![Go Reference](https://pkg.go.dev/badge/github.com/sudo-bmitch/oci-digest.svg)](https://pkg.go.dev/github.com/sudo-bmitch/oci-digest)
![License](https://img.shields.io/github/license/sudo-bmitch/oci-digest)
[![Go Report Card](https://goreportcard.com/badge/github.com/sudo-bmitch/oci-digest)](https://goreportcard.com/report/github.com/sudo-bmitch/oci-digest)
[![Go Workflow Status](https://img.shields.io/github/actions/workflow/status/sudo-bmitch/oci-digest/go.yml?branch=main&label=Go%20build)](https://github.com/sudo-bmitch/oci-digest/actions/workflows/go.yml)

OCI Digest is an alternative to OCI's <https://github.com/opencontainers/go-digest>.

Key differences include:

- Data types are structs with private fields that are verified on creation rather than parsing strings on usage.
- The package should return an error or empty values rather than panic.
- Alternate encodings are supported per algorithm.
- Pass-through reader and writer implementations allow the calculation and/or verification of a digest without a separate `io.TeeReader` or `io.MultiWriter`.
