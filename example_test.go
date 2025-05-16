package digest_test

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"

	digest "github.com/sudo-bmitch/oci-digest"
)

func ExampleReader() {
	// src is our test data
	src := []byte("hello world")
	expect, err := digest.FromBytes(src)
	if err != nil {
		slog.Error("failed to setup expected digest", "err", err)
		return
	}
	// origin is an upstream reader, e.g. an http body
	origin := bytes.NewReader(src)

	// Create a new pass through reader with the canonical algorithm
	r := digest.NewReader(origin, digest.Canonical)
	// Read your app data from the reader
	data, err := io.ReadAll(r)
	if err != nil {
		slog.Error("failed to read data", "err", err)
		return
	}

	// if we do not know the digest, we can extract it
	rcv, err := r.Digest()
	if err != nil {
		slog.Error("failed to compute digest", "err", err)
		return
	}
	// that extracted value will match the expected value
	if !expect.Equal(rcv) {
		slog.Error("received digest did not match expected value", "expected", expect.String(), "received", rcv.String())
	}
	// or if we are expecting a digest, we can verify it
	if !r.Verify(expect) {
		slog.Error("digest did not match expected value")
	}

	fmt.Println(string(data))
	// Output: hello world
}

func ExampleWriter_buf() {
	// src is our test data
	src := []byte("hello world")
	expect, err := digest.FromBytes(src)
	if err != nil {
		slog.Error("failed to setup expected digest", "err", err)
		return
	}
	// buf is an output destination, e.g. a file
	buf := bytes.Buffer{}

	// Create a new pass through writer with the canonical algorithm
	w := digest.NewWriter(&buf, digest.Canonical)
	// Write the test data
	_, err = w.Write(src)
	if err != nil {
		slog.Error("failed to write test data", "err", err)
		return
	}

	// if we do not know the digest, we can extract it
	rcv, err := w.Digest()
	if err != nil {
		slog.Error("failed to compute digest", "err", err)
		return
	}
	// that extracted value will match the expected value
	if !expect.Equal(rcv) {
		slog.Error("received digest did not match expected value", "expected", expect.String(), "received", rcv.String())
	}
	// or if we are expecting a digest, we can verify it
	if !w.Verify(expect) {
		slog.Error("digest did not match expected value")
	}

	fmt.Println(buf.String())
	// Output: hello world
}

func ExampleWriter_nil() {
	// src is our test data
	src := []byte("hello world")
	expect, err := digest.FromBytes(src)
	if err != nil {
		slog.Error("failed to setup expected digest", "err", err)
		return
	}

	// Create a new writer with the canonical algorithm.
	// The nil writer input means this does not pass through to an underlying writer.
	w := digest.NewWriter(nil, digest.Canonical)
	// Write the test data
	_, err = w.Write(src)
	if err != nil {
		slog.Error("failed to write test data", "err", err)
		return
	}

	// if we do not know the digest, we can extract it
	rcv, err := w.Digest()
	if err != nil {
		slog.Error("failed to compute digest", "err", err)
		return
	}
	// that extracted value will match the expected value
	if !expect.Equal(rcv) {
		slog.Error("received digest did not match expected value", "expected", expect.String(), "received", rcv.String())
	}
	// or if we are expecting a digest, we can verify it
	if !w.Verify(expect) {
		slog.Error("digest did not match expected value")
	}

	// Output:
}
