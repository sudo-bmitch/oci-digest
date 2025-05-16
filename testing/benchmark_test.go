package testing

import (
	"encoding/json"
	"testing"

	json2 "github.com/go-json-experiment/json"
	upstream "github.com/opencontainers/go-digest"

	digest "github.com/sudo-bmitch/oci-digest"
)

func BenchmarkFromBytes(b *testing.B) {
	exampleBytes := []byte("hash me")
	b.Run("digest", func(b *testing.B) {
		for b.Loop() {
			_, _ = digest.FromBytes(exampleBytes)
		}
	})
	b.Run("upstream", func(b *testing.B) {
		for b.Loop() {
			_ = upstream.FromBytes(exampleBytes)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	dig, err := digest.FromString("hello world")
	if err != nil {
		b.Fatalf("failed to setup digest from string: %v", err)
	}
	exampleDig := dig.String()
	b.Run("digest", func(b *testing.B) {
		for b.Loop() {
			_, _ = digest.Parse(exampleDig)
		}
	})
	b.Run("upstream", func(b *testing.B) {
		for b.Loop() {
			_, _ = upstream.Parse(exampleDig)
		}
	})
}

func BenchmarkDigester(b *testing.B) {
	exampleBytes := []byte("hash me")
	b.Run("digest", func(b *testing.B) {
		for b.Loop() {
			d, err := digest.Canonical.Digester()
			if err != nil {
				b.Fatalf("failed to create digester: %v", err)
			}
			_, err = d.Write(exampleBytes)
			if err != nil {
				b.Fatalf("failed to write to digester: %v", err)
			}
			_, _ = d.Digest()
		}
	})
	b.Run("upstream", func(b *testing.B) {
		for b.Loop() {
			d := upstream.Canonical.Digester()
			h := d.Hash()
			_, err := h.Write(exampleBytes)
			if err != nil {
				b.Fatalf("failed to write to digester: %v", err)
			}
			_ = d.Digest()
		}
	})
}

func BenchmarkJSON(b *testing.B) {
	exampleStrings := []string{"hello", "world", "foo", "bar", "buzz", "baz", "test", "data", "random", "list"}
	exampleDigests := make([]digest.Digest, len(exampleStrings))
	exampleUpstream := make([]upstream.Digest, len(exampleStrings))
	var err error
	for i, s := range exampleStrings {
		exampleDigests[i], err = digest.FromString(s)
		if err != nil {
			b.Fatalf("failed to setup example digest %d: %v", i, err)
		}
		exampleUpstream[i] = upstream.FromString(s)
	}
	exampleJSON, err := json.Marshal(exampleDigests)
	if err != nil {
		b.Fatalf("failed to marshal json: %v", err)
	}
	b.Run("digest-marshal-v1", func(b *testing.B) {
		for b.Loop() {
			_, err := json.Marshal(exampleDigests)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("upstream-marshal-v1", func(b *testing.B) {
		for b.Loop() {
			_, err := json.Marshal(exampleUpstream)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("digest-marshal-v2", func(b *testing.B) {
		for b.Loop() {
			_, err := json2.Marshal(exampleDigests)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("upstream-marshal-v2", func(b *testing.B) {
		for b.Loop() {
			_, err := json2.Marshal(exampleUpstream)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("digest-unmarshal-v1", func(b *testing.B) {
		for b.Loop() {
			out := []digest.Digest{}
			err = json.Unmarshal(exampleJSON, &out)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("upstream-unmarshal-v1", func(b *testing.B) {
		for b.Loop() {
			out := []upstream.Digest{}
			err = json.Unmarshal(exampleJSON, &out)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
			// validation is separate from the unmarshaling in upstream
			for _, d := range out {
				err = d.Validate()
				if err != nil {
					b.Fatalf("failed to validate: %v", err)
				}
			}
		}
	})
	b.Run("digest-unmarshal-v2", func(b *testing.B) {
		for b.Loop() {
			out := []digest.Digest{}
			err = json2.Unmarshal(exampleJSON, &out)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
		}
	})
	b.Run("upstream-unmarshal-v2", func(b *testing.B) {
		for b.Loop() {
			out := []upstream.Digest{}
			err = json2.Unmarshal(exampleJSON, &out)
			if err != nil {
				b.Fatalf("failed to unmarshal json: %v", err)
			}
			// validation is separate from the unmarshaling in upstream
			for _, d := range out {
				err = d.Validate()
				if err != nil {
					b.Fatalf("failed to validate: %v", err)
				}
			}
		}
	})
}
