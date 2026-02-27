package gzipdecouple

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

func TestDecoupleGzip_ParsesPayload(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = "file.txt"
	if _, err := zw.Write([]byte("hello")); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}

	tmp, err := os.CreateTemp("", "sample-*.gz")
	if err != nil {
		t.Fatalf("create temp gzip file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		t.Fatalf("write temp gzip file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp gzip file: %v", err)
	}

	rep, err := DecoupleGzip(tmp.Name(), "gz", nil)
	if err != nil {
		t.Fatalf("DecoupleGzip: %v", err)
	}
	if len(rep.Nodes) != 1 {
		t.Fatalf("nodes len = %d, want 1", len(rep.Nodes))
	}
	if rep.Nodes[0].Path != "file.txt" {
		t.Fatalf("node path = %q, want file.txt", rep.Nodes[0].Path)
	}
	if rep.Nodes[0].SHA256 == nil {
		t.Fatalf("expected SHA256 for gzip payload")
	}
}
