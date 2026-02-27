package zipdecouple

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecoupleZip_KnownHashes(t *testing.T) {
	zipPath := filepath.Join("..", "..", "testdata", "sample.zip")
	if _, err := os.Stat(zipPath); err != nil {
		t.Skipf("testdata/sample.zip not found: %v", err)
	}
	report, err := DecoupleZip(zipPath, nil, "zip")
	if err != nil {
		t.Fatalf("DecoupleZip: %v", err)
	}
	h1 := sha256.Sum256([]byte("hello\n"))
	h2 := sha256.Sum256([]byte("world\n"))

	wantHashes := map[string]string{
		"sampledir/sub/a.txt": hex.EncodeToString(h1[:]),
		"sampledir/sub/b.txt": hex.EncodeToString(h2[:]),
	}
	for path, wantHash := range wantHashes {
		var found *string
		for i := range report.Nodes {
			if report.Nodes[i].Path == path {
				found = report.Nodes[i].SHA256
				break
			}
		}
		if found == nil {
			t.Errorf("node %q not found", path)
			continue
		}
		if *found != wantHash {
			t.Errorf("node %q sha256 = %q, want %q", path, *found, wantHash)
		}
	}
}

func TestDecoupleZip_Deterministic(t *testing.T) {
	zipPath := filepath.Join("..", "..", "testdata", "sample.zip")
	if _, err := os.Stat(zipPath); err != nil {
		t.Skipf("testdata/sample.zip not found: %v", err)
	}

	r1, err := DecoupleZip(zipPath, nil, "zip")
	if err != nil {
		t.Fatalf("DecoupleZip 1: %v", err)
	}
	r2, err := DecoupleZip(zipPath, nil, "zip")
	if err != nil {
		t.Fatalf("DecoupleZip 2: %v", err)
	}

	j1, _ := json.Marshal(r1)
	j2, _ := json.Marshal(r2)
	if string(j1) != string(j2) {
		t.Error("output is not deterministic: two runs produced different JSON")
	}
}
