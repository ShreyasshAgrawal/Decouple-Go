package detect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"decouple/internal/artifact"
)

func TestDetect_ZipFamily(t *testing.T) {
	extensions := []string{".zip", ".jar"}
	for _, ext := range extensions {
		path := filepath.Join("..", "..", "testdata", "sample"+ext)
		if _, err := os.Stat(path); err != nil {
			t.Skipf("testdata/sample%s not found: %v", ext, err)
		}
		format, err := Detect(path)
		if err != nil {
			t.Errorf("Detect(sample%s) err = %v", ext, err)
		}
		if format != artifact.FormatZip {
			t.Errorf("Detect(sample%s) = %q, want zip", ext, format)
		}
	}
}

func TestDetect_UnknownFormat(t *testing.T) {
	tmp, err := os.CreateTemp("", "test*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("hello world this is not a zip")
	tmp.Close()

	_, err = Detect(tmp.Name())
	if err == nil {
		t.Error("expected error for plain text file, got nil")
	}
}

func TestDetectBytes_PEByMZMagic(t *testing.T) {
	format, err := DetectBytes([]byte{0x4D, 0x5A, 0x00, 0x00})
	if err != nil {
		t.Fatalf("DetectBytes(MZ) err = %v", err)
	}
	if format != artifact.FormatPE {
		t.Fatalf("DetectBytes(MZ) = %q, want %q", format, artifact.FormatPE)
	}
}

func TestDetect_GzipFamily_ContentFirst(t *testing.T) {
	tarGzPath := writeTempTarGz(t)
	defer os.Remove(tarGzPath)

	f1, err := Detect(tarGzPath)
	if err != nil {
		t.Fatalf("Detect(tar.gz): %v", err)
	}
	if f1 != artifact.FormatGzip {
		t.Fatalf("Detect(tar.gz) = %q, want %q", f1, artifact.FormatGzip)
	}

	gzPath := writeTempGzip(t, []byte("plain"))
	defer os.Remove(gzPath)

	f2, err := Detect(gzPath)
	if err != nil {
		t.Fatalf("Detect(.gz): %v", err)
	}
	if f2 != artifact.FormatGzip {
		t.Fatalf("Detect(.gz) = %q, want %q", f2, artifact.FormatGzip)
	}
}

func TestDetect_ImgFallbackByExtension(t *testing.T) {
	tmp, err := os.CreateTemp("", "sample-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write([]byte("not a known magic")); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	format, err := Detect(tmp.Name())
	if err != nil {
		t.Fatalf("Detect(.img): %v", err)
	}
	if format != artifact.FormatIMG {
		t.Fatalf("Detect(.img) = %q, want %q", format, artifact.FormatIMG)
	}
}

func writeTempGzip(t *testing.T, payload []byte) string {
	t.Helper()
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	if _, err := gw.Write(payload); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	f, err := os.CreateTemp("", "sample-*.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b.Bytes()); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func writeTempTarGz(t *testing.T) string {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{
		Name: "file.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTempGzip(t, tarBuf.Bytes())
}
