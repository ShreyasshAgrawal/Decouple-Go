package archivedecouple

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"decouple/internal/artifact"
	"decouple/internal/detect"
)

const unknownNestedSize uint64 = ^uint64(0)

func walkNestedGzip(path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	br := bufio.NewReader(gz)
	peek, _ := br.Peek(512)
	detectedFormat, err := detect.DetectBytes(peek)
	if err != nil {
		return nil
	}
	entryPath := strings.TrimSpace(gz.Name)
	if entryPath == "" {
		// Keep tar.gz traversal path-transparent (no extra virtual segment).
		if detectedFormat == artifact.FormatTar {
			entryPath = ""
		} else {
			entryPath = defaultGzipPayloadPath(path)
		}
	}

	openCalled := false
	open := func() (io.ReadCloser, error) {
		if openCalled {
			return nil, io.ErrUnexpectedEOF
		}
		openCalled = true
		return io.NopCloser(br), nil
	}

	if err := fn(entryPath, unknownNestedSize, open); err != nil {
		return err
	}
	if !openCalled {
		if _, err := io.Copy(io.Discard, br); err != nil {
			return err
		}
	}
	return nil
}

func defaultGzipPayloadPath(path string) string {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "decouple-nested-") {
		return "payload"
	}
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".gz") && len(base) > 3 {
		return base[:len(base)-3]
	}
	return "payload"
}
