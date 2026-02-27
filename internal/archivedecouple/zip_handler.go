package archivedecouple

import (
	"archive/zip"
	"io"
	"os"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/safety"
)

func walkNestedZip(path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return err
	}

	for _, zf := range zr.File {
		info := zf.FileInfo()
		if !info.Mode().IsRegular() {
			continue
		}

		if _, ok := detectZipEntryFormat(zf); !ok {
			continue
		}

		entryPath := zf.Name
		if normalized, nerr := safety.NormalizeZipPath(zf.Name); nerr == nil {
			entryPath = normalized
		}

		open := func() (io.ReadCloser, error) {
			return zf.Open()
		}
		if err := fn(entryPath, zf.UncompressedSize64, open); err != nil {
			return err
		}
	}
	return nil
}

func detectZipEntryFormat(zf *zip.File) (artifact.Format, bool) {
	rc, err := zf.Open()
	if err != nil {
		return artifact.FormatUnknown, false
	}
	defer rc.Close()

	header := make([]byte, 512)
	n, err := rc.Read(header)
	if err != nil && err != io.EOF {
		return artifact.FormatUnknown, false
	}
	format, err := detect.DetectBytes(header[:n])
	if err != nil {
		return artifact.FormatUnknown, false
	}
	return format, true
}
