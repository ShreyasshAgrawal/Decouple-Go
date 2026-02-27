package archivedecouple

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"io"
	"os"

	"decouple/internal/detect"
	"decouple/internal/safety"
)

func walkNestedTar(path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	tr, closeFn, err := openTarReader(path)
	if err != nil {
		return err
	}
	defer closeFn()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}

		entryPath := hdr.Name
		if normalized, nerr := safety.NormalizeZipPath(hdr.Name); nerr == nil {
			entryPath = normalized
		}

		size := hdr.Size
		lr := io.LimitReader(tr, size)
		br := bufio.NewReader(lr)
		peek, _ := br.Peek(512)
		if _, err := detect.DetectBytes(peek); err != nil {
			if _, err := io.Copy(io.Discard, br); err != nil {
				return err
			}
			continue
		}

		openCalled := false
		open := func() (io.ReadCloser, error) {
			if openCalled {
				return nil, io.ErrUnexpectedEOF
			}
			openCalled = true
			return io.NopCloser(br), nil
		}

		if err := fn(entryPath, uint64(size), open); err != nil {
			return err
		}
		if !openCalled && size > 0 {
			if _, err := io.Copy(io.Discard, br); err != nil {
				return err
			}
		}
	}
}

func openTarReader(path string) (*tar.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	closeFn := func() { _ = f.Close() }

	buf := bufio.NewReader(f)
	header, err := buf.Peek(2)
	if err != nil {
		closeFn()
		return nil, nil, err
	}

	var r io.Reader = buf
	if header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(buf)
		if err != nil {
			closeFn()
			return nil, nil, err
		}
		oldClose := closeFn
		closeFn = func() {
			_ = gz.Close()
			oldClose()
		}
		r = gz
	}
	return tar.NewReader(r), closeFn, nil
}
