package archivedecouple

import (
	"archive/tar"
	"bufio"
	"context"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/report"
	"decouple/internal/safety"
	"decouple/internal/scanconfig"
)

type tarHandler struct{}

func (h *tarHandler) Format() artifact.Format { return artifact.FormatTar }

func (h *tarHandler) Detect(header []byte, path string) bool {
	n := len(header)
	if n >= 262 && string(header[257:262]) == "ustar" {
		return true
	}
	if n >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		kind := artifact.KindFromPath(path)
		if kind == "tar.gz" {
			return true
		}
	}
	return false
}

func (h *tarHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	header, err := buf.Peek(2)
	if err != nil {
		return nil, fmt.Errorf("peek header: %w", err)
	}

	var r io.Reader = buf
	if header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(buf)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	maxBytes := cfg.EffectiveMaxFileBytesToHash()
	maxFiles := cfg.EffectiveMaxFiles()
	maxTotal := cfg.EffectiveMaxTotalBytes()

	rep := &report.Report{
		Artifact: report.Artifact{
			InputPath: path,
			Kind:      kind,
		},
	}

	tr := tar.NewReader(r)
	fileCount := 0
	var totalBytes uint64

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rep, fmt.Errorf("tar read: %w", err)
		}

		fileCount++
		if fileCount > maxFiles {
			return rep, fmt.Errorf("archive exceeds max files (%d)", maxFiles)
		}

		totalBytes += uint64(hdr.Size)
		if totalBytes > maxTotal {
			return rep, fmt.Errorf("archive exceeds max total bytes (%d)", maxTotal)
		}

		node := report.Node{}
		normalized, nerr := safety.NormalizeZipPath(hdr.Name)
		if nerr != nil && hdr.Name == "./" {
			continue
		}

		if nerr != nil {
			node.Path = hdr.Name
			node.PathNormalizationError = nerr.Error()
		} else {
			node.Path = normalized
		}

		mode := uint32(hdr.FileInfo().Mode())
		node.Mode = &mode

		switch hdr.Typeflag {
		case tar.TypeDir:
			node.Type = "dir"
		case tar.TypeReg, tar.TypeRegA:
			node.Type = "file"
		case tar.TypeSymlink:
			node.Type = "symlink"
		default:
			node.Type = "other"
		}

		node.SizeBytes = uint64(hdr.Size)
		if !hdr.ModTime.IsZero() {
			node.ModifiedTime = &hdr.ModTime
		}

		bodyConsumed := false
		if node.Type == "file" && hdr.Size > 0 {
			if hdr.Size > int64(maxBytes) {
				node.HashError = fmt.Sprintf("file exceeds max size for hashing (%d bytes)", maxBytes)
				rep.Stats.FilesSkipped++
			} else {
				h := sha256.New()
				limited := io.LimitReader(tr, int64(maxBytes))
				n, hashErr := io.Copy(h, limited)
				if hashErr != nil {
					node.HashError = hashErr.Error()
					rep.Stats.FilesSkipped++
				} else {
					hashHex := hex.EncodeToString(h.Sum(nil))
					node.SHA256 = &hashHex
					rep.Stats.BytesHashed += uint64(n)
					bodyConsumed = true
				}
			}
		}

		if !bodyConsumed && hdr.Size > 0 {
			if _, err := io.Copy(io.Discard, io.LimitReader(tr, hdr.Size)); err != nil {
				return rep, fmt.Errorf("skip body %q: %w", hdr.Name, err)
			}
		}

		rep.Nodes = append(rep.Nodes, node)
	}

	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})
	updateStats(rep)
	return rep, nil
}

func (h *tarHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	tr, closeFn, err := openTarReader(path)
	if err != nil {
		return err
	}
	defer closeFn()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

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
		peek, _ := br.Peek(1100)
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
