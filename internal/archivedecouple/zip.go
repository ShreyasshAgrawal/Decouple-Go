package archivedecouple

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/report"
	"decouple/internal/safety"
	"decouple/internal/scanconfig"
)

type zipHandler struct{}

func (h *zipHandler) Format() artifact.Format { return artifact.FormatZip }

func (h *zipHandler) Detect(header []byte, path string) bool {
	format, _ := detect.DetectBytes(header)
	return format == artifact.FormatZip
}

func (h *zipHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat zip: %w", err)
	}

	r, err := zip.NewReader(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("open zip reader: %w", err)
	}

	rep := &report.Report{
		Artifact: report.Artifact{InputPath: path, Kind: kind},
	}
	maxFiles := cfg.EffectiveMaxFiles()
	maxTotalBytes := cfg.EffectiveMaxTotalBytes()
	maxFileBytesToHash := cfg.EffectiveMaxFileBytesToHash()
	var totalBytes uint64

	var wg sync.WaitGroup
	var nodesMu sync.Mutex
	sem := make(chan struct{}, cfg.EffectiveMaxConcurrentScans())

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if len(rep.Nodes) >= maxFiles {
			return nil, fmt.Errorf("zip exceeds max file count (%d)", maxFiles)
		}
		node := report.Node{}
		normalized, nerr := safety.NormalizeZipPath(f.Name)
		if nerr != nil {
			node.Path = f.Name
			node.PathNormalizationError = nerr.Error()
		} else {
			node.Path = normalized
		}

		fi := f.FileInfo()
		mode := uint32(fi.Mode())
		node.Mode = &mode
		if fi.Mode()&os.ModeSymlink != 0 {
			node.Type = "symlink"
		} else if fi.IsDir() || strings.HasSuffix(f.Name, "/") {
			node.Type = "dir"
		} else if fi.Mode().IsRegular() {
			node.Type = "file"
		} else {
			node.Type = "other"
		}
		node.SizeBytes = f.UncompressedSize64
		node.CompressedSizeBytes = f.CompressedSize64
		mt := f.Modified
		if !mt.IsZero() {
			node.ModifiedTime = &mt
		}
		if totalBytes+f.UncompressedSize64 > maxTotalBytes {
			return nil, fmt.Errorf("zip exceeds max total uncompressed bytes (%d)", maxTotalBytes)
		}

		totalBytes += f.UncompressedSize64

		// If it's a file, hash it in parallel
		if node.Type == "file" && f.UncompressedSize64 > 0 {
			if f.UncompressedSize64 > maxFileBytesToHash {
				node.HashError = fmt.Sprintf("file too large to hash (%d bytes)", f.UncompressedSize64)
				nodesMu.Lock()
				rep.Stats.FilesSkipped++
				nodesMu.Unlock()
			} else {
				wg.Add(1)
				go func(zf *zip.File, n *report.Node) {
					defer wg.Done()
					select {
					case <-ctx.Done():
						return
					case sem <- struct{}{}:
					}
					defer func() { <-sem }()

					hash, nbytes, err := hashZipFile(ctx, zf, maxFileBytesToHash)
					nodesMu.Lock()
					defer nodesMu.Unlock()
					if err != nil {
						n.HashError = err.Error()
						rep.Stats.FilesSkipped++
					} else {
						n.SHA256 = &hash
						rep.Stats.BytesHashed += nbytes
					}
				}(f, &node)
			}
		}

		rep.Nodes = append(rep.Nodes, node)
	}

	wg.Wait()
	updateStats(rep)
	return rep, nil
}

func (h *zipHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		info := zf.FileInfo()
		if !info.Mode().IsRegular() {
			continue
		}

		// ZIP allows random access, so we can peek without advancing a global state.
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		header := make([]byte, 512)
		n, _ := rc.Read(header)
		rc.Close()

		if format, _ := detect.DetectBytes(header[:n]); format == artifact.FormatUnknown {
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

func hashZipFile(ctx context.Context, f *zip.File, maxbytes uint64) (string, uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()
	h := sha256.New()
	limited := io.LimitReader(rc, int64(maxbytes))

	// Use a helper that respects context if needed, but for now we'll just check context periodically
	// or use a context-aware copy if we had one. Standard io.Copy doesn't.
	// For small files it's fine. For larger files we could use a custom copy loop.
	n, err := io.Copy(h, limited)
	if err != nil {
		return "", uint64(n), fmt.Errorf("read: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), uint64(n), nil
}

func updateStats(rep *report.Report) {
	// Reset stats to recount (to handle parallel updates correctly)
	rep.Stats.Files = 0
	rep.Stats.Dirs = 0
	rep.Stats.Symlinks = 0
	rep.Stats.Other = 0

	for _, n := range rep.Nodes {
		switch n.Type {
		case "file":
			rep.Stats.Files++
		case "dir":
			rep.Stats.Dirs++
		case "symlink":
			rep.Stats.Symlinks++
		case "other":
			rep.Stats.Other++
		}
	}
	rep.Stats.TotalNodes = len(rep.Nodes)
}
