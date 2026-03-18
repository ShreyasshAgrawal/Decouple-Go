package archivedecouple

import (
	"bufio"
	"context"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/report"
	"decouple/internal/safety"
	"decouple/internal/scanconfig"
)

type gzipHandler struct{}

func (h *gzipHandler) Format() artifact.Format { return artifact.FormatGzip }

func (h *gzipHandler) Detect(header []byte, path string) bool {
	return len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b
}

func (h *gzipHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	rep := &report.Report{
		Artifact: report.Artifact{
			InputPath: path,
			Kind:      kind,
		},
	}

	payloadPath := strings.TrimSpace(gz.Name)
	if payloadPath == "" {
		payloadPath = defaultPayloadPath(path)
	}
	if normalized, nerr := safety.NormalizeZipPath(payloadPath); nerr == nil {
		payloadPath = normalized
	}

	node := report.Node{
		Path: payloadPath,
		Type: "file",
	}

	h_sha := sha256.New()
	maxBytes := cfg.EffectiveMaxFileBytesToHash()
	limited := io.LimitReader(gz, int64(maxBytes)+1)
	n, err := io.Copy(h_sha, limited)
	if err != nil {
		node.HashError = fmt.Sprintf("read gzip payload: %v", err)
		rep.Stats.FilesSkipped++
	} else if uint64(n) > maxBytes {
		node.HashError = fmt.Sprintf("file too large to hash (%d bytes)", maxBytes)
		rep.Stats.FilesSkipped++
	} else {
		hash := hex.EncodeToString(h_sha.Sum(nil))
		node.SHA256 = &hash
		rep.Stats.BytesHashed += uint64(n)
		node.SizeBytes = uint64(n)
	}
	if node.SizeBytes == 0 {
		node.SizeBytes = uint64(n)
	}

	rep.Nodes = append(rep.Nodes, node)
	updateStats(rep)
	return rep, nil
}

func (h *gzipHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
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
	if len(peek) < 2 {
		return nil
	}

	if format, _ := detect.DetectBytes(peek); format != artifact.FormatUnknown {
		entryName := gz.Name
		if entryName == "" {
			entryName = "payload"
			base := strings.TrimSuffix(filepath.Base(path), ".gz")
			if base != filepath.Base(path) {
				entryName = base
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

		return fn(entryName, 0, open)
	}

	return nil
}

func defaultPayloadPath(path string) string {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".gz") && len(base) > 3 {
		return base[:len(base)-3]
	}
	return "payload"
}
