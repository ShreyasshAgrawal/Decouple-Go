package tardecouple

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"decouple/internal/report"
	"decouple/internal/safety"
	"decouple/internal/scanconfig"
)

type Config = scanconfig.Config

func DecoupleTar(path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return DecoupleTarReader(f, path, kind, cfg)
}

// DecoupleTarReader produces a report from TAR bytes. kind is the artifact kind (tar, tar.gz).
func DecoupleTarReader(src io.Reader, inputPath string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)
	buf := bufio.NewReader(src)
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
			InputPath: inputPath,
			Kind:      kind,
		},
	}

	tr := tar.NewReader(r)
	fileCount := 0
	var totalBytes uint64

	for {
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
		// TAR has no per-file compressed size
		if !hdr.ModTime.IsZero() {
			node.ModifiedTime = &hdr.ModTime
		}

		// Compute SHA-256 for regular files by streaming
		bodyConsumed := false
		if node.Type == "file" && hdr.Size > 0 {
			if hdr.Size > int64(maxBytes) {
				node.HashError = fmt.Sprintf("file exceeds max size for hashing (%d bytes)", maxBytes)
				rep.Stats.FilesSkipped++
			} else {
				hashHex, n, hashErr := hashTarEntry(tr, int64(maxBytes))
				if hashErr != nil {
					node.HashError = hashErr.Error()
					rep.Stats.FilesSkipped++
				} else {
					node.SHA256 = &hashHex
					rep.Stats.BytesHashed += uint64(n)
					bodyConsumed = true
				}

			}
		}

		// Skip remaining body if we didn't consume it (required for correct tar iteration)
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

	return rep, nil
}

func hashTarEntry(r io.Reader, maxBytes int64) (hashHex string, bytesRead int64, err error) {
	h := sha256.New()
	limited := io.LimitReader(r, maxBytes)
	n, err := io.Copy(h, limited)
	if err != nil {
		return "", n, fmt.Errorf("read: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
