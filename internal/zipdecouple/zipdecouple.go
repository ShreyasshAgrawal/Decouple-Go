package zipdecouple

import (
	"archive/zip"
	"crypto/sha256"
	"decouple/internal/report"
	"decouple/internal/safety"
	"decouple/internal/scanconfig"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type Config = scanconfig.Config

func DecoupleZip(zipPath string, cfg *scanconfig.Config, kind string) (*report.Report, error) {
	cfg = ensureConfig(cfg)
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat zip: %w", err)
	}
	return DecoupleZipReaderAt(f, st.Size(), zipPath, kind, cfg)
}

func DecoupleZipReaderAt(rat io.ReaderAt, size int64, inputPath string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)
	r, err := zip.NewReader(rat, size)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	rep := &report.Report{
		Artifact: report.Artifact{InputPath: inputPath, Kind: kind},
	}
	maxFiles := cfg.EffectiveMaxFiles()
	maxTotalBytes := cfg.EffectiveMaxTotalBytes()
	maxFileBytesToHash := cfg.EffectiveMaxFileBytesToHash()
	var totalBytes uint64

	for _, f := range r.File {
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
		if node.Type == "file" && f.UncompressedSize64 > 0 {
			if f.UncompressedSize64 > maxFileBytesToHash {
				node.HashError = fmt.Sprintf("file too large to hash (%d bytes)", f.UncompressedSize64)
				rep.Stats.FilesSkipped++
			} else {
				hashedfile, n, err := hashZipFile(f, maxFileBytesToHash)
				if err != nil {
					node.HashError = err.Error()
					rep.Stats.FilesSkipped++
				} else {
					node.SHA256 = hashedfile
					rep.Stats.BytesHashed += n
				}
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

func hashZipFile(f *zip.File, maxbytes uint64) (*string, uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, 0, err
	}
	defer rc.Close()
	h := sha256.New()
	limited := io.LimitReader(rc, int64(maxbytes))
	n, err := io.Copy(h, limited)
	if err != nil {
		return nil, uint64(n), fmt.Errorf("read : %w", err)
	}
	hashstr := hex.EncodeToString(h.Sum(nil))
	return &hashstr, uint64(n), nil
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
