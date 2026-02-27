package gzipdecouple

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

type Config = scanconfig.Config

func DecoupleGzip(path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)

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

	node := report.Node{
		Path: payloadPath,
		Type: "file",
	}

	h := sha256.New()
	maxBytes := cfg.EffectiveMaxFileBytesToHash()
	limited := io.LimitReader(gz, int64(maxBytes)+1)
	n, err := io.Copy(h, limited)
	if err != nil {
		node.HashError = fmt.Sprintf("read gzip payload: %v", err)
		rep.Stats.FilesSkipped++
	} else if uint64(n) > maxBytes {
		node.HashError = fmt.Sprintf("file too large to hash (%d bytes)", maxBytes)
		rep.Stats.FilesSkipped++
	} else {
		hash := hex.EncodeToString(h.Sum(nil))
		node.SHA256 = &hash
		rep.Stats.BytesHashed += uint64(n)
		node.SizeBytes = uint64(n)
	}
	if node.SizeBytes == 0 {
		node.SizeBytes = uint64(n)
	}

	rep.Nodes = append(rep.Nodes, node)
	rep.Stats.TotalNodes = 1
	rep.Stats.Files = 1
	return rep, nil
}

func defaultPayloadPath(path string) string {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".gz") && len(base) > 3 {
		return base[:len(base)-3]
	}
	return "payload"
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
