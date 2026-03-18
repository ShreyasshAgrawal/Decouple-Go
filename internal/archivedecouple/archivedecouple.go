package archivedecouple

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"decouple/internal/artifact"
	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

type runtimeState struct {
	mu                    sync.Mutex
	nestedArchivesScanned int
	tempDiskBytesWritten  uint64
	sem                   chan struct{}
	tempDir               string
}

func (s *runtimeState) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tempDir != "" {
		slog.Debug("cleaning up temp directory", "dir", s.tempDir)
		os.RemoveAll(s.tempDir)
	}
}

func (s *runtimeState) createTempFile() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tempDir == "" {
		d, err := os.MkdirTemp("", "decouple-scan-*")
		if err != nil {
			return nil, err
		}
		s.tempDir = d
		slog.Debug("created temp directory for scan", "dir", d)
	}
	return os.CreateTemp(s.tempDir, "nested-*")
}

const unknownNestedSize = 0

func DecouplePath(ctx context.Context, path string, displayName string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	RegisterDefaults()
	cfg = ensureConfig(cfg)
	state := &runtimeState{
		sem: make(chan struct{}, cfg.EffectiveMaxConcurrentScans()),
	}
	defer state.cleanup()

	if strings.TrimSpace(displayName) == "" {
		displayName = filepath.Base(path)
	}

	slog.Info("starting scan", "path", path, "kind", kind, "display_name", displayName)

	rep, err := decoupleArchive(ctx, path, kind, cfg, state, 0, displayName, displayName)
	if err != nil {
		slog.Error("scan failed", "path", path, "error", err)
		return nil, err
	}
	rep.Stats.NestedArchivesScanned = state.nestedArchivesScanned
	rep.Stats.TotalNodes = len(rep.Nodes)
	
	slog.Info("scan complete", "path", path, "nodes", rep.Stats.TotalNodes, "nested_archives", rep.Stats.NestedArchivesScanned, "nested_errors", rep.Stats.NestedErrors)
	return rep, nil
}

func decoupleArchive(ctx context.Context, path string, kind string, cfg *scanconfig.Config, state *runtimeState, depth int, displayName string, pathPrefix string) (*report.Report, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	header := make([]byte, 512)
	n, _ := f.Read(header)
	f.Close()

	handler := FindHandler(header[:n], displayName)
	if handler == nil {
		slog.Warn("unsupported format", "path", path, "display_name", displayName)
		return nil, fmt.Errorf("unsupported format for %q", path)
	}

	slog.Debug("detected format", "path", path, "handler", handler.Format(), "depth", depth)

	if kind == "" {
		var ok bool
		kind, ok = artifact.DefaultKindForFormat(handler.Format())
		if !ok {
			kind = string(handler.Format())
		}
	}

	rep, err := handler.Decouple(ctx, path, kind, cfg)
	if err != nil {
		return nil, err
	}

	if pathPrefix != "" {
		for i := range rep.Nodes {
			rep.Nodes[i].Path = joinArchivePath(pathPrefix, rep.Nodes[i].Path)
		}
	}

	if depth >= cfg.EffectiveMaxDepth() {
		sortNodes(rep)
		rep.Stats.TotalNodes = len(rep.Nodes)
		return rep, nil
	}

	nodeIndex := make(map[string]int, len(rep.Nodes))
	for i := range rep.Nodes {
		nodeIndex[rep.Nodes[i].Path] = i
	}

	var wg sync.WaitGroup
	var repMu sync.Mutex

	err = handler.WalkNested(ctx, path, func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fullNodePath := joinArchivePath(pathPrefix, entryPath)
		nestedKind := artifact.KindFromPath(entryPath)

		// We MUST extract synchronously to ensure we don't advance the archive reader (e.g. for TAR)
		// but we can scan the extracted file in parallel.
		tempPath, err := prepareNestedArchive(ctx, fullNodePath, size, cfg, state, depth, rep, nodeIndex, open)
		if err != nil || tempPath == "" {
			return nil // Limit exceeded or error already set
		}

		wg.Add(1)
		go func(tPath string, nPath string, nKind string) {
			defer wg.Done()
			defer os.Remove(tPath)

			select {
			case <-ctx.Done():
				return
			case state.sem <- struct{}{}: // Acquire
			}
			defer func() { <-state.sem }() // Release

			slog.Debug("recursing into nested archive", "path", nPath, "depth", depth+1)
			childRep, err := decoupleArchive(ctx, tPath, nKind, cfg, state, depth+1, filepath.Base(nPath), nPath)
			if err != nil {
				slog.Warn("nested scan failed", "path", nPath, "error", err)
				repMu.Lock()
				setNodeNestedError(rep, nodeIndex, nPath, "nested_archive_parse_failed", err.Error())
				repMu.Unlock()
				return
			}

			repMu.Lock()
			mergeReport(rep, childRep)
			repMu.Unlock()
		}(tempPath, fullNodePath, nestedKind)

		return nil
	})
	wg.Wait()

	if err != nil {
		return nil, err
	}

	sortNodes(rep)
	rep.Stats.TotalNodes = len(rep.Nodes)
	return rep, nil
}

func prepareNestedArchive(ctx context.Context, nodePath string, size uint64, cfg *scanconfig.Config, state *runtimeState, depth int, rep *report.Report, nodeIndex map[string]int, open func() (io.ReadCloser, error)) (string, error) {
	sizeKnown := size != unknownNestedSize
	if depth+1 > cfg.EffectiveMaxDepth() {
		setNodeNestedError(rep, nodeIndex, nodePath, "max_depth_exceeded", "nested max depth exceeded")
		return "", nil
	}

	state.mu.Lock()
	if state.nestedArchivesScanned >= cfg.EffectiveMaxNestedArchives() {
		state.mu.Unlock()
		slog.Warn("safety limit: max nested archives exceeded", "limit", cfg.EffectiveMaxNestedArchives(), "path", nodePath)
		setNodeNestedError(rep, nodeIndex, nodePath, "max_nested_archives_exceeded", "max nested archives exceeded")
		return "", nil
	}
	if sizeKnown && size > cfg.EffectiveMaxNestedBytes() {
		state.mu.Unlock()
		slog.Warn("safety limit: nested archive too large", "size", size, "limit", cfg.EffectiveMaxNestedBytes(), "path", nodePath)
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_too_large", fmt.Sprintf("nested archive exceeds max size (%d)", cfg.EffectiveMaxNestedBytes()))
		return "", nil
	}
	if sizeKnown && state.tempDiskBytesWritten+size > cfg.EffectiveMaxTempDiskBytes() {
		state.mu.Unlock()
		slog.Warn("safety limit: max temp disk bytes exceeded", "written", state.tempDiskBytesWritten, "next_size", size, "limit", cfg.EffectiveMaxTempDiskBytes(), "path", nodePath)
		setNodeNestedError(rep, nodeIndex, nodePath, "max_temp_disk_bytes_exceeded", fmt.Sprintf("temp disk write budget exceeded (%d)", cfg.EffectiveMaxTempDiskBytes()))
		return "", nil
	}
	state.mu.Unlock()

	temp, err := state.createTempFile()
	if err != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "temp_file_create_failed", err.Error())
		return "", nil
	}
	tempPath := temp.Name()
	defer temp.Close()

	rc, err := open()
	if err != nil {
		os.Remove(tempPath)
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", err.Error())
		return "", nil
	}
	defer rc.Close()

	limit := cfg.EffectiveMaxNestedBytes() + 1
	if sizeKnown {
		limit = size + 1
	}
	limited := io.LimitReader(rc, int64(limit))
	// io.Copy doesn't check context, but we are inside prepareNestedArchive which is synchronous per-archive
	n, copyErr := io.Copy(temp, limited)
	if copyErr != nil {
		os.Remove(tempPath)
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", copyErr.Error())
		return "", nil
	}
	if sizeKnown && uint64(n) > size {
		os.Remove(tempPath)
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", "copied beyond declared size")
		return "", nil
	}
	if !sizeKnown && uint64(n) > cfg.EffectiveMaxNestedBytes() {
		os.Remove(tempPath)
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_too_large", fmt.Sprintf("nested archive exceeds max size (%d)", cfg.EffectiveMaxNestedBytes()))
		return "", nil
	}

	written := uint64(n)
	state.mu.Lock()
	if state.tempDiskBytesWritten+written > cfg.EffectiveMaxTempDiskBytes() {
		state.mu.Unlock()
		os.Remove(tempPath)
		setNodeNestedError(rep, nodeIndex, nodePath, "max_temp_disk_bytes_exceeded", fmt.Sprintf("temp disk write budget exceeded (%d)", cfg.EffectiveMaxTempDiskBytes()))
		return "", nil
	}
	state.tempDiskBytesWritten += written
	state.nestedArchivesScanned++
	state.mu.Unlock()

	return tempPath, nil
}

func mergeReport(dst *report.Report, src *report.Report) {
	dst.Nodes = append(dst.Nodes, src.Nodes...)
	dst.Stats.Files += src.Stats.Files
	dst.Stats.Dirs += src.Stats.Dirs
	dst.Stats.Symlinks += src.Stats.Symlinks
	dst.Stats.Other += src.Stats.Other
	dst.Stats.BytesHashed += src.Stats.BytesHashed
	dst.Stats.FilesSkipped += src.Stats.FilesSkipped
	dst.Stats.NestedErrors += src.Stats.NestedErrors
	dst.Stats.NestedArchivesScanned += src.Stats.NestedArchivesScanned
	dst.Stats.TotalNodes = len(dst.Nodes)
}

func setNodeNestedError(rep *report.Report, nodeIndex map[string]int, nodePath string, code string, msg string) {
	idx, ok := nodeIndex[nodePath]
	if !ok {
		return
	}
	rep.Nodes[idx].NestedArchiveErrorCode = code
	rep.Nodes[idx].NestedArchiveError = msg
	rep.Stats.NestedErrors++
}

func sortNodes(rep *report.Report) {
	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})
}

func joinArchivePath(prefix string, p string) string {
	p = strings.TrimPrefix(p, "/")
	if prefix == "" {
		return p
	}
	if p == "" {
		return prefix
	}
	return prefix + "/" + p
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
