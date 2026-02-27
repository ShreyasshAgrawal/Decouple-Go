package archivedecouple

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/gzipdecouple"
	"decouple/internal/imgdecouple"
	"decouple/internal/pedecouple"
	"decouple/internal/report"
	"decouple/internal/scanconfig"
	"decouple/internal/tardecouple"
	"decouple/internal/zipdecouple"
)

type runtimeState struct {
	nestedArchivesScanned int
	tempDiskBytesWritten  uint64
}

func DecouplePath(path string, displayName string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)
	state := &runtimeState{}
	if strings.TrimSpace(displayName) == "" {
		displayName = filepath.Base(path)
	}

	rep, err := decoupleArchive(path, kind, cfg, state, 0, displayName)
	if err != nil {
		return nil, err
	}
	rep.Stats.NestedArchivesScanned = state.nestedArchivesScanned
	rep.Stats.TotalNodes = len(rep.Nodes)
	return rep, nil
}

func decoupleArchive(path string, kind string, cfg *scanconfig.Config, state *runtimeState, depth int, pathPrefix string) (*report.Report, error) {
	format, err := detect.Detect(path)
	if err != nil {
		if kind == "img" {
			format = artifact.FormatIMG
		} else {
			return nil, err
		}
	}

	if kind == "" {
		var ok bool
		kind, ok = artifact.DefaultKindForFormat(format)
		if !ok {
			return nil, fmt.Errorf("unsupported format %q", format)
		}
	}

	var walkNested func(path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error

	var rep *report.Report
	switch format {
	case artifact.FormatZip:
		rep, err = zipdecouple.DecoupleZip(path, cfg, kind)
		walkNested = walkNestedZip
	case artifact.FormatTar:
		rep, err = tardecouple.DecoupleTar(path, kind, cfg)
		walkNested = walkNestedTar
	case artifact.FormatGzip:
		rep, err = gzipdecouple.DecoupleGzip(path, kind, cfg)
		walkNested = walkNestedGzip
	case artifact.FormatIMG:
		rep, err = imgdecouple.DecoupleIMG(path, kind, cfg)
		walkNested = func(_ string, _ func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
			return nil
		}
	case artifact.FormatPE:
		rep, err = pedecouple.DecouplePE(path, kind, cfg)
		walkNested = func(_ string, _ func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
			return nil
		}
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return nil, err
	}

	if pathPrefix != "" {
		for i := range rep.Nodes {
			rep.Nodes[i].Path = joinArchivePath(pathPrefix, rep.Nodes[i].Path)
		}
	}

	if depth > cfg.EffectiveMaxDepth() {
		sortNodes(rep)
		rep.Stats.TotalNodes = len(rep.Nodes)
		return rep, nil
	}

	nodeIndex := make(map[string]int, len(rep.Nodes))
	for i := range rep.Nodes {
		nodeIndex[rep.Nodes[i].Path] = i
	}

	if err := walkNested(path, func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error {
		fullNodePath := joinArchivePath(pathPrefix, entryPath)
		nestedKind := artifact.KindFromPath(entryPath)
		processNestedArchive(fullNodePath, size, cfg, state, depth, rep, nodeIndex, open, nestedKind)
		return nil
	}); err != nil {
		return nil, err
	}

	sortNodes(rep)
	rep.Stats.TotalNodes = len(rep.Nodes)
	return rep, nil
}

func processNestedArchive(nodePath string, size uint64, cfg *scanconfig.Config, state *runtimeState, depth int, rep *report.Report, nodeIndex map[string]int, open func() (io.ReadCloser, error), nestedKind string) {
	sizeKnown := size != unknownNestedSize
	if depth+1 > cfg.EffectiveMaxDepth() {
		setNodeNestedError(rep, nodeIndex, nodePath, "max_depth_exceeded", "nested max depth exceeded")
		return
	}
	if state.nestedArchivesScanned >= cfg.EffectiveMaxNestedArchives() {
		setNodeNestedError(rep, nodeIndex, nodePath, "max_nested_archives_exceeded", "max nested archives exceeded")
		return
	}
	if sizeKnown && size > cfg.EffectiveMaxNestedBytes() {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_too_large", fmt.Sprintf("nested archive exceeds max size (%d)", cfg.EffectiveMaxNestedBytes()))
		return
	}
	if sizeKnown && state.tempDiskBytesWritten+size > cfg.EffectiveMaxTempDiskBytes() {
		setNodeNestedError(rep, nodeIndex, nodePath, "max_temp_disk_bytes_exceeded", fmt.Sprintf("temp disk write budget exceeded (%d)", cfg.EffectiveMaxTempDiskBytes()))
		return
	}

	temp, err := os.CreateTemp("", "decouple-nested-*")
	if err != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "temp_file_create_failed", err.Error())
		return
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	defer temp.Close()

	rc, err := open()
	if err != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", err.Error())
		return
	}
	limit := cfg.EffectiveMaxNestedBytes() + 1
	if sizeKnown {
		limit = size + 1
	}
	limited := io.LimitReader(rc, int64(limit))
	n, copyErr := io.Copy(temp, limited)
	closeErr := rc.Close()
	if copyErr != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", copyErr.Error())
		return
	}
	if closeErr != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", closeErr.Error())
		return
	}
	if sizeKnown && uint64(n) > size {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_extract_failed", "copied beyond declared size")
		return
	}
	if !sizeKnown && uint64(n) > cfg.EffectiveMaxNestedBytes() {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_too_large", fmt.Sprintf("nested archive exceeds max size (%d)", cfg.EffectiveMaxNestedBytes()))
		return
	}

	written := uint64(n)
	if state.tempDiskBytesWritten+written > cfg.EffectiveMaxTempDiskBytes() {
		setNodeNestedError(rep, nodeIndex, nodePath, "max_temp_disk_bytes_exceeded", fmt.Sprintf("temp disk write budget exceeded (%d)", cfg.EffectiveMaxTempDiskBytes()))
		return
	}
	state.tempDiskBytesWritten += written

	state.nestedArchivesScanned++
	childRep, err := decoupleArchive(tempPath, nestedKind, cfg, state, depth+1, nodePath)
	if err != nil {
		setNodeNestedError(rep, nodeIndex, nodePath, "nested_archive_parse_failed", err.Error())
		return
	}
	mergeReport(rep, childRep)
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
