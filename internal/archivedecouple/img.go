package archivedecouple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/report"
	"decouple/internal/scanconfig"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
)

type imgHandler struct{}

func (h *imgHandler) Format() artifact.Format { return artifact.FormatIMG }

func (h *imgHandler) Detect(header []byte, path string) bool {
	if artifact.KindFromPath(path) == "img" {
		return true
	}
	if len(header) >= 512 && header[510] == 0x55 && header[511] == 0xAA {
		return true
	}
	if len(header) >= 520 && string(header[512:520]) == "EFI PART" {
		return true
	}
	return false
}

const (
	imgConfidenceAuthoritative = "authoritative"
	imgConfidenceHeuristic     = "heuristic"
	imgConfidenceUnreadable    = "unreadable"

	imgProviderDiskfs  = "diskfs"
	imgProviderExt4    = "ext4"
	imgProviderMagic   = "internal_magic"
	imgProviderUnknown = "img_handler"

	imgReasonFilesystemParseFailed   = "FILESYSTEM_PARSE_FAILED"
	imgReasonUnsupportedNTFS         = "UNSUPPORTED_NTFS_DRIVER"
	imgReasonUnsupportedXFS          = "UNSUPPORTED_XFS_DRIVER"
	imgReasonUnsupportedBTRFS        = "UNSUPPORTED_BTRFS_DRIVER"
	imgReasonUnsupportedLVM          = "UNSUPPORTED_LVM_CONTAINER"
	imgReasonLUKSEncrypted           = "LUKS_ENCRYPTED"
	imgReasonUnsupportedQCOW2        = "UNSUPPORTED_QCOW2_CONTAINER"
	imgReasonUnsupportedVMDK         = "UNSUPPORTED_VMDK_CONTAINER"
	imgReasonUnsupportedVHDX         = "UNSUPPORTED_VHDX_CONTAINER"
	imgReasonUnsupportedCompressedGZ = "UNSUPPORTED_COMPRESSED_GZIP_IMG"
	imgReasonCorruptFilesystem       = "CORRUPT_FILESYSTEM"
	imgReasonReadIOFailed            = "READ_IO_FAILED"
)

type imgSignatureProbe struct {
	f *os.File
}

func newIMGSignatureProbe(path string) (*imgSignatureProbe, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &imgSignatureProbe{f: f}, nil
}

func (p *imgSignatureProbe) Close() error {
	if p == nil || p.f == nil {
		return nil
	}
	return p.f.Close()
}

func (p *imgSignatureProbe) readAt(offset int64, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	readN, err := p.f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:readN], nil
}

func (p *imgSignatureProbe) detectContainerStatus() *report.AnalysisStatus {
	head, err := p.readAt(0, 520)
	if err != nil {
		return nil
	}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		return &report.AnalysisStatus{Confidence: imgConfidenceUnreadable, Reason: imgReasonUnsupportedCompressedGZ, Provider: imgProviderMagic}
	}
	if len(head) >= 4 && bytes.Equal(head[:4], []byte{'Q', 'F', 'I', 0xfb}) {
		return &report.AnalysisStatus{Confidence: imgConfidenceUnreadable, Reason: imgReasonUnsupportedQCOW2, Provider: imgProviderMagic}
	}
	if len(head) >= 4 && bytes.Equal(head[:4], []byte{'K', 'D', 'M', 'V'}) {
		return &report.AnalysisStatus{Confidence: imgConfidenceUnreadable, Reason: imgReasonUnsupportedVMDK, Provider: imgProviderMagic}
	}
	if len(head) >= 8 && bytes.Equal(head[:8], []byte("vhdxfile")) {
		return &report.AnalysisStatus{Confidence: imgConfidenceUnreadable, Reason: imgReasonUnsupportedVHDX, Provider: imgProviderMagic}
	}
	if len(head) >= 520 && string(head[512:520]) == "EFI PART" {
		return &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Provider: imgProviderMagic}
	}
	if len(head) >= 512 && head[510] == 0x55 && head[511] == 0xAA {
		return &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Provider: imgProviderMagic}
	}
	return &report.AnalysisStatus{Confidence: imgConfidenceHeuristic, Provider: imgProviderMagic}
}

func (p *imgSignatureProbe) detectFilesystemSignature(offset uint64) (string, *report.AnalysisStatus) {
	if magic, _ := p.readAt(int64(offset)+512, 8); len(magic) == 8 && string(magic) == "LABELONE" {
		return "LVM2_member", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedLVM, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+1024, 8); len(magic) == 8 && string(magic) == "LABELONE" {
		return "LVM2_member", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedLVM, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset), 8); len(magic) >= 6 && bytes.Equal(magic[:6], []byte{'L', 'U', 'K', 'S', 0xBA, 0xBE}) {
		return "LUKS", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonLUKSEncrypted, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset), 4); len(magic) >= 4 && bytes.Equal(magic[:4], []byte("XFSB")) {
		return "XFS", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedXFS, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset), 8); len(magic) >= 8 && bytes.Equal(magic[:8], []byte("vhdxfile")) {
		return "VHDX", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedVHDX, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+3, 8); len(magic) == 8 && string(magic) == "NTFS    " {
		return "NTFS", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedNTFS, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+0x52, 5); len(magic) == 5 && string(magic) == "FAT32" {
		return "FAT32", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+1024+56, 2); len(magic) == 2 && magic[0] == 0x53 && magic[1] == 0xEF {
		return "Ext4", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+0x10040, 8); len(magic) == 8 && bytes.Equal(magic, []byte("_BHRfS_M")) {
		return "Btrfs", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Reason: imgReasonUnsupportedBTRFS, Provider: imgProviderMagic}
	}
	if magic, _ := p.readAt(int64(offset)+0x8001, 5); len(magic) == 5 && string(magic) == "CD001" {
		return "ISO9660", &report.AnalysisStatus{Confidence: imgConfidenceAuthoritative, Provider: imgProviderMagic}
	}
	return "Unknown", &report.AnalysisStatus{Confidence: imgConfidenceHeuristic, Provider: imgProviderMagic}
}

func (h *imgHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	rep := &report.Report{
		Artifact: report.Artifact{
			InputPath: path,
			Kind:      kind,
		},
	}

	probe, probeErr := newIMGSignatureProbe(path)
	if probeErr == nil {
		defer probe.Close()
		rep.Artifact.Status = probe.detectContainerStatus()
	}

	d, err := diskfs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open disk: %w", err)
	}
	defer d.Close()

	table, err := d.GetPartitionTable()
	if err != nil {
		if fsErr := h.decoupleFilesystem(ctx, d, 0, 0, d.Size, "root", rep, cfg, path, probe); fsErr != nil {
			st, _ := os.Stat(path)
			fileSize := uint64(0)
			if st != nil {
				fileSize = uint64(st.Size())
			}
			fsType, status := h.detectFilesystem(path, 0, probe)
			rep.Nodes = append(rep.Nodes, report.Node{
				Path:           "",
				Type:           "file",
				SizeBytes:      fileSize,
				FilesystemType: fsType,
				HashError:      fmt.Sprintf("filesystem parse failed: %v", fsErr),
				Status:         h.unreadableStatusForError(status, fsErr),
			})
		}
		updateStats(rep)
		return rep, nil
	}

	partitions := table.GetPartitions()
	maxParts := cfg.EffectiveMaxIMGPartitions()
	for i, p := range partitions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if i >= maxParts {
			break
		}
		partName := fmt.Sprintf("partition_%d", i+1)
		if err := h.decoupleFilesystem(ctx, d, i+1, p.GetStart(), p.GetSize(), partName, rep, cfg, path, probe); err != nil {
			idx := i + 1
			start := uint64(p.GetStart())
			size := uint64(p.GetSize())
			end := start + size - 1
			fsType, status := h.detectFilesystem(path, start, probe)
			rep.Nodes = append(rep.Nodes, report.Node{
				Path:             partName,
				Type:             "file",
				SizeBytes:        size,
				PartitionIndex:   &idx,
				StartOffsetBytes: &start,
				EndOffsetBytes:   &end,
				FilesystemType:   fsType,
				HashError:        fmt.Sprintf("filesystem parse failed: %v", err),
				Status:           h.unreadableStatusForError(status, err),
			})
		}
	}

	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})
	updateStats(rep)
	return rep, nil
}

func (h *imgHandler) unreadableStatusForError(fromSignature *report.AnalysisStatus, parseErr error) *report.AnalysisStatus {
	if fromSignature != nil && fromSignature.Reason != "" {
		return &report.AnalysisStatus{
			Confidence: imgConfidenceUnreadable,
			Reason:     fromSignature.Reason,
			Provider:   fromSignature.Provider,
		}
	}
	reason, provider := h.mapFilesystemParseError(parseErr)
	return &report.AnalysisStatus{
		Confidence: imgConfidenceUnreadable,
		Reason:     reason,
		Provider:   provider,
	}
}

func (h *imgHandler) mapFilesystemParseError(parseErr error) (string, string) {
	if parseErr == nil {
		return imgReasonFilesystemParseFailed, imgProviderDiskfs
	}
	lower := strings.ToLower(parseErr.Error())
	if strings.Contains(lower, "superblock") || strings.Contains(lower, "invalid") || strings.Contains(lower, "corrupt") || strings.Contains(lower, "bad magic") {
		return imgReasonCorruptFilesystem, imgProviderDiskfs
	}
	if strings.Contains(lower, "i/o") || strings.Contains(lower, "input/output") || strings.Contains(lower, "short read") {
		return imgReasonReadIOFailed, imgProviderDiskfs
	}
	if strings.Contains(lower, "ext4") || strings.Contains(lower, "ext") {
		return imgReasonFilesystemParseFailed, imgProviderExt4
	}
	return imgReasonFilesystemParseFailed, imgProviderDiskfs
}

func (h *imgHandler) detectFilesystem(path string, offset uint64, probe *imgSignatureProbe) (string, *report.AnalysisStatus) {
	if probe != nil {
		return probe.detectFilesystemSignature(offset)
	}
	tmpProbe, err := newIMGSignatureProbe(path)
	if err != nil {
		return "Unknown", &report.AnalysisStatus{Confidence: imgConfidenceHeuristic, Provider: imgProviderUnknown}
	}
	defer tmpProbe.Close()
	return tmpProbe.detectFilesystemSignature(offset)
}

func (h *imgHandler) openFilesystem(d *disk.Disk, partIndex int, start, partSize int64, diskPath string, probe *imgSignatureProbe) (filesystem.FileSystem, error) {
	fs, err := d.GetFilesystem(partIndex)
	if err == nil {
		return fs, nil
	}

	fsType, _ := h.detectFilesystem(diskPath, uint64(start), probe)
	if fsType == "Ext4" {
		return ext4.Read(d.Backend, partSize, start, d.LogicalBlocksize)
	}

	return nil, err
}

func (h *imgHandler) decoupleFilesystem(ctx context.Context, d *disk.Disk, partIndex int, start, partSize int64, prefix string, rep *report.Report, cfg *scanconfig.Config, diskPath string, probe *imgSignatureProbe) error {
	fs, err := h.openFilesystem(d, partIndex, start, partSize, diskPath, probe)
	if err != nil {
		return err
	}

	maxFiles := cfg.EffectiveMaxFiles()
	maxHash := cfg.EffectiveMaxFileBytesToHash()
	maxIMGWorkers := cfg.EffectiveMaxIMGConcurrentScans()

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, maxIMGWorkers)

	err = h.walkFilesystem(ctx, fs, "/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		nodePath := filepath.Join(prefix, path)
		node := report.Node{
			Path:      nodePath,
			SizeBytes: uint64(info.Size()),
		}

		if info.IsDir() {
			node.Type = "dir"
		} else if info.Mode()&os.ModeSymlink != 0 {
			node.Type = "symlink"
		} else {
			node.Type = "file"
		}

		mt := info.ModTime()
		if !mt.IsZero() {
			node.ModifiedTime = &mt
		}

		mu.Lock()
		if len(rep.Nodes) >= maxFiles {
			mu.Unlock()
			return fmt.Errorf("exceeded max files (%d)", maxFiles)
		}
		rep.Nodes = append(rep.Nodes, node)
		nodeIdx := len(rep.Nodes) - 1
		if rep.Artifact.OSHint == "" && node.Type == "file" && shouldCheckOSHintPath(path) {
			h.sniffOSHint(ctx, fs, path, rep)
		}
		mu.Unlock()

		if node.Type != "file" || node.SizeBytes == 0 {
			return nil
		}
		if node.SizeBytes > maxHash {
			mu.Lock()
			rep.Nodes[nodeIdx].HashError = fmt.Sprintf("file too large to hash (%d bytes)", node.SizeBytes)
			rep.Stats.FilesSkipped++
			mu.Unlock()
			return nil
		}

		wg.Add(1)
		go func(p string, idx int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			hash, bytes, hashErr := h.hashFsFile(ctx, fs, p, maxHash)
			mu.Lock()
			defer mu.Unlock()
			if hashErr != nil {
				rep.Nodes[idx].HashError = hashErr.Error()
				rep.Stats.FilesSkipped++
				return
			}
			rep.Nodes[idx].SHA256 = &hash
			rep.Stats.BytesHashed += bytes
		}(path, nodeIdx)

		return nil
	})

	wg.Wait()
	return err
}

func (h *imgHandler) walkFilesystem(ctx context.Context, fs filesystem.FileSystem, path string, fn func(path string, info os.FileInfo, err error) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	entries, err := fs.ReadDir(path)
	if err != nil {
		return fn(path, nil, err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		fullPath := filepath.Join(path, entry.Name())
		if err := fn(fullPath, entry, nil); err != nil {
			return err
		}
		if entry.IsDir() {
			if err := h.walkFilesystem(ctx, fs, fullPath, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *imgHandler) hashFsFile(ctx context.Context, fs filesystem.FileSystem, path string, max uint64) (string, uint64, error) {
	f, err := fs.OpenFile(path, os.O_RDONLY)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(f, int64(max)))
	if err != nil {
		return "", uint64(n), err
	}
	return hex.EncodeToString(hasher.Sum(nil)), uint64(n), nil
}

func (h *imgHandler) sniffOSHint(ctx context.Context, fs filesystem.FileSystem, path string, rep *report.Report) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	clean := normalizeIMGPath(path)
	switch clean {
	case "/etc/os-release", "/usr/lib/os-release":
		hint, err := readOSReleaseHint(fs, clean)
		if err != nil || hint == "" {
			return
		}
		rep.Artifact.OSHint = hint
	case "/Windows/System32/config/SOFTWARE", "/WINDOWS/system32/config/SOFTWARE":
		rep.Artifact.OSHint = "Windows (registry hive detected)"
	}
}

func shouldCheckOSHintPath(path string) bool {
	clean := normalizeIMGPath(path)
	return clean == "/etc/os-release" ||
		clean == "/usr/lib/os-release" ||
		clean == "/Windows/System32/config/SOFTWARE" ||
		clean == "/WINDOWS/system32/config/SOFTWARE"
}

func normalizeIMGPath(path string) string {
	return filepath.Clean(strings.ReplaceAll(path, "\\", "/"))
}

func readOSReleaseHint(fs filesystem.FileSystem, path string) (string, error) {
	f, err := fs.OpenFile(path, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer f.Close()

	limited := io.LimitReader(f, 64*1024)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	var name, version, pretty string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"")
		switch k {
		case "PRETTY_NAME":
			pretty = v
		case "NAME":
			name = v
		case "VERSION":
			version = v
		}
	}
	if pretty != "" {
		return pretty, nil
	}
	if name != "" && version != "" {
		return name + " " + version, nil
	}
	if name != "" {
		return name, nil
	}
	return "", nil
}

func (h *imgHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	d, err := diskfs.Open(path)
	if err != nil {
		return nil // Ignore open error during walk, Decouple already handled it
	}
	defer d.Close()

	probe, probeErr := newIMGSignatureProbe(path)
	if probeErr == nil {
		defer probe.Close()
	}

	table, err := d.GetPartitionTable()
	if err != nil {
		_ = h.emitRawNestedCandidate(ctx, path, 0, d.Size, "root", fn)
		_ = h.walkNestedFilesystem(ctx, d, path, 0, 0, d.Size, "root", fn, probe)
		return nil
	}

	for i, p := range table.GetPartitions() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		prefix := fmt.Sprintf("partition_%d", i+1)
		_ = h.emitRawNestedCandidate(ctx, path, p.GetStart(), p.GetSize(), prefix, fn)
		_ = h.walkNestedFilesystem(ctx, d, path, i+1, p.GetStart(), p.GetSize(), prefix, fn, probe)
	}
	return nil
}

func (h *imgHandler) emitRawNestedCandidate(ctx context.Context, diskPath string, start, size int64, prefix string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	if size <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f, err := os.Open(diskPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	headerLen := int64(520)
	if size < headerLen {
		headerLen = size
	}
	header := make([]byte, headerLen)
	n, _ := f.ReadAt(header, start)
	if n < 2 {
		return nil
	}
	header = header[:n]

	format, _ := detect.DetectBytes(header)
	if format == artifact.FormatUnknown {
		return nil
	}

	open := func() (io.ReadCloser, error) {
		fd, err := os.Open(diskPath)
		if err != nil {
			return nil, err
		}
		return &sectionReadCloser{
			Reader: io.NewSectionReader(fd, start, size),
			f:      fd,
		}, nil
	}
	return fn(prefix, uint64(size), open)
}

func (h *imgHandler) walkNestedFilesystem(ctx context.Context, d *disk.Disk, diskPath string, partIndex int, start, partSize int64, prefix string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error, probe *imgSignatureProbe) error {
	fs, err := h.openFilesystem(d, partIndex, start, partSize, diskPath, probe)
	if err != nil {
		return nil // Skip this FS
	}

	return h.walkFilesystem(ctx, fs, "/", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		f, err := fs.OpenFile(path, os.O_RDONLY)
		if err != nil {
			return nil
		}
		defer f.Close()

		header := make([]byte, 512)
		n, _ := f.Read(header)
		if n < 2 {
			return nil
		}

		if format, _ := detect.DetectBytes(header[:n]); format != artifact.FormatUnknown {
			entryPath := filepath.Join(prefix, path)
			entrySize := uint64(info.Size())

			open := func() (io.ReadCloser, error) {
				d2, err := diskfs.Open(diskPath)
				if err != nil {
					return nil, err
				}
				fs2, err := h.openFilesystem(d2, partIndex, start, partSize, diskPath, nil)
				if err != nil {
					d2.Close()
					return nil, err
				}
				f2, err := fs2.OpenFile(path, os.O_RDONLY)
				if err != nil {
					d2.Close()
					return nil, err
				}
				return &fsReadCloser{f: f2, d: d2}, nil
			}

			return fn(entryPath, entrySize, open)
		}
		return nil
	})
}

type fsReadCloser struct {
	f filesystem.File
	d *disk.Disk
}

func (rc *fsReadCloser) Read(p []byte) (n int, err error) { return rc.f.Read(p) }
func (rc *fsReadCloser) Close() error {
	err1 := rc.f.Close()
	err2 := rc.d.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

type sectionReadCloser struct {
	Reader io.Reader
	f      *os.File
}

func (rc *sectionReadCloser) Read(p []byte) (int, error) {
	return rc.Reader.Read(p)
}

func (rc *sectionReadCloser) Close() error {
	return rc.f.Close()
}
