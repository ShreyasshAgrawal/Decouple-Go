package archivedecouple

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

func TestDecouplePath_MaxDepthBoundary(t *testing.T) {
	leafZip := buildZipBytes(t, map[string][]byte{
		"leaf.txt": []byte("leaf"),
	})
	middleZip := buildZipBytes(t, map[string][]byte{
		"inner.zip": leafZip,
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"middle.zip": middleZip,
	})
	defer os.Remove(outerZip)

	t.Run("exactly MaxDepth includes that level", func(t *testing.T) {
		rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
			MaxDepth:          1,
			MaxNestedArchives: 10,
			MaxNestedBytes:    20 * 1024 * 1024,
			MaxTempDiskBytes:  20 * 1024 * 1024,
		})
		if err != nil {
			t.Fatalf("DecouplePath: %v", err)
		}
		if findNodeByPath(rep, "middle.zip/inner.zip") == nil {
			t.Fatalf("expected node at depth=1 to be present")
		}
		if findNodeByPath(rep, "middle.zip/inner.zip/leaf.txt") != nil {
			t.Fatalf("unexpected node beyond MaxDepth")
		}
	})

	t.Run("one beyond MaxDepth is not recursed", func(t *testing.T) {
		rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
			MaxDepth:          2,
			MaxNestedArchives: 10,
			MaxNestedBytes:    20 * 1024 * 1024,
			MaxTempDiskBytes:  20 * 1024 * 1024,
		})
		if err != nil {
			t.Fatalf("DecouplePath: %v", err)
		}
		if findNodeByPath(rep, "middle.zip/inner.zip/leaf.txt") == nil {
			t.Fatalf("expected deeper node when MaxDepth=2")
		}
	})
}

func TestDecouplePath_MaxNestedArchivesLimit(t *testing.T) {
	nested := buildZipBytes(t, map[string][]byte{
		"a.txt": []byte("A"),
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"a.zip": nested,
		"b.zip": nested,
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 1,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	if rep.Stats.NestedArchivesScanned != 1 {
		t.Fatalf("NestedArchivesScanned = %d, want 1", rep.Stats.NestedArchivesScanned)
	}
	if countNodesWithErrorCode(rep, "max_nested_archives_exceeded") != 1 {
		t.Fatalf("expected exactly one node with max_nested_archives_exceeded")
	}
}

func TestDecouplePath_MaxNestedBytesLimit(t *testing.T) {
	outerZip := buildZipFile(t, map[string][]byte{
		"inner.zip": buildZipBytes(t, map[string][]byte{
			"tiny.txt": []byte("tiny"),
		}),
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    8, // force rejection
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	inner := findNodeByPath(rep, "inner.zip")
	if inner == nil {
		t.Fatalf("missing inner.zip node")
	}
	if inner.NestedArchiveErrorCode != "nested_archive_too_large" {
		t.Fatalf("NestedArchiveErrorCode = %q, want nested_archive_too_large", inner.NestedArchiveErrorCode)
	}
	if findNodeByPath(rep, "inner.zip/tiny.txt") != nil {
		t.Fatalf("unexpected nested child when max nested bytes is exceeded")
	}
}

func TestDecouplePath_MaxTempDiskBytesLimit(t *testing.T) {
	outerZip := buildZipFile(t, map[string][]byte{
		"inner.zip": buildZipBytes(t, map[string][]byte{
			"tiny.txt": []byte("tiny"),
		}),
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  16, // force rejection before write
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	inner := findNodeByPath(rep, "inner.zip")
	if inner == nil {
		t.Fatalf("missing inner.zip node")
	}
	if inner.NestedArchiveErrorCode != "max_temp_disk_bytes_exceeded" {
		t.Fatalf("NestedArchiveErrorCode = %q, want max_temp_disk_bytes_exceeded", inner.NestedArchiveErrorCode)
	}
}

func TestDecouplePath_MalformedNestedTar_SetsNodeError(t *testing.T) {
	malformedTar := buildMalformedTarBytes(t)
	outerZip := buildZipFile(t, map[string][]byte{
		"bad.tar": malformedTar,
		"ok.txt":  []byte("ok"),
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	bad := findNodeByPath(rep, "bad.tar")
	if bad == nil {
		t.Fatalf("missing bad.tar node")
	}
	if bad.NestedArchiveErrorCode == "" {
		t.Fatalf("expected nested error on malformed nested tar")
	}
	if !strings.HasPrefix(bad.NestedArchiveErrorCode, "nested_archive_") {
		t.Fatalf("unexpected nested error code %q", bad.NestedArchiveErrorCode)
	}
}

func TestDecouplePath_PathPrefixingAndMixedFormats_ZipZipTar(t *testing.T) {
	innerTar := buildTarBytes(t, map[string][]byte{
		"./inner.txt": []byte("hello"),
	})
	middleZip := buildZipBytes(t, map[string][]byte{
		"inner.tar": innerTar,
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"dir/middle.zip": middleZip,
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          4,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	expected := "dir/middle.zip/inner.tar/inner.txt"
	if findNodeByPath(rep, expected) == nil {
		t.Fatalf("missing expected deeply-prefixed node %q", expected)
	}
	for _, n := range rep.Nodes {
		if strings.Contains(n.Path, "//") {
			t.Fatalf("path contains double slash: %q", n.Path)
		}
		if strings.HasPrefix(n.Path, "/") {
			t.Fatalf("path unexpectedly has leading slash: %q", n.Path)
		}
		if strings.Contains(n.Path, "../") {
			t.Fatalf("path unexpectedly contains parent traversal: %q", n.Path)
		}
	}
}

func TestDecouplePath_HappyPath_ZipContainsTarGzContainsFile(t *testing.T) {
	innerTarGz := buildTarGzBytes(t, map[string][]byte{
		"file.txt": []byte("hello"),
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"inner.tar.gz": innerTarGz,
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	if findNodeByPath(rep, "inner.tar.gz/file.txt") == nil {
		t.Fatalf("missing expected node %q", "inner.tar.gz/file.txt")
	}
}

func TestDecouplePath_MixedFormats_ZipInsideTarGzInsideZip(t *testing.T) {
	innerZip := buildZipBytes(t, map[string][]byte{
		"file.txt": []byte("hello"),
	})
	middleTarGz := buildTarGzBytes(t, map[string][]byte{
		"inner.zip": innerZip,
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"middle.tar.gz": middleTarGz,
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          4,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	expected := "middle.tar.gz/inner.zip/file.txt"
	if findNodeByPath(rep, expected) == nil {
		t.Fatalf("missing expected mixed-format node %q", expected)
	}
}

func TestDecouplePath_MaxDepthExceeded_SetsNodeErrorAndSkipsLeaf(t *testing.T) {
	leafZip := buildZipBytes(t, map[string][]byte{
		"file.txt": []byte("hello"),
	})
	innerTarGz := buildTarGzBytes(t, map[string][]byte{
		"inner.zip": leafZip,
	})
	outerZip := buildZipFile(t, map[string][]byte{
		"inner.tar.gz": innerTarGz,
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{
		MaxDepth:          1,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	if findNodeByPath(rep, "inner.tar.gz/inner.tar/inner.zip/file.txt") != nil {
		t.Fatalf("unexpected leaf file when max depth exceeded")
	}
}

func TestDecouplePath_TarContainsGzip_RecursesPayload(t *testing.T) {
	innerGz := buildGzipBytes(t, "file.txt", []byte("hello-gzip"))
	outerTar := buildTarFile(t, map[string][]byte{
		"inner.gz": innerGz,
	})
	defer os.Remove(outerTar)

	rep, err := DecouplePath(context.Background(), outerTar, "", "tar", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	if findNodeByPath(rep, "inner.gz/file.txt") == nil {
		t.Fatalf("missing gzip payload node under nested prefix")
	}
}

func TestDecouplePath_GzipPayloadArchive_RecursesFurther(t *testing.T) {
	innerZip := buildZipBytes(t, map[string][]byte{
		"leaf.txt": []byte("leaf"),
	})
	innerGz := buildGzipBytes(t, "inner.zip", innerZip)
	outerTar := buildTarFile(t, map[string][]byte{
		"inner.gz": innerGz,
	})
	defer os.Remove(outerTar)

	rep, err := DecouplePath(context.Background(), outerTar, "", "tar", &scanconfig.Config{
		MaxDepth:          4,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	if findNodeByPath(rep, "inner.gz/inner.zip/leaf.txt") == nil {
		t.Fatalf("missing recursively discovered leaf inside gzip payload archive")
	}
}

func TestDecouplePath_GzipNoEmbeddedName_UsesDeterministicFallbackPath(t *testing.T) {
	innerZip := buildZipBytes(t, map[string][]byte{
		"leaf.txt": []byte("leaf"),
	})
	innerGzNoName := buildGzipBytesNoName(t, innerZip)
	outerTar := buildTarFile(t, map[string][]byte{
		"inner.gz": innerGzNoName,
	})
	defer os.Remove(outerTar)

	rep, err := DecouplePath(context.Background(), outerTar, "", "tar", &scanconfig.Config{
		MaxDepth:          4,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	expected := "inner.gz/payload/leaf.txt"
	if findNodeByPath(rep, expected) == nil {
		t.Fatalf("missing fallback-path nested node %q", expected)
	}
}

func TestDecouplePath_IMGTopLevel_UsesDisplayNameFallback(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(imgPath, []byte("img-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := DecouplePath(context.Background(), imgPath, "", "img", &scanconfig.Config{})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	if findNodeByPath(rep, "disk.img") == nil {
		t.Fatalf("expected top-level img node path to use base filename")
	}
	if rep.Artifact.Status == nil {
		t.Fatalf("expected artifact analysis_status")
	}
	if rep.Artifact.Status.Provider != "internal_magic" {
		t.Fatalf("artifact analysis_status.provider = %q, want internal_magic", rep.Artifact.Status.Provider)
	}
}

func TestDecouplePath_IMGFilesystemParseFailure_SetsExplicitUnreadableStatus(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "disk.img")
	imgBytes := make([]byte, 4096)
	// LUKS header magic: LUKS + 0xBA 0xBE
	copy(imgBytes[:6], []byte{'L', 'U', 'K', 'S', 0xBA, 0xBE})
	if err := os.WriteFile(imgPath, imgBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := DecouplePath(context.Background(), imgPath, "", "img", &scanconfig.Config{})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	node := findNodeByPath(rep, "disk.img")
	if node == nil {
		t.Fatalf("expected top-level img node")
	}
	if node.HashError == "" {
		t.Fatalf("expected hash_error describing filesystem parse failure")
	}
	if !strings.Contains(node.HashError, "filesystem parse failed") {
		t.Fatalf("unexpected hash_error: %q", node.HashError)
	}
	if node.Status == nil {
		t.Fatalf("expected node analysis_status")
	}
	if node.Status.Confidence != "unreadable" {
		t.Fatalf("analysis_status.confidence = %q, want unreadable", node.Status.Confidence)
	}
	if node.Status.Reason != "LUKS_ENCRYPTED" {
		t.Fatalf("analysis_status.reason = %q, want LUKS_ENCRYPTED", node.Status.Reason)
	}
	if node.Status.Provider != "internal_magic" {
		t.Fatalf("analysis_status.provider = %q, want internal_magic", node.Status.Provider)
	}
}

func TestDecouplePath_IMGLVMPartition_SetsUnsupportedLVMReason(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "disk.img")
	imgBytes := make([]byte, 8192)
	copy(imgBytes[512:520], []byte("LABELONE"))
	if err := os.WriteFile(imgPath, imgBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := DecouplePath(context.Background(), imgPath, "", "img", &scanconfig.Config{})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	node := findNodeByPath(rep, "disk.img")
	if node == nil {
		t.Fatalf("expected top-level img node")
	}
	if node.Status == nil {
		t.Fatalf("expected node analysis_status")
	}
	if node.Status.Reason != "UNSUPPORTED_LVM_CONTAINER" {
		t.Fatalf("analysis_status.reason = %q, want UNSUPPORTED_LVM_CONTAINER", node.Status.Reason)
	}
}

func TestIMGUnreadableStatusForError_MapsCorruptFilesystemReason(t *testing.T) {
	h := &imgHandler{}
	status := h.unreadableStatusForError(nil, errors.New("invalid superblock checksum"))
	if status == nil {
		t.Fatalf("expected status")
	}
	if status.Reason != "CORRUPT_FILESYSTEM" {
		t.Fatalf("reason = %q, want CORRUPT_FILESYSTEM", status.Reason)
	}
}

func TestDecouplePath_ZipContainsIMG_NodePathContract(t *testing.T) {
	outerZip := buildZipFile(t, map[string][]byte{
		"firmware.img": []byte("img"),
	})
	defer os.Remove(outerZip)

	rep, err := DecouplePath(context.Background(), outerZip, "", "zip", &scanconfig.Config{})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}
	if findNodeByPath(rep, "firmware.img") == nil {
		t.Fatalf("expected nested img node path")
	}
}

func TestDecouplePath_PEWithOverlayZip_Recurses(t *testing.T) {
	overlayZip := buildZipBytes(t, map[string][]byte{
		"nested.txt": []byte("hello-from-overlay"),
	})
	pePath := buildTestPEWithOverlay(t, overlayZip)
	defer os.Remove(pePath)

	rep, err := DecouplePath(context.Background(), pePath, "", "exe", &scanconfig.Config{
		MaxDepth:          3,
		MaxNestedArchives: 10,
		MaxNestedBytes:    20 * 1024 * 1024,
		MaxTempDiskBytes:  20 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("DecouplePath: %v", err)
	}

	if findNodeByPath(rep, "overlay") == nil {
		t.Fatalf("missing overlay node for pe")
	}
	if findNodeByPath(rep, "overlay/nested.txt") == nil {
		t.Fatalf("missing nested file discovered from pe overlay zip")
	}
}

func buildZipFile(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "outer-*.zip")
	if err != nil {
		t.Fatalf("create temp zip: %v", err)
	}
	path := tmp.Name()
	if err := writeZipToFile(tmp, entries); err != nil {
		_ = tmp.Close()
		t.Fatalf("write zip: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}
	return path
}

func buildTarFile(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "outer-*.tar")
	if err != nil {
		t.Fatalf("create temp tar: %v", err)
	}
	path := tmp.Name()

	tw := tar.NewWriter(tmp)
	for _, name := range mapKeys(entries) {
		content := entries[name]
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = tmp.Close()
			t.Fatalf("write tar header %q: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			_ = tw.Close()
			_ = tmp.Close()
			t.Fatalf("write tar content %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = tmp.Close()
		t.Fatalf("close tar writer: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close tar file: %v", err)
	}
	return path
}

func buildZipBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	keys := mapKeys(entries)
	for _, k := range keys {
		w, err := zw.Create(k)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", k, err)
		}
		if _, err := w.Write(entries[k]); err != nil {
			t.Fatalf("write zip entry %q: %v", k, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func writeZipToFile(f *os.File, entries map[string][]byte) error {
	zw := zip.NewWriter(f)
	keys := mapKeys(entries)
	for _, k := range keys {
		w, err := zw.Create(k)
		if err != nil {
			return err
		}
		if _, err := w.Write(entries[k]); err != nil {
			return err
		}
	}
	return zw.Close()
}

func buildTarBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	keys := mapKeys(entries)
	for _, name := range keys {
		content := entries[name]
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %q: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write tar content %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}

func buildTarGzBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	tarBytes := buildTarBytes(t, entries)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(tarBytes); err != nil {
		t.Fatalf("write gzip content: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildGzipBytes(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = name
	if _, err := zw.Write(content); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildGzipBytesNoName(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(content); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildMalformedTarBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "bad.txt",
		Mode: 0o644,
		Size: 128, // claims body bytes that won't be written
	}); err != nil {
		t.Fatalf("write malformed tar header: %v", err)
	}
	// Intentionally do not write body and do not close tar writer.
	return buf.Bytes()
}

func buildTestPEWithOverlay(t *testing.T, overlay []byte) string {
	t.Helper()

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	exePath := filepath.Join(tmpDir, "sample.exe")

	src := "package main\nfunc main(){}\n"
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", exePath, srcPath)
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build test pe: %v\n%s", err, string(out))
	}

	f, err := os.OpenFile(exePath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open pe for append: %v", err)
	}
	if _, err := f.Write(overlay); err != nil {
		_ = f.Close()
		t.Fatalf("append overlay zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close appended pe: %v", err)
	}

	return exePath
}

func mapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func countNodesWithErrorCode(rep *report.Report, code string) int {
	count := 0
	for _, n := range rep.Nodes {
		if n.NestedArchiveErrorCode == code {
			count++
		}
	}
	return count
}

func findNodeByPath(rep *report.Report, path string) *report.Node {
	for i := range rep.Nodes {
		if rep.Nodes[i].Path == path || strings.HasSuffix(rep.Nodes[i].Path, "/"+path) {
			return &rep.Nodes[i]
		}
	}
	return nil
}
