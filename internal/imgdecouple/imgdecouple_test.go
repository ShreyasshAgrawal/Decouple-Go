package imgdecouple

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

func TestDecoupleIMG_Basic(t *testing.T) {
	tmp, err := os.CreateTemp("", "sample-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	payload := []byte("img payload")
	if _, err := tmp.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := DecoupleIMG(tmp.Name(), "img", nil)
	if err != nil {
		t.Fatalf("DecoupleIMG: %v", err)
	}
	if rep.Artifact.Kind != "img" {
		t.Fatalf("artifact kind = %q, want img", rep.Artifact.Kind)
	}
	if rep.Artifact.InputPath != tmp.Name() {
		t.Fatalf("artifact input path = %q, want %q", rep.Artifact.InputPath, tmp.Name())
	}
	if len(rep.Nodes) < 1 {
		t.Fatalf("nodes len = %d, want >= 1", len(rep.Nodes))
	}
	if rep.Nodes[0].Type != "file" {
		t.Fatalf("node type = %q, want file", rep.Nodes[0].Type)
	}
	if rep.Nodes[0].SizeBytes != uint64(len(payload)) {
		t.Fatalf("node size = %d, want %d", rep.Nodes[0].SizeBytes, len(payload))
	}
	if rep.Nodes[0].SHA256 == nil {
		t.Fatalf("expected SHA256")
	}
	if findNodeByPath(rep, "unallocated/1") == nil {
		t.Fatalf("expected unallocated node for img with no partition table entries")
	}
}

func TestDecoupleIMG_PathDoesNotLeakToNodePath(t *testing.T) {
	tmpPath := filepath.Join(t.TempDir(), "x.img")
	if err := os.WriteFile(tmpPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := DecoupleIMG(tmpPath, "img", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nodes[0].Path != "" {
		t.Fatalf("node path = %q, want empty relative path", rep.Nodes[0].Path)
	}
}

func TestDecoupleIMG_RespectsHashLimit(t *testing.T) {
	tmpPath := filepath.Join(t.TempDir(), "big.img")
	payload := []byte("0123456789")
	if err := os.WriteFile(tmpPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := DecoupleIMG(tmpPath, "img", &scanconfig.Config{
		MaxFileBytesToHash: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stats.FilesSkipped != 1 {
		t.Fatalf("FilesSkipped = %d, want 1", rep.Stats.FilesSkipped)
	}
	if rep.Nodes[0].HashError == "" {
		t.Fatalf("expected hash_error for over-limit img")
	}
	if rep.Nodes[0].SHA256 != nil {
		t.Fatalf("did not expect sha256 when hashing is skipped")
	}
}

func TestDecoupleIMG_MBRPartitionsAndUnallocated(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "disk.img")
	size := 16 * 1024 * 1024
	buf := make([]byte, size)

	// MBR signature
	buf[510] = 0x55
	buf[511] = 0xAA

	// Partition 1: FAT32, start LBA 2048, sectors 1024
	p1 := 446
	buf[p1+4] = 0x0C
	binary.LittleEndian.PutUint32(buf[p1+8:p1+12], 2048)
	binary.LittleEndian.PutUint32(buf[p1+12:p1+16], 1024)
	// FAT32 marker at start+0x52
	copy(buf[2048*512+0x52:], []byte("FAT32"))

	// Partition 2: Linux, start LBA 4096, sectors 1024
	p2 := 446 + 16
	buf[p2+4] = 0x83
	binary.LittleEndian.PutUint32(buf[p2+8:p2+12], 4096)
	binary.LittleEndian.PutUint32(buf[p2+12:p2+16], 1024)
	// Ext marker at start+1024+56
	extOff := 4096*512 + 1024 + 56
	buf[extOff] = 0x53
	buf[extOff+1] = 0xEF

	if err := os.WriteFile(imgPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := DecoupleIMG(imgPath, "img", &scanconfig.Config{
		MaxIMGProbeBytes: 4 * 1024 * 1024,
		MaxIMGPartitions: 16,
	})
	if err != nil {
		t.Fatalf("DecoupleIMG: %v", err)
	}

	if findNodeByPath(rep, "partitions/1") == nil {
		t.Fatalf("missing partitions/1")
	}
	if findNodeByPath(rep, "partitions/2") == nil {
		t.Fatalf("missing partitions/2")
	}
	if findNodeByPath(rep, "unallocated/1") == nil {
		t.Fatalf("expected at least one unallocated node")
	}

	p1Node := findNodeByPath(rep, "partitions/1")
	if p1Node == nil || p1Node.FilesystemType != "FAT32" {
		t.Fatalf("partition 1 fs type = %q, want FAT32", p1Node.FilesystemType)
	}
	p2Node := findNodeByPath(rep, "partitions/2")
	if p2Node == nil || p2Node.FilesystemType != "Ext4" {
		t.Fatalf("partition 2 fs type = %q, want Ext4", p2Node.FilesystemType)
	}
}

func findNodeByPath(rep *report.Report, path string) *report.Node {
	for i := range rep.Nodes {
		if rep.Nodes[i].Path == path {
			return &rep.Nodes[i]
		}
	}
	return nil
}
