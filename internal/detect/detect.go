package detect

import (
	"fmt"
	"os"

	"decouple/internal/artifact"
)

// ZIP magic bytes: PK (0x50 0x4B) at start
var zipMagic = []byte{0x50, 0x4B}

// Gzip magic: 1f 8b at start (tar.gz, tgz)
var gzipMagic = []byte{0x1f, 0x8b}

// TAR ustar magic at offset 257 (5 bytes)
var tarMagic = []byte("ustar")

// PE magic: MZ at offset 0
var peMagic = []byte{0x4D, 0x5A}

// Detect reads the file header and returns the format. Does not rely on extension.
// Check order: gzip first (2 bytes, fastest), then zip, then PE, then plain tar (512 bytes).
func Detect(path string) (artifact.Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return artifact.FormatUnknown, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// Read at least 2 bytes for gzip/zip; may need 512 for tar
	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil {
		return artifact.FormatUnknown, fmt.Errorf("read header: %w", err)
	}
	format, err := DetectBytes(header[:n])
	if err == nil {
		return format, nil
	}
	if artifact.KindFromPath(path) == "img" {
		return artifact.FormatIMG, nil
	}
	return artifact.FormatUnknown, err
}

func DetectBytes(header []byte) (artifact.Format, error) {
	n := len(header)
	if n < 2 {
		return artifact.FormatUnknown, fmt.Errorf("file too small to detect format")
	}
	// 1. Gzip magic first (only 2 bytes, fastest)
	if n >= 2 && header[0] == gzipMagic[0] && header[1] == gzipMagic[1] {
		return artifact.FormatGzip, nil
	}

	// 2. ZIP magic
	if n >= 2 && header[0] == zipMagic[0] && header[1] == zipMagic[1] {
		return artifact.FormatZip, nil
	}

	// 3. Plain TAR: ustar at offset 257 (needs 262 bytes minimum)
	if n >= 262 && string(header[257:262]) == string(tarMagic) {
		return artifact.FormatTar, nil
	}

	// 4. PE: MZ at offset 0
	if n >= 2 && header[0] == peMagic[0] && header[1] == peMagic[1] {
		return artifact.FormatPE, nil
	}

	// 5. IMG (MBR or GPT)
	if n >= 512 && header[510] == 0x55 && header[511] == 0xAA {
		return artifact.FormatIMG, nil
	}
	if n >= 520 && string(header[512:520]) == "EFI PART" {
		return artifact.FormatIMG, nil
	}

	// 6. Raw Filesystem Images (detect as IMG for handler processing)
	// Ext4 superblock at 1024 offset: 0x53 0xEF at byte 56
	if n >= 1024+58 && header[1024+56] == 0x53 && header[1024+57] == 0xEF {
		return artifact.FormatIMG, nil
	}
	// FAT32 signature at offset 0x52
	if n >= 0x52+5 && string(header[0x52:0x52+5]) == "FAT32" {
		return artifact.FormatIMG, nil
	}

	return artifact.FormatUnknown, fmt.Errorf("unsupported format: unknown magic bytes")
}
