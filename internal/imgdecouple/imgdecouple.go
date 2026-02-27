package imgdecouple

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

type Config = scanconfig.Config

const sectorSize uint64 = 512

type partition struct {
	index int
	start uint64
	end   uint64
}

func DecoupleIMG(path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)

	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open img: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat img: %w", err)
	}
	fileSize := uint64(st.Size())

	rep := &report.Report{
		Artifact: report.Artifact{
			InputPath: path,
			Kind:      kind,
		},
	}

	root := report.Node{
		Path:      "",
		Type:      "file",
		SizeBytes: fileSize,
	}

	maxHash := cfg.EffectiveMaxFileBytesToHash()
	if root.SizeBytes > maxHash {
		root.HashError = fmt.Sprintf("file too large to hash (%d bytes)", root.SizeBytes)
		rep.Stats.FilesSkipped++
	} else {
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, int64(maxHash)))
		if err != nil {
			root.HashError = fmt.Sprintf("read img: %v", err)
			rep.Stats.FilesSkipped++
		} else {
			sum := hex.EncodeToString(h.Sum(nil))
			root.SHA256 = &sum
			rep.Stats.BytesHashed += uint64(n)
		}
	}
	rep.Nodes = append(rep.Nodes, root)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek img: %w", err)
	}
	probeBytes, err := readProbe(f, fileSize, cfg.EffectiveMaxIMGProbeBytes())
	if err != nil {
		return nil, fmt.Errorf("read img probe: %w", err)
	}

	var parts []partition
	if isGPT(probeBytes) {
		parts = parseGPTPartitions(probeBytes, fileSize, cfg.EffectiveMaxIMGPartitions())
	} else if isMBR(probeBytes) {
		parts = parseMBRPartitions(probeBytes, fileSize)
		if len(parts) > cfg.EffectiveMaxIMGPartitions() {
			parts = parts[:cfg.EffectiveMaxIMGPartitions()]
		}
	}

	for _, p := range parts {
		idx := p.index
		start := p.start
		end := p.end
		node := report.Node{
			Path:           fmt.Sprintf("partitions/%d", p.index),
			Type:           "file",
			SizeBytes:      end - start + 1,
			PartitionIndex: &idx,
			StartOffsetBytes: func(v uint64) *uint64 {
				return &v
			}(start),
			EndOffsetBytes: func(v uint64) *uint64 {
				return &v
			}(end),
			FilesystemType: guessFilesystemType(f, fileSize, p.start),
		}
		rep.Nodes = append(rep.Nodes, node)
	}

	for i, g := range computeUnallocated(parts, fileSize) {
		idx := i + 1
		start := g.start
		end := g.end
		node := report.Node{
			Path:             fmt.Sprintf("unallocated/%d", idx),
			Type:             "file",
			SizeBytes:        end - start + 1,
			PartitionIndex:   &idx,
			StartOffsetBytes: &start,
			EndOffsetBytes:   &end,
			FilesystemType:   "Unallocated",
		}
		rep.Nodes = append(rep.Nodes, node)
	}

	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})

	for _, n := range rep.Nodes {
		if n.Type == "file" {
			rep.Stats.Files++
		}
	}
	rep.Stats.TotalNodes = len(rep.Nodes)
	return rep, nil
}

func readProbe(f *os.File, fileSize uint64, maxProbe uint64) ([]byte, error) {
	n := fileSize
	if maxProbe < n {
		n = maxProbe
	}
	buf := make([]byte, n)
	readN, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:readN], nil
}

func isMBR(b []byte) bool {
	return len(b) >= 512 && b[510] == 0x55 && b[511] == 0xAA
}

func isGPT(b []byte) bool {
	if len(b) < 1024 {
		return false
	}
	return string(b[512:520]) == "EFI PART"
}

func parseMBRPartitions(b []byte, fileSize uint64) []partition {
	if !isMBR(b) {
		return nil
	}
	out := make([]partition, 0, 4)
	for i := 0; i < 4; i++ {
		eoff := 446 + i*16
		if eoff+16 > len(b) {
			break
		}
		e := b[eoff : eoff+16]
		ptype := e[4]
		startLBA := binary.LittleEndian.Uint32(e[8:12])
		sectors := binary.LittleEndian.Uint32(e[12:16])
		if ptype == 0 || sectors == 0 {
			continue
		}
		start := uint64(startLBA) * sectorSize
		size := uint64(sectors) * sectorSize
		end := start + size - 1
		if start >= fileSize {
			continue
		}
		if end >= fileSize {
			end = fileSize - 1
		}
		out = append(out, partition{index: i + 1, start: start, end: end})
	}
	return out
}

func parseGPTPartitions(b []byte, fileSize uint64, maxParts int) []partition {
	if !isGPT(b) {
		return nil
	}
	h := b[512:]
	if len(h) < 92 {
		return nil
	}
	entriesLBA := binary.LittleEndian.Uint64(h[72:80])
	numEntries := binary.LittleEndian.Uint32(h[80:84])
	sizeEntry := binary.LittleEndian.Uint32(h[84:88])
	if sizeEntry == 0 || numEntries == 0 {
		return nil
	}
	if int(numEntries) > maxParts {
		numEntries = uint32(maxParts)
	}

	start := entriesLBA * sectorSize
	if start >= uint64(len(b)) {
		return nil
	}
	out := make([]partition, 0, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		off := start + uint64(i)*uint64(sizeEntry)
		if off+56 > uint64(len(b)) {
			break
		}
		e := b[off : off+uint64(sizeEntry)]
		if allZero(e[:16]) {
			continue
		}
		firstLBA := binary.LittleEndian.Uint64(e[32:40])
		lastLBA := binary.LittleEndian.Uint64(e[40:48])
		if lastLBA < firstLBA {
			continue
		}
		pstart := firstLBA * sectorSize
		pend := (lastLBA+1)*sectorSize - 1
		if pstart >= fileSize {
			continue
		}
		if pend >= fileSize {
			pend = fileSize - 1
		}
		out = append(out, partition{index: int(i) + 1, start: pstart, end: pend})
	}
	return out
}

func computeUnallocated(parts []partition, fileSize uint64) []partition {
	if fileSize == 0 {
		return nil
	}
	if len(parts) == 0 {
		return []partition{{index: 1, start: 0, end: fileSize - 1}}
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].start < parts[j].start
	})

	gaps := make([]partition, 0, len(parts)+1)
	cursor := uint64(0)
	for _, p := range parts {
		if p.start > cursor {
			gaps = append(gaps, partition{start: cursor, end: p.start - 1})
		}
		if p.end+1 > cursor {
			cursor = p.end + 1
		}
	}
	if cursor < fileSize {
		gaps = append(gaps, partition{start: cursor, end: fileSize - 1})
	}
	return gaps
}

func guessFilesystemType(f *os.File, fileSize uint64, start uint64) string {
	// FAT32 hint near partition start.
	if start+0x5A < fileSize {
		buf := make([]byte, 5)
		if _, err := f.ReadAt(buf, int64(start+0x52)); err == nil {
			if string(buf) == "FAT32" {
				return "FAT32"
			}
		}
	}
	// ext* hint at superblock magic.
	if start+1081 < fileSize {
		buf := make([]byte, 2)
		if _, err := f.ReadAt(buf, int64(start+1024+56)); err == nil {
			if buf[0] == 0x53 && buf[1] == 0xEF {
				return "Ext4"
			}
		}
	}
	return "Unknown"
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
