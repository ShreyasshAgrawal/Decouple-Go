package archivedecouple

import (
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"decouple/internal/artifact"
	"decouple/internal/detect"
	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

type peHandler struct{}

func (h *peHandler) Format() artifact.Format { return artifact.FormatPE }

func (h *peHandler) Detect(header []byte, path string) bool {
	format, _ := detect.DetectBytes(header)
	return format == artifact.FormatPE
}

func (h *peHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pe: %w", err)
	}
	defer f.Close()

	if len(f.Sections) > cfg.EffectiveMaxPESections() {
		return nil, fmt.Errorf("pe exceeds max sections (%d)", cfg.EffectiveMaxPESections())
	}

	rep := &report.Report{
		Artifact: report.Artifact{
			InputPath: path,
			Kind:      kind,
		},
	}
	var maxSectionEnd uint64
	maxFileBytesToHash := cfg.EffectiveMaxFileBytesToHash()

	for _, s := range f.Sections {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		sectionName := strings.Trim(s.Name, "\x00 ")
		if sectionName == "" {
			sectionName = fmt.Sprintf("section_%d", len(rep.Nodes))
		}
		node := report.Node{
			Path:      "sections/" + sectionName,
			Type:      "file",
			SizeBytes: uint64(s.Size),
		}
		sectionEnd := uint64(s.Offset) + uint64(s.Size)
		if sectionEnd > maxSectionEnd {
			maxSectionEnd = sectionEnd
		}

		if uint64(s.Size) > maxFileBytesToHash {
			node.HashError = fmt.Sprintf("section too large to hash (%d bytes)", s.Size)
			rep.Stats.FilesSkipped++
		} else {
			sr := io.NewSectionReader(s, 0, int64(s.Size))
			h := sha256.New()
			n, err := io.Copy(h, sr)
			if err != nil {
				node.HashError = fmt.Sprintf("hash section: %v", err)
				rep.Stats.FilesSkipped++
			} else {
				hash := hex.EncodeToString(h.Sum(nil))
				node.SHA256 = &hash
				rep.Stats.BytesHashed += uint64(n)
			}
		}

		rep.Nodes = append(rep.Nodes, node)
	}

	st, err := os.Stat(path)
	if err == nil && maxSectionEnd < uint64(st.Size()) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		overlaySize := uint64(st.Size()) - maxSectionEnd
		if overlaySize > 0 {
			node := report.Node{
				Path:      "overlay",
				Type:      "file",
				SizeBytes: overlaySize,
			}
			if overlaySize > maxFileBytesToHash {
				node.HashError = fmt.Sprintf("overlay too large to hash (%d bytes)", overlaySize)
				rep.Stats.FilesSkipped++
			} else {
				fraw, err := os.Open(path)
				if err == nil {
					defer fraw.Close()
					sr := io.NewSectionReader(fraw, int64(maxSectionEnd), int64(overlaySize))
					h := sha256.New()
					n, err := io.Copy(h, sr)
					if err != nil {
						node.HashError = fmt.Sprintf("hash overlay: %v", err)
						rep.Stats.FilesSkipped++
					} else {
						hash := hex.EncodeToString(h.Sum(nil))
						node.SHA256 = &hash
						rep.Stats.BytesHashed += uint64(n)
					}
				} else {
					node.HashError = fmt.Sprintf("open overlay: %v", err)
					rep.Stats.FilesSkipped++
				}
			}
			rep.Nodes = append(rep.Nodes, node)
		}
	}

	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})
	updateStats(rep)
	return rep, nil
}

func (h *peHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var maxSectionEnd uint64
	for idx, section := range f.Sections {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		end := uint64(section.Offset) + uint64(section.Size)
		if end > maxSectionEnd {
			maxSectionEnd = end
		}

		sr := io.NewSectionReader(section, 0, int64(section.Size))
		header := make([]byte, 512)
		n, _ := sr.Read(header)
		if n < 2 {
			continue
		}

		if format, _ := detect.DetectBytes(header[:n]); format != artifact.FormatUnknown {
			name := strings.Trim(section.Name, "\x00 ")
			if name == "" {
				name = fmt.Sprintf("section_%d", idx)
			}
			open := func() (io.ReadCloser, error) {
				return io.NopCloser(io.NewSectionReader(section, 0, int64(section.Size))), nil
			}
			if err := fn("sections/"+name, uint64(section.Size), open); err != nil {
				return err
			}
		}
	}

	st, err := os.Stat(path)
	if err == nil && maxSectionEnd < uint64(st.Size()) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		overlaySize := uint64(st.Size()) - maxSectionEnd
		if overlaySize > 0 {
			fraw, err := os.Open(path)
			if err == nil {
				defer fraw.Close()
				sr := io.NewSectionReader(fraw, int64(maxSectionEnd), int64(overlaySize))
				header := make([]byte, 512)
				n, _ := sr.Read(header)
				if n >= 2 {
					if format, _ := detect.DetectBytes(header[:n]); format != artifact.FormatUnknown {
						open := func() (io.ReadCloser, error) {
							f2, err := os.Open(path)
							if err != nil {
								return nil, err
							}
							return struct {
								io.Reader
								io.Closer
							}{io.NewSectionReader(f2, int64(maxSectionEnd), int64(overlaySize)), f2}, nil
						}
						if err := fn("overlay", overlaySize, open); err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return nil
}
