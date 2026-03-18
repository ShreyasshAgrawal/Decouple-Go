package archivedecouple

import (
	"context"
	"decouple/internal/artifact"
	"decouple/internal/report"
	"decouple/internal/scanconfig"
	"io"
)

type fatHandler struct{}

func (h *fatHandler) Format() artifact.Format { return "fat32" }

func (h *fatHandler) Detect(header []byte, path string) bool {
	if len(header) < 512 {
		return false
	}
	return string(header[0x52:0x57]) == "FAT32"
}

func (h *fatHandler) Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	rep := &report.Report{
		Artifact: report.Artifact{InputPath: path, Kind: "fat32"},
	}
	updateStats(rep)
	return rep, nil
}

func (h *fatHandler) WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error {
	return nil
}
