package pedecouple

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

type Config = scanconfig.Config

func DecouplePE(path string, kind string, cfg *scanconfig.Config) (*report.Report, error) {
	cfg = ensureConfig(cfg)

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

	for _, s := range f.Sections {
		sectionName := strings.Trim(s.Name, "\x00 ")
		node := report.Node{
			Path:      "sections/" + sectionName,
			Type:      "file",
			SizeBytes: uint64(s.Size),
		}

		data, err := s.Data()
		if err != nil {
			node.HashError = fmt.Sprintf("read section: %v", err)
			rep.Stats.FilesSkipped++
		} else {
			sum := sha256.Sum256(data)
			hash := hex.EncodeToString(sum[:])
			node.SHA256 = &hash
			rep.Stats.BytesHashed += uint64(len(data))
		}

		rep.Nodes = append(rep.Nodes, node)
	}

	sort.Slice(rep.Nodes, func(i, j int) bool {
		return rep.Nodes[i].Path < rep.Nodes[j].Path
	})
	rep.Stats.TotalNodes = len(rep.Nodes)
	rep.Stats.Files = len(rep.Nodes)
	return rep, nil
}

func ensureConfig(cfg *scanconfig.Config) *scanconfig.Config {
	if cfg == nil {
		return &scanconfig.Config{}
	}
	return cfg
}
