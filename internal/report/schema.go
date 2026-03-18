package report

import (
	"time"
)

type Report struct {
	Artifact Artifact `json:"artifact"`
	Nodes    []Node   `json:"nodes"`
	Stats    Stats    `json:"stats"`
}

type Artifact struct {
	InputPath string          `json:"input_path"`
	Kind      string          `json:"kind"`
	OSHint    string          `json:"os_hint,omitempty"`
	Status    *AnalysisStatus `json:"analysis_status,omitempty"`
}

type AnalysisStatus struct {
	Confidence string `json:"confidence"` // authoritative, heuristic, unreadable
	Reason     string `json:"reason,omitempty"`
	Provider   string `json:"provider"`
}

type Node struct {
	Path                   string          `json:"path"`
	Type                   string          `json:"type"`
	SizeBytes              uint64          `json:"size_bytes,omitempty"`
	CompressedSizeBytes    uint64          `json:"compressed_size_bytes,omitempty"`
	ModifiedTime           *time.Time      `json:"modified_time,omitempty"`
	Mode                   *uint32         `json:"mode,omitempty"`
	SHA256                 *string         `json:"sha256,omitempty"`
	PathNormalizationError string          `json:"path_normalization_error,omitempty"`
	HashError              string          `json:"hash_error,omitempty"`
	NestedArchiveErrorCode string          `json:"nested_archive_error_code,omitempty"`
	NestedArchiveError     string          `json:"nested_archive_error,omitempty"`
	PartitionIndex         *int            `json:"partition_index,omitempty"`
	StartOffsetBytes       *uint64         `json:"start_offset_bytes,omitempty"`
	EndOffsetBytes         *uint64         `json:"end_offset_bytes,omitempty"`
	FilesystemType         string          `json:"filesystem_type,omitempty"`
	Status                 *AnalysisStatus `json:"analysis_status,omitempty"`
}

type Stats struct {
	TotalNodes            int    `json:"total_nodes"`
	Files                 int    `json:"files"`
	Dirs                  int    `json:"dirs"`
	Symlinks              int    `json:"symlinks"`
	Other                 int    `json:"other"`
	BytesHashed           uint64 `json:"bytes_hashed"`
	FilesSkipped          int    `json:"files_skipped"`
	NestedArchivesScanned int    `json:"nested_archives_scanned"`
	NestedErrors          int    `json:"nested_errors"`
}
