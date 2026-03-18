# decouple v2

`decouple` is a Go-based artifact analysis tool with both:
- a CLI (`cmd/decouple`)
- an HTTP API (`cmd/api`)

It scans archive and binary artifacts and returns a structured JSON report containing discovered nodes, metadata, hashes, and scan stats.

## Version 2: What's new

Version 2 introduces significant enhancements for modern artifact analysis:
- **Disk Image Analysis (`.img`)**: Full support for partition table parsing (MBR/GPT) and filesystem traversal (ext4, FAT32) using `diskfs`.
- **OS Hinting**: Automatic detection of OS/Distribution information within disk images (e.g., `/etc/os-release`, Windows Registry hives).
- **Expanded Format Support**: Added PE binary family (`.exe`, `.dll`, `.sys`) and deep recursive inspection for nested archives.
- **Enhanced Safety**: Improved controls for recursion depth, maximum file sizes, and concurrent scanning limits.
- **Improved API**: More detailed analysis status and confidence levels.

## Supported inputs

- **Archive family**: `.zip`, `.jar`, `.war`, `.whl`, `.apk`, `.aab`, `.ipa`
- **Tar family**: `.tar`, `.tar.gz`, `.tgz`
- **Gzip**: `.gz`
- **PE family**: `.exe`, `.dll`, `.sys`
- **Disk images**: `.img` (partition and supported filesystem traversal)

Format detection uses magic bytes when extension-based detection is ambiguous.

## Key capabilities

- Recursive nested-archive scanning
- SHA-256 hashing for files (bounded by safety limits)
- Per-node metadata:
  - type, path, size, compressed size
  - mode and modified time (where available)
  - hash and nested-archive errors
- **New in v2**: Partition index, start/end offsets, and filesystem type for disk images.
- Safety controls to limit:
  - maximum files and bytes
  - recursion depth
  - nested archive count and temp-disk usage

## Quick start

### Prerequisites

- Go 1.25+

### Build

```bash
go build -o decouple ./cmd/decouple
go build -o decouple-api ./cmd/api
```

### Run CLI

```bash
./decouple --input /path/to/your-artifact.zip
```

### Run API

```bash
./decouple-api
```

Server starts on `:8080`.

- Analyze endpoint: `POST /analyze`
- Swagger UI: `GET /swagger/index.html`

## Example output shape

```json
{
  "artifact": {
    "input_path": "sample.img",
    "kind": "img",
    "os_hint": "Ubuntu 22.04 LTS",
    "analysis_status": {
      "confidence": "authoritative",
      "provider": "diskfs"
    }
  },
  "nodes": [
    {
      "path": "partition_1/etc/os-release",
      "type": "file",
      "size_bytes": 348,
      "sha256": "...",
      "filesystem_type": "Ext4",
      "partition_index": 1
    }
  ],
  "stats": {
    "total_nodes": 1,
    "files": 1,
    "dirs": 0,
    "symlinks": 0,
    "other": 0,
    "bytes_hashed": 348,
    "files_skipped": 0,
    "nested_archives_scanned": 0,
    "nested_errors": 0
  }
}
```

## Project layout

- `cmd/decouple`: CLI entrypoint
- `cmd/api`: Gin HTTP API + Swagger route
- `internal/archivedecouple`: format dispatch and nested scan orchestration
- `internal/artifact`: artifact type and path normalization
- `internal/detect`: magic-byte based format detection
- `internal/report`: report schema
- `internal/safety`: scan safety limits
- `internal/scanconfig`: scan configuration
- `docs/`: swagger artifacts

## Notes

- This repository currently focuses on static artifact introspection, not malware detection.
- `.img` analysis attempts partition parsing and filesystem traversal (including ext4 fallback); unsupported images fall back to partition/file metadata.
