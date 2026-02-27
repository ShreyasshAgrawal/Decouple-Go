# decouple

`decouple` is a Go-based artifact analysis tool with both:
- a CLI (`cmd/decouple`)
- an HTTP API (`cmd/api`)

It scans archive and binary artifacts and returns a structured JSON report containing discovered nodes, metadata, hashes, and scan stats.

## Why this project exists

Build and release artifacts are often nested and heterogeneous. `decouple` provides a single scanner that can:
- normalize paths safely
- recursively inspect nested archives with depth and size guards
- emit deterministic JSON for downstream tooling

## Supported inputs

- Archive family: `.zip`, `.jar`, `.war`, `.whl`, `.apk`, `.aab`, `.ipa`
- Tar family: `.tar`, `.tar.gz`, `.tgz`
- Gzip: `.gz`
- PE family: `.exe`, `.dll`, `.sys`
- Disk images: `.img` (metadata-only partition reporting)

Format detection uses magic bytes when extension-based detection is ambiguous.

## Key capabilities

- Recursive nested-archive scanning
- SHA-256 hashing for files (bounded by safety limits)
- Per-node metadata:
  - type, path, size, compressed size
  - mode and modified time (where available)
  - hash and nested-archive errors
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

Write JSON to file:

```bash
./decouple --input /path/to/your-artifact.tar.gz --output report.json
```

### Run API

```bash
./decouple-api
```

Server starts on `:8080`.

- Analyze endpoint: `POST /analyze` (`multipart/form-data`, field name: `file`)
- Swagger UI: `GET /swagger/index.html`

Example:

```bash
curl -s -X POST http://localhost:8080/analyze \
  -F "file=@/path/to/your-artifact.zip"
```

## Test

```bash
GOCACHE=$(pwd)/.gocache go test ./...
```

## Example output shape

```json
{
  "artifact": {
    "input_path": "sample.zip",
    "kind": "archive"
  },
  "nodes": [
    {
      "path": "sub/a.txt",
      "type": "file",
      "size_bytes": 5,
      "sha256": "..."
    }
  ],
  "stats": {
    "total_nodes": 1,
    "files": 1,
    "dirs": 0,
    "symlinks": 0,
    "other": 0,
    "bytes_hashed": 5,
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
- `internal/*decouple`: format-specific scanners (zip, tar, gzip, pe, img)
- `internal/report`: report schema
- `internal/safety`: scan safety limits
- `docs/`: swagger artifacts

## Notes

- This repository currently focuses on static artifact introspection, not malware detection.
- `.img` analysis currently reports partition metadata only and does not perform filesystem extraction.
