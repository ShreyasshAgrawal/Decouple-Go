package safety

// MaxFileBytesToHash is the maximum uncompressed size (bytes) we will stream for SHA-256.
// Larger files are skipped to avoid zip bombs and long runtimes.
const MaxFileBytesToHash uint64 = 256 * 1024 * 1024 // 256 MiB

// MaxFiles is the maximum number of entries allowed in an archive (zip bomb protection).
const MaxFiles int = 1_000_000

// MaxTotalBytes is the maximum total uncompressed bytes to process (zip bomb protection).
const MaxTotalBytes uint64 = 10 * 1024 * 1024 * 1024 // 10 GiB

// MaxDepth is the maximum recursion depth for nested archives.
const MaxDepth int = 3

// MaxNestedArchives is the maximum number of nested archives processed per request.
const MaxNestedArchives int = 1_000

// MaxNestedBytes is the maximum uncompressed size of a nested archive candidate file.
const MaxNestedBytes uint64 = 8 * 1024 * 1024 * 1024 // 8 GiB

// MaxTempDiskBytes is the maximum cumulative bytes written to temp files for nested scanning.
const MaxTempDiskBytes uint64 = 16 * 1024 * 1024 * 1024 // 16 GiB

// MaxPESections is the maximum number of PE sections to parse.
const MaxPESections int = 96

// MaxIMGProbeBytes is the maximum number of leading bytes read from .img for partition-table parsing.
const MaxIMGProbeBytes uint64 = 4 * 1024 * 1024 // 4 MiB

// MaxIMGPartitions is the maximum number of partition nodes emitted for .img metadata parsing.
const MaxIMGPartitions int = 256

// MaxIMGConcurrentScans is the maximum parallel hashing workers within IMG filesystem traversal.
// Kept lower than MaxConcurrentScans to reduce random I/O thrash on large disk images.
const MaxIMGConcurrentScans int = 4

// MaxConcurrentScans is the maximum number of parallel goroutines for hashing and nested scanning.
const MaxConcurrentScans int = 16
