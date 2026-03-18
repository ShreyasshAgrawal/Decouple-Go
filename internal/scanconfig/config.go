package scanconfig

import "decouple/internal/safety"

// Config contains decouple limits. Zero values use safety defaults.
type Config struct {
	MaxFileBytesToHash    uint64
	MaxFiles              int
	MaxTotalBytes         uint64
	MaxPESections         int
	MaxIMGProbeBytes      uint64
	MaxIMGPartitions      int
	MaxIMGConcurrentScans int
	MaxDepth              int
	MaxNestedArchives     int
	MaxNestedBytes        uint64
	MaxTempDiskBytes      uint64
	MaxConcurrentScans    int
}

func (c *Config) EffectiveMaxFileBytesToHash() uint64 {
	if c != nil && c.MaxFileBytesToHash > 0 {
		return c.MaxFileBytesToHash
	}
	return safety.MaxFileBytesToHash
}

func (c *Config) EffectiveMaxFiles() int {
	if c != nil && c.MaxFiles > 0 {
		return c.MaxFiles
	}
	return safety.MaxFiles
}

func (c *Config) EffectiveMaxTotalBytes() uint64 {
	if c != nil && c.MaxTotalBytes > 0 {
		return c.MaxTotalBytes
	}
	return safety.MaxTotalBytes
}

func (c *Config) EffectiveMaxPESections() int {
	if c != nil && c.MaxPESections > 0 {
		return c.MaxPESections
	}
	return safety.MaxPESections
}

func (c *Config) EffectiveMaxIMGProbeBytes() uint64 {
	if c != nil && c.MaxIMGProbeBytes > 0 {
		return c.MaxIMGProbeBytes
	}
	return safety.MaxIMGProbeBytes
}

func (c *Config) EffectiveMaxIMGPartitions() int {
	if c != nil && c.MaxIMGPartitions > 0 {
		return c.MaxIMGPartitions
	}
	return safety.MaxIMGPartitions
}

func (c *Config) EffectiveMaxIMGConcurrentScans() int {
	if c != nil && c.MaxIMGConcurrentScans > 0 {
		return c.MaxIMGConcurrentScans
	}
	return safety.MaxIMGConcurrentScans
}

func (c *Config) EffectiveMaxDepth() int {
	if c != nil && c.MaxDepth > 0 {
		return c.MaxDepth
	}
	return safety.MaxDepth
}

func (c *Config) EffectiveMaxNestedArchives() int {
	if c != nil && c.MaxNestedArchives > 0 {
		return c.MaxNestedArchives
	}
	return safety.MaxNestedArchives
}

func (c *Config) EffectiveMaxNestedBytes() uint64 {
	if c != nil && c.MaxNestedBytes > 0 {
		return c.MaxNestedBytes
	}
	return safety.MaxNestedBytes
}

func (c *Config) EffectiveMaxTempDiskBytes() uint64 {
	if c != nil && c.MaxTempDiskBytes > 0 {
		return c.MaxTempDiskBytes
	}
	return safety.MaxTempDiskBytes
}

func (c *Config) EffectiveMaxConcurrentScans() int {
	if c != nil && c.MaxConcurrentScans > 0 {
		return c.MaxConcurrentScans
	}
	return safety.MaxConcurrentScans
}
