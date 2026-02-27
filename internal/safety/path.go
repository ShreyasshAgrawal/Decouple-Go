package safety

import (
	"fmt"
	"path"
	"strings"
)

func NormalizeZipPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty path")
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", fmt.Errorf("volume path not allowed: %q", name)
	}

	name = strings.ReplaceAll(name, "\\", "/")

	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("Absolute path not alowed")
	}

	cleaned := path.Clean(name)
	cleaned = strings.TrimPrefix(cleaned, "./")
	if cleaned == "." {
		return "", fmt.Errorf("invalid path")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path traversal not allowed")
	}
	return cleaned, nil
}
