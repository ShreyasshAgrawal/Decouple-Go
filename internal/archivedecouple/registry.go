package archivedecouple

import (
	"context"
	"io"
	"sync"

	"decouple/internal/artifact"
	"decouple/internal/report"
	"decouple/internal/scanconfig"
)

// Handler defines the interface for an artifact format handler.
type Handler interface {
	// Format returns the primary format this handler handles.
	Format() artifact.Format
	// Detect returns true if the header or path matches this format.
	Detect(header []byte, path string) bool
	// Decouple performs the initial non-recursive scan of the artifact.
	Decouple(ctx context.Context, path string, kind string, cfg *scanconfig.Config) (*report.Report, error)
	// WalkNested iterates over potential nested archives within the artifact.
	WalkNested(ctx context.Context, path string, fn func(entryPath string, size uint64, open func() (io.ReadCloser, error)) error) error
}

var (
	registryMu      sync.RWMutex
	handlers        []Handler
	once            sync.Once
)

// RegisterDefaults registers all built-in handlers in the correct priority order.
func RegisterDefaults() {
	once.Do(func() {
		// Specific handlers first
		Register(&tarHandler{})
		Register(&zipHandler{})
		Register(&peHandler{})
		Register(&imgHandler{})
		Register(&fatHandler{})
		// Generic fallback last
		Register(&gzipHandler{})
	})
}

// Register adds a handler to the global registry.
func Register(h Handler) {
	registryMu.Lock()
	defer registryMu.Unlock()
	handlers = append(handlers, h)
}

// FindHandler identifies the correct handler based on magic bytes and path.
func FindHandler(header []byte, path string) Handler {
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, h := range handlers {
		if h.Detect(header, path) {
			return h
		}
	}
	return nil
}

// AllHandlers returns all registered handlers.
func AllHandlers() []Handler {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return append([]Handler(nil), handlers...)
}
