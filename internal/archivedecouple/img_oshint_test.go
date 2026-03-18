package archivedecouple

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"decouple/internal/report"

	"github.com/diskfs/go-diskfs/filesystem"
)

func TestIMGSniffOSHint_LinuxPrettyName(t *testing.T) {
	h := &imgHandler{}
	rep := &report.Report{}
	fs := newFakeFS(map[string][]byte{
		"/etc/os-release": []byte("PRETTY_NAME=\"Ubuntu 22.04.6 LTS\"\n"),
	})

	h.sniffOSHint(context.Background(), fs, "/etc/os-release", rep)
	if rep.Artifact.OSHint != "Ubuntu 22.04.6 LTS" {
		t.Fatalf("os_hint = %q, want Ubuntu 22.04.6 LTS", rep.Artifact.OSHint)
	}
}

func TestIMGSniffOSHint_LinuxNameVersionFallback(t *testing.T) {
	h := &imgHandler{}
	rep := &report.Report{}
	fs := newFakeFS(map[string][]byte{
		"/usr/lib/os-release": []byte("NAME=Debian GNU/Linux\nVERSION=12 (bookworm)\n"),
	})

	h.sniffOSHint(context.Background(), fs, "/usr/lib/os-release", rep)
	if rep.Artifact.OSHint != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("os_hint = %q, want Debian GNU/Linux 12 (bookworm)", rep.Artifact.OSHint)
	}
}

func TestIMGSniffOSHint_WindowsMarker(t *testing.T) {
	h := &imgHandler{}
	rep := &report.Report{}
	fs := newFakeFS(nil)

	h.sniffOSHint(context.Background(), fs, "/Windows/System32/config/SOFTWARE", rep)
	if rep.Artifact.OSHint != "Windows (registry hive detected)" {
		t.Fatalf("os_hint = %q, want Windows marker hint", rep.Artifact.OSHint)
	}
}

func TestIMGSniffOSHint_NoKnownMarker(t *testing.T) {
	h := &imgHandler{}
	rep := &report.Report{}
	fs := newFakeFS(map[string][]byte{
		"/random/file.txt": []byte("hello"),
	})

	h.sniffOSHint(context.Background(), fs, "/random/file.txt", rep)
	if rep.Artifact.OSHint != "" {
		t.Fatalf("os_hint = %q, want empty", rep.Artifact.OSHint)
	}
}

func TestShouldCheckOSHintPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/etc/os-release", want: true},
		{path: "/usr/lib/os-release", want: true},
		{path: "/Windows/System32/config/SOFTWARE", want: true},
		{path: "\\Windows\\System32\\config\\SOFTWARE", want: true},
		{path: "/var/log/messages", want: false},
		{path: "/home/user/data.txt", want: false},
	}
	for _, tt := range tests {
		if got := shouldCheckOSHintPath(tt.path); got != tt.want {
			t.Fatalf("shouldCheckOSHintPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

type fakeFS struct {
	files map[string][]byte
}

func newFakeFS(files map[string][]byte) *fakeFS {
	if files == nil {
		files = map[string][]byte{}
	}
	return &fakeFS{files: files}
}

func (f *fakeFS) Type() filesystem.Type       { return filesystem.TypeFat32 }
func (f *fakeFS) Mkdir(pathname string) error { return errors.New("not implemented") }
func (f *fakeFS) Mknod(pathname string, mode uint32, dev int) error {
	return errors.New("not implemented")
}
func (f *fakeFS) Link(oldpath, newpath string) error        { return errors.New("not implemented") }
func (f *fakeFS) Symlink(oldpath, newpath string) error     { return errors.New("not implemented") }
func (f *fakeFS) Chmod(name string, mode os.FileMode) error { return errors.New("not implemented") }
func (f *fakeFS) Chown(name string, uid, gid int) error     { return errors.New("not implemented") }
func (f *fakeFS) ReadDir(pathname string) ([]os.FileInfo, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeFS) Rename(oldpath, newpath string) error { return errors.New("not implemented") }
func (f *fakeFS) Remove(pathname string) error         { return errors.New("not implemented") }
func (f *fakeFS) Label() string                        { return "" }
func (f *fakeFS) SetLabel(label string) error          { return errors.New("not implemented") }
func (f *fakeFS) Close() error                         { return nil }
func (f *fakeFS) OpenFile(pathname string, flag int) (filesystem.File, error) {
	b, ok := f.files[filepathClean(pathname)]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &fakeFile{Reader: bytes.NewReader(b)}, nil
}

type fakeFile struct {
	*bytes.Reader
}

func (f *fakeFile) Write(p []byte) (int, error) {
	return 0, errors.New("read-only")
}

func (f *fakeFile) Close() error { return nil }

func filepathClean(p string) string {
	if p == "" {
		return "/"
	}
	clean := filepath.Clean(p)
	if clean == "." {
		return "/"
	}
	if clean[0] != '/' {
		clean = "/" + clean
	}
	return clean
}

var _ filesystem.FileSystem = (*fakeFS)(nil)
var _ filesystem.File = (*fakeFile)(nil)
var _ io.ReadWriteSeeker = (*fakeFile)(nil)
