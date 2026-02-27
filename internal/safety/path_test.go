package safety

import (
	"testing"
)

func TestNormalizeZipPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"absolute path rejected", "/etc/passwd", "", true},
		{"path traversal rejected", "../evil", "", true},
		{"path traversal prefix rejected", "../../etc/passwd", "", true},
		{"single dot invalid", ".", "", true},
		{"windows volume path rejected", "C:\\windows", "", true},
		{"valid file", "a.txt", "a.txt", false},
		{"valid nested", "foo/bar/baz.txt", "foo/bar/baz.txt", false},
		{"backslash normalized", "foo\\bar\\baz.txt", "foo/bar/baz.txt", false},
		{"leading dot slash", "./a.txt", "a.txt", false},
		{"double slash cleaned", "foo//bar", "foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeZipPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeZipPath(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("NormalizeZipPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}

}
