package artifact

import (
	"path/filepath"
	"strings"
)

type Format string

const (
	FormatZip     Format = "zip" // ZIP, JAR, WAR, WHL, APK, AAB, IPA
	FormatTar     Format = "tar" // TAR, TAR.GZ, etc. (future)
	FormatGzip    Format = "gz"  // Plain gzip stream (.gz)
	FormatIMG     Format = "img" // Disk image file (.img)
	FormatPE      Format = "pe"  // EXE/DLL/SYS
	FormatUnknown Format = ""
)

var ZipFamilyExtensions = map[string]string{
	".zip": "zip",
	".jar": "jar",
	".war": "war",
	".whl": "whl",
	".apk": "apk",
	".aab": "aab",
	".ipa": "ipa",
}

var TarFamilyExtensions = map[string]string{
	".tar": "tar",
}
var TarFamilyDoubleExtensions = map[string]string{
	".tar.gz": "tar.gz",
	".tgz":    "tar.gz",
}

var PEFamilyExtensions = map[string]string{
	".exe": "exe",
	".dll": "dll",
	".sys": "sys",
}

var GzipFamilyExtensions = map[string]string{
	".gz": "gz",
}

var ImgFamilyExtensions = map[string]string{
	".img": "img",
}

func KindFromPath(path string) string {
	lower := strings.ToLower(path)

	// Double extension checks FIRST (e.g. .tar.gz before .gz)
	for ext, k := range TarFamilyDoubleExtensions {
		if strings.HasSuffix(lower, ext) {
			return k
		}
	}

	// Single extension checks
	ext := strings.ToLower(filepath.Ext(path))
	if k, ok := TarFamilyExtensions[ext]; ok {
		return k
	}
	if k, ok := ZipFamilyExtensions[ext]; ok {
		return k
	}
	if k, ok := PEFamilyExtensions[ext]; ok {
		return k
	}
	if k, ok := GzipFamilyExtensions[ext]; ok {
		return k
	}
	if k, ok := ImgFamilyExtensions[ext]; ok {
		return k
	}
	return ""
}

func DefaultKindForFormat(format Format) (string, bool) {
	switch format {
	case FormatZip:
		return "zip", true
	case FormatTar:
		return "tar", true
	case FormatGzip:
		return "gz", true
	case FormatIMG:
		return "img", true
	case FormatPE:
		return "exe", true
	default:
		return "", false
	}
}
