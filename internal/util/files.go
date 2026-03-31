package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func WriteFile(path string, data []byte) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ResolveOutputPath(base, ext string) (string, error) {
	base = strings.TrimSpace(base)
	ext = strings.TrimPrefix(strings.TrimSpace(ext), ".")
	if ext == "" {
		return "", fmt.Errorf("empty extension")
	}
	if base == "" {
		base = "./reports"
	}

	clean := filepath.Clean(base)
	if currentExt := strings.TrimPrefix(filepath.Ext(clean), "."); currentExt != "" {
		if err := EnsureDir(filepath.Dir(clean)); err != nil {
			return "", err
		}
		return clean, nil
	}

	if err := EnsureDir(clean); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("osint-report-%s.%s", time.Now().UTC().Format("20060102-150405"), ext)
	return filepath.Join(clean, filename), nil
}
