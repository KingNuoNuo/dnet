package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyCountryDBRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(path, []byte("definitely not a maxmind database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCountryDB(path); err == nil {
		t.Fatal("损坏文件应该被拒绝")
	}
	if err := verifyCountryDB(filepath.Join(t.TempDir(), "missing.mmdb")); err == nil {
		t.Fatal("文件不存在应该被拒绝")
	}
}
