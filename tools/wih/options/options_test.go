package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wih/util"
)

func TestOptionsCSVDefaultsToResultFile(t *testing.T) {
	tempDir := t.TempDir()
	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd failed: %v", err)
	}
	previousArgs := os.Args
	defer func() {
		_ = os.Chdir(previousWD)
		os.Args = previousArgs
		util.SetDefaultOutputRootDir("output")
	}()

	if err = os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir temp dir failed: %v", err)
	}

	os.Args = []string{"wih", "-t", "https://example.com", "--csv"}
	option := Options()
	if option == nil {
		t.Fatal("options should not be nil")
	}
	if option.OutputDir != "output" {
		t.Fatalf("unexpected output dir: %s", option.OutputDir)
	}
	if option.OutputFilePath != "result.csv" {
		t.Fatalf("unexpected output file path: %s", option.OutputFilePath)
	}
}

func TestOptionsCSVPreservesExplicitStdout(t *testing.T) {
	tempDir := t.TempDir()
	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd failed: %v", err)
	}
	previousArgs := os.Args
	defer func() {
		_ = os.Chdir(previousWD)
		os.Args = previousArgs
		util.SetDefaultOutputRootDir("output")
	}()

	if err = os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir temp dir failed: %v", err)
	}

	os.Args = []string{"wih", "-t", "https://example.com", "--csv", "-o", "-"}
	option := Options()
	if option == nil {
		t.Fatal("options should not be nil")
	}
	if option.OutputFilePath != "-" {
		t.Fatalf("unexpected explicit stdout output path: %s", option.OutputFilePath)
	}
}

func TestOptionsOutputDirAffectsResolvedPath(t *testing.T) {
	tempDir := t.TempDir()
	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd failed: %v", err)
	}
	previousArgs := os.Args
	defer func() {
		_ = os.Chdir(previousWD)
		os.Args = previousArgs
		util.SetDefaultOutputRootDir("output")
	}()

	if err = os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir temp dir failed: %v", err)
	}

	os.Args = []string{"wih", "-t", "https://example.com", "--csv", "--output-dir", "reports"}
	option := Options()
	if option == nil {
		t.Fatal("options should not be nil")
	}
	if option.OutputDir != "reports" {
		t.Fatalf("unexpected output dir: %s", option.OutputDir)
	}

	resolved := util.ResolveOutputPathForTarget("https://example.com", option.OutputFilePath)
	expectedPrefix := filepath.Join("reports", "example.com_")
	if !strings.HasPrefix(resolved, expectedPrefix) {
		t.Fatalf("unexpected resolved output path: %s", resolved)
	}
	if !strings.HasSuffix(resolved, filepath.Join("", "result.csv")) && !strings.HasSuffix(resolved, "result.csv") {
		t.Fatalf("unexpected resolved output file name: %s", resolved)
	}
}
