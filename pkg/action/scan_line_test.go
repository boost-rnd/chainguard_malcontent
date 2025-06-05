package action

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
)

func TestScanWithLineInfo(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create a test file with known content and patterns
	testFile := filepath.Join(tmpDir, "test.sh")
	content := `#!/bin/bash
# This is a test script
curl http://example.com
echo "Hello World"
wget http://malicious.com
nc -l 1234
openssl enc -aes-256-cbc
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.Background()

	// Load rules
	ruleFS := []fs.FS{rules.FS}
	compiledRules, err := CachedRules(ctx, ruleFS)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Test with line info enabled
	configWithLineInfo := malcontent.Config{
		Concurrency:      1,
		IncludeDataFiles: true,
		LineInfo:         true,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            compiledRules,
		ScanPaths:        []string{testFile},
		Renderer:         render.NewSimple(os.Stdout),
	}

	frs, err := recursiveScan(ctx, configWithLineInfo)
	if err != nil {
		t.Fatalf("Scan with line info failed: %v", err)
	}

	// Check that we got results
	var fileReport *malcontent.FileReport
	frs.Files.Range(func(_, value any) bool {
		if fr, ok := value.(*malcontent.FileReport); ok {
			fileReport = fr
			return false
		}
		return true
	})

	if fileReport == nil {
		t.Fatal("No file report found")
	}

	// Verify we have behaviors detected
	if len(fileReport.Behaviors) == 0 {
		t.Fatal("No behaviors detected")
	}

	// Check that line numbers are present for behaviors with matches
	var foundLineNumbers bool
	for _, behavior := range fileReport.Behaviors {
		if len(behavior.MatchStrings) > 0 && len(behavior.LineNumbers) > 0 {
			foundLineNumbers = true

			// Verify line numbers are reasonable (between 1 and total lines)
			for _, lineNum := range behavior.LineNumbers {
				if lineNum < 1 || lineNum > 7 { // We have 7 lines in our test file
					t.Errorf("Invalid line number %d", lineNum)
				}
			}
		}
	}

	if !foundLineNumbers {
		t.Error("No line numbers found in behaviors with matches")
	}

	// Test with line info disabled
	configWithoutLineInfo := malcontent.Config{
		Concurrency:      1,
		IncludeDataFiles: true,
		LineInfo:         false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            compiledRules,
		ScanPaths:        []string{testFile},
		Renderer:         render.NewSimple(os.Stdout),
	}

	frs2, err := recursiveScan(ctx, configWithoutLineInfo)
	if err != nil {
		t.Fatalf("Scan without line info failed: %v", err)
	}

	// Check that line numbers are NOT present when disabled
	frs2.Files.Range(func(_, value any) bool {
		if fr, ok := value.(*malcontent.FileReport); ok {
			for _, behavior := range fr.Behaviors {
				if len(behavior.LineNumbers) > 0 {
					t.Error("Line numbers found when line info is disabled")
				}
			}
		}
		return true
	})
}

func TestScanBinaryWithLineInfo(t *testing.T) {
	// Test that binary files also work correctly with line info
	tmpDir := t.TempDir()

	// Create a simple binary file with some recognizable patterns
	binaryFile := filepath.Join(tmpDir, "test.bin")
	binaryContent := []byte{
		0x7F, 0x45, 0x4C, 0x46, // ELF magic
		0x0A, // newline
		'h', 't', 't', 'p', ':', '/', '/', 't', 'e', 's', 't', '.', 'c', 'o', 'm',
		0x0A, // newline
		's', 's', 'h', ':', '/', '/', 'r', 'o', 'o', 't', '@', '1', '2', '7', '.', '0', '.', '0', '.', '1',
		0x0A,                   // newline
		0x00, 0x00, 0x00, 0x00, // padding
	}

	if err := os.WriteFile(binaryFile, binaryContent, 0o644); err != nil {
		t.Fatalf("Failed to write binary file: %v", err)
	}

	ctx := context.Background()

	// Load rules
	ruleFS := []fs.FS{rules.FS}
	compiledRules, err := CachedRules(ctx, ruleFS)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	config := malcontent.Config{
		Concurrency:      1,
		IncludeDataFiles: true,
		LineInfo:         true,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            compiledRules,
		ScanPaths:        []string{binaryFile},
		Renderer:         render.NewSimple(os.Stdout),
	}

	frs, err := recursiveScan(ctx, config)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify scan completed without errors
	found := false
	frs.Files.Range(func(_, _ any) bool {
		found = true
		return false
	})

	if !found {
		t.Error("No scan results for binary file")
	}
}

func TestScanWithLineInfoJSON(t *testing.T) {
	// Test JSON output with line info to verify line number splitting
	tmpDir := t.TempDir()

	// Create a test file with patterns that will match on multiple lines
	testFile := filepath.Join(tmpDir, "multi_match.sh")
	content := `#!/bin/bash
curl http://test1.com
echo "Processing..."
curl http://test2.com
sleep 1
curl http://test3.com
openssl enc -aes-256-cbc -in file.txt
echo "Done"
openssl dgst -sha256 file.txt
`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.Background()

	// Load rules
	ruleFS := []fs.FS{rules.FS}
	compiledRules, err := CachedRules(ctx, ruleFS)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Test with JSON renderer and line info enabled
	var jsonBuf bytes.Buffer
	config := malcontent.Config{
		Concurrency:      1,
		IncludeDataFiles: true,
		LineInfo:         true,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            compiledRules,
		ScanPaths:        []string{testFile},
		Renderer:         render.NewJSON(&jsonBuf),
	}

	report, err := Scan(ctx, config)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Render the report
	if err := config.Renderer.Full(ctx, &config, report); err != nil {
		t.Fatalf("Failed to render JSON: %v", err)
	}

	// Parse the JSON output
	var output render.Report
	if err := json.Unmarshal(jsonBuf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Find behaviors that should have multiple matches
	for _, fileReport := range output.Files {
		// Count behaviors by ID
		behaviorCounts := make(map[string]int)
		lineNumbersByID := make(map[string][]int)

		for _, behavior := range fileReport.Behaviors {
			behaviorCounts[behavior.ID]++
			if len(behavior.LineNumbers) > 0 {
				lineNumbersByID[behavior.ID] = append(lineNumbersByID[behavior.ID], behavior.LineNumbers[0])
			}
		}

		// Check that behaviors with multiple line matches are split
		for id, lines := range lineNumbersByID {
			if len(lines) > 1 {
				// Each behavior should have exactly one line number
				for _, behavior := range fileReport.Behaviors {
					if behavior.ID == id && len(behavior.LineNumbers) > 1 {
						t.Errorf("Behavior %s has multiple line numbers in JSON output: %v",
							id, behavior.LineNumbers)
					}
				}

				// Verify line numbers are unique
				seen := make(map[int]bool)
				for _, line := range lines {
					if seen[line] {
						t.Errorf("Duplicate line number %d for behavior %s", line, id)
					}
					seen[line] = true
				}
			}
		}
	}

	// Test with line info disabled - behaviors should not be split
	jsonBuf.Reset()
	config.LineInfo = false

	report2, err := Scan(ctx, config)
	if err != nil {
		t.Fatalf("Scan without line info failed: %v", err)
	}

	if err := config.Renderer.Full(ctx, &config, report2); err != nil {
		t.Fatalf("Failed to render JSON without line info: %v", err)
	}

	var output2 render.Report
	if err := json.Unmarshal(jsonBuf.Bytes(), &output2); err != nil {
		t.Fatalf("Failed to parse JSON output without line info: %v", err)
	}

	// Without line info, behaviors should not be split
	for _, fileReport := range output2.Files {
		behaviorIDs := make(map[string]int)
		for _, behavior := range fileReport.Behaviors {
			behaviorIDs[behavior.ID]++
		}

		// Each unique behavior ID should appear only once
		for id, count := range behaviorIDs {
			if count > 1 {
				t.Errorf("Behavior %s appears %d times when line info is disabled", id, count)
			}
		}
	}
}
