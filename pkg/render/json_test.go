package render

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestJSONLineNumberSplitting(t *testing.T) {
	tests := []struct {
		name          string
		lineInfo      bool
		behaviors     []*malcontent.Behavior
		expectedCount int
		expectedLines [][]int
	}{
		{
			name:     "Line info disabled - no splitting",
			lineInfo: false,
			behaviors: []*malcontent.Behavior{
				{
					ID:          "test/behavior",
					Description: "Test behavior",
					LineNumbers: []int{10, 20, 30},
					RiskScore:   2,
					RiskLevel:   "MEDIUM",
				},
			},
			expectedCount: 1,
			expectedLines: [][]int{{10, 20, 30}},
		},
		{
			name:     "Line info enabled - single line number",
			lineInfo: true,
			behaviors: []*malcontent.Behavior{
				{
					ID:          "test/single",
					Description: "Single line behavior",
					LineNumbers: []int{42},
					RiskScore:   3,
					RiskLevel:   "HIGH",
				},
			},
			expectedCount: 1,
			expectedLines: [][]int{{42}},
		},
		{
			name:     "Line info enabled - multiple line numbers split",
			lineInfo: true,
			behaviors: []*malcontent.Behavior{
				{
					ID:           "net/http",
					Description:  "HTTP connection",
					LineNumbers:  []int{10, 25, 47},
					MatchStrings: []string{"http://example.com"},
					RiskScore:    2,
					RiskLevel:    "MEDIUM",
				},
			},
			expectedCount: 3,
			expectedLines: [][]int{{10}, {25}, {47}},
		},
		{
			name:     "Line info enabled - mixed behaviors",
			lineInfo: true,
			behaviors: []*malcontent.Behavior{
				{
					ID:          "crypto/aes",
					Description: "AES encryption",
					LineNumbers: []int{5, 15},
					RiskScore:   1,
					RiskLevel:   "LOW",
				},
				{
					ID:          "net/socket",
					Description: "Socket connection",
					LineNumbers: []int{20},
					RiskScore:   2,
					RiskLevel:   "MEDIUM",
				},
				{
					ID:          "exec/shell",
					Description: "Shell execution",
					LineNumbers: []int{30, 35, 40},
					RiskScore:   3,
					RiskLevel:   "HIGH",
				},
			},
			expectedCount: 6, // 2 + 1 + 3
			expectedLines: [][]int{{5}, {15}, {20}, {30}, {35}, {40}},
		},
		{
			name:     "Line info enabled - empty line numbers",
			lineInfo: true,
			behaviors: []*malcontent.Behavior{
				{
					ID:          "test/no-lines",
					Description: "No line numbers",
					LineNumbers: []int{},
					RiskScore:   1,
					RiskLevel:   "LOW",
				},
			},
			expectedCount: 1,
			expectedLines: [][]int{{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test file report
			fr := &malcontent.FileReport{
				Path:      "test.sh",
				Size:      1024,
				RiskScore: 3,
				RiskLevel: "HIGH",
				Behaviors: tt.behaviors,
			}

			// Create a test report
			report := &malcontent.Report{}
			report.Files.Store("test.sh", fr)

			// Create config
			config := &malcontent.Config{
				LineInfo: tt.lineInfo,
			}

			// Render to JSON
			var buf bytes.Buffer
			renderer := NewJSON(&buf)

			ctx := context.Background()
			if err := renderer.Full(ctx, config, report); err != nil {
				t.Fatalf("Failed to render JSON: %v", err)
			}

			// Parse the JSON output
			var output Report
			if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
				t.Fatalf("Failed to parse JSON output: %v", err)
			}

			// Check the file report
			fileReport, exists := output.Files["test.sh"]
			if !exists {
				t.Fatal("Expected file report not found in output")
			}

			// Verify behavior count
			if len(fileReport.Behaviors) != tt.expectedCount {
				t.Errorf("Expected %d behaviors, got %d", tt.expectedCount, len(fileReport.Behaviors))
			}

			// Verify line numbers
			for i, behavior := range fileReport.Behaviors {
				if i < len(tt.expectedLines) {
					if !equalIntSlices(behavior.LineNumbers, tt.expectedLines[i]) {
						t.Errorf("Behavior %d: expected line numbers %v, got %v",
							i, tt.expectedLines[i], behavior.LineNumbers)
					}
				}
			}

			// When line info is enabled and behaviors are split, verify that each
			// behavior maintains the same properties except line numbers
			if tt.lineInfo && len(tt.behaviors) > 0 && len(tt.behaviors[0].LineNumbers) > 1 {
				firstOriginal := tt.behaviors[0]
				for _, behavior := range fileReport.Behaviors {
					if behavior.ID != firstOriginal.ID {
						continue
					}
					if behavior.Description != firstOriginal.Description {
						t.Errorf("Description mismatch: expected %q, got %q",
							firstOriginal.Description, behavior.Description)
					}
					if behavior.RiskScore != firstOriginal.RiskScore {
						t.Errorf("RiskScore mismatch: expected %d, got %d",
							firstOriginal.RiskScore, behavior.RiskScore)
					}
					if behavior.RiskLevel != firstOriginal.RiskLevel {
						t.Errorf("RiskLevel mismatch: expected %q, got %q",
							firstOriginal.RiskLevel, behavior.RiskLevel)
					}
				}
			}
		})
	}
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
