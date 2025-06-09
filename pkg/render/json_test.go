package render

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestJSONLineInfoOutput(t *testing.T) {
	tests := []struct {
		name      string
		behaviors []*malcontent.Behavior
	}{
		{
			name: "Line info disabled - no line numbers",
			behaviors: []*malcontent.Behavior{
				{
					ID:             "test/behavior",
					Description:    "Test behavior",
					StartingLine:   0, // Should be 0 when line info is disabled
					EndingLine:     0,
					StartingOffset: 0,
					EndingOffset:   0,
					RiskScore:      2,
					RiskLevel:      "MEDIUM",
				},
			},
		},
		{
			name: "Line info single line match",
			behaviors: []*malcontent.Behavior{
				{
					ID:             "test/single",
					Description:    "Single line behavior",
					StartingLine:   42,
					EndingLine:     42,
					StartingOffset: 10,
					EndingOffset:   25,
					RiskScore:      3,
					RiskLevel:      "HIGH",
				},
			},
		},
		{
			name: "Line info enabled - multi-line match",
			behaviors: []*malcontent.Behavior{
				{
					ID:             "net/http",
					Description:    "HTTP connection spanning lines",
					StartingLine:   10,
					EndingLine:     12,
					StartingOffset: 15,
					EndingOffset:   5,
					MatchStrings:   []string{"http://example.com"},
					RiskScore:      2,
					RiskLevel:      "MEDIUM",
				},
			},
		},
		{
			name: "Line info enabled - multiple behaviors",
			behaviors: []*malcontent.Behavior{
				{
					ID:             "crypto/aes",
					Description:    "AES encryption",
					StartingLine:   5,
					EndingLine:     5,
					StartingOffset: 0,
					EndingOffset:   20,
					RiskScore:      1,
					RiskLevel:      "LOW",
				},
				{
					ID:             "net/socket",
					Description:    "Socket connection",
					StartingLine:   20,
					EndingLine:     22,
					StartingOffset: 5,
					EndingOffset:   15,
					RiskScore:      2,
					RiskLevel:      "MEDIUM",
				},
				{
					ID:             "exec/shell",
					Description:    "Shell execution",
					StartingLine:   30,
					EndingLine:     30,
					StartingOffset: 0,
					EndingOffset:   50,
					RiskScore:      3,
					RiskLevel:      "HIGH",
				},
			},
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
			config := &malcontent.Config{}

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

			// Verify behavior count matches input
			if len(fileReport.Behaviors) != len(tt.behaviors) {
				t.Errorf("Expected %d behaviors, got %d", len(tt.behaviors), len(fileReport.Behaviors))
			}

			// Verify each behavior
			for i, behavior := range fileReport.Behaviors {
				if i >= len(tt.behaviors) {
					break
				}
				expected := tt.behaviors[i]

				// Check all fields match
				if behavior.ID != expected.ID {
					t.Errorf("Behavior %d: ID mismatch: expected %q, got %q", i, expected.ID, behavior.ID)
				}
				if behavior.Description != expected.Description {
					t.Errorf("Behavior %d: Description mismatch: expected %q, got %q", i, expected.Description, behavior.Description)
				}
				if behavior.RiskScore != expected.RiskScore {
					t.Errorf("Behavior %d: RiskScore mismatch: expected %d, got %d", i, expected.RiskScore, behavior.RiskScore)
				}
				if behavior.RiskLevel != expected.RiskLevel {
					t.Errorf("Behavior %d: RiskLevel mismatch: expected %q, got %q", i, expected.RiskLevel, behavior.RiskLevel)
				}

				// Check line info fields
				if behavior.StartingLine != expected.StartingLine {
					t.Errorf("Behavior %d: StartingLine mismatch: expected %d, got %d", i, expected.StartingLine, behavior.StartingLine)
				}
				if behavior.EndingLine != expected.EndingLine {
					t.Errorf("Behavior %d: EndingLine mismatch: expected %d, got %d", i, expected.EndingLine, behavior.EndingLine)
				}
				if behavior.StartingOffset != expected.StartingOffset {
					t.Errorf("Behavior %d: StartingOffset mismatch: expected %d, got %d", i, expected.StartingOffset, behavior.StartingOffset)
				}
				if behavior.EndingOffset != expected.EndingOffset {
					t.Errorf("Behavior %d: EndingOffset mismatch: expected %d, got %d", i, expected.EndingOffset, behavior.EndingOffset)
				}
			}
		})
	}
}
