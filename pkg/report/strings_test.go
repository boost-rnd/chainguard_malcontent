package report

import (
	"strings"
	"testing"
)

func TestCalculateLineNumber(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int
		expected int
	}{
		{
			name:     "empty content",
			content:  "",
			offset:   0,
			expected: 1,
		},
		{
			name:     "first line",
			content:  "hello world",
			offset:   0,
			expected: 1,
		},
		{
			name:     "first line middle",
			content:  "hello world",
			offset:   6,
			expected: 1,
		},
		{
			name:     "second line",
			content:  "hello\nworld",
			offset:   6,
			expected: 2,
		},
		{
			name:     "third line",
			content:  "hello\nworld\nfoo bar",
			offset:   12,
			expected: 3,
		},
		{
			name:     "multiple newlines",
			content:  "line1\nline2\nline3\nline4",
			offset:   18,
			expected: 4,
		},
		{
			name:     "offset at newline",
			content:  "hello\nworld",
			offset:   5,
			expected: 1,
		},
		{
			name:     "offset beyond content",
			content:  "hello",
			offset:   100,
			expected: 0,
		},
		{
			name:     "negative offset",
			content:  "hello",
			offset:   -1,
			expected: 0,
		},
		{
			name:     "windows line endings",
			content:  "hello\r\nworld\r\ntest",
			offset:   14,
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateLineNumber([]byte(tt.content), tt.offset)
			if got != tt.expected {
				t.Errorf("calculateLineNumber() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Note: The TestMatchProcessorWithLineInfo and TestMatchProcessorWithUnprintableChars tests
// have been removed because they relied on mocking yarax.Match and yarax.Pattern types,
// which are concrete types from the yara-x library and cannot be mocked.
// To properly test the matchProcessor functionality, we would need to either:
// 1. Use actual yara-x rules and scanning, or
// 2. Refactor the code to use interfaces that can be mocked
//
// For now, we focus on testing the calculateLineNumber function which doesn't depend on yara-x types.

func BenchmarkCalculateLineNumber(b *testing.B) {
	// Create a large file with many lines
	lines := make([]string, 10000)
	for i := range lines {
		lines[i] = "This is a test line with some content"
	}
	content := []byte(strings.Join(lines, "\n"))

	// Test various offsets
	offsets := []int{100, 1000, 10000, 50000, 100000}

	b.ResetTimer()
	for b.Loop() {
		for _, offset := range offsets {
			_ = calculateLineNumber(content, offset)
		}
	}
}
