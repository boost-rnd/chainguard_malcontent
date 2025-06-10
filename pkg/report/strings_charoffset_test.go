package report

import (
	"testing"
)

func TestGetLineInfo_CharOnly(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int
		expected int
	}{
		{
			name:     "beginning of file",
			content:  "hello world",
			offset:   0,
			expected: 0,
		},
		{
			name:     "middle of first line",
			content:  "hello world",
			offset:   6,
			expected: 6,
		},
		{
			name:     "beginning of second line",
			content:  "hello\nworld",
			offset:   6,
			expected: 0,
		},
		{
			name:     "middle of second line",
			content:  "hello\nworld",
			offset:   8,
			expected: 2,
		},
		{
			name:     "multiple lines",
			content:  "line1\nline2\nline3",
			offset:   13,
			expected: 1,
		},
		{
			name:     "empty lines",
			content:  "line1\n\nline3",
			offset:   7,
			expected: 0,
		},
		{
			name:     "offset at newline",
			content:  "hello\nworld",
			offset:   5,
			expected: 5,
		},
		{
			name:     "out of bounds offset",
			content:  "hello",
			offset:   10,
			expected: 0,
		},
		{
			name:     "negative offset",
			content:  "hello",
			offset:   -1,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte(tt.content)
			mp := &matchProcessor{
				lineOffsets: computeLineOffsets(content),
				fc:          content,
			}

			_, char := mp.getLineInfo(tt.offset)
			if char != tt.expected {
				t.Errorf("getLineInfo(%d).char = %d, want %d", tt.offset, char, tt.expected)
			}
		})
	}
}

func TestCalculateLineNumberWithOffset(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int
		expected int
	}{
		{
			name:     "first line",
			content:  "hello world",
			offset:   5,
			expected: 1,
		},
		{
			name:     "second line",
			content:  "hello\nworld",
			offset:   8,
			expected: 2,
		},
		{
			name:     "third line",
			content:  "line1\nline2\nline3",
			offset:   13,
			expected: 3,
		},
		{
			name:     "empty lines",
			content:  "line1\n\nline3",
			offset:   7,
			expected: 3,
		},
		{
			name:     "at newline",
			content:  "hello\nworld",
			offset:   5,
			expected: 1,
		},
		{
			name:     "out of bounds",
			content:  "hello",
			offset:   10,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte(tt.content)
			mp := &matchProcessor{fc: content, lineOffsets: computeLineOffsets(content)}

			line, _ := mp.getLineInfo(tt.offset)
			if line != tt.expected {
				t.Errorf("getLineInfo(%d).line = %d, want %d", tt.offset, line, tt.expected)
			}
		})
	}
}
