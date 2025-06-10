package report

import (
	"slices"
	"sort"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/pool"
)

var (
	initializeOnce sync.Once
	matchPool      *pool.BufferPool
)

// StringPool holds data to handle string interning.
type StringPool struct {
	sync.RWMutex
	strings map[string]string
}

// NewStringPool creates a new string pool.
func NewStringPool(length int) *StringPool {
	return &StringPool{
		strings: make(map[string]string, length),
	}
}

// Intern returns an interned version of the input string.
func (sp *StringPool) Intern(s string) string {
	sp.RLock()
	if interned, ok := sp.strings[s]; ok {
		sp.RUnlock()
		return interned
	}
	sp.RUnlock()

	sp.Lock()
	defer sp.Unlock()

	if interned, ok := sp.strings[s]; ok {
		return interned
	}

	sp.strings[s] = s
	return s
}

type MatchResult struct {
	Strings        []string
	StartingLine   int
	EndingLine     int
	StartingOffset int
	EndingOffset   int
}

type matchProcessor struct {
	fc          []byte
	pool        *StringPool
	matches     []yarax.Match
	patterns    []yarax.Pattern
	mu          sync.Mutex
	lineOffsets []int
}

func newMatchProcessor(fc []byte, matches []yarax.Match, mp []yarax.Pattern) *matchProcessor {
	return &matchProcessor{
		fc:          fc,
		pool:        NewStringPool(len(matches)),
		matches:     matches,
		patterns:    mp,
		lineOffsets: computeLineOffsets(fc),
	}
}

var matchResultPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, 32)
		return &s
	},
}

// process performantly handles the conversion of matched data to strings.
// yara-x does not expose the rendered string via the API due to performance overhead.
func (mp *matchProcessor) process() *MatchResult {
	if len(mp.matches) == 0 {
		return &MatchResult{}
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	var result *[]string
	var ok bool
	if result, ok = matchResultPool.Get().(*[]string); ok {
		*result = (*result)[:0]
	} else {
		slice := make([]string, 0, 32)
		result = &slice
	}
	defer matchResultPool.Put(result)

	// Track the overall range of matches
	var startingLine, endingLine, startingOffset, endingOffset int
	firstMatch := true

	initializeOnce.Do(func() {
		matchPool = pool.NewBufferPool(len(mp.matches))
	})

	buffer := matchPool.Get(8)
	defer matchPool.Put(buffer)

	patternsCap := len(mp.patterns)
	var patterns []string

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	for _, match := range mp.matches {
		l := int(match.Length())
		o := int(match.Offset())

		if o < 0 || o+l > len(mp.fc) {
			continue
		}

		matchBytes := mp.fc[o : o+l]

		if !containsUnprintable(matchBytes) {
			if l <= cap(buffer) {
				buffer = buffer[:l]
				copy(buffer, matchBytes)
				*result = append(*result, mp.pool.Intern(string(buffer)))
			} else {
				*result = append(*result, mp.pool.Intern(string(matchBytes)))
			}

			mp.updateLineInfo(o, l, &startingLine, &endingLine, &startingOffset, &endingOffset, &firstMatch)
		} else {
			if patterns == nil || cap(patterns) < patternsCap {
				patterns = make([]string, 0, patternsCap)
			} else {
				patterns = patterns[:0]
			}
			for _, p := range mp.patterns {
				patterns = append(patterns, p.Identifier())
			}
			*result = append(*result, slices.Compact(patterns)...)

			mp.updateLineInfo(o, l, &startingLine, &endingLine, &startingOffset, &endingOffset, &firstMatch)
		}
	}

	finalResult := make([]string, len(*result))
	copy(finalResult, *result)

	return &MatchResult{
		Strings:        finalResult,
		StartingLine:   startingLine,
		EndingLine:     endingLine,
		StartingOffset: startingOffset,
		EndingOffset:   endingOffset,
	}
}

// updateLineInfo updates the line and offset tracking for a match.
func (mp *matchProcessor) updateLineInfo(offset, length int, startLine, endLine, startOffset, endOffset *int, firstMatch *bool) {
	ml, mo := mp.getLineInfo(offset)
	el, eo := mp.getLineInfo(offset + length - 1)

	if *firstMatch {
		*startLine, *startOffset = ml, mo
		*endLine, *endOffset = el, eo
		*firstMatch = false
		return
	}
	if ml < *startLine || (ml == *startLine && mo < *startOffset) {
		*startLine, *startOffset = ml, mo
	}
	if el > *endLine || (el == *endLine && eo > *endOffset) {
		*endLine, *endOffset = el, eo
	}
}

func (mp *matchProcessor) getLineInfo(pos int) (line, char int) {
	// find highest index i where offsets[i] <= pos
	if pos < 0 || pos >= len(mp.fc) {
		return 1, 0
	}
	idx := sort.Search(len(mp.lineOffsets), func(i int) bool {
		return mp.lineOffsets[i] > pos
	}) - 1
	if idx < 0 {
		idx = 0
	}
	return idx + 1, pos - mp.lineOffsets[idx]
}

// containsUnprintable determines if a byte is a valid character.
func containsUnprintable(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return true
		}
	}
	return false
}

func computeLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}
