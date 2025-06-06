# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

malcontent is a malware detection and supply chain compromise discovery tool that uses 14,500+ YARA rules to analyze programs. It supports Linux, macOS, and Windows programs across multiple file formats and languages.

## Key Commands

### Build
```bash
# Install required yara-x dependency first
make install-yara-x

# Build malcontent binary
make out/mal

# Alternative build with custom yara-x paths
CGO_LDFLAGS="-L$(pwd)/out/lib -Wl,-rpath,$(pwd)/out/lib" \
CGO_CPPFLAGS="-I$(pwd)/out/include" \
PKG_CONFIG_PATH="$(pwd)/out/lib/pkgconfig" \
go build -o out/mal ./cmd/mal
```

### Test
```bash
# Run unit tests
make test

# Run integration tests (downloads sample malware)
make integration

# Run specific test
go test -v ./pkg/action -run TestScanArchive

# Benchmark tests
make bench
```

### Lint
```bash
# Run linters
make lint

# Fix lint issues automatically
make fix
```

### Development
```bash
# Test a rule against a file
go run ./cmd/mal analyze <file>

# Debug YARA rule directly
yara -s -w rules/<path-to-rule>.yara <file>

# Refresh test data after adding samples
make refresh-sample-testdata

# Generate CPU/memory profiles
mal --profile=true scan /path
```

## Architecture

### Code Structure
- `cmd/mal/mal.go` - CLI entry point with subcommands (analyze, diff, scan, refresh)
- `pkg/action/` - Core scanning logic, archive handling, and diff operations
- `pkg/compile/` - YARA rule compilation and caching
- `pkg/render/` - Output formatting (JSON, YAML, Markdown, Terminal UI)
- `pkg/report/` - Risk scoring and report generation
- `rules/` - YARA rules organized by behavior category

### Key Architectural Patterns

1. **File Processing Pipeline**:
   - `action.recursiveScan()` → `action.scanPath()` → `action.scanFile()`
   - Archives are transparently extracted and scanned recursively
   - File type detection via `programkind.File()`

2. **Rule Compilation**:
   - Rules are compiled on first use via `compile.Compile()`
   - Cached compilation for performance
   - Third-party rules integrated from `third_party/yara/`

3. **Risk Scoring**:
   - Each rule has a risk score (1-4)
   - Behaviors are aggregated and weighted
   - Differential analysis compares risk changes between versions

4. **Rendering Pipeline**:
   - `render.Renderer` interface for multiple output formats
   - Terminal renderer uses Bubble Tea for interactive UI
   - Markdown/JSON/YAML for CI/CD integration

### Adding New Features

1. **New YARA Rules**:
   - Add to appropriate category in `rules/`
   - Include metadata: description, risk score, references
   - Test with sample files in `tests/`

2. **New File Formats**:
   - Extend `archive/` package for extraction
   - Update `programkind/` for detection

3. **New Renderers**:
   - Implement `render.Renderer` interface
   - Add to `render.New()` factory

### Testing Approach
- Unit tests for individual components
- Integration tests with real malware samples
- Benchmark tests for performance regression
- Test data organized by OS and malware family in `tests/`

### Common Development Tasks

1. **Debugging False Positives**:
   - Check rule in `rules/false_positives/`
   - Use `--include-tags` to test specific behaviors
   - Add exceptions to existing rules if needed

2. **Performance Optimization**:
   - Use `--profile=true` to generate pprof files
   - Focus on `compile.Compile()` and `action.scanFile()`
   - Consider parallelization in `pool.Process()`

3. **Rule Development**:
   - Study existing rules in similar categories
   - Use `strings` and `condition` sections effectively
   - Test against both malicious and benign samples