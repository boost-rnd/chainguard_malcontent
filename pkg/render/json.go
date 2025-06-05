// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

type JSON struct {
	w io.Writer
}

func NewJSON(w io.Writer) JSON {
	return JSON{w: w}
}

func (r JSON) Name() string { return "JSON" }

func (r JSON) Scanning(_ context.Context, _ string) {}

func (r JSON) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r JSON) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	jr := Report{
		Diff:   rep.Diff,
		Files:  make(map[string]*malcontent.FileReport),
		Filter: "",
	}

	rep.Files.Range(func(key, value any) bool {
		if ctx.Err() != nil {
			return false
		}

		if key == nil || value == nil {
			return true
		}
		if path, ok := key.(string); ok {
			if r, ok := value.(*malcontent.FileReport); ok {
				if r.Skipped == "" {
					// Filter out diff-related fields
					r.ArchiveRoot = ""
					r.FullPath = ""

					// If line info is enabled, split behaviors with multiple line numbers
					if c != nil && c.LineInfo {
						r = splitBehaviorsByLineNumbers(r)
					}

					jr.Files[path] = r
				}
			}
		}
		return true
	})

	if c != nil && c.Stats && jr.Diff == nil {
		jr.Stats = serializedStats(c, rep)
	}

	j, err := json.MarshalIndent(jr, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", j)
	return err
}

// splitBehaviorsByLineNumbers creates multiple behavior instances when a behavior has multiple line numbers.
// Each resulting behavior will have exactly one line number.
func splitBehaviorsByLineNumbers(fr *malcontent.FileReport) *malcontent.FileReport {
	// Create a copy of the FileReport to avoid modifying the original
	newFR := &malcontent.FileReport{
		Path:                 fr.Path,
		SHA256:               fr.SHA256,
		Size:                 fr.Size,
		Skipped:              fr.Skipped,
		Meta:                 fr.Meta,
		Syscalls:             fr.Syscalls,
		Pledge:               fr.Pledge,
		Capabilities:         fr.Capabilities,
		FilteredBehaviors:    fr.FilteredBehaviors,
		PreviousPath:         fr.PreviousPath,
		PreviousRelPath:      fr.PreviousRelPath,
		PreviousRelPathScore: fr.PreviousRelPathScore,
		PreviousRiskScore:    fr.PreviousRiskScore,
		PreviousRiskLevel:    fr.PreviousRiskLevel,
		RiskScore:            fr.RiskScore,
		RiskLevel:            fr.RiskLevel,
		IsMalcontent:         fr.IsMalcontent,
		Overrides:            fr.Overrides,
		ArchiveRoot:          fr.ArchiveRoot,
		FullPath:             fr.FullPath,
		Behaviors:            make([]*malcontent.Behavior, 0),
	}

	// Process each behavior
	for _, b := range fr.Behaviors {
		if len(b.LineNumbers) <= 1 {
			// If there's 0 or 1 line number, just copy the behavior as-is
			newFR.Behaviors = append(newFR.Behaviors, b)
		} else {
			// Split into multiple behaviors, one per line number
			for i, lineNum := range b.LineNumbers {
				charOffset := 0
				if i < len(b.CharOffsets) {
					charOffset = b.CharOffsets[i]
				}
				newBehavior := &malcontent.Behavior{
					Description:    b.Description,
					MatchStrings:   b.MatchStrings,
					LineNumbers:    []int{lineNum},
					CharOffsets:    []int{charOffset},
					RiskScore:      b.RiskScore,
					RiskLevel:      b.RiskLevel,
					RuleURL:        b.RuleURL,
					ReferenceURL:   b.ReferenceURL,
					RuleAuthor:     b.RuleAuthor,
					RuleAuthorURL:  b.RuleAuthorURL,
					RuleLicense:    b.RuleLicense,
					RuleLicenseURL: b.RuleLicenseURL,
					DiffAdded:      b.DiffAdded,
					DiffRemoved:    b.DiffRemoved,
					ID:             b.ID,
					RuleName:       b.RuleName,
					Override:       b.Override,
				}
				newFR.Behaviors = append(newFR.Behaviors, newBehavior)
			}
		}
	}

	return newFR
}
