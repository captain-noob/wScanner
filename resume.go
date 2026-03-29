package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Scan phases — each phase saves its output so that subsequent runs
// can skip already-completed work.
const (
	PhaseNone         = 0
	PhasePortScan     = 1
	PhaseSchemeDetect = 2
	PhaseHTTPProbe    = 3
	PhaseRecheck      = 4
	PhaseFuzz         = 5
	PhaseEnrich       = 6
	PhaseDone         = 7
)

// PhaseNames maps phase constants to human-readable strings for logging.
var PhaseNames = map[int]string{
	PhaseNone:         "none",
	PhasePortScan:     "port_scan",
	PhaseSchemeDetect: "scheme_detection",
	PhaseHTTPProbe:    "http_probe",
	PhaseRecheck:      "recheck",
	PhaseFuzz:         "fuzzing",
	PhaseEnrich:       "enrichment",
	PhaseDone:         "done",
}

// ScanState holds the serializable state of a scan in progress.
// After each phase completes, the state is saved so that the scan
// can be resumed from the last completed phase.
type ScanState struct {
	// CompletedPhase is the last phase that finished successfully.
	CompletedPhase int `json:"completed_phase"`

	// Targets and Ports are the original inputs (needed to validate
	// that a resume matches the original scan parameters).
	Targets []string `json:"targets"`
	Ports   []string `json:"ports"`

	// OpenPorts holds results from the port scan phase.
	OpenPorts ScanResultList `json:"open_ports,omitempty"`

	// ProbeResults holds HTTP probe results (including recheck & fuzz data).
	ProbeResults ResponseResultList `json:"probe_results,omitempty"`

	// RecheckedIndices tracks which result indices were re-checked.
	RecheckedIndices []int `json:"rechecked_indices,omitempty"`
}

const resumeFileName = ".resume.json"

// resumePath returns the full path to the resume file.
func resumePath(folder string) string {
	return folder + "/" + resumeFileName
}

// SaveState writes the current scan state to .resume.json in the output folder.
func SaveState(folder string, state *ScanState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return os.WriteFile(resumePath(folder), data, 0644)
}

// LoadState reads the scan state from .resume.json in the output folder.
// Returns nil, nil if the file does not exist.
func LoadState(folder string) (*ScanState, error) {
	data, err := os.ReadFile(resumePath(folder))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &state, nil
}

// ClearState removes the .resume.json file after a successful scan.
func ClearState(folder string) {
	os.Remove(resumePath(folder))
}
