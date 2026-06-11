package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CoGoRepo/KubeNetMods/internal/model"
)

func TestFinishReportTerminalModes(t *testing.T) {
	rep := model.NewReport("check service", model.Target{Namespace: "app", Service: "api"})
	rep.Add("Layer", "check", model.StatusPass, "all good")
	rep.Diagnose("Primary issue: example diagnosis.")

	tests := []struct {
		name         string
		mode         terminalOutputMode
		want         []string
		doNotWant    []string
		wantNoStdout bool
	}{
		{
			name:      "full output",
			mode:      terminalOutputFull,
			want:      []string{"KubeNetMods check service", "[PASS] check: all good", "Primary issue: example diagnosis."},
			doNotWant: nil,
		},
		{
			name:      "diagnosis output",
			mode:      terminalOutputDiagnosis,
			want:      []string{"== Diagnosis ==", "Primary issue: example diagnosis."},
			doNotWant: []string{"[PASS] check: all good"},
		},
		{
			name:         "no terminal output",
			mode:         terminalOutputNone,
			wantNoStdout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := finishReport(rep, nil, tt.mode, false, nil, "", "", &stdout, &stderr)
			if code != 0 {
				t.Fatalf("finishReport returned %d, stderr=%q", code, stderr.String())
			}
			got := stdout.String()
			if tt.wantNoStdout && got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("stdout missing %q in %q", want, got)
				}
			}
			for _, unwanted := range tt.doNotWant {
				if strings.Contains(got, unwanted) {
					t.Fatalf("stdout contains unwanted %q in %q", unwanted, got)
				}
			}
		})
	}
}

func TestFinishReportQuietNoDiagnosisIsSilent(t *testing.T) {
	rep := model.NewReport("check gateway", model.Target{})
	rep.Add("Gateway API Scan", "obvious problems", model.StatusPass, "No obvious Gateway API problems found.")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := finishReport(rep, nil, terminalOutputDiagnosis, false, nil, "", "", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("finishReport returned %d, stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestFinishReportFailOnWarn(t *testing.T) {
	rep := model.NewReport("check service", model.Target{})
	rep.Add("Runtime", "probe", model.StatusWarn, "runtime tooling unavailable")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := finishReport(rep, nil, terminalOutputNone, false, nil, "", "", &stdout, &stderr); code != 0 {
		t.Fatalf("finishReport without failOnWarn returned %d, want 0", code)
	}
	if code := finishReport(rep, nil, terminalOutputNone, true, nil, "", "", &stdout, &stderr); code != 1 {
		t.Fatalf("finishReport with failOnWarn returned %d, want 1", code)
	}
}

func TestFinishReportFailOnWarnIgnoresCategory(t *testing.T) {
	rep := model.NewReport("check service", model.Target{})
	rep.AddCategorized("Runtime", "probe", model.StatusWarn, warnCategoryRuntimeUnavailable, "runtime tooling unavailable")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := finishReport(rep, nil, terminalOutputNone, true, map[string]bool{warnCategoryRuntimeUnavailable: true}, "", "", &stdout, &stderr); code != 0 {
		t.Fatalf("finishReport with ignored runtime warning returned %d, want 0", code)
	}
}

func TestFinishReportFailOnWarnIgnoresUncategorized(t *testing.T) {
	rep := model.NewReport("check service", model.Target{})
	rep.Add("Layer", "check", model.StatusWarn, "uncategorized warning")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := finishReport(rep, nil, terminalOutputNone, true, map[string]bool{warnCategoryUncategorized: true}, "", "", &stdout, &stderr); code != 0 {
		t.Fatalf("finishReport with ignored uncategorized warning returned %d, want 0", code)
	}
}

func TestWarningCategoryFlag(t *testing.T) {
	var flag warningCategoryFlag
	if err := flag.Set("1, api-inspection"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	got := flag.set()
	if !got[warnCategoryRuntimeUnavailable] || !got[warnCategoryAPIInspection] {
		t.Fatalf("parsed categories = %#v", got)
	}
	if err := flag.Set("made-up"); err == nil {
		t.Fatalf("Set unknown category returned nil error")
	}
}
