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
			code := finishReport(rep, nil, tt.mode, "", "", &stdout, &stderr)
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
