package calico

import "testing"

func TestParseSelectorUsesCalicoEngine(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		labels   map[string]string
		want     bool
	}{
		{
			name:     "all selector",
			selector: "all()",
			labels:   map[string]string{"app": "web"},
			want:     true,
		},
		{
			name:     "has and namespace selector",
			selector: `app == "nginx" && has(role) && projectcalico.org/namespace != "kube-system"`,
			labels: map[string]string{
				"app":                         "nginx",
				"role":                        "frontend",
				"projectcalico.org/namespace": "default",
			},
			want: true,
		},
		{
			name:     "not in exclusion",
			selector: `projectcalico.org/name not in {"kube-system", "argocd"}`,
			labels: map[string]string{
				"projectcalico.org/name": "argocd",
			},
			want: false,
		},
		{
			name:     "complex in not-in and has",
			selector: `app in {"web", "api"} && env not in {"dev", "qa"} && has(version)`,
			labels: map[string]string{
				"app":     "web",
				"env":     "prod",
				"version": "v1",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := ParseSelector(tt.selector)
			if err != nil {
				t.Fatalf("ParseSelector() error = %v", err)
			}
			if got := selector.Matches(tt.labels); got != tt.want {
				t.Fatalf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMalformedSelectorReturnsError(t *testing.T) {
	if _, err := ParseSelector(`projectcalico.org/name not in {"kube-system", "monitoring}`); err == nil {
		t.Fatal("ParseSelector() error = nil, want parse error")
	}
}
