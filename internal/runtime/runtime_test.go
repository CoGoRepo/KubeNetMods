package runtime

import "testing"

func TestClassifyRuntimeHTTPFailureRuntimeUnavailable(t *testing.T) {
	cases := []string{
		`exec: "sh": executable file not found`,
		`sh: curl: not found`,
		`curl: command not found`,
		`no resolver tool available: nslookup/getent`,
		`pods "curl" is forbidden: User cannot create resource "pods/exec"`,
	}

	for _, text := range cases {
		got := ClassifyRuntimeHTTPFailure(RuntimeHTTPResult{Error: text})
		if got.Kind != "runtime-unavailable" {
			t.Fatalf("ClassifyRuntimeHTTPFailure(%q) kind = %q, want runtime-unavailable", text, got.Kind)
		}
	}
}

func TestClassifyRuntimeHTTPFailureKeepsRealNetworkFailure(t *testing.T) {
	got := ClassifyRuntimeHTTPFailure(RuntimeHTTPResult{Error: "curl: (7) Failed to connect to 10.0.0.1 port 8080: Connection refused"})
	if got.Kind != "connection-refused" {
		t.Fatalf("kind = %q, want connection-refused", got.Kind)
	}
}
