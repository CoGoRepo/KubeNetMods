package cilium

import "testing"

func TestEndpointSelectorUsesCiliumEngine(t *testing.T) {
	selector, err := FromMatchLabels(map[string]string{"app": "client", "role": "dev"})
	if err != nil {
		t.Fatalf("FromMatchLabels() error = %v", err)
	}
	if !selector.Matches(map[string]string{"app": "client", "role": "dev"}) {
		t.Fatal("selector should match labels")
	}
	if selector.Matches(map[string]string{"app": "client", "role": "prod"}) {
		t.Fatal("selector should not match different role")
	}
}
