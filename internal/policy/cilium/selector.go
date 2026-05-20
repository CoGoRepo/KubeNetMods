package cilium

import (
	"fmt"

	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
)

type Selector struct {
	raw    string
	parsed ciliumapi.EndpointSelector
}

func FromMatchLabels(matchLabels map[string]string) (*Selector, error) {
	selector := ciliumapi.NewESFromK8sLabelSelector("", &slimmetav1.LabelSelector{
		MatchLabels: matchLabels,
	})
	if err := selector.Sanitize(); err != nil {
		return nil, err
	}
	return &Selector{raw: selector.String(), parsed: selector}, nil
}

func FromSlimLabelSelector(labelSelector *slimmetav1.LabelSelector) (*Selector, error) {
	if labelSelector == nil {
		return nil, fmt.Errorf("nil Cilium label selector")
	}
	selector := ciliumapi.NewESFromK8sLabelSelector("", labelSelector)
	if err := selector.Sanitize(); err != nil {
		return nil, err
	}
	return &Selector{raw: selector.String(), parsed: selector}, nil
}

func (s *Selector) Matches(labels map[string]string) bool {
	if s == nil {
		return false
	}
	return s.parsed.Matches(slimlabels.Set(labels))
}

func (s *Selector) String() string {
	if s == nil {
		return ""
	}
	return s.raw
}
