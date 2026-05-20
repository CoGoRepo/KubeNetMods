package calico

import calicoselector "github.com/projectcalico/libcalico-go/lib/selector"

type Selector struct {
	raw    string
	parsed calicoselector.Selector
}

func ParseSelector(raw string) (*Selector, error) {
	parsed, err := calicoselector.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &Selector{raw: raw, parsed: parsed}, nil
}

func (s *Selector) Matches(labels map[string]string) bool {
	if s == nil || s.parsed == nil {
		return false
	}
	return s.parsed.Evaluate(labels)
}

func (s *Selector) String() string {
	if s == nil {
		return ""
	}
	return s.raw
}
