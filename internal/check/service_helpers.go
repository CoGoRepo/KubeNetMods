package check

import (
	"strings"
	"time"
)

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func formatList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func hasNodeLocalResolver(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "169.254.") {
			return true
		}
	}
	return false
}
