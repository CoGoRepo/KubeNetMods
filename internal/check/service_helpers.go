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

func int32PortFromInt(value int) (int32, bool) {
	if value <= 0 || value > 65535 {
		return 0, false
	}
	return int32(value), true
}

func int32PortFromInt64(value int64) (int32, bool) {
	if value <= 0 || value > 65535 {
		return 0, false
	}
	return int32(value), true
}

func uint32PortFromInt32(value int32) (uint32, bool) {
	if value <= 0 || value > 65535 {
		return 0, false
	}
	return uint32(value), true
}
