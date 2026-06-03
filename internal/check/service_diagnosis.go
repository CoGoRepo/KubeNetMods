package check

import (
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/model"
)

func hasDiagnosisContaining(report *model.Report, fragment string) bool {
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, fragment) {
			return true
		}
	}
	return false
}

func hasIstioDiagnosis(report *model.Report) bool {
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, "Istio") ||
			strings.Contains(diagnosis.Message, "DestinationRule") ||
			strings.Contains(diagnosis.Message, "VirtualService") ||
			strings.Contains(diagnosis.Message, "Envoy") {
			return true
		}
	}
	return false
}

func hasPolicyPathDiagnosis(report *model.Report) bool {
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, "Calico ") || strings.Contains(diagnosis.Message, "Cilium ") || strings.Contains(diagnosis.Message, "NetworkPolicy ") {
			return true
		}
	}
	return false
}

func hasTargetBackendDiagnosis(report *model.Report) bool {
	fragments := []string{
		"no target pods matched selector",
		"has no ready EndpointSlice addresses",
		"ready pod IPs missing from EndpointSlices",
		"target pods for Service",
	}
	for _, diagnosis := range report.Diagnoses {
		for _, fragment := range fragments {
			if strings.Contains(diagnosis.Message, fragment) {
				return true
			}
		}
	}
	return false
}
