package model

import "time"

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusInfo Status = "INFO"
	StatusSkip Status = "SKIP"
)

type Target struct {
	Context        string `json:"context,omitempty"`
	Namespace      string `json:"namespace"`
	Service        string `json:"service"`
	Deployment     string `json:"deployment,omitempty"`
	ServicePort    int32  `json:"servicePort,omitempty"`
	SourceContext  string `json:"sourceContext,omitempty"`
	SourceNS       string `json:"sourceNamespace,omitempty"`
	SourcePod      string `json:"sourcePod,omitempty"`
	SourceSelector string `json:"sourceSelector,omitempty"`
}

type Result struct {
	Layer   string `json:"layer"`
	Check   string `json:"check"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

type Diagnosis struct {
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message"`
}

type Report struct {
	Tool        string      `json:"tool"`
	Command     string      `json:"command"`
	Timestamp   time.Time   `json:"timestamp"`
	Target      Target      `json:"target"`
	Results     []Result    `json:"results"`
	Diagnoses   []Diagnosis `json:"diagnoses"`
	Limitations []string    `json:"limitations,omitempty"`
}

func NewReport(command string, target Target) *Report {
	return &Report{
		Tool:      "KubeNetMods",
		Command:   command,
		Timestamp: time.Now(),
		Target:    target,
	}
}

func (r *Report) Add(layer, check string, status Status, message string) {
	r.Results = append(r.Results, Result{
		Layer:   layer,
		Check:   check,
		Status:  status,
		Message: message,
	})
}

func (r *Report) Diagnose(message string) {
	for _, existing := range r.Diagnoses {
		if existing.Message == message {
			return
		}
	}
	r.Diagnoses = append(r.Diagnoses, Diagnosis{Message: message})
}

func (r *Report) CountByStatus(status Status) int {
	count := 0
	for _, result := range r.Results {
		if result.Status == status {
			count++
		}
	}
	return count
}
