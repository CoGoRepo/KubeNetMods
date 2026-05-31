package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/model"
)

func PrintText(w io.Writer, r *model.Report) {
	colors := terminalColors()
	fmt.Fprintf(w, "KubeNetMods %s\n", r.Command)
	fmt.Fprintf(w, "Target: %s/%s\n", r.Target.Namespace, r.Target.Service)
	if r.Target.Context != "" {
		fmt.Fprintf(w, "Context: %s\n", r.Target.Context)
	}
	if r.Target.SourceNS != "" {
		fmt.Fprintf(w, "Source: %s", r.Target.SourceNS)
		if r.Target.SourcePod != "" {
			fmt.Fprintf(w, "/%s", r.Target.SourcePod)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	lastLayer := ""
	for _, result := range r.Results {
		if result.Layer != lastLayer {
			if lastLayer != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "== %s ==\n", result.Layer)
			lastLayer = result.Layer
		}
		fmt.Fprintf(w, "[%s] %s: %s\n", colors.Status(result.Status), result.Check, result.Message)
	}

	fmt.Fprintln(w, "\n== Summary ==")
	statuses := []model.Status{model.StatusFail, model.StatusWarn, model.StatusPass, model.StatusInfo, model.StatusSkip}
	for _, status := range statuses {
		if count := r.CountByStatus(status); count > 0 {
			fmt.Fprintf(w, "%s: %d\n", colors.Status(status), count)
		}
	}

	if len(r.Diagnoses) > 0 {
		fmt.Fprintln(w, "\n== Diagnosis ==")
		for _, diag := range r.Diagnoses {
			fmt.Fprintf(w, " - %s\n", diag.Message)
		}
	}
}

func PrintBlockers(w io.Writer, r *model.Report, wide bool) {
	if wide {
		printBlockersWide(w, r)
		return
	}
	printBlockersCompact(w, r)
}

func printBlockersCompact(w io.Writer, r *model.Report) {
	colors := terminalColors()
	verdict, reason := blockerVerdict(r)
	subject := blockerSubject(r)
	fmt.Fprintf(w, "%s\n\n", colors.Bold("KubeNetMods: Policy Blocker Check"))
	fmt.Fprintf(w, "Subject: %s\n", subject.Compact())
	fmt.Fprintf(w, "Path:    %s\n\n", blockerPathLine(r))
	fmt.Fprintf(w, "Result:  %s\n", colors.Verdict(verdictLabel(verdict)))
	if reason != "" {
		fmt.Fprintf(w, "Reason:  %s\n", reason)
	}
	fmt.Fprintln(w)

	rows := blockerRows(r)
	if len(rows) == 0 {
		fmt.Fprintln(w, "No policy blockers found.")
	} else {
		fmt.Fprintf(w, "%-10s %-28s %-5s %-8s %s\n", "Provider", "Policy", "Rule", "Action", "Reason")
		fmt.Fprintf(w, "%-10s %-28s %-5s %-8s %s\n", "--------", "------", "----", "------", "------")
		for _, row := range rows {
			fmt.Fprintf(w, "%s %s %s %s %s\n",
				colors.Provider(padRight(row.Provider, 10)),
				padRight(truncate(row.Policy, 28), 28),
				padRight(row.Rule, 5),
				colors.Action(padRight(row.Action, 8)),
				row.Reason,
			)
		}
	}

	notes := blockerNotes(r)
	notes = append(notes, allowMissNotes(rows)...)
	if len(notes) > 0 {
		fmt.Fprintln(w)
		for _, note := range notes {
			fmt.Fprintln(w, note)
		}
	}
}

func printBlockersWide(w io.Writer, r *model.Report) {
	colors := terminalColors()
	verdict, reason := blockerVerdict(r)
	subject := blockerSubject(r)
	fmt.Fprintf(w, "%s\n\n", colors.Bold("KubeNetMods: Policy Blocker Check"))
	fmt.Fprintf(w, "Verdict: %s\n", colors.Verdict(verdictLabel(verdict)))
	if reason != "" {
		fmt.Fprintf(w, "Reason:  %s\n", reason)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, colors.Bold("Subject"))
	fmt.Fprintf(w, "  Namespace: %-10s\n", subject.Namespace)
	if subject.Labels != "" {
		fmt.Fprintf(w, "  Labels:    %-10s\n", subject.Labels)
	}
	if subject.ServiceAccount != "" && subject.ServiceAccount != "default" {
		fmt.Fprintf(w, "  Service Account: %s\n", subject.ServiceAccount)
	}
	if subject.Pod != "" && subject.Pod != "preflight-subject" {
		fmt.Fprintf(w, "  Pod:       %-10s\n", subject.Pod)
	}
	direction, port := blockerDirectionPort(r)
	fmt.Fprintf(w, "  Direction: %-10s\n", direction)
	fmt.Fprintf(w, "  Port:      TCP/%s\n\n", port)

	rows := blockerRows(r)
	if len(rows) == 0 {
		fmt.Fprintln(w, "No policy blockers found.")
	} else {
		fmt.Fprintln(w, colors.Bold("Blockers"))
		for i, row := range rows {
			if i > 0 {
				fmt.Fprintln(w)
				fmt.Fprintln(w, strings.Repeat("-", 64))
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "  [%s] %s  (%d/%d)\n", colors.Provider(row.Provider), row.Policy, i+1, len(rows))
			fmt.Fprintf(w, "    Action: %s\n", colors.Action(row.Action))
			fmt.Fprintf(w, "    Rule:   %s\n", row.Rule)
			fmt.Fprintf(w, "    Why:    %s\n", row.Reason)
		}
	}

	notes := blockerNotes(r)
	notes = append(notes, allowMissNotes(rows)...)
	if len(notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Notes")
		for _, note := range notes {
			fmt.Fprintf(w, "  %s\n", note)
		}
	}
}

func allowMissNotes(rows []blockerRow) []string {
	var misses []string
	for _, row := range rows {
		for _, miss := range row.Misses {
			if !containsStringLocal(misses, miss) {
				misses = append(misses, miss)
			}
		}
	}
	if len(misses) == 0 {
		return nil
	}
	notes := []string{"Earlier Allow did not match:"}
	for _, miss := range misses {
		notes = append(notes, "  - "+miss)
	}
	return notes
}

type blockerRow struct {
	Provider  string
	Check     string
	Status    model.Status
	Message   string
	Diagnosis string
	Policy    string
	Rule      string
	Action    string
	Reason    string
	Misses    []string
}

func blockerRows(r *model.Report) []blockerRow {
	diagnoses := map[string]string{}
	for _, diag := range r.Diagnoses {
		diagnoses[diagnosisKey(diag.Message)] = diag.Message
	}
	var rows []blockerRow
	for _, result := range r.Results {
		if !isBlockerResult(result) {
			continue
		}
		rows = append(rows, blockerRow{
			Provider:  blockerProvider(result.Layer),
			Check:     result.Check,
			Status:    result.Status,
			Message:   result.Message,
			Diagnosis: diagnoses[diagnosisKey(result.Message)],
			Policy:    blockerPolicy(result),
			Rule:      blockerRule(result),
			Action:    blockerAction(result),
			Reason:    blockerReason(result),
			Misses:    blockerAllowMisses(result),
		})
	}
	return rows
}

func blockerNotes(r *model.Report) []string {
	var notes []string
	for _, result := range r.Results {
		if result.Layer == "Subject" || result.Layer == "Target" {
			continue
		}
		if strings.Contains(result.Layer, "NetworkPolicy Blockers") && result.Status == model.StatusPass {
			notes = append(notes, "No native NetworkPolicy blockers found.")
			continue
		}
		if strings.Contains(result.Layer, "Blockers") && result.Status == model.StatusInfo {
			notes = append(notes, result.Message)
		}
	}
	if len(notes) == 0 && len(blockerRows(r)) > 0 {
		return nil
	}
	return notes
}

func isBlockerResult(result model.Result) bool {
	return result.Status == model.StatusFail
}

func blockerVerdict(r *model.Report) (model.Status, string) {
	if r.CountByStatus(model.StatusFail) > 0 {
		return model.StatusFail, blockerReasonSummary(r)
	}
	for _, result := range r.Results {
		if result.Status == model.StatusWarn && !isContextOnlyBlockerWarning(result) {
			return model.StatusWarn, blockerReasonSummary(r)
		}
	}
	return model.StatusPass, blockerReasonSummary(r)
}

func isContextOnlyBlockerWarning(result model.Result) bool {
	return strings.Contains(result.Layer, "Blockers") && strings.Contains(strings.ToLower(result.Check), "selected")
}

func blockerReasonSummary(r *model.Report) string {
	if len(r.Diagnoses) > 0 {
		return r.Diagnoses[0].Message
	}
	for _, row := range blockerRows(r) {
		if row.Diagnosis != "" {
			return row.Diagnosis
		}
		if row.Provider != "" && row.Action != "" {
			if row.Action == "Deny" {
				return row.Provider + " explicit Deny"
			}
			if strings.Contains(strings.ToLower(row.Check), "default") {
				return row.Provider + " default deny"
			}
			return row.Provider + " " + row.Action
		}
	}
	return ""
}

type blockerSubjectInfo struct {
	Namespace      string
	Pod            string
	Labels         string
	Context        string
	ServiceAccount string
}

func (s blockerSubjectInfo) Compact() string {
	subject := s.Namespace
	if s.Pod != "" {
		subject += "/" + s.Pod
	}
	if s.Labels != "" {
		subject += " labels(" + s.Labels + ")"
	}
	if s.ServiceAccount != "" && s.ServiceAccount != "default" {
		subject += " serviceAccount(" + s.ServiceAccount + ")"
	}
	if s.Context != "" {
		subject += " context=" + s.Context
	}
	return subject
}

func blockerSubject(r *model.Report) blockerSubjectInfo {
	info := blockerSubjectInfo{
		Namespace: r.Target.SourceNS,
		Pod:       r.Target.SourcePod,
		Context:   r.Target.Context,
	}
	if info.Namespace == "" {
		info.Namespace = r.Target.Namespace
	}
	if info.Namespace == "" {
		info.Namespace = "(unknown)"
	}
	for _, result := range r.Results {
		if result.Layer != "Subject" || result.Check != "pod" {
			continue
		}
		if strings.Contains(result.Message, "Using preflight labels") {
			labelsText := strings.TrimSuffix(after(result.Message, ": "), ".")
			if index := strings.Index(labelsText, ". ServiceAccount="); index >= 0 {
				info.Labels = labelsText[:index]
				info.ServiceAccount = labelsText[index+len(". ServiceAccount="):]
			} else {
				info.Labels = labelsText
			}
			if info.Pod == "" {
				info.Pod = "preflight-subject"
			}
			continue
		}
		if strings.Contains(result.Message, "Using deployed pod") && info.Pod == "" {
			pod := strings.TrimPrefix(result.Message, "Using deployed pod ")
			pod = strings.TrimSuffix(pod, ".")
			parts := strings.Split(pod, "/")
			if len(parts) == 2 {
				info.Namespace = parts[0]
				info.Pod = parts[1]
			}
		}
	}
	return info
}

func blockerPathLine(r *model.Report) string {
	direction, port := blockerDirectionPort(r)
	path := direction
	if port != "" {
		path += " TCP/" + port
	}
	var target string
	for _, result := range r.Results {
		if result.Layer == "Target" && target == "" {
			if result.Check == "none" {
				target = "(port posture mode)"
			} else {
				target = result.Message
			}
		}
	}
	if target == "" {
		return path
	}
	return path + "  " + target
}

func blockerDirectionPort(r *model.Report) (string, string) {
	for _, result := range r.Results {
		if result.Layer == "Subject" && result.Check == "direction" {
			message := strings.TrimPrefix(result.Message, "Checking ")
			message = strings.TrimSuffix(message, ".")
			re := regexp.MustCompile(`(?i)^(egress|ingress) policy for TCP/(.+)$`)
			if match := re.FindStringSubmatch(message); len(match) == 3 {
				return strings.ToLower(match[1]), match[2]
			}
		}
	}
	return "policy path", ""
}

func blockerProvider(layer string) string {
	switch {
	case strings.Contains(layer, "Calico"):
		return "Calico"
	case strings.Contains(layer, "Cilium"):
		return "Cilium"
	case strings.Contains(layer, "NetworkPolicy"):
		return "Kubernetes"
	default:
		return layer
	}
}

func diagnosisKey(message string) string {
	message = strings.ToLower(message)
	message = strings.ReplaceAll(message, "primary issue:", "")
	message = strings.TrimSpace(message)
	if len(message) > 64 {
		return message[:64]
	}
	return message
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func padRight(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}

func verdictLabel(status model.Status) string {
	switch status {
	case model.StatusFail:
		return "BLOCKED"
	case model.StatusWarn:
		return "RISK"
	default:
		return "ALLOWED"
	}
}

func blockerPolicy(result model.Result) string {
	re := regexp.MustCompile(`\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+) rule \d+`)
	if match := re.FindStringSubmatch(result.Message); len(match) == 2 {
		return match[1]
	}
	if strings.Contains(strings.ToLower(result.Check), "default") {
		return "(default deny)"
	}
	return result.Check
}

func blockerRule(result model.Result) string {
	re := regexp.MustCompile(`\brule (\d+)`)
	if match := re.FindStringSubmatch(result.Message); len(match) == 2 {
		return match[1]
	}
	return "-"
}

func blockerAction(result model.Result) string {
	if strings.Contains(result.Message, " explicitly Denies ") || strings.Contains(result.Message, " explicit Deny") {
		return "Deny"
	}
	if strings.Contains(strings.ToLower(result.Check), "default") {
		return "Default deny"
	}
	if result.Status == model.StatusFail {
		return "Block"
	}
	return string(result.Status)
}

func blockerReason(result model.Result) string {
	if reason := after(result.Message, "Reason: "); reason != "" {
		if index := strings.Index(reason, " Earlier allow-rule miss: "); index >= 0 {
			reason = reason[:index]
		}
		reason = strings.TrimSuffix(reason, ".")
		reason = strings.ReplaceAll(reason, "this port", blockerMessagePort(result.Message))
		return reason
	}
	if strings.Contains(strings.ToLower(result.Check), "default") {
		return "no matching allow rule was found"
	}
	return result.Message
}

func blockerAllowMisses(result model.Result) []string {
	raw := after(result.Message, "Earlier allow-rule miss: ")
	if raw == "" {
		raw = after(result.Message, "Closest allow-rule miss: ")
	}
	if raw == "" {
		return nil
	}
	raw = strings.TrimSuffix(raw, ".")
	parts := splitAllowMisses(raw)
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitAllowMisses(raw string) []string {
	pattern := regexp.MustCompile(`[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+ rule \d+:`)
	matches := pattern.FindAllStringIndex(raw, -1)
	if len(matches) <= 1 {
		return []string{raw}
	}
	var out []string
	for index, match := range matches {
		start := match[0]
		end := len(raw)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		part := strings.TrimSpace(raw[start:end])
		part = strings.TrimPrefix(part, ";")
		part = strings.TrimSuffix(part, ";")
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func containsStringLocal(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func blockerMessagePort(message string) string {
	re := regexp.MustCompile(`TCP/([A-Za-z0-9_.:-]+)`)
	if match := re.FindStringSubmatch(message); len(match) == 2 {
		return "TCP/" + match[1]
	}
	return "this port"
}

func after(value string, marker string) string {
	index := strings.Index(value, marker)
	if index < 0 {
		return ""
	}
	return value[index+len(marker):]
}

type ansiColors struct {
	enabled bool
}

func terminalColors() ansiColors {
	_, noColor := os.LookupEnv("NO_COLOR")
	if noColor {
		return ansiColors{}
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") != "" {
		return ansiColors{enabled: true}
	}
	term := os.Getenv("TERM")
	if term == "dumb" {
		return ansiColors{}
	}
	if runtime.GOOS == "windows" {
		return ansiColors{enabled: windowsANSISupported()}
	}
	return ansiColors{enabled: term != ""}
}

func windowsANSISupported() bool {
	if os.Getenv("WT_SESSION") != "" ||
		os.Getenv("ANSICON") != "" ||
		strings.EqualFold(os.Getenv("ConEmuANSI"), "ON") ||
		os.Getenv("COLORTERM") != "" ||
		os.Getenv("TERM_PROGRAM") != "" {
		return true
	}
	term := os.Getenv("TERM")
	return term != "" && term != "dumb"
}

func (c ansiColors) Bold(value string) string {
	if !c.enabled {
		return value
	}
	return "\x1b[1m" + value + "\x1b[0m"
}

func (c ansiColors) Status(status model.Status) string {
	if !c.enabled {
		return string(status)
	}
	code := "37"
	switch status {
	case model.StatusFail:
		code = "31"
	case model.StatusWarn:
		code = "33"
	case model.StatusPass:
		code = "32"
	case model.StatusInfo:
		code = "36"
	case model.StatusSkip:
		code = "35"
	}
	return "\x1b[" + code + ";1m" + string(status) + "\x1b[0m"
}

func (c ansiColors) Verdict(value string) string {
	if !c.enabled {
		return value
	}
	code := "32"
	switch value {
	case "BLOCKED":
		code = "31"
	case "RISK":
		code = "33"
	}
	return "\x1b[" + code + ";1m" + value + "\x1b[0m"
}

func (c ansiColors) Provider(value string) string {
	if !c.enabled {
		return value
	}
	return "\x1b[36;1m" + value + "\x1b[0m"
}

func (c ansiColors) Action(value string) string {
	if !c.enabled {
		return value
	}
	code := "37"
	switch strings.TrimSpace(value) {
	case "Deny", "Block":
		code = "31"
	case "Default deny":
		code = "33"
	case "Allow":
		code = "32"
	}
	return "\x1b[" + code + ";1m" + value + "\x1b[0m"
}

func WriteJSON(path string, r *model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func WriteHTML(path string, r *model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return htmlReport.Execute(file, struct {
		Report *model.Report
		Counts map[model.Status]int
	}{
		Report: r,
		Counts: counts(r),
	})
}

func counts(r *model.Report) map[model.Status]int {
	out := map[model.Status]int{}
	for _, result := range r.Results {
		out[result.Status]++
	}
	return out
}

func SortedStatuses(counts map[model.Status]int) []model.Status {
	statuses := make([]model.Status, 0, len(counts))
	for status := range counts {
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		order := map[model.Status]int{
			model.StatusFail: 0,
			model.StatusWarn: 1,
			model.StatusPass: 2,
			model.StatusInfo: 3,
			model.StatusSkip: 4,
		}
		return order[statuses[i]] < order[statuses[j]]
	})
	return statuses
}

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"sortedStatuses": SortedStatuses,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KubeNetMods Report</title>
<style>
:root { color-scheme: dark; --bg:#0b1017; --panel:#151c25; --line:#2b3542; --text:#f4f7fb; --muted:#aab6c5; --fail:#ff5c67; --warn:#f0b84a; --pass:#39d98a; --info:#66aaff; --skip:#a78bfa; }
body { margin:0; font-family:Segoe UI, system-ui, sans-serif; background:var(--bg); color:var(--text); }
main { max-width:1180px; margin:0 auto; padding:32px 24px 56px; }
h1 { margin:0 0 18px; font-size:32px; }
h2 { margin:28px 0 12px; }
.grid { display:grid; grid-template-columns:1.2fr .8fr; gap:16px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }
.meta { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; }
.meta div { border:1px solid var(--line); border-radius:6px; padding:10px; color:var(--muted); }
code { background:#202a36; color:var(--text); border-radius:4px; padding:2px 6px; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th, td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { color:var(--muted); font-size:13px; }
tr:last-child td { border-bottom:0; }
.status { font-weight:700; }
.PASS { color:var(--pass); } .FAIL { color:var(--fail); } .WARN { color:var(--warn); } .INFO { color:var(--info); } .SKIP { color:var(--skip); }
.diag { border-left:4px solid var(--fail); }
.muted { color:var(--muted); }
@media (max-width: 850px) { .grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main>
<h1>KubeNetMods Report</h1>
<div class="grid">
  <section class="card diag">
    <h2>Diagnosis</h2>
    {{if .Report.Diagnoses}}
      <ul>{{range .Report.Diagnoses}}<li>{{.Message}}</li>{{end}}</ul>
    {{else}}
      <p class="muted">No dominant diagnosis was inferred.</p>
    {{end}}
  </section>
  <section class="card">
    <h2>Target</h2>
    <div class="meta">
      <div>Command<br><code>{{.Report.Command}}</code></div>
      <div>Namespace<br><code>{{.Report.Target.Namespace}}</code></div>
      <div>Service<br><code>{{.Report.Target.Service}}</code></div>
      {{if .Report.Target.Deployment}}<div>Deployment<br><code>{{.Report.Target.Deployment}}</code></div>{{end}}
      {{if .Report.Target.ServicePort}}<div>Service Port<br><code>{{.Report.Target.ServicePort}}</code></div>{{end}}
      {{if .Report.Target.Context}}<div>Context<br><code>{{.Report.Target.Context}}</code></div>{{end}}
      {{if .Report.Target.SourceContext}}<div>Source Context<br><code>{{.Report.Target.SourceContext}}</code></div>{{end}}
      {{if .Report.Target.SourceNS}}<div>Source Namespace<br><code>{{.Report.Target.SourceNS}}</code></div>{{end}}
      {{if .Report.Target.SourcePod}}<div>Source Pod<br><code>{{.Report.Target.SourcePod}}</code></div>{{end}}
      {{if .Report.Target.SourceSelector}}<div>Source Selector<br><code>{{.Report.Target.SourceSelector}}</code></div>{{end}}
      <div>Timestamp<br><code>{{.Report.Timestamp.Format "2006-01-02 15:04:05 MST"}}</code></div>
    </div>
  </section>
</div>
<section class="card" style="margin-top:16px">
  <h2>Summary</h2>
  {{range $status := sortedStatuses .Counts}}<span class="status {{$status}}">{{$status}}: {{index $.Counts $status}}</span>&nbsp;&nbsp;{{end}}
</section>
<h2>Results</h2>
<table>
  <thead><tr><th>Layer</th><th>Check</th><th>Status</th><th>Message</th></tr></thead>
  <tbody>{{range .Report.Results}}<tr><td>{{.Layer}}</td><td>{{.Check}}</td><td class="status {{.Status}}">{{.Status}}</td><td>{{.Message}}</td></tr>{{end}}</tbody>
</table>
{{if .Report.Limitations}}
<h2>Limitations</h2>
<ul>{{range .Report.Limitations}}<li class="muted">{{.}}</li>{{end}}</ul>
{{end}}
</main>
</body>
</html>`))
