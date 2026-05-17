# Reports

KubeNetMods can export reports as HTML, JSON, or PowerShell objects.

## HTML

HTML reports are for humans.

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -ExportHtml .\reports\postgres-path.html
```

The HTML report includes:

- diagnosis
- run metadata
- status summary
- failures
- warnings
- results grouped by layer

## JSON

JSON reports are for automation and later tooling.

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -ExportJson .\reports\postgres-path.json
```

## PassThru

Use `-PassThru` to get the report object directly:

```powershell
$report = Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -PassThru

$report.Diagnoses
$report.Failures
```

## Report Shape

All public diagnostic commands return the same top-level shape:

```text
Target
Diagnoses
StatusSummary
Failures
Warnings
RawResults
ExitCode
```

`Target` currently contains command metadata. The name is retained for compatibility with the existing report renderer.

## Verbose

Use `-Verbose` to see underlying Kubernetes commands:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -Verbose
```

## Status Meanings

| Status | Meaning |
|---|---|
| `FAIL` | A deterministic config problem or runtime test failure. |
| `WARN` | Suspicious configuration that may matter, but is not proven broken. |
| `PASS` | The check succeeded. |
| `SKIP` | The check did not apply or was disabled. |
| `INFO` | Context collected for the report. |

## Examples

Example reports live in [`../examples/reports`](../examples/reports).
