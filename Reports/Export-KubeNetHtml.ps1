function Export-KubeNetHtml {
    param([object]$Report, [string]$Path)

    function HtmlEncode([string]$Text) {
        if ($null -eq $Text) { return '' }
        [System.Net.WebUtility]::HtmlEncode($Text)
    }

    function InlineCode([string]$Text) {
        $encoded = HtmlEncode $Text
        $encoded -replace '`([^`]+)`', '<code>$1</code>'
    }

    function StatusClass([string]$Status) {
        "status status-$($Status.ToLowerInvariant())"
    }

    $targetRows = foreach ($property in $Report.Target.PSObject.Properties) {
        "<tr><th>$(HtmlEncode $property.Name)</th><td><code>$(HtmlEncode ([string]$property.Value))</code></td></tr>"
    }
    $diagnoses = if ($Report.Diagnoses.Count -gt 0) {
        foreach ($diagnosis in $Report.Diagnoses) { "<li>$(InlineCode $diagnosis)</li>" }
    } else {
        '<li>No dominant diagnosis inferred.</li>'
    }
    $summaryCards = foreach ($item in $Report.StatusSummary) {
        "<div class='stat'><span class='$(StatusClass $item.Status)'>$(HtmlEncode $item.Status)</span><strong>$($item.Count)</strong></div>"
    }
    $failureRows = if ($Report.Failures.Count -gt 0) {
        foreach ($result in $Report.Failures) {
            "<tr><td>$(HtmlEncode $result.Layer)</td><td>$(HtmlEncode $result.Check)</td><td><span class='$(StatusClass $result.Status)'>$(HtmlEncode $result.Status)</span></td><td>$(InlineCode $result.Message)</td></tr>"
        }
    } else {
        "<tr><td colspan='4'>No failures found.</td></tr>"
    }
    $warningRows = if ($Report.Warnings.Count -gt 0) {
        foreach ($result in $Report.Warnings) {
            "<tr><td>$(HtmlEncode $result.Layer)</td><td>$(HtmlEncode $result.Check)</td><td><span class='$(StatusClass $result.Status)'>$(HtmlEncode $result.Status)</span></td><td>$(InlineCode $result.Message)</td></tr>"
        }
    } else {
        "<tr><td colspan='4'>No warnings found.</td></tr>"
    }
    $layerSections = foreach ($group in $Report.RawResults | Group-Object Layer) {
        $rows = foreach ($result in $group.Group) {
            "<tr><td>$(HtmlEncode $result.Check)</td><td><span class='$(StatusClass $result.Status)'>$(HtmlEncode $result.Status)</span></td><td>$(InlineCode $result.Message)</td></tr>"
        }
        "<section class='panel'><h2>$(HtmlEncode $group.Name)</h2><table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></section>"
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KubeNetMods Report</title>
<style>
:root { color-scheme: dark; --bg:#0b1117; --panel:#141b23; --line:#2b3542; --text:#f0f5fb; --muted:#9fb0c3; --pass:#44d07b; --fail:#ff5d62; --warn:#ffcc66; --skip:#a78bfa; --info:#65b7ff; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:Segoe UI, Arial, sans-serif; line-height:1.45; }
main { width:min(1260px, calc(100vw - 48px)); margin:28px auto 44px; }
h1 { margin:0 0 22px; font-size:34px; }
h2 { margin:0 0 14px; font-size:21px; }
.grid { display:grid; grid-template-columns:minmax(0, 1.4fr) minmax(360px, .9fr); gap:16px; align-items:start; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; margin-bottom:16px; overflow:auto; }
.diagnosis { border-left:4px solid var(--warn); }
.stats { display:flex; flex-wrap:wrap; gap:10px; }
.stat { min-width:110px; border:1px solid var(--line); border-radius:8px; padding:10px 12px; display:flex; justify-content:space-between; align-items:center; gap:14px; }
table { width:100%; border-collapse:collapse; }
th,td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.meta-table th { width:190px; }
code { background:#26313d; border-radius:4px; padding:2px 5px; color:#f7fafc; }
.status { font-weight:700; font-size:12px; letter-spacing:.02em; }
.status-pass { color:var(--pass); }
.status-fail { color:var(--fail); }
.status-warn { color:var(--warn); }
.status-skip { color:var(--skip); }
.status-info { color:var(--info); }
li + li { margin-top:8px; }
@media (max-width: 900px) { main { width:min(100vw - 24px, 1260px); } .grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main>
<h1>KubeNetMods Network Check</h1>
<section class="grid">
<div class="panel diagnosis"><h2>Diagnosis</h2><ul>$($diagnoses -join "`n")</ul></div>
<div class="panel"><h2>Target</h2><table class="meta-table"><tbody>$($targetRows -join "`n")</tbody></table></div>
</section>
<section class="panel"><h2>Status Summary</h2><div class="stats">$($summaryCards -join "`n")</div></section>
<section class="panel"><h2>Failures</h2><table><thead><tr><th>Layer</th><th>Check</th><th>Status</th><th>Message</th></tr></thead><tbody>$($failureRows -join "`n")</tbody></table></section>
<section class="panel"><h2>Warnings</h2><table><thead><tr><th>Layer</th><th>Check</th><th>Status</th><th>Message</th></tr></thead><tbody>$($warningRows -join "`n")</tbody></table></section>
<h2 style="margin-top:28px">Results By Layer</h2>
$($layerSections -join "`n")
</main>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $Path -Encoding UTF8
}
